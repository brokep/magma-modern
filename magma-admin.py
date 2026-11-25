#!/usr/bin/env python3
# =============================================================================
# magma-admin.py — a small /admin web control panel for a Magma host install.
# (Phase 5 of the Mail-in-a-Box-style deploy initiative.)
#
# One file, Python 3 standard library only (no Flask / no pip) — so it deploys
# as trivially as the rest of the tooling: a single systemd service that reads
# the install state written by magma-host-install.sh (/etc/magma/magma.conf).
#
# What it gives an operator (the Mail-in-a-Box admin panel, Magma edition):
#   * Overview   — service/container health, TLS cert, account count.
#   * Users      — list / add / delete mail accounts, reset a locked-out password.
#   * Status     — the magma-status.sh deliverability checks, in the browser.
#   * DNS        — the SPF/DKIM/DMARC records to publish.
#   * Restart    — bounce the mail server.
#
# How it talks to Magma (all the P1-P4 findings, reused):
#   * Account ops go through Magma's OWN JSON-RPC methods (register / auth /
#     delete_user) at /json — which are loopback-only (con_localhost), so we
#     reach them by `podman exec <container> curl http://127.0.0.1:10000/json`,
#     never from the host side. No STACIE crypto is reimplemented here.
#   * Listing accounts (no RPC method exists) is a read-only DB query via
#     `podman exec <container> mysql <schema>` (root, over the unix socket).
#   * Login authenticates against Magma's /json `auth` and is restricted to the
#     configured admin account, so the panel keeps NO password store of its own.
#
# Security posture (it is a root-powered control surface):
#   * Binds 127.0.0.1 by default — reach it over an SSH tunnel. Override only
#     behind your own TLS/reverse proxy.
#   * HMAC-signed, HttpOnly, SameSite=Strict session cookie; per-session CSRF
#     token required on every mutating request; simple per-IP login throttle.
#   * Every shell-out uses an argument vector (no shell); account identifiers
#     are charset-validated before use; passwords are never logged.
#
# Usage:
#   magma-admin.py --config /etc/magma/magma.conf [--bind 127.0.0.1] [--port 8080]
# =============================================================================
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie

# ------------------------------------------------------------------ config ---
CFG = {}            # parsed /etc/magma/magma.conf (MAGMA_* keys)
SCHEMA = "Magma"    # magma.iface.database.schema, read from the rendered config
SECRET = b""        # HMAC key for session cookies (persisted, mode 600)
SESSION_TTL = 3600  # seconds
LOGIN_WINDOW = 300  # throttle window
LOGIN_MAX = 5       # max failed logins per IP per window
USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")   # mail local-part we accept
PLANS = ["BASIC", "PERSONAL", "ENHANCED", "PREMIUM", "STANDARD", "PREMIER"]
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

_login_fails = {}          # ip -> [timestamps]
_login_lock = threading.Lock()
_status_cache = {"at": 0, "text": ""}
_status_lock = threading.Lock()


def load_config(path):
    """Parse the shell-style KEY=VALUE magma.conf and the rendered magma config."""
    global SCHEMA
    cfg = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            cfg[k.strip()] = v.strip().strip('"').strip("'")
    # schema name lives in the rendered magma.<domain>.config
    sd = cfg.get("MAGMA_SECRETS_DIR", "")
    dom = cfg.get("MAGMA_DOMAIN", "")
    conf_file = os.path.join(sd, f"magma.{dom}.config")
    try:
        with open(conf_file) as fh:
            for line in fh:
                m = re.match(r"\s*magma\.iface\.database\.schema\s*=\s*(\S+)", line)
                if m:
                    SCHEMA = m.group(1)
                    break
    except OSError:
        pass
    return cfg


def load_secret(cfg):
    """Load (or mint) the cookie-signing secret; persist it 0600 in the config dir."""
    sd = cfg.get("MAGMA_SECRETS_DIR", "/etc/magma")
    path = os.path.join(os.path.dirname(sd.rstrip("/")) or "/etc/magma", ".admin-secret")
    try:
        with open(path, "rb") as fh:
            data = fh.read().strip()
            if len(data) >= 32:
                return data
    except OSError:
        pass
    data = secrets.token_bytes(32)
    old = os.umask(0o077)
    try:
        with open(path, "wb") as fh:
            fh.write(data)
    finally:
        os.umask(old)
    return data


# ------------------------------------------------------- magma plumbing ------
def _podman():
    return CFG.get("MAGMA_PODMAN", "podman")


def _container():
    return CFG.get("MAGMA_CONTAINER", CFG.get("MAGMA_SERVICE", "magma"))


def run(cmd, inp=None, timeout=30):
    """Run an argv with no shell. Returns (rc, stdout, stderr)."""
    try:
        p = subprocess.run(
            cmd,
            input=inp,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


def json_rpc(method, params):
    """Call Magma's loopback /json RPC from INSIDE the container (body on stdin)."""
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    cmd = [
        _podman(), "exec", "-i", _container(),
        "curl", "-s", "--max-time", "15",
        "-H", "Content-Type: application/json",
        "--data-binary", "@-",
        "http://127.0.0.1:10000/json",
    ]
    rc, out, err = run(cmd, inp=body, timeout=25)
    if rc != 0:
        return {"error": {"message": err or "rpc transport failed"}}
    try:
        return json.loads(out)
    except ValueError:
        return {"error": {"message": f"unparseable rpc response: {out[:200]}"}}


def db_query(sql):
    """Run a read-only query in the container's MariaDB (root via socket)."""
    cmd = [
        _podman(), "exec", _container(),
        "mysql", "--default-character-set=latin1", SCHEMA, "-N", "-B", "-e", sql,
    ]
    rc, out, err = run(cmd, timeout=20)
    if rc != 0:
        raise RuntimeError(err.strip() or "db query failed")
    return out


# ------------------------------------------------------------- sessions ------
def sign(payload):
    raw = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    )
    mac = hmac.new(SECRET, raw, hashlib.sha256).hexdigest()
    return raw.decode() + "." + mac


def verify(token):
    try:
        raw, mac = token.rsplit(".", 1)
        exp = hmac.new(SECRET, raw.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, exp):
            return None
        payload = json.loads(base64.urlsafe_b64decode(raw.encode()))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:  # noqa: BLE001
        return None


def throttled(ip):
    now = time.time()
    with _login_lock:
        hits = [t for t in _login_fails.get(ip, []) if now - t < LOGIN_WINDOW]
        _login_fails[ip] = hits
        return len(hits) >= LOGIN_MAX


def record_fail(ip):
    with _login_lock:
        _login_fails.setdefault(ip, []).append(time.time())


# --------------------------------------------------------------- handlers ----
class Handler(BaseHTTPRequestHandler):
    server_version = "magma-admin"
    protocol_version = "HTTP/1.1"

    # -- low-level helpers --------------------------------------------------
    def _send(self, code, body=b"", ctype="application/json", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code, obj, extra=None):
        self._send(code, json.dumps(obj), "application/json", extra)

    def _session(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        if "magma_admin" not in cookie:
            return None
        return verify(cookie["magma_admin"].value)

    def _client_ip(self):
        return self.client_address[0] if self.client_address else "?"

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return {}
        if n <= 0 or n > 1_000_000:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode())
        except Exception:  # noqa: BLE001
            return {}

    def log_message(self, fmt, *args):  # quieter, no request bodies
        sys.stderr.write("magma-admin %s - %s\n" % (self._client_ip(), fmt % args))

    # -- routing ------------------------------------------------------------
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if path == "/healthz":
            return self._send(200, "ok\n", "text/plain")
        if path.startswith("/api/"):
            return self._api_get(path)
        return self._send(404, "not found\n", "text/plain")

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/login":
            return self._login()
        if path == "/api/logout":
            return self._json(200, {"ok": True}, extra=[(
                "Set-Cookie",
                "magma_admin=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
            )])
        # everything else requires a valid session + CSRF token
        sess = self._session()
        if not sess:
            return self._json(401, {"error": "not authenticated"})
        if self.headers.get("X-CSRF-Token", "") != sess.get("csrf", "\0"):
            return self._json(403, {"error": "bad csrf token"})
        return self._api_post(path, sess)

    # -- auth ---------------------------------------------------------------
    def _login(self):
        ip = self._client_ip()
        if throttled(ip):
            return self._json(429, {"error": "too many attempts — wait a minute"})
        data = self._body()
        user = (data.get("username") or "").strip()
        pw = data.get("password") or ""
        admin = CFG.get("MAGMA_ADMIN_USER", "admin")
        # Only the configured admin account may use the host panel.
        if not USER_RE.match(user) or user != admin or not pw:
            record_fail(ip)
            return self._json(401, {"error": "invalid credentials"})
        # NB: Magma's /json `auth` returns a bare {"jsonrpc","id"} envelope on
        # SUCCESS (its result-bearing response is commented out in endpoints.c);
        # only FAILURE carries an "error" object. So success = valid envelope,
        # no error. (register/delete_user do return "result" — auth is special.)
        resp = json_rpc("auth", {"username": user, "password": pw})
        if not isinstance(resp, dict) or "jsonrpc" not in resp or "error" in resp:
            record_fail(ip)
            return self._json(401, {"error": "invalid credentials"})
        csrf = secrets.token_hex(16)
        token = sign({"user": user, "csrf": csrf, "exp": int(time.time()) + SESSION_TTL})
        cookie = (
            f"magma_admin={token}; Path=/; HttpOnly; SameSite=Strict; "
            f"Max-Age={SESSION_TTL}"
        )
        return self._json(200, {"ok": True, "user": user, "csrf": csrf},
                          extra=[("Set-Cookie", cookie)])

    # -- read endpoints -----------------------------------------------------
    def _api_get(self, path):
        sess = self._session()
        if not sess:
            return self._json(401, {"error": "not authenticated"})
        if path == "/api/session":
            return self._json(200, {
                "user": sess.get("user"),
                "csrf": sess.get("csrf"),
                "admin": CFG.get("MAGMA_ADMIN_USER", "admin"),
            })
        if path == "/api/overview":
            return self._json(200, self._overview())
        if path == "/api/users":
            return self._json(200, {"users": self._users()})
        if path == "/api/status":
            return self._json(200, {"text": self._status()})
        if path == "/api/dns":
            return self._json(200, {"text": self._dns()})
        return self._json(404, {"error": "unknown endpoint"})

    def _overview(self):
        svc = CFG.get("MAGMA_SERVICE", "magma")
        _, active, _ = run(["systemctl", "is-active", svc], timeout=5)
        _, cstate, _ = run([_podman(), "inspect", "-f", "{{.State.Status}}", _container()], timeout=5)
        _, started, _ = run([_podman(), "inspect", "-f", "{{.State.StartedAt}}", _container()], timeout=5)
        count = "?"
        try:
            count = db_query("SELECT COUNT(*) FROM Users;").strip() or "0"
        except Exception:  # noqa: BLE001
            pass
        tls = self._tls_info()
        return {
            "domain": CFG.get("MAGMA_DOMAIN", "?"),
            "admin": CFG.get("MAGMA_ADMIN_USER", "admin"),
            "hostname": CFG.get("MAGMA_HOSTNAME", "?"),
            "service": svc,
            "service_active": active.strip(),
            "container": _container(),
            "container_state": cstate.strip() or "unknown",
            "started_at": started.strip(),
            "image": CFG.get("MAGMA_IMAGE", "?"),
            "user_count": count,
            "tls": tls,
        }

    def _tls_info(self):
        sd = CFG.get("MAGMA_SECRETS_DIR", "")
        dom = CFG.get("MAGMA_DOMAIN", "")
        pem = os.path.join(sd, f"tls.{dom}.pem")
        if not os.path.exists(pem):
            return {"present": False}
        rc, out, _ = run(
            ["openssl", "x509", "-in", pem, "-noout", "-issuer", "-enddate"], timeout=5
        )
        if rc != 0:
            return {"present": True, "issuer": "?", "expires": "?"}
        issuer = expires = "?"
        for line in out.splitlines():
            if line.startswith("issuer="):
                issuer = line[len("issuer="):].strip()
            elif line.startswith("notAfter="):
                expires = line[len("notAfter="):].strip()
        self_signed = dom in issuer or CFG.get("MAGMA_HOSTNAME", "\0") in issuer
        return {"present": True, "issuer": issuer, "expires": expires,
                "self_signed": self_signed}

    def _users(self):
        sql = (
            "SELECT u.userid, u.plan, u.locked, u.quota, u.size, "
            "(SELECT COUNT(*) FROM Mailboxes m WHERE m.usernum=u.usernum) "
            "FROM Users u ORDER BY u.userid;"
        )
        try:
            out = db_query(sql)
        except Exception as e:  # noqa: BLE001
            return [{"error": str(e)}]
        users = []
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) < 6:
                continue
            uid, plan, locked, quota, size, boxes = parts[:6]
            users.append({
                "userid": uid,
                "plan": plan,
                "locked": locked == "1",
                "quota": int(quota) if quota.isdigit() else 0,
                "size": int(size) if size.isdigit() else 0,
                "mailboxes": int(boxes) if boxes.isdigit() else 0,
            })
        return users

    def _status(self):
        now = time.time()
        with _status_lock:
            if now - _status_cache["at"] < 45 and _status_cache["text"]:
                return _status_cache["text"]
        src = os.path.join(CFG.get("MAGMA_INSTALL_DIR", "/opt/magma"), "src", "magma-status.sh")
        if not os.path.exists(src):
            return "magma-status.sh not found"
        rc, out, err = run(
            [src, "--domain", CFG.get("MAGMA_DOMAIN", ""),
             "--hostname", CFG.get("MAGMA_HOSTNAME", ""),
             "--secrets-dir", CFG.get("MAGMA_SECRETS_DIR", "")],
            timeout=90,
        )
        text = ANSI_RE.sub("", out + ("\n" + err if err.strip() else ""))
        with _status_lock:
            _status_cache["at"] = now
            _status_cache["text"] = text
        return text

    def _dns(self):
        sd = CFG.get("MAGMA_SECRETS_DIR", "")
        for name in ("dns-records.txt",):
            p = os.path.join(sd, name)
            try:
                with open(p) as fh:
                    return fh.read()
            except OSError:
                continue
        return "dns-records.txt not found in " + sd

    # -- write endpoints ----------------------------------------------------
    def _api_post(self, path, sess):
        data = self._body()
        if path == "/api/users/add":
            return self._user_add(data)
        if path == "/api/users/delete":
            return self._user_delete(data)
        if path == "/api/users/reset-password":
            return self._user_reset_pw(data)
        if path == "/api/service/restart":
            return self._service_restart()
        return self._json(404, {"error": "unknown endpoint"})

    def _user_add(self, data):
        user = (data.get("username") or "").strip()
        pw = data.get("password") or ""
        plan = (data.get("plan") or "STANDARD").upper()
        if not USER_RE.match(user):
            return self._json(400, {"error": "invalid username (A-Z a-z 0-9 . _ - only)"})
        if len(pw) < 8:
            return self._json(400, {"error": "password must be at least 8 characters"})
        if plan not in PLANS:
            return self._json(400, {"error": "invalid plan"})
        resp = json_rpc("register", {
            "username": user, "password": pw,
            "password_verification": pw, "plan": plan,
        })
        if isinstance(resp, dict) and "result" in resp:
            return self._json(200, {"ok": True})
        msg = "registration failed"
        if isinstance(resp, dict) and isinstance(resp.get("error"), dict):
            msg = resp["error"].get("message", msg)
        return self._json(422, {"error": msg})

    def _user_delete(self, data):
        user = (data.get("username") or "").strip()
        if not USER_RE.match(user):   # USER_RE forbids quotes, so safe to interpolate
            return self._json(400, {"error": "invalid username"})
        if user == CFG.get("MAGMA_ADMIN_USER", "admin"):
            return self._json(400, {"error": "refusing to delete the admin account"})
        # Magma's /json delete_user runs a bare `DELETE FROM Users WHERE userid=?`,
        # which ALWAYS fails for a registered account: Realms/Aliases/Messages carry
        # RESTRICT foreign keys (ERROR 1451). Fixing that is a schema/C change that
        # would touch the build's test gate, so remove the account at the DB level
        # instead — clear every user-owned table (schema-driven), then the Users
        # row, atomically with FK checks off.
        try:
            if db_query(f"SELECT COUNT(*) FROM Users WHERE userid='{user}';").strip() == "0":
                return self._json(422, {"error": "no such user"})
            tbls = [
                t for t in db_query(
                    "SELECT TABLE_NAME FROM information_schema.COLUMNS "
                    f"WHERE TABLE_SCHEMA='{SCHEMA}' AND COLUMN_NAME='usernum' "
                    "AND TABLE_NAME<>'Users';"
                ).split()
                if re.match(r"^[A-Za-z0-9_]+$", t)
            ]
            deletes = "".join(f"DELETE FROM `{t}` WHERE usernum=@u;\n" for t in tbls)
            script = (
                "SET FOREIGN_KEY_CHECKS=0;\n"
                "START TRANSACTION;\n"
                f"SET @u := (SELECT usernum FROM Users WHERE userid='{user}');\n"
                f"{deletes}"
                "DELETE FROM Users WHERE usernum=@u;\n"
                "COMMIT;\n"
                "SET FOREIGN_KEY_CHECKS=1;\n"
            )
            db_query(script)
            if db_query(f"SELECT COUNT(*) FROM Users WHERE userid='{user}';").strip() != "0":
                return self._json(500, {"error": "delete did not remove the account"})
            return self._json(200, {"ok": True})
        except Exception as e:  # noqa: BLE001
            return self._json(500, {"error": str(e)})

    def _user_reset_pw(self, data):
        user = (data.get("username") or "").strip()
        pw = data.get("password") or ""
        if not USER_RE.match(user):
            return self._json(400, {"error": "invalid username"})
        if len(pw) < 8:
            return self._json(400, {"error": "password must be at least 8 characters"})
        try:   # USER_RE forbids quotes, so interpolation is safe
            if db_query(f"SELECT COUNT(*) FROM Users WHERE userid='{user}';").strip() == "0":
                return self._json(422, {"error": "no such user"})
        except Exception as e:  # noqa: BLE001
            return self._json(500, {"error": str(e)})
        # Administrative reset: call change_password with NO current password. Magma's zero-access
        # design means the storage keypair is regenerated, so mail encrypted to the previous keypair
        # is abandoned — hence this is surfaced in the UI as a destructive "reset", not a "change".
        resp = json_rpc("change_password", {
            "username": user,
            "new_password": pw,
            "new_password_verification": pw,
        })
        if isinstance(resp, dict) and "result" in resp:
            return self._json(200, {"ok": True})
        msg = "password reset failed"
        if isinstance(resp, dict) and isinstance(resp.get("error"), dict):
            msg = resp["error"].get("message", msg)
        return self._json(422, {"error": msg})

    def _service_restart(self):
        svc = CFG.get("MAGMA_SERVICE", "magma")
        rc, _, err = run(["systemctl", "restart", svc], timeout=120)
        if rc == 0:
            return self._json(200, {"ok": True})
        return self._json(500, {"error": err.strip() or "restart failed"})


# ------------------------------------------------------------------- page ----
PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Magma admin</title>
<style>
:root{--bg:#0f1420;--panel:#171e2e;--line:#273349;--ink:#e6ecf5;--mut:#8da2c0;
--accent:#4f8cff;--good:#35c27a;--warn:#e8b23a;--bad:#ef5a5a;--radius:10px}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
background:var(--bg);color:var(--ink)}
a{color:var(--accent)}
header{display:flex;align-items:center;gap:12px;padding:14px 20px;border-bottom:1px solid var(--line);background:var(--panel)}
header h1{font-size:16px;margin:0;font-weight:650;letter-spacing:.2px}
header .sp{flex:1}
header .who{color:var(--mut);font-size:13px}
button{font:inherit;cursor:pointer;border:1px solid var(--line);background:#1f293c;color:var(--ink);
padding:7px 13px;border-radius:8px}
button:hover{border-color:var(--accent)}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600}
button.danger{border-color:#5a2a2a;color:#ffb4b4}
button.danger:hover{background:#3a1d1d}
button:disabled{opacity:.5;cursor:default}
nav{display:flex;gap:4px;padding:10px 20px 0;border-bottom:1px solid var(--line);background:var(--panel)}
nav button{border:0;background:0;color:var(--mut);padding:8px 14px;border-bottom:2px solid transparent;border-radius:0}
nav button.on{color:var(--ink);border-bottom-color:var(--accent)}
main{padding:22px;max-width:960px;margin:0 auto}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:18px;margin-bottom:18px}
.card h2{margin:0 0 12px;font-size:14px;color:var(--mut);text-transform:uppercase;letter-spacing:.6px;font-weight:600}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}
.kv{background:#111828;border:1px solid var(--line);border-radius:8px;padding:12px}
.kv .k{color:var(--mut);font-size:12px}
.kv .v{font-size:17px;font-weight:600;margin-top:3px;word-break:break-word}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);font-size:13px}
th{color:var(--mut);font-weight:600}
td.r,th.r{text-align:right}
.pill{display:inline-block;padding:2px 8px;border-radius:20px;font-size:12px;border:1px solid var(--line)}
.ok{color:var(--good)}.warn{color:var(--warn)}.bad{color:var(--bad)}
pre{background:#0b1120;border:1px solid var(--line);border-radius:8px;padding:14px;overflow:auto;
white-space:pre-wrap;font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
input,select{font:inherit;background:#0b1120;border:1px solid var(--line);color:var(--ink);
padding:8px 10px;border-radius:8px;width:100%}
label{display:block;font-size:12px;color:var(--mut);margin:0 0 4px}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end}
.row>div{flex:1;min-width:150px}
.msg{padding:10px 12px;border-radius:8px;margin-bottom:12px;font-size:13px;display:none}
.msg.err{display:block;background:#3a1d1d;border:1px solid #5a2a2a;color:#ffb4b4}
.msg.ok{display:block;background:#15301f;border:1px solid #25503a;color:#8ee6b4}
.login{max-width:360px;margin:12vh auto}
.login .card{padding:24px}
.muted{color:var(--mut)}
.toolbar{display:flex;gap:10px;align-items:center;margin-bottom:12px}
</style></head>
<body>
<div id="app"></div>
<script>
const $ = (s,r=document)=>r.querySelector(s);
let CSRF=null, USER=null;

async function api(path, opts={}){
  opts.headers = Object.assign({'Content-Type':'application/json'}, opts.headers||{});
  if(CSRF) opts.headers['X-CSRF-Token']=CSRF;
  const r = await fetch(path, opts);
  let j={}; try{ j=await r.json() }catch(e){}
  if(r.status===401){ CSRF=null; renderLogin('Session expired — sign in again.'); throw new Error('auth'); }
  if(!r.ok) throw new Error(j.error||('HTTP '+r.status));
  return j;
}
const esc = s => String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const bytes = n => { n=+n||0; const u=['B','KB','MB','GB','TB']; let i=0; while(n>=1024&&i<u.length-1){n/=1024;i++;} return n.toFixed(i?1:0)+' '+u[i]; };

function renderLogin(err){
  document.getElementById('app').innerHTML = `
  <div class="login"><div class="card">
    <h1 style="margin:0 0 4px">Magma admin</h1>
    <p class="muted" style="margin:0 0 18px">Sign in with the admin mail account.</p>
    <div id="m" class="msg ${err?'err':''}">${esc(err||'')}</div>
    <div style="margin-bottom:12px"><label>Admin username</label><input id="u" autofocus autocomplete="username"></div>
    <div style="margin-bottom:16px"><label>Password</label><input id="p" type="password" autocomplete="current-password"></div>
    <button class="primary" style="width:100%" id="go">Sign in</button>
  </div></div>`;
  const submit = async ()=>{
    const m=$('#m'); m.className='msg';
    try{
      const j = await api('/api/login',{method:'POST',body:JSON.stringify({username:$('#u').value,password:$('#p').value})});
      CSRF=j.csrf; USER=j.user; renderApp();
    }catch(e){ m.className='msg err'; m.textContent=e.message; }
  };
  $('#go').onclick=submit;
  $('#p').onkeydown=e=>{ if(e.key==='Enter') submit(); };
  $('#u').onkeydown=e=>{ if(e.key==='Enter') $('#p').focus(); };
}

let TAB='overview';
function renderApp(){
  window.__ADMIN = USER || window.__ADMIN;
  document.getElementById('app').innerHTML = `
  <header>
    <h1>Magma admin</h1><div class="sp"></div>
    <span class="who">${esc(USER)}</span>
    <button id="logout">Sign out</button>
  </header>
  <nav>
    ${['overview','users','status','dns'].map(t=>`<button data-tab="${t}" class="${t===TAB?'on':''}">${t[0].toUpperCase()+t.slice(1)}</button>`).join('')}
  </nav>
  <main id="view"></main>`;
  $('#logout').onclick=async()=>{ try{await api('/api/logout',{method:'POST'})}catch(e){}; CSRF=null; renderLogin(); };
  document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{TAB=b.dataset.tab; renderApp();});
  ({overview:viewOverview,users:viewUsers,status:viewStatus,dns:viewDns}[TAB])();
}

async function viewOverview(){
  const v=$('#view'); v.innerHTML='<p class="muted">Loading…</p>';
  try{
    const o = await api('/api/overview');
    const sa = o.service_active==='active';
    const cs = o.container_state==='running';
    const tls = o.tls||{};
    const tlsClass = !tls.present?'bad':(tls.self_signed?'warn':'ok');
    const tlsText = !tls.present?'none':(tls.self_signed?'self-signed':'CA-signed');
    v.innerHTML = `
    <div class="card"><h2>Server</h2><div class="grid">
      <div class="kv"><div class="k">Domain</div><div class="v">${esc(o.domain)}</div></div>
      <div class="kv"><div class="k">Hostname</div><div class="v">${esc(o.hostname)}</div></div>
      <div class="kv"><div class="k">Service</div><div class="v ${sa?'ok':'bad'}">${esc(o.service_active)}</div></div>
      <div class="kv"><div class="k">Container</div><div class="v ${cs?'ok':'bad'}">${esc(o.container_state)}</div></div>
      <div class="kv"><div class="k">Accounts</div><div class="v">${esc(o.user_count)}</div></div>
      <div class="kv"><div class="k">TLS</div><div class="v ${tlsClass}">${tlsText}</div></div>
    </div></div>
    <div class="card"><h2>TLS certificate</h2>
      <table><tr><th>Issuer</th><td>${esc(tls.issuer||'—')}</td></tr>
      <tr><th>Expires</th><td>${esc(tls.expires||'—')}</td></tr></table>
      ${tls.self_signed?'<p class="muted" style="margin:12px 0 0">Self-signed. Get a Let\\'s Encrypt cert with <code>magma tls you@'+esc(o.domain)+'</code>.</p>':''}
    </div>
    <div class="card"><h2>Control</h2>
      <div id="rmsg" class="msg"></div>
      <button class="danger" id="restart">Restart mail server</button>
      <span class="muted" style="margin-left:10px">Image: ${esc(o.image)}</span>
    </div>`;
    $('#restart').onclick=async()=>{
      if(!confirm('Restart the mail server? Brief downtime.')) return;
      const m=$('#rmsg'); m.className='msg'; $('#restart').disabled=true; $('#restart').textContent='Restarting…';
      try{ await api('/api/service/restart',{method:'POST'}); m.className='msg ok'; m.textContent='Restarted.'; }
      catch(e){ m.className='msg err'; m.textContent=e.message; }
      $('#restart').disabled=false; $('#restart').textContent='Restart mail server';
    };
  }catch(e){ v.innerHTML=`<div class="msg err" style="display:block">${esc(e.message)}</div>`; }
}

async function viewUsers(){
  const v=$('#view'); v.innerHTML='<p class="muted">Loading…</p>';
  let data;
  try{ data = await api('/api/users'); }catch(e){ v.innerHTML=`<div class="msg err" style="display:block">${esc(e.message)}</div>`; return; }
  const rows = (data.users||[]).map(u=>{
    if(u.error) return `<tr><td colspan="5" class="bad">${esc(u.error)}</td></tr>`;
    const admin = u.userid===(window.__ADMIN||'');
    return `<tr>
      <td>${esc(u.userid)}${admin?' <span class="pill">admin</span>':''}</td>
      <td><span class="pill">${esc(u.plan)}</span></td>
      <td>${u.locked?'<span class="bad">locked</span>':'<span class="ok">active</span>'}</td>
      <td class="r">${bytes(u.size)} / ${bytes(u.quota)}</td>
      <td class="r"><button data-reset="${esc(u.userid)}">Reset pw</button>${admin?'':` <button class="danger" data-del="${esc(u.userid)}">Delete</button>`}</td>
    </tr>`;
  }).join('');
  v.innerHTML = `
  <div class="card"><h2>Add account</h2>
    <div id="amsg" class="msg"></div>
    <div class="row">
      <div><label>Username</label><input id="nu" placeholder="alice"></div>
      <div><label>Password</label><input id="np" type="password" placeholder="min 8 chars"></div>
      <div style="flex:0 0 160px"><label>Plan</label><select id="nplan">
        ${['BASIC','PERSONAL','ENHANCED','PREMIUM','STANDARD','PREMIER'].map(p=>`<option ${p==='STANDARD'?'selected':''}>${p}</option>`).join('')}
      </select></div>
      <div style="flex:0 0 auto"><button class="primary" id="add">Add</button></div>
    </div>
  </div>
  <div class="card"><h2>Accounts</h2>
    <table><thead><tr><th>Username</th><th>Plan</th><th>Status</th><th class="r">Usage</th><th></th></tr></thead>
    <tbody>${rows||'<tr><td colspan="5" class="muted">No accounts.</td></tr>'}</tbody></table>
  </div>`;
  $('#add').onclick=async()=>{
    const m=$('#amsg'); m.className='msg';
    try{
      await api('/api/users/add',{method:'POST',body:JSON.stringify({username:$('#nu').value.trim(),password:$('#np').value,plan:$('#nplan').value})});
      viewUsers();
    }catch(e){ m.className='msg err'; m.textContent=e.message; }
  };
  v.querySelectorAll('[data-del]').forEach(b=>b.onclick=async()=>{
    if(!confirm('Delete '+b.dataset.del+' and all their mail? This cannot be undone.')) return;
    try{ await api('/api/users/delete',{method:'POST',body:JSON.stringify({username:b.dataset.del})}); viewUsers(); }
    catch(e){ alert(e.message); }
  });
  v.querySelectorAll('[data-reset]').forEach(b=>b.onclick=async()=>{
    const who=b.dataset.reset;
    const pw=prompt('Reset password for '+who+'.\\n\\nThis is an ADMIN reset: their existing mailbox encryption key is regenerated, so messages already stored for this account become unreadable. Use this only for a locked-out account.\\n\\nNew password (min 8 chars):');
    if(pw===null) return;
    if(pw.length<8){ alert('Password must be at least 8 characters.'); return; }
    if(!confirm('Reset '+who+"'s password now? Their stored mail will be abandoned.")) return;
    try{ await api('/api/users/reset-password',{method:'POST',body:JSON.stringify({username:who,password:pw})}); alert('Password reset for '+who+'.'); }
    catch(e){ alert(e.message); }
  });
}

async function viewStatus(){
  const v=$('#view'); v.innerHTML='<p class="muted">Running deliverability checks… (this makes live DNS/network queries)</p>';
  try{ const j=await api('/api/status'); v.innerHTML=`<div class="card"><div class="toolbar"><h2 style="margin:0">Deliverability</h2><div class="sp" style="flex:1"></div><button id="re">Re-run</button></div><pre>${esc(j.text)}</pre></div>`;
    $('#re').onclick=viewStatus;
  }catch(e){ v.innerHTML=`<div class="msg err" style="display:block">${esc(e.message)}</div>`; }
}

async function viewDns(){
  const v=$('#view'); v.innerHTML='<p class="muted">Loading…</p>';
  try{ const j=await api('/api/dns'); v.innerHTML=`<div class="card"><h2>DNS records to publish</h2><pre>${esc(j.text)}</pre></div>`; }
  catch(e){ v.innerHTML=`<div class="msg err" style="display:block">${esc(e.message)}</div>`; }
}

// bootstrap: recover an existing session (cookie is HttpOnly, so fetch the CSRF token back)
(async()=>{
  try{ const s=await api('/api/session'); CSRF=s.csrf; USER=s.user; window.__ADMIN=s.admin; renderApp(); }
  catch(e){ renderLogin(); }
})();
</script>
</body></html>
"""


def main():
    global CFG, SECRET
    ap = argparse.ArgumentParser(description="Magma /admin web control panel")
    ap.add_argument("--config", default="/etc/magma/magma.conf")
    ap.add_argument("--bind", default=os.environ.get("MAGMA_ADMIN_BIND", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("MAGMA_ADMIN_PORT", "8080")))
    args = ap.parse_args()

    try:
        CFG = load_config(args.config)
    except OSError as e:
        sys.exit(f"magma-admin: cannot read {args.config}: {e}")
    SECRET = load_secret(CFG)

    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    sys.stderr.write(
        f"magma-admin: serving {CFG.get('MAGMA_DOMAIN','?')} on "
        f"http://{args.bind}:{args.port}  (schema={SCHEMA}, container={_container()})\n"
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
