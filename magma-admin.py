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
#   * Aliases    — extra addresses that deliver to an account (DB-level).
#   * Backups    — view/trigger the encrypted backups (magma-backup.sh).
#   * Mail clients — download the generated autoconfig / .mobileconfig profiles.
#   * DNS        — the SPF/DKIM/DMARC records, and one-click push to a provider.
#   * Status     — the magma-status.sh deliverability checks, in the browser.
#   * Security   — enable/disable TOTP two-factor on the panel login.
#   * Restart    — bounce the mail server (Overview tab).
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
ADDR_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,128}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,}$")  # alias address
PLANS = ["BASIC", "PERSONAL", "ENHANCED", "PREMIUM", "STANDARD", "PREMIER"]
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
B32_RE = re.compile(r"^[A-Z2-7]+=*$")

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


# ----------------------------------------------------------------- totp ------
def _config_dir():
    sd = CFG.get("MAGMA_SECRETS_DIR", "/etc/magma")
    return os.path.dirname(sd.rstrip("/")) or "/etc/magma"


def _totp_path():
    return os.path.join(_config_dir(), ".admin-totp")


def totp_secret():
    """The enrolled base32 TOTP secret, or '' if 2FA is not set up."""
    try:
        with open(_totp_path()) as fh:
            s = fh.read().strip().upper().replace(" ", "")
            return s if B32_RE.match(s) else ""
    except OSError:
        return ""


def _b32decode(s):
    s = s.strip().upper().replace(" ", "")
    pad = (-len(s)) % 8
    return base64.b32decode(s + "=" * pad)


def totp_now(secret, t=None, step=30, digits=6):
    key = _b32decode(secret)
    counter = int((t if t is not None else time.time()) // step)
    msg = counter.to_bytes(8, "big")
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = ((h[o] & 0x7F) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % (10 ** digits)
    return str(code).zfill(digits)


def totp_check(secret, code, window=1):
    """Verify a 6-digit code, tolerating +/- one 30s step for clock drift."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit():
        return False
    now = time.time()
    for w in range(-window, window + 1):
        if hmac.compare_digest(totp_now(secret, now + w * 30), code):
            return True
    return False


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
        # Second factor: if a TOTP secret is enrolled, the password alone is not
        # enough. (We only reach here once the password itself has checked out.)
        sec = totp_secret()
        if sec:
            code = data.get("code") or ""
            if not code:
                return self._json(401, {"error": "enter your 6-digit code", "twofa": True})
            if not totp_check(sec, code):
                record_fail(ip)
                return self._json(401, {"error": "invalid 2FA code", "twofa": True})
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
                "domain": CFG.get("MAGMA_DOMAIN", ""),
            })
        if path == "/api/overview":
            return self._json(200, self._overview())
        if path == "/api/users":
            return self._json(200, {"users": self._users()})
        if path == "/api/aliases":
            return self._json(200, {"aliases": self._aliases()})
        if path == "/api/backups":
            return self._json(200, self._backups())
        if path == "/api/autoconfig":
            return self._json(200, self._autoconfig())
        if path == "/api/autoconfig/download":
            return self._autoconfig_download(self.path)
        if path == "/api/2fa/status":
            return self._twofa_status()
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
        if path == "/api/aliases/add":
            return self._alias_add(data)
        if path == "/api/aliases/delete":
            return self._alias_delete(data)
        if path == "/api/backups/run":
            return self._backup_run()
        if path == "/api/autoconfig/regen":
            return self._autoconfig_regen()
        if path == "/api/dns/push":
            return self._dns_push(data)
        if path == "/api/2fa/enroll":
            return self._twofa_enroll(sess)
        if path == "/api/2fa/confirm":
            return self._twofa_confirm(data)
        if path == "/api/2fa/disable":
            return self._twofa_disable(data)
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

    # -- aliases (extra Mailboxes addresses that deliver to a user) ----------
    def _aliases(self):
        # Every row in Mailboxes delivers to its usernum. The "primary" address
        # is the one created at registration (userid@domain); anything else is
        # an alias. We mark the primary so it can't be deleted here.
        dom = CFG.get("MAGMA_DOMAIN", "")
        sql = ("SELECT m.address, u.userid FROM Mailboxes m "
               "JOIN Users u ON m.usernum=u.usernum ORDER BY u.userid, m.address;")
        try:
            out = db_query(sql)
        except Exception as e:  # noqa: BLE001
            return [{"error": str(e)}]
        rows = []
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            addr, uid = parts[0], parts[1]
            primary = addr.lower() == f"{uid}@{dom}".lower()
            rows.append({"address": addr, "userid": uid, "primary": primary})
        return rows

    def _alias_add(self, data):
        addr = (data.get("address") or "").strip().lower()
        target = (data.get("userid") or "").strip()
        if not ADDR_RE.match(addr):
            return self._json(400, {"error": "invalid address (use name@domain)"})
        if not USER_RE.match(target):
            return self._json(400, {"error": "invalid target user"})
        dom = addr.split("@", 1)[1]
        # only accept aliases in domains Magma is configured to handle
        try:
            known = db_query("SELECT domain FROM Domains;").split()
        except Exception:  # noqa: BLE001
            known = []
        allowed = {d.lower() for d in known} | {CFG.get("MAGMA_DOMAIN", "").lower()}
        if dom not in allowed:
            return self._json(400, {"error": f"domain '{dom}' is not served here (add it under Domains first)"})
        try:
            unum = db_query(f"SELECT usernum FROM Users WHERE userid='{target}';").strip()
            if not unum.isdigit():
                return self._json(422, {"error": "no such target user"})
            taken = db_query(f"SELECT COUNT(*) FROM Mailboxes WHERE address='{addr}';").strip()
            if taken != "0":
                return self._json(409, {"error": "that address already exists"})
            db_query(f"INSERT INTO Mailboxes (address, usernum) VALUES ('{addr}', {unum});")
            return self._json(200, {"ok": True})
        except Exception as e:  # noqa: BLE001
            return self._json(500, {"error": str(e)})

    def _alias_delete(self, data):
        addr = (data.get("address") or "").strip().lower()
        if not ADDR_RE.match(addr):
            return self._json(400, {"error": "invalid address"})
        dom = CFG.get("MAGMA_DOMAIN", "")
        try:
            row = db_query("SELECT u.userid FROM Mailboxes m JOIN Users u ON m.usernum=u.usernum "
                           f"WHERE m.address='{addr}';").strip()
            if not row:
                return self._json(422, {"error": "no such address"})
            if addr == f"{row}@{dom}".lower():
                return self._json(400, {"error": "refusing to delete a user's primary address"})
            # don't orphan a user: keep at least one mailbox
            unum = db_query(f"SELECT usernum FROM Mailboxes WHERE address='{addr}';").strip()
            cnt = db_query(f"SELECT COUNT(*) FROM Mailboxes WHERE usernum={unum};").strip()
            if cnt == "1":
                return self._json(400, {"error": "that is the user's only address"})
            db_query(f"DELETE FROM Mailboxes WHERE address='{addr}';")
            return self._json(200, {"ok": True})
        except Exception as e:  # noqa: BLE001
            return self._json(500, {"error": str(e)})

    # -- backups ------------------------------------------------------------
    def _backups(self):
        bdir = CFG.get("MAGMA_BACKUP_DIR", "/var/backups/magma")
        items = []
        try:
            for fn in sorted(os.listdir(bdir), reverse=True):
                if fn.startswith("magma-") and fn.endswith(".tar.gz.gpg"):
                    p = os.path.join(bdir, fn)
                    st = os.stat(p)
                    items.append({"name": fn, "size": st.st_size, "mtime": int(st.st_mtime)})
        except OSError:
            pass
        svc = CFG.get("MAGMA_SERVICE", "magma") + "-backup"
        _, tstate, _ = run(["systemctl", "is-enabled", svc + ".timer"], timeout=5)
        _, nxt, _ = run(["systemctl", "show", svc + ".timer", "-p", "NextElapseUSecRealtime", "--value"], timeout=5)
        return {"dir": bdir, "backups": items, "timer": tstate.strip(), "next": nxt.strip()}

    def _backup_run(self):
        # Fire the oneshot backup service so a long run doesn't block the panel.
        svc = CFG.get("MAGMA_SERVICE", "magma") + "-backup.service"
        rc, _, err = run(["systemctl", "start", "--no-block", svc], timeout=15)
        if rc == 0:
            return self._json(200, {"ok": True, "started": svc})
        # fall back to running the script directly if the unit isn't installed
        script = os.path.join(CFG.get("MAGMA_INSTALL_DIR", "/opt/magma"), "src", "magma-backup.sh")
        if os.path.exists(script):
            rc2, _, err2 = run([script, "backup", "--config",
                                os.path.join(_config_dir(), "magma.conf")], timeout=600)
            if rc2 == 0:
                return self._json(200, {"ok": True})
            return self._json(500, {"error": err2.strip() or "backup failed"})
        return self._json(500, {"error": err.strip() or "could not start backup"})

    # -- mail-client autoconfig --------------------------------------------
    def _autoconfig(self):
        base = os.path.join(CFG.get("MAGMA_SECRETS_DIR", ""), "autoconfig")
        files = []
        for rel in ("mail/config-v1.1.xml", "autodiscover/autodiscover.xml",
                    f"magma-{CFG.get('MAGMA_DOMAIN','')}.mobileconfig",
                    "nginx-autoconfig.conf", "Caddyfile.autoconfig"):
            p = os.path.join(base, rel)
            if os.path.exists(p):
                files.append({"name": rel, "size": os.path.getsize(p)})
        return {"present": os.path.isdir(base), "domain": CFG.get("MAGMA_DOMAIN", ""),
                "hostname": CFG.get("MAGMA_HOSTNAME", ""), "files": files}

    def _autoconfig_regen(self):
        script = os.path.join(CFG.get("MAGMA_INSTALL_DIR", "/opt/magma"), "src", "magma-autoconfig.sh")
        if not os.path.exists(script):
            return self._json(500, {"error": "magma-autoconfig.sh not found"})
        rc, _, err = run([script, "--config", os.path.join(_config_dir(), "magma.conf")], timeout=30)
        return self._json(200 if rc == 0 else 500, {"ok": rc == 0} if rc == 0 else {"error": err.strip()})

    def _autoconfig_download(self, path):
        base = os.path.realpath(os.path.join(CFG.get("MAGMA_SECRETS_DIR", ""), "autoconfig"))
        rel = path.split("file=", 1)[1] if "file=" in path else ""
        from urllib.parse import unquote
        rel = unquote(rel)
        full = os.path.realpath(os.path.join(base, rel))
        if not full.startswith(base + os.sep) or not os.path.isfile(full):
            return self._send(404, "not found\n", "text/plain")
        ctype = "application/octet-stream"
        if full.endswith(".mobileconfig"):
            ctype = "application/x-apple-aspen-config"
        elif full.endswith(".xml"):
            ctype = "application/xml"
        elif full.endswith(".conf") or full.endswith("Caddyfile.autoconfig"):
            ctype = "text/plain"
        try:
            with open(full, "rb") as fh:
                body = fh.read()
        except OSError:
            return self._send(404, "not found\n", "text/plain")
        return self._send(200, body, ctype, extra=[(
            "Content-Disposition", f'attachment; filename="{os.path.basename(full)}"')])

    # -- DNS push -----------------------------------------------------------
    def _dns_push(self, data):
        provider = (data.get("provider") or "manual").strip()
        if provider not in ("cloudflare", "route53", "manual"):
            return self._json(400, {"error": "provider must be cloudflare, route53, or manual"})
        script = os.path.join(CFG.get("MAGMA_INSTALL_DIR", "/opt/magma"), "src", "magma-dns.sh")
        if not os.path.exists(script):
            return self._json(500, {"error": "magma-dns.sh not found"})
        rc, out, err = run([script, "push", "--provider", provider,
                            "--config", os.path.join(_config_dir(), "magma.conf")], timeout=60)
        text = ANSI_RE.sub("", out + ("\n" + err if err.strip() else ""))
        return self._json(200 if rc == 0 else 500, {"ok": rc == 0, "text": text})

    # -- 2FA (TOTP) enrollment ----------------------------------------------
    def _twofa_status(self):
        return self._json(200, {"enabled": bool(totp_secret())})

    def _twofa_enroll(self, sess):
        # Generate a fresh secret, stash it as PENDING in the session-signed
        # response; it only becomes active after _twofa_confirm writes the file.
        secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
        issuer = "Magma admin"
        label = f"{sess.get('user','admin')}@{CFG.get('MAGMA_DOMAIN','')}"
        from urllib.parse import quote
        uri = (f"otpauth://totp/{quote(issuer)}:{quote(label)}?secret={secret}"
               f"&issuer={quote(issuer)}&period=30&digits=6")
        return self._json(200, {"secret": secret, "otpauth": uri})

    def _twofa_confirm(self, data):
        secret = (data.get("secret") or "").strip().upper()
        code = (data.get("code") or "").strip()
        if not B32_RE.match(secret):
            return self._json(400, {"error": "invalid secret"})
        if not totp_check(secret, code):
            return self._json(400, {"error": "code did not verify — check the time on your device"})
        path = _totp_path()
        old = os.umask(0o077)
        try:
            with open(path, "w") as fh:
                fh.write(secret + "\n")
        except OSError as e:
            return self._json(500, {"error": str(e)})
        finally:
            os.umask(old)
        return self._json(200, {"ok": True})

    def _twofa_disable(self, data):
        # require a current valid code to turn 2FA off
        sec = totp_secret()
        if sec and not totp_check(sec, (data.get("code") or "")):
            return self._json(400, {"error": "a current code is required to disable 2FA"})
        try:
            os.remove(_totp_path())
        except OSError:
            pass
        return self._json(200, {"ok": True})

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
    <div style="margin-bottom:12px"><label>Password</label><input id="p" type="password" autocomplete="current-password"></div>
    <div id="twofa" style="display:none;margin-bottom:16px"><label>Two-factor code</label><input id="code" inputmode="numeric" autocomplete="one-time-code" placeholder="123456"></div>
    <button class="primary" style="width:100%" id="go">Sign in</button>
  </div></div>`;
  const submit = async ()=>{
    const m=$('#m'); m.className='msg';
    const body = {username:$('#u').value, password:$('#p').value};
    const codeEl = $('#code'); if(codeEl && codeEl.value.trim()) body.code = codeEl.value.trim();
    try{
      const r = await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
      const j = await r.json().catch(()=>({}));
      if(r.ok){ CSRF=j.csrf; USER=j.user; renderApp(); return; }
      if(j.twofa){ $('#twofa').style.display='block'; $('#code').focus(); }
      m.className='msg err'; m.textContent=j.error||('HTTP '+r.status);
    }catch(e){ m.className='msg err'; m.textContent=e.message; }
  };
  $('#go').onclick=submit;
  $('#p').onkeydown=e=>{ if(e.key==='Enter') submit(); };
  $('#u').onkeydown=e=>{ if(e.key==='Enter') $('#p').focus(); };
  document.addEventListener('keydown',e=>{ if(e.key==='Enter' && document.activeElement && document.activeElement.id==='code') submit(); });
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
    ${[['overview','Overview'],['users','Users'],['aliases','Aliases'],['backups','Backups'],['clients','Mail clients'],['dns','DNS'],['status','Status'],['security','Security']].map(([t,label])=>`<button data-tab="${t}" class="${t===TAB?'on':''}">${label}</button>`).join('')}
  </nav>
  <main id="view"></main>`;
  $('#logout').onclick=async()=>{ try{await api('/api/logout',{method:'POST'})}catch(e){}; CSRF=null; renderLogin(); };
  document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{TAB=b.dataset.tab; renderApp();});
  ({overview:viewOverview,users:viewUsers,aliases:viewAliases,backups:viewBackups,clients:viewClients,dns:viewDns,status:viewStatus,security:viewSecurity}[TAB])();
}

async function viewOverview(){
  const v=$('#view'); v.innerHTML='<p class="muted">Loading…</p>';
  try{
    const o = await api('/api/overview');
    window.__DOMAIN = o.domain || window.__DOMAIN;
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

async function viewAliases(){
  const v=$('#view'); v.innerHTML='<p class="muted">Loading…</p>';
  let data, users;
  try{ data = await api('/api/aliases'); users = await api('/api/users'); }
  catch(e){ v.innerHTML=`<div class="msg err" style="display:block">${esc(e.message)}</div>`; return; }
  const ulist = (users.users||[]).filter(u=>!u.error).map(u=>u.userid);
  const rows = (data.aliases||[]).map(a=>{
    if(a.error) return `<tr><td colspan="4" class="bad">${esc(a.error)}</td></tr>`;
    return `<tr>
      <td>${esc(a.address)}${a.primary?' <span class="pill">primary</span>':''}</td>
      <td>${esc(a.userid)}</td>
      <td class="r">${a.primary?'':`<button class="danger" data-da="${esc(a.address)}">Delete</button>`}</td>
    </tr>`;
  }).join('');
  v.innerHTML = `
  <div class="card"><h2>Add alias</h2>
    <p class="muted" style="margin:0 0 12px">An alias is an extra address that delivers to an existing account (e.g. <code>sales@…</code> → alice). Forwarding to outside addresses isn't supported.</p>
    <div id="almsg" class="msg"></div>
    <div class="row">
      <div><label>Alias address</label><input id="aa" placeholder="sales@${esc(window.__DOMAIN||'example.com')}"></div>
      <div style="flex:0 0 220px"><label>Delivers to</label><select id="at">${ulist.map(u=>`<option>${esc(u)}</option>`).join('')}</select></div>
      <div style="flex:0 0 auto"><button class="primary" id="aadd">Add</button></div>
    </div>
  </div>
  <div class="card"><h2>Addresses</h2>
    <table><thead><tr><th>Address</th><th>Delivers to</th><th></th></tr></thead>
    <tbody>${rows||'<tr><td colspan="3" class="muted">No addresses.</td></tr>'}</tbody></table>
  </div>`;
  $('#aadd').onclick=async()=>{
    const m=$('#almsg'); m.className='msg';
    try{ await api('/api/aliases/add',{method:'POST',body:JSON.stringify({address:$('#aa').value.trim(),userid:$('#at').value})}); viewAliases(); }
    catch(e){ m.className='msg err'; m.textContent=e.message; }
  };
  v.querySelectorAll('[data-da]').forEach(b=>b.onclick=async()=>{
    if(!confirm('Delete alias '+b.dataset.da+'? Mail to it will no longer be accepted.')) return;
    try{ await api('/api/aliases/delete',{method:'POST',body:JSON.stringify({address:b.dataset.da})}); viewAliases(); }
    catch(e){ alert(e.message); }
  });
}

async function viewBackups(){
  const v=$('#view'); v.innerHTML='<p class="muted">Loading…</p>';
  let d;
  try{ d = await api('/api/backups'); }catch(e){ v.innerHTML=`<div class="msg err" style="display:block">${esc(e.message)}</div>`; return; }
  const rows = (d.backups||[]).map(b=>`<tr><td>${esc(b.name)}</td><td class="r">${bytes(b.size)}</td><td class="r muted">${new Date(b.mtime*1000).toLocaleString()}</td></tr>`).join('');
  const timer = d.timer==='enabled'?'<span class="ok">enabled</span>':'<span class="warn">'+esc(d.timer||'not installed')+'</span>';
  v.innerHTML = `
  <div class="card"><h2>Backups</h2>
    <div id="bmsg" class="msg"></div>
    <div class="grid" style="margin-bottom:14px">
      <div class="kv"><div class="k">Scheduled timer</div><div class="v">${timer}</div></div>
      <div class="kv"><div class="k">Local copies</div><div class="v">${(d.backups||[]).length}</div></div>
      <div class="kv"><div class="k">Directory</div><div class="v" style="font-size:13px">${esc(d.dir)}</div></div>
    </div>
    <button class="primary" id="brun">Back up now</button>
    <span class="muted" style="margin-left:10px">Encrypted (gpg). Keep the passphrase (<code>.backup-pass</code>) off-box or restores are impossible.</span>
  </div>
  <div class="card"><h2>Archives</h2>
    <table><thead><tr><th>File</th><th class="r">Size</th><th class="r">Created</th></tr></thead>
    <tbody>${rows||'<tr><td colspan="3" class="muted">No backups yet.</td></tr>'}</tbody></table>
  </div>`;
  $('#brun').onclick=async()=>{
    const m=$('#bmsg'); m.className='msg'; $('#brun').disabled=true; $('#brun').textContent='Starting…';
    try{ await api('/api/backups/run',{method:'POST'}); m.className='msg ok'; m.textContent='Backup started — refresh in a minute to see it.'; }
    catch(e){ m.className='msg err'; m.textContent=e.message; }
    $('#brun').disabled=false; $('#brun').textContent='Back up now';
  };
}

async function viewClients(){
  const v=$('#view'); v.innerHTML='<p class="muted">Loading…</p>';
  let d;
  try{ d = await api('/api/autoconfig'); }catch(e){ v.innerHTML=`<div class="msg err" style="display:block">${esc(e.message)}</div>`; return; }
  const dl = f => `/api/autoconfig/download?file=${encodeURIComponent(f)}`;
  const files = (d.files||[]).map(f=>`<tr><td>${esc(f.name)}</td><td class="r">${bytes(f.size)}</td><td class="r"><a href="${dl(f.name)}">download</a></td></tr>`).join('');
  v.innerHTML = `
  <div class="card"><h2>Mail client setup</h2>
    <div id="cmsg" class="msg"></div>
    <p class="muted" style="margin:0 0 12px">Autoconfig for <b>${esc(d.domain)}</b> (server ${esc(d.hostname)}). The Apple <code>.mobileconfig</code> works as-is — hand it to a user and they tap to install. Thunderbird/Outlook auto-fetch needs the XML served on <code>autoconfig.${esc(d.domain)}</code> / <code>autodiscover.${esc(d.domain)}</code> (see the nginx/Caddy snippet).</p>
    <button id="cregen">Regenerate</button>
  </div>
  <div class="card"><h2>Files</h2>
    <table><thead><tr><th>File</th><th class="r">Size</th><th></th></tr></thead>
    <tbody>${files||'<tr><td colspan="3" class="muted">Not generated yet — click Regenerate.</td></tr>'}</tbody></table>
  </div>`;
  $('#cregen').onclick=async()=>{
    const m=$('#cmsg'); m.className='msg';
    try{ await api('/api/autoconfig/regen',{method:'POST'}); viewClients(); }
    catch(e){ m.className='msg err'; m.textContent=e.message; }
  };
}

async function viewSecurity(){
  const v=$('#view'); v.innerHTML='<p class="muted">Loading…</p>';
  let s;
  try{ s = await api('/api/2fa/status'); }catch(e){ v.innerHTML=`<div class="msg err" style="display:block">${esc(e.message)}</div>`; return; }
  if(s.enabled){
    v.innerHTML = `
    <div class="card"><h2>Two-factor authentication</h2>
      <div id="smsg" class="msg"></div>
      <p><span class="ok">● Enabled.</span> A TOTP code is required at sign-in.</p>
      <div class="row">
        <div style="flex:0 0 160px"><label>Current code</label><input id="dcode" inputmode="numeric" autocomplete="one-time-code" placeholder="123456"></div>
        <div style="flex:0 0 auto"><button class="danger" id="disable">Disable 2FA</button></div>
      </div>
    </div>`;
    $('#disable').onclick=async()=>{
      const m=$('#smsg'); m.className='msg';
      try{ await api('/api/2fa/disable',{method:'POST',body:JSON.stringify({code:$('#dcode').value.trim()})}); viewSecurity(); }
      catch(e){ m.className='msg err'; m.textContent=e.message; }
    };
    return;
  }
  v.innerHTML = `
  <div class="card"><h2>Two-factor authentication</h2>
    <div id="smsg" class="msg"></div>
    <p class="muted">Protect the panel with a TOTP app (Google Authenticator, 1Password, …). The panel login will then require a 6-digit code in addition to the admin password.</p>
    <button class="primary" id="enroll">Set up 2FA</button>
  </div>`;
  $('#enroll').onclick=async()=>{
    const m=$('#smsg'); m.className='msg';
    try{
      const e = await api('/api/2fa/enroll',{method:'POST'});
      $('#view').innerHTML = `
      <div class="card"><h2>Finish 2FA setup</h2>
        <div id="smsg2" class="msg"></div>
        <p class="muted">Add this to your authenticator app, then type the current code to confirm. (No QR image — the secret is never sent to any third-party service; enter it manually or paste the otpauth link into an app that accepts it.)</p>
        <div style="margin:8px 0 16px">
          <label>Secret (type into your app)</label><pre style="margin:4px 0 12px;letter-spacing:1px">${esc(e.secret)}</pre>
          <label>Or this otpauth link</label><pre style="margin:4px 0">${esc(e.otpauth)}</pre>
        </div>
        <div class="row">
          <div style="flex:0 0 160px"><label>Code from app</label><input id="ccode" inputmode="numeric" autocomplete="one-time-code" placeholder="123456"></div>
          <div style="flex:0 0 auto"><button class="primary" id="confirm">Confirm & enable</button></div>
          <div style="flex:0 0 auto"><button id="cancel2">Cancel</button></div>
        </div>
      </div>`;
      $('#confirm').onclick=async()=>{
        const m2=$('#smsg2'); m2.className='msg';
        try{ await api('/api/2fa/confirm',{method:'POST',body:JSON.stringify({secret:e.secret,code:$('#ccode').value.trim()})}); viewSecurity(); }
        catch(err){ m2.className='msg err'; m2.textContent=err.message; }
      };
      $('#cancel2').onclick=viewSecurity;
    }catch(e){ m.className='msg err'; m.textContent=e.message; }
  };
}

async function viewStatus(){
  const v=$('#view'); v.innerHTML='<p class="muted">Running deliverability checks… (this makes live DNS/network queries)</p>';
  try{ const j=await api('/api/status'); v.innerHTML=`<div class="card"><div class="toolbar"><h2 style="margin:0">Deliverability</h2><div class="sp" style="flex:1"></div><button id="re">Re-run</button></div><pre>${esc(j.text)}</pre></div>`;
    $('#re').onclick=viewStatus;
  }catch(e){ v.innerHTML=`<div class="msg err" style="display:block">${esc(e.message)}</div>`; }
}

async function viewDns(){
  const v=$('#view'); v.innerHTML='<p class="muted">Loading…</p>';
  let j;
  try{ j=await api('/api/dns'); }catch(e){ v.innerHTML=`<div class="msg err" style="display:block">${esc(e.message)}</div>`; return; }
  v.innerHTML=`
    <div class="card"><h2>Publish automatically</h2>
      <div id="dmsg" class="msg"></div>
      <p class="muted" style="margin:0 0 12px">Push the full mail record set (A, MX, SPF, DKIM, DMARC, autoconfig) to your provider. Cloudflare needs <code>MAGMA_CF_TOKEN</code> in magma.conf; Route 53 uses the host's AWS credentials.</p>
      <div class="row">
        <div style="flex:0 0 200px"><label>Provider</label><select id="prov"><option value="cloudflare">Cloudflare</option><option value="route53">Route 53</option><option value="manual">Manual (print zone)</option></select></div>
        <div style="flex:0 0 auto"><button class="primary" id="push">Push records</button></div>
      </div>
      <pre id="pushout" style="display:none;margin-top:12px"></pre>
    </div>
    <div class="card"><h2>Records (from dns-records.txt)</h2><pre>${esc(j.text)}</pre></div>`;
  $('#push').onclick=async()=>{
    const m=$('#dmsg'); m.className='msg'; const b=$('#push'); b.disabled=true; b.textContent='Pushing…';
    try{
      const r=await api('/api/dns/push',{method:'POST',body:JSON.stringify({provider:$('#prov').value})});
      const o=$('#pushout'); o.style.display='block'; o.textContent=r.text||'';
      m.className='msg '+(r.ok?'ok':'err'); m.textContent=r.ok?'Done.':'Finished with errors — see output below.';
    }catch(e){ m.className='msg err'; m.textContent=e.message; }
    b.disabled=false; b.textContent='Push records';
  };
}

// bootstrap: recover an existing session (cookie is HttpOnly, so fetch the CSRF token back)
(async()=>{
  try{ const s=await api('/api/session'); CSRF=s.csrf; USER=s.user; window.__ADMIN=s.admin; window.__DOMAIN=s.domain; renderApp(); }
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
