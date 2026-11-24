#!/usr/bin/env bash
# =============================================================================
# magma-setup.sh — one-command interactive installer for a modernized Magma.
#
# Phase 1 (container wizard): ask the few things only a human knows, then do the
# rest. Builds/reuses the image, generates real secrets (TLS, DKIM, DIME, DB),
# boots the full stack, mints the admin account through Magma's OWN register
# endpoint (so credentials are derived the real way, server-side), and prints
# the DNS records + next steps.
#
# The goal is Mail-in-a-Box-grade ease:  ./magma-setup.sh   and answer 4 prompts.
#
# Usage:
#   ./magma-setup.sh                         # interactive
#   ./magma-setup.sh --domain example.com --hostname mail.example.com \
#       --admin-user admin --admin-pass 'S3cret!' --yes   # non-interactive
#
# Options (anything not given is prompted for, with sane defaults):
#   --domain <d>          primary mail domain (e.g. example.com)
#   --hostname <h>        this server's FQDN  (default: mail.<domain>)
#   --admin-user <u>      admin account local part (default: admin)
#   --admin-pass <p>      admin password (prompted hidden if omitted)
#   --engine <e>          container engine: podman|docker (default: autodetect)
#   --image <t>           image tag to build/use (default: magma:port)
#   --ref <branch>        magma branch to build (default: openssl3)
#   --container <n>       container name (default: magma)
#   --secrets-dir <p>     where generated secrets land (default: ./secrets/<domain>)
#   --letsencrypt <email> after boot, get a real CA cert via Let's Encrypt
#                         (needs DNS pointed here + :80 reachable; see magma-tls.sh)
#   --le-staging          use Let's Encrypt staging (test issuance, untrusted cert)
#   --no-build            don't build; the --image must already exist
#   --rebuild             force an image rebuild even if --image exists
#   --yes                 assume yes; never prompt (requires the flags above)
#   -h | --help           this help
# =============================================================================
set -euo pipefail

# ------------------------------------------------------------------ defaults --
DOMAIN="" HOSTNAME_FQDN="" ADMIN_USER="admin" ADMIN_PASS=""
ENGINE="" IMAGE="magma:port" REF="openssl3" CONTAINER="magma"
SECRETS_DIR="" BUILD="auto" ASSUME_YES="no"
LE_EMAIL="" LE_STAGING="no"
HERE="$(cd "$(dirname "$0")" && pwd)"

# Host:container port map (see magma.prod.config.template).
PORT_MAP=(
  "25:7000"     # SMTP  (inbound MX + submission/STARTTLS)
  "587:7000"    # submission (STARTTLS) — same plain listener
  "465:7500"    # submission (implicit TLS)
  "110:8000"    # POP3
  "995:8500"    # POP3S
  "143:9000"    # IMAP
  "993:9500"    # IMAPS
  "80:10000"    # webmail HTTP
  "443:10500"   # webmail HTTPS (also the admin-mint/JSON-RPC endpoint)
)
HTTPS_HOST_PORT="443"   # the host port mapped to magma's TLS HTTP listener (10500)

# ------------------------------------------------------------------- helpers --
c_blue=$'\033[1;34m'; c_grn=$'\033[1;32m'; c_yel=$'\033[1;33m'; c_red=$'\033[1;31m'; c_0=$'\033[0m'
say()  { printf '%s>>%s %s\n' "$c_blue" "$c_0" "$*"; }
ok()   { printf '%s ✓%s %s\n' "$c_grn"  "$c_0" "$*"; }
warn() { printf '%s !!%s %s\n' "$c_yel" "$c_0" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$c_red" "$c_0" "$*" >&2; exit 1; }

ask() { # ask <prompt> <default> -> echoes answer
  local p="$1" d="${2:-}" a=""
  if [ "$ASSUME_YES" = yes ]; then printf '%s' "$d"; return; fi
  if [ -n "$d" ]; then read -r -p "$p [$d]: " a || true; else read -r -p "$p: " a || true; fi
  printf '%s' "${a:-$d}"
}
json_escape() { # minimal JSON string escaping (backslash + double-quote) for safe body construction
  local s=$1; s=${s//\\/\\\\}; s=${s//\"/\\\"}; printf '%s' "$s"
}
ask_secret() { # ask_secret <prompt> -> echoes password, confirmed, hidden
  local p="$1" a="" b=""
  if [ "$ASSUME_YES" = yes ]; then printf '%s' "$ADMIN_PASS"; return; fi
  while :; do
    read -r -s -p "$p: " a; echo >&2
    read -r -s -p "$p (again): " b; echo >&2
    [ -n "$a" ] || { warn "password cannot be empty"; continue; }
    [ "$a" = "$b" ] || { warn "passwords did not match, try again"; continue; }
    printf '%s' "$a"; return
  done
}

# -------------------------------------------------------------------- parse ---
while [ $# -gt 0 ]; do
  case "$1" in
    --domain)      DOMAIN="$2"; shift 2;;
    --hostname)    HOSTNAME_FQDN="$2"; shift 2;;
    --admin-user)  ADMIN_USER="$2"; shift 2;;
    --admin-pass)  ADMIN_PASS="$2"; shift 2;;
    --engine)      ENGINE="$2"; shift 2;;
    --image)       IMAGE="$2"; shift 2;;
    --ref)         REF="$2"; shift 2;;
    --container)   CONTAINER="$2"; shift 2;;
    --secrets-dir) SECRETS_DIR="$2"; shift 2;;
    --letsencrypt) LE_EMAIL="$2"; shift 2;;
    --le-staging)  LE_STAGING="yes"; shift;;
    --no-build)    BUILD="no"; shift;;
    --rebuild)     BUILD="force"; shift;;
    --yes|-y)      ASSUME_YES="yes"; shift;;
    -h|--help)     sed -n '2,45p' "$0"; exit 0;;
    *)             die "unknown option: $1 (try --help)";;
  esac
done

# ------------------------------------------------------- engine autodetect ----
if [ -z "$ENGINE" ]; then
  if command -v podman >/dev/null 2>&1; then ENGINE=podman
  elif command -v docker >/dev/null 2>&1; then ENGINE=docker
  else die "no container engine found — install podman (recommended) or docker"; fi
fi
command -v "$ENGINE" >/dev/null 2>&1 || die "engine '$ENGINE' not on PATH"
# SELinux relabel option: podman honours :z on bind mounts; docker labels differently, so omit it.
# Build the -v value so multiple options are comma-joined (podman rejects ':ro:z').
if [ "$ENGINE" = podman ]; then ZOPT="z"; else ZOPT=""; fi
rw_vol() { if [ -n "$ZOPT" ]; then printf '%s:%s:%s' "$1" "$2" "$ZOPT"; else printf '%s:%s' "$1" "$2"; fi; }
ro_vol() { if [ -n "$ZOPT" ]; then printf '%s:%s:ro,%s' "$1" "$2" "$ZOPT"; else printf '%s:%s:ro' "$1" "$2"; fi; }

cat <<BANNER

  ${c_blue}Magma${c_0} — modernized mail server setup
  ----------------------------------------
  One command, a few answers, a running encrypted mail server.
  Engine: $ENGINE    Image: $IMAGE

BANNER

# ----------------------------------------------------------- gather inputs ----
[ -n "$DOMAIN" ] || DOMAIN="$(ask 'Primary mail domain (e.g. example.com)' '')"
[ -n "$DOMAIN" ] || die "a domain is required"
case "$DOMAIN" in *.*) :;; *) die "'$DOMAIN' does not look like a domain";; esac

[ -n "$HOSTNAME_FQDN" ] || HOSTNAME_FQDN="$(ask 'This server hostname (FQDN)' "mail.$DOMAIN")"
[ -n "$ADMIN_USER" ]    || ADMIN_USER="$(ask 'Admin account (local part)' 'admin')"
[ -n "$ADMIN_PASS" ]    || ADMIN_PASS="$(ask_secret "Password for ${ADMIN_USER}@${DOMAIN}")"
[ -n "$ADMIN_PASS" ]    || die "an admin password is required"
[ -n "$SECRETS_DIR" ]   || SECRETS_DIR="$HERE/secrets/$DOMAIN"

cat <<PLAN

  About to set up:
    domain        $DOMAIN
    hostname      $HOSTNAME_FQDN
    admin login   ${ADMIN_USER}@${DOMAIN}
    secrets ->    $SECRETS_DIR
    container     $CONTAINER   (from $IMAGE)

PLAN
[ "$(ask 'Proceed?' 'yes')" = yes ] || { say "aborted"; exit 0; }

# --------------------------------------------------------------- build image --
image_exists() { "$ENGINE" image exists "$IMAGE" 2>/dev/null || "$ENGINE" image inspect "$IMAGE" >/dev/null 2>&1; }
if [ "$BUILD" = force ] || { [ "$BUILD" = auto ] && ! image_exists; }; then
  [ -f "$HERE/Containerfile" ] || die "Containerfile not found in $HERE"
  say "building image $IMAGE (branch $REF) — this takes a while the first time"
  "$ENGINE" build -t "$IMAGE" --build-arg MAGMA_REF="$REF" -f "$HERE/Containerfile" "$HERE" \
    || die "image build failed"
  ok "image built"
elif ! image_exists; then
  die "--no-build given but image '$IMAGE' does not exist"
else
  ok "reusing existing image $IMAGE"
fi

# ------------------------------------------------- generate real secrets ------
# Run gen-secrets.sh INSIDE the image: it has openssl + the built signet binary
# (for the PRIME/DIME org key), and writes the rendered config + key material to
# a host-mounted directory. The DB/path defaults match magma-start.sh's prod mode.
say "generating secrets for $DOMAIN"
mkdir -p "$SECRETS_DIR"; chmod 700 "$SECRETS_DIR"
"$ENGINE" run --rm \
  -v "$(rw_vol "$SECRETS_DIR" /out)" \
  --entrypoint /bin/bash \
  "$IMAGE" -lc "cd /root/magma && ./gen-secrets.sh \
      --domain '$DOMAIN' --out /out --force \
      --dime --config-prefix /etc/magma \
      --install-root /root/magma --data-root /var/lib/magma \
      --db-socket /var/lib/mysql/mysql.sock" \
  || die "secret generation failed"
# gen-secrets writes root-owned files via the container; make them readable to us.
"$ENGINE" unshare chown -R "$(id -u):$(id -g)" "$SECRETS_DIR" 2>/dev/null || true
ok "secrets written to $SECRETS_DIR"

# -------------------------------------------------- (re)start the container ---
if "$ENGINE" container exists "$CONTAINER" 2>/dev/null || "$ENGINE" inspect "$CONTAINER" >/dev/null 2>&1; then
  say "removing existing container '$CONTAINER'"
  "$ENGINE" rm -f "$CONTAINER" >/dev/null 2>&1 || true
fi
pflags=(); for m in "${PORT_MAP[@]}"; do pflags+=(-p "$m"); done
say "starting $CONTAINER"
"$ENGINE" run -d --name "$CONTAINER" \
  --ulimit memlock=-1:-1 --ulimit nofile=65536:65536 \
  --hostname "$HOSTNAME_FQDN" \
  -e MAGMA_SEED_DEMO=0 \
  -v "$(ro_vol "$SECRETS_DIR" /etc/magma)" \
  "${pflags[@]}" \
  "$IMAGE" >/dev/null || die "container failed to start"
ok "container up"

# --------------------------------------------------- wait for the portal ------
# magma-start loads the schema + applies grant/domains, then launches magmad; on
# first boot that can take a few minutes. Readiness = the webmail HTTP listener
# answering on the container's own loopback (probed via exec, since that's also
# where we mint the admin account).
say "waiting for Magma to come up (first-boot schema load can take a few minutes)…"
INTERNAL_JSON="http://127.0.0.1:10000/json"   # json_api endpoint — loopback-only (TLS does NOT substitute)
cexec() { "$ENGINE" exec "$CONTAINER" "$@"; }
ready="no"
for i in $(seq 1 180); do   # up to ~6 min
  code=$(cexec curl -s --max-time 4 -o /dev/null -w '%{http_code}' http://127.0.0.1:10000/ 2>/dev/null || true)
  case "$code" in 2*|3*|4*) ready="yes"; break;; esac
  sleep 2
done
[ "$ready" = yes ] || warn "portal did not answer in time; check: $ENGINE logs $CONTAINER"

# ------------------------------------------------------- mint admin account ---
# Create the admin user via Magma's own JSON-RPC 'register' method (server-side
# STACIE derivation — the correct way). The json_api endpoint is loopback-only,
# so we POST from INSIDE the container (exec) and feed the body over stdin to
# avoid any shell-quoting damage to the password.
mint_admin() {
  local json resp
  json=$(printf '{"jsonrpc":"2.0","method":"register","id":1,"params":{"username":"%s","password":"%s","password_verification":"%s","plan":"PREMIER"}}' \
         "$(json_escape "$ADMIN_USER")" "$(json_escape "$ADMIN_PASS")" "$(json_escape "$ADMIN_PASS")")
  resp=$(printf '%s' "$json" | "$ENGINE" exec -i "$CONTAINER" \
         curl -s --max-time 15 -H 'Content-Type: application/json' --data-binary @- "$INTERNAL_JSON" 2>/dev/null || true)
  printf '%s' "$resp"
}
if [ "$ready" = yes ]; then
  say "creating admin account ${ADMIN_USER}@${DOMAIN}"
  RESP="$(mint_admin)"
  if printf '%s' "$RESP" | grep -q '"result"'; then
    ok "admin account created"
  elif printf '%s' "$RESP" | grep -qiE 'already|exists|duplicate'; then
    ok "admin account already present"
  else
    warn "could not confirm admin creation; response was: ${RESP:-<empty>}"
    warn "you can register at the webmail portal instead, or re-run with the portal up."
  fi
fi

# --------------------------------------------- Let's Encrypt (optional) -------
# Hand off to magma-tls.sh for a real CA-signed cert. Needs DNS pointed at this
# host and :80 reachable from the internet, so it runs AFTER the server is up.
TLS_IS_LE="no"
if [ -n "$LE_EMAIL" ]; then
  if [ ! -x "$HERE/magma-tls.sh" ]; then
    warn "magma-tls.sh not found/executable in $HERE — skipping Let's Encrypt"
  else
    say "requesting a Let's Encrypt certificate for $HOSTNAME_FQDN"
    le_args=( --hostname "$HOSTNAME_FQDN" --email "$LE_EMAIL" --domain "$DOMAIN"
              --secrets-dir "$SECRETS_DIR" --container "$CONTAINER" --engine "$ENGINE" )
    # Certify the bare domain too when the hostname is a subdomain of it.
    [ "$HOSTNAME_FQDN" != "$DOMAIN" ] && le_args+=( --extra-domain "$DOMAIN" )
    [ "$LE_STAGING" = yes ] && le_args+=( --staging )
    [ "$ASSUME_YES" = yes ] && le_args+=( --yes )
    if "$HERE/magma-tls.sh" "${le_args[@]}"; then
      TLS_IS_LE="yes"
    else
      warn "Let's Encrypt step did not complete — Magma is still up on its self-signed cert."
      warn "fix DNS/:80 and re-run:  sudo $HERE/magma-tls.sh --hostname $HOSTNAME_FQDN --email $LE_EMAIL --domain $DOMAIN --secrets-dir $SECRETS_DIR"
    fi
  fi
fi

# ---------------------------------------------------------------- summary -----
DKIM_LINE="$( [ -f "$SECRETS_DIR/dns-records.txt" ] && echo "see $SECRETS_DIR/dns-records.txt" || echo "(dns-records.txt missing)" )"
cat <<DONE

${c_grn}============================================================${c_0}
${c_grn} Magma is running.${c_0}
${c_grn}============================================================${c_0}

  Webmail:   https://${HOSTNAME_FQDN}/        (and http://…/ )
  Admin login: ${ADMIN_USER}@${DOMAIN}

  Mail ports published on this host:
    SMTP 25/587/465   IMAP 143/993   POP 110/995   Web 80/443

  ${c_yel}You still have to do these yourself${c_0} (like any mail server):
    1. Point DNS at this host:
         MX     ${DOMAIN}.        ->  ${HOSTNAME_FQDN}.
         A      ${HOSTNAME_FQDN}. ->  <this host's public IP>
         PTR (reverse DNS) for that IP -> ${HOSTNAME_FQDN}   (set at your provider)
    2. Publish SPF / DKIM / DMARC:  ${DKIM_LINE}
    3. Make sure your host/ISP does not block outbound port 25.

$( if [ "$TLS_IS_LE" = yes ]; then
printf '  TLS is CA-signed by Lets Encrypt and renews automatically (see magma-tls.sh).'
else
printf '  TLS is self-signed for now. For a real cert:\n'
printf '      sudo %s/magma-tls.sh --hostname %s --email you@%s --domain %s --secrets-dir %s\n' "$HERE" "$HOSTNAME_FQDN" "$DOMAIN" "$DOMAIN" "$SECRETS_DIR"
printf '  (needs DNS pointed here and :80 reachable), or drop a CA cert into %s/ and restart.' "$SECRETS_DIR"
fi )

  Logs:    $ENGINE logs -f $CONTAINER
  Stop:    $ENGINE rm -f $CONTAINER     (secrets in $SECRETS_DIR are kept)

DONE
ok "done"
