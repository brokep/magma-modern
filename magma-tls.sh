#!/usr/bin/env bash
# =============================================================================
# magma-tls.sh — Let's Encrypt (ACME) TLS for a modernized Magma.  (Phase 2)
#
# Magma loads ONE PEM per TLS listener:  $CONFIG_PREFIX/tls.<domain>.pem,
# which is the private key followed by the certificate chain (see gen-secrets.sh:
# `cat key crt > pem`).  This script obtains/renews a real CA-signed certificate
# with certbot and drops it into that exact file, then reloads Magma — and wires
# up unattended renewal so it keeps working.
#
# How it stays simple and robust:
#   * certbot --standalone answers the HTTP-01 challenge on :80.  Magma also
#     publishes :80 (webmail), so we hand certbot a --pre-hook that stops the
#     container and a --post-hook that starts it.  certbot only runs those when a
#     certificate is actually due, so Magma restarts ~once every 60 days, not on
#     every twice-daily renew check.
#   * --deploy-hook rebuilds tls.<domain>.pem from the freshly issued key+chain,
#     atomically, mode 600.  It runs on first issuance AND every future renewal.
#   * All three hooks are saved into certbot's renewal config, so `certbot renew`
#     (driven by certbot.timer) does the whole dance with no further setup.
#
# Must run as root (certbot writes /etc/letsencrypt and binds :80).
#
# Usage (standalone):
#   sudo ./magma-tls.sh --hostname mail.example.com --email you@example.com \
#        --domain example.com --secrets-dir ./secrets/example.com
#
# Usually invoked for you by:  ./magma-setup.sh --letsencrypt you@example.com
#
# Options:
#   --hostname <h>       FQDN to certify (primary SAN).            [required]
#   --email <e>          contact for the ACME account / expiry mail.[required]
#   --domain <d>         mail domain — names the PEM (tls.<d>.pem). [required]
#   --secrets-dir <p>    dir holding tls.<d>.pem (default ./secrets/<domain>)
#   --extra-domain <h>   add another SAN (repeatable; e.g. the bare domain)
#   --container <n>      Magma container to stop/start (default magma)
#   --engine <e>         podman|docker (default: autodetect)
#   --cert-name <n>      certbot lineage name (default magma-<hostname>)
#   --hook-dir <p>       where hook scripts are written (default <secrets>/letsencrypt)
#   --staging            use Let's Encrypt staging (untrusted, high rate limits)
#   --dry-run            certbot --dry-run (test issuance, nothing installed)
#   --force-renewal      renew even if the current cert is not near expiry
#   --no-timer           don't enable certbot.timer (you arrange renewal yourself)
#   --no-install         don't try to install certbot if it's missing
#   -y | --yes           don't prompt
#   -h | --help          this help
# =============================================================================
set -euo pipefail

# --------------------------------------------------------------- defaults ----
HOSTNAME_FQDN="" EMAIL="" DOMAIN="" SECRETS_DIR="" CONTAINER="magma" ENGINE=""
CERT_NAME="" HOOK_DIR="" STAGING="no" DRY_RUN="no" FORCE="no"
WANT_TIMER="yes" WANT_INSTALL="yes" ASSUME_YES="no"
EXTRA_DOMAINS=()
HERE="$(cd "$(dirname "$0")" && pwd)"

# ---------------------------------------------------------------- helpers ----
c_blue=$'\033[1;34m'; c_grn=$'\033[1;32m'; c_yel=$'\033[1;33m'; c_red=$'\033[1;31m'; c_0=$'\033[0m'
say()  { printf '%s>>%s %s\n' "$c_blue" "$c_0" "$*"; }
ok()   { printf '%s ✓%s %s\n' "$c_grn"  "$c_0" "$*"; }
warn() { printf '%s !!%s %s\n' "$c_yel" "$c_0" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$c_red" "$c_0" "$*" >&2; exit 1; }

# ----------------------------------------------------------------- parse -----
while [ $# -gt 0 ]; do
  case "$1" in
    --hostname)     HOSTNAME_FQDN="$2"; shift 2;;
    --email)        EMAIL="$2"; shift 2;;
    --domain)       DOMAIN="$2"; shift 2;;
    --secrets-dir)  SECRETS_DIR="$2"; shift 2;;
    --extra-domain) EXTRA_DOMAINS+=("$2"); shift 2;;
    --container)    CONTAINER="$2"; shift 2;;
    --engine)       ENGINE="$2"; shift 2;;
    --cert-name)    CERT_NAME="$2"; shift 2;;
    --hook-dir)     HOOK_DIR="$2"; shift 2;;
    --staging)      STAGING="yes"; shift;;
    --dry-run)      DRY_RUN="yes"; shift;;
    --force-renewal) FORCE="yes"; shift;;
    --no-timer)     WANT_TIMER="no"; shift;;
    --no-install)   WANT_INSTALL="no"; shift;;
    -y|--yes)       ASSUME_YES="yes"; shift;;
    -h|--help)      sed -n '2,55p' "$0"; exit 0;;
    *)              die "unknown option: $1 (try --help)";;
  esac
done

# --------------------------------------------------------------- validate ----
[ -n "$HOSTNAME_FQDN" ] || die "--hostname is required"
[ -n "$EMAIL" ]         || die "--email is required"
[ -n "$DOMAIN" ]        || die "--domain is required (names tls.<domain>.pem)"
case "$HOSTNAME_FQDN" in *.*) :;; *) die "'$HOSTNAME_FQDN' is not an FQDN";; esac
[ -n "$SECRETS_DIR" ]   || SECRETS_DIR="$HERE/secrets/$DOMAIN"
[ -n "$CERT_NAME" ]     || CERT_NAME="magma-$HOSTNAME_FQDN"
[ -n "$HOOK_DIR" ]      || HOOK_DIR="$SECRETS_DIR/letsencrypt"
[ -d "$SECRETS_DIR" ]   || die "secrets dir not found: $SECRETS_DIR (run magma-setup.sh first)"
[ "$(id -u)" = 0 ]      || die "must run as root (certbot writes /etc/letsencrypt and binds :80) — try: sudo $0 …"

PEM="$SECRETS_DIR/tls.$DOMAIN.pem"   # the file Magma's config points __TLS_CERT__ at

# ------------------------------------------------------- engine autodetect ---
if [ -z "$ENGINE" ]; then
  if command -v podman >/dev/null 2>&1; then ENGINE=podman
  elif command -v docker >/dev/null 2>&1; then ENGINE=docker
  else die "no container engine found — install podman (recommended) or docker"; fi
fi
command -v "$ENGINE" >/dev/null 2>&1 || die "engine '$ENGINE' not on PATH"

# ----------------------------------------------------------- ensure certbot --
if ! command -v certbot >/dev/null 2>&1; then
  if [ "$WANT_INSTALL" = no ]; then die "certbot not found and --no-install given"; fi
  say "certbot not found — installing it"
  if   command -v dnf >/dev/null 2>&1;     then dnf -y install certbot
  elif command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get -y install certbot
  elif command -v yum >/dev/null 2>&1;     then yum -y install certbot
  elif command -v zypper >/dev/null 2>&1;  then zypper -n install certbot
  elif command -v apk >/dev/null 2>&1;     then apk add --no-cache certbot
  else die "could not install certbot automatically — install it, then re-run"; fi
  command -v certbot >/dev/null 2>&1 || die "certbot still not on PATH after install"
fi
ok "certbot: $(certbot --version 2>&1 | head -n1)"

# ------------------------------------------------------- reachability note ---
# HTTP-01 needs this host reachable from the internet on :80 at $HOSTNAME_FQDN.
# We don't hard-fail (DNS may have just been set), but we warn so a failure is
# understood rather than mysterious.
PUBIP="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
RESOLVED="$(getent hosts "$HOSTNAME_FQDN" 2>/dev/null | awk '{print $1}' | head -n1 || true)"
if [ -n "$PUBIP" ] && [ -n "$RESOLVED" ] && [ "$PUBIP" != "$RESOLVED" ]; then
  warn "$HOSTNAME_FQDN resolves to ${RESOLVED:-<nothing>}, but this host's public IP looks like $PUBIP."
  warn "Let's Encrypt validates over the public internet — if DNS/:80 aren't pointed here yet, issuance will fail."
  if [ "$ASSUME_YES" != yes ]; then
    read -r -p "Continue anyway? [y/N]: " a || true
    case "${a:-N}" in y|Y|yes) :;; *) die "aborted — point DNS at this host, open :80, then re-run";; esac
  fi
fi

# ----------------------------------------------------- write the LE hooks ----
# certbot invokes these itself (now, and on every future renewal via the saved
# renewal config). They are host-side scripts; values are baked in so certbot
# can call them with no arguments.
say "installing renewal hooks in $HOOK_DIR"
mkdir -p "$HOOK_DIR"; chmod 700 "$HOOK_DIR"

cat > "$HOOK_DIR/pre-hook.sh" <<EOF
#!/bin/sh
# Free :80 for certbot's standalone HTTP-01 challenge. Runs only when a cert is
# actually due for renewal, so Magma is not bounced on routine renew checks.
exec $ENGINE stop "$CONTAINER" 2>/dev/null || true
EOF

cat > "$HOOK_DIR/post-hook.sh" <<EOF
#!/bin/sh
# Bring Magma back after the challenge (it re-reads the PEM on start).
$ENGINE start "$CONTAINER" 2>/dev/null || true
EOF

cat > "$HOOK_DIR/deploy-hook.sh" <<EOF
#!/bin/sh
# Rebuild the PEM Magma loads: private key THEN full chain (matches gen-secrets).
# certbot exports \$RENEWED_LINEAGE for deploy hooks. Written atomically, 0600.
set -eu
PEM="$PEM"
umask 077
cat "\$RENEWED_LINEAGE/privkey.pem" "\$RENEWED_LINEAGE/fullchain.pem" > "\$PEM.tmp"
chmod 600 "\$PEM.tmp"
mv -f "\$PEM.tmp" "\$PEM"
echo "magma-tls: installed \$RENEWED_DOMAINS -> \$PEM"
EOF

chmod +x "$HOOK_DIR"/pre-hook.sh "$HOOK_DIR"/post-hook.sh "$HOOK_DIR"/deploy-hook.sh
ok "hooks written (pre/post/deploy)"

# --------------------------------------------------------- run certbot -------
CB=(certbot certonly --standalone --non-interactive --agree-tos --no-eff-email
    --preferred-challenges http --http-01-port 80
    -m "$EMAIL" --cert-name "$CERT_NAME"
    --pre-hook  "$HOOK_DIR/pre-hook.sh"
    --post-hook "$HOOK_DIR/post-hook.sh"
    --deploy-hook "$HOOK_DIR/deploy-hook.sh"
    -d "$HOSTNAME_FQDN")
for d in "${EXTRA_DOMAINS[@]:-}"; do [ -n "$d" ] && CB+=(-d "$d"); done
[ "$STAGING" = yes ] && CB+=(--staging)
[ "$DRY_RUN" = yes ] && CB+=(--dry-run)
[ "$FORCE"   = yes ] && CB+=(--force-renewal)

say "requesting certificate for: $HOSTNAME_FQDN${EXTRA_DOMAINS:+ ${EXTRA_DOMAINS[*]}}"
if ! "${CB[@]}"; then
  "$ENGINE" start "$CONTAINER" >/dev/null 2>&1 || true   # make sure Magma is back up even on failure
  die "certbot failed — see the output above and /var/log/letsencrypt/letsencrypt.log"
fi

if [ "$DRY_RUN" = yes ]; then
  ok "dry run succeeded — Magma's cert was NOT changed. Re-run without --dry-run to install."
  exit 0
fi

# ----------------------------------------------------------- verify ----------
[ -s "$PEM" ] || die "certbot reported success but $PEM is missing/empty — check the deploy hook"
if ! grep -q 'BEGIN CERTIFICATE' "$PEM" || ! grep -qE 'BEGIN (PRIVATE|RSA PRIVATE|EC PRIVATE) KEY' "$PEM"; then
  die "$PEM does not contain both a key and a certificate"
fi
ISSUER="$(openssl x509 -in "$PEM" -noout -issuer 2>/dev/null | sed 's/^issuer=//' || true)"
NOTAFTER="$(openssl x509 -in "$PEM" -noout -enddate 2>/dev/null | sed 's/notAfter=//' || true)"
ok "installed cert into $PEM"
[ -n "$ISSUER" ]   && say "  issuer:  $ISSUER"
[ -n "$NOTAFTER" ] && say "  expires: $NOTAFTER"

# Make sure Magma is running with the new cert (post-hook should have started it;
# start is idempotent).
"$ENGINE" start "$CONTAINER" >/dev/null 2>&1 || true

# ------------------------------------------------------- renewal timer -------
if [ "$WANT_TIMER" = yes ]; then
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^certbot.timer'; then
    systemctl enable --now certbot.timer >/dev/null 2>&1 \
      && ok "certbot.timer enabled — renewals are unattended" \
      || warn "could not enable certbot.timer; enable renewal yourself (e.g. a daily 'certbot renew' cron)"
  elif command -v crontab >/dev/null 2>&1; then
    # Idempotent: add a daily renew line if none exists.
    if ! crontab -l 2>/dev/null | grep -q 'certbot renew'; then
      ( crontab -l 2>/dev/null; echo "17 3 * * * certbot renew --quiet" ) | crontab - \
        && ok "added a daily 'certbot renew' cron job" \
        || warn "could not add a renew cron job; arrange 'certbot renew' yourself"
    else
      ok "a 'certbot renew' cron job is already present"
    fi
  else
    warn "no systemd/cron found — arrange to run 'certbot renew' daily yourself"
  fi
fi

cat <<DONE

${c_grn}============================================================${c_0}
${c_grn} TLS is now CA-signed (Let's Encrypt).${c_0}
${c_grn}============================================================${c_0}

  Certificate: $PEM
  Covers:      $HOSTNAME_FQDN${EXTRA_DOMAINS:+ ${EXTRA_DOMAINS[*]}}
  Renewal:     certbot renews automatically; on renewal it stops Magma briefly,
               rebuilds the PEM, and starts Magma again (hooks in $HOOK_DIR).

  Test it:     openssl s_client -connect $HOSTNAME_FQDN:443 -servername $HOSTNAME_FQDN </dev/null 2>/dev/null | openssl x509 -noout -issuer -dates
  Force renew: sudo certbot renew --cert-name $CERT_NAME --force-renewal

DONE
ok "done"
