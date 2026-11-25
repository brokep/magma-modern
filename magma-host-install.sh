#!/usr/bin/env bash
# =============================================================================
# magma-host-install.sh — install a modernized Magma as a host service. (Phase 4)
#
# The Mail-in-a-Box front door, host edition:
#
#     curl -fsSL https://raw.githubusercontent.com/brokep/magma-modern/openssl3/magma-host-install.sh | sudo bash
#
# Magma is a C daemon whose vendored OpenSSL builds only on a pinned Rocky 9
# toolchain (that's why the container exists). Rather than fight a native build
# on whatever distro the host runs, this installs Magma as a *systemd-managed
# container*: a real service that starts on boot, with the host firewall opened
# and an idempotent `magma` command for day-2 ops. Re-running this script is
# safe — it reuses existing secrets and just reconciles the service.
#
# Steps: install prerequisites (podman + tools) → fetch the source → build (or
# reuse) the image → render real secrets → write & start a systemd unit → open
# the firewall → mint the admin account → (optionally) get a Let's Encrypt cert
# → install the `magma` control command → run the deliverability checks.
#
# Non-interactive via flags or env (MAGMA_DOMAIN / MAGMA_HOSTNAME /
# MAGMA_ADMIN_USER / MAGMA_ADMIN_PASS / MAGMA_LE_EMAIL); interactive prompts fall
# back to /dev/tty so it also works when piped from curl.
#
# Options:
#   --domain <d>        primary mail domain                         [required]
#   --hostname <h>      this server's FQDN (default mail.<domain>)
#   --admin-user <u>    admin local part (default admin)
#   --admin-pass <p>    admin password (prompted on /dev/tty if omitted)
#   --letsencrypt <e>   also obtain a Let's Encrypt cert for the hostname
#   --image <t>         image tag (default magma:local)
#   --ref <branch>      source branch to build (default openssl3)
#   --repo <url>        git repo to build from (default the fork)
#   --install-dir <p>   where source/scripts live (default /opt/magma)
#   --config-dir <p>    where secrets/config live (default /etc/magma)
#   --service <n>       systemd service name (default magma)
#   --admin-bind <ip>   /admin panel bind address (default 127.0.0.1, loopback)
#   --admin-port <n>    /admin panel port (default 8080)
#   --no-admin          don't install the /admin web control panel
#   --data-dir <p>      host dir for mail storage (default /var/lib/magma-data)
#   --db-dir <p>        host dir for the database (default /var/lib/magma-db)
#   --backup-dir <p>    where encrypted backups land (default /var/backups/magma)
#   --backup-schedule <t> systemd OnCalendar for backups (default '*-*-* 03:30:00')
#   --no-harden         don't install fail2ban / automatic security updates
#   --no-backup         don't install the scheduled backup timer
#   --no-build          reuse --image; don't build (image must exist)
#   --no-firewall       don't touch the firewall; print what to open instead
#   --no-start          install the unit but don't start it
#   --dry-run           print mutating actions without doing them
#   --yes               don't prompt (requires the flags/env above)
#   -h | --help         this help
# =============================================================================
set -euo pipefail

# --------------------------------------------------------------- defaults ----
DOMAIN="${MAGMA_DOMAIN:-}" HOSTNAME_FQDN="${MAGMA_HOSTNAME:-}"
ADMIN_USER="${MAGMA_ADMIN_USER:-admin}" ADMIN_PASS="${MAGMA_ADMIN_PASS:-}"
LE_EMAIL="${MAGMA_LE_EMAIL:-}"
IMAGE="magma:local" REF="openssl3" REPO="https://github.com/brokep/magma-modern.git"
INSTALL_DIR="/opt/magma" CONFIG_DIR="/etc/magma" SERVICE="magma"
DO_BUILD="yes" DO_FIREWALL="yes" DO_START="yes" DRY="no" ASSUME_YES="no"
DO_ADMIN="yes" ADMIN_BIND="127.0.0.1" ADMIN_PORT="8080"
# Persistent host storage (so accounts + mail survive restarts/reboots), host
# hardening (fail2ban + automatic security updates) and scheduled backups.
DATA_DIR="/var/lib/magma-data" DB_DIR="/var/lib/magma-db" LOG_DIR="/var/log/magma"
DO_HARDEN="yes" DO_BACKUP="yes" BACKUP_DIR="/var/backups/magma" BACKUP_SCHEDULE="*-*-* 03:30:00"

PORT_MAP=( "25:7000" "587:7000" "465:7500" "110:8000" "995:8500"
           "143:9000" "993:9500" "80:10000" "443:10500" )
FW_PORTS=( 25 587 465 110 995 143 993 80 443 )   # host ports to open

# ---------------------------------------------------------------- helpers ----
c_blue=$'\033[1;34m'; c_grn=$'\033[1;32m'; c_yel=$'\033[1;33m'; c_red=$'\033[1;31m'; c_0=$'\033[0m'
say()  { printf '%s>>%s %s\n' "$c_blue" "$c_0" "$*"; }
ok()   { printf '%s ✓%s %s\n' "$c_grn"  "$c_0" "$*"; }
warn() { printf '%s !!%s %s\n' "$c_yel" "$c_0" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$c_red" "$c_0" "$*" >&2; exit 1; }
run()  { if [ "$DRY" = yes ]; then printf '   %s[dry-run]%s %s\n' "$c_yel" "$c_0" "$*"; else "$@"; fi; }

tty_read() { # tty_read <var> <prompt> <default> [secret]
  local __v="$1" p="$2" d="${3:-}" secret="${4:-}" a=""
  if [ "$ASSUME_YES" = yes ] || [ ! -r /dev/tty ]; then printf -v "$__v" '%s' "$d"; return; fi
  if [ -n "$secret" ]; then read -r -s -p "$p: " a </dev/tty; echo >&2
  elif [ -n "$d" ]; then read -r -p "$p [$d]: " a </dev/tty || true
  else read -r -p "$p: " a </dev/tty || true; fi
  printf -v "$__v" '%s' "${a:-$d}"
}
json_escape() { local s=$1; s=${s//\\/\\\\}; s=${s//\"/\\\"}; printf '%s' "$s"; }

# ----------------------------------------------------------------- parse -----
while [ $# -gt 0 ]; do
  case "$1" in
    --domain)      DOMAIN="$2"; shift 2;;
    --hostname)    HOSTNAME_FQDN="$2"; shift 2;;
    --admin-user)  ADMIN_USER="$2"; shift 2;;
    --admin-pass)  ADMIN_PASS="$2"; shift 2;;
    --letsencrypt) LE_EMAIL="$2"; shift 2;;
    --image)       IMAGE="$2"; shift 2;;
    --ref)         REF="$2"; shift 2;;
    --repo)        REPO="$2"; shift 2;;
    --install-dir) INSTALL_DIR="$2"; shift 2;;
    --config-dir)  CONFIG_DIR="$2"; shift 2;;
    --service)     SERVICE="$2"; shift 2;;
    --admin-bind)  ADMIN_BIND="$2"; shift 2;;
    --admin-port)  ADMIN_PORT="$2"; shift 2;;
    --no-admin)    DO_ADMIN="no"; shift;;
    --no-harden)   DO_HARDEN="no"; shift;;
    --no-backup)   DO_BACKUP="no"; shift;;
    --data-dir)    DATA_DIR="$2"; shift 2;;
    --db-dir)      DB_DIR="$2"; shift 2;;
    --backup-dir)  BACKUP_DIR="$2"; shift 2;;
    --backup-schedule) BACKUP_SCHEDULE="$2"; shift 2;;
    --no-build)    DO_BUILD="no"; shift;;
    --no-firewall) DO_FIREWALL="no"; shift;;
    --no-start)    DO_START="no"; shift;;
    --dry-run)     DRY="yes"; shift;;
    --yes|-y)      ASSUME_YES="yes"; shift;;
    -h|--help)     sed -n '2,49p' "$0"; exit 0;;
    *)             die "unknown option: $1 (try --help)";;
  esac
done

# -------------------------------------------------------------- preflight ----
[ "$(id -u)" = 0 ] || die "must run as root — pipe through sudo:  curl -fsSL … | sudo bash"
[ "$(uname -s)" = Linux ] || die "the host installer targets Linux (systemd). On macOS use magma-setup.sh (container)."
command -v systemctl >/dev/null 2>&1 || die "systemd (systemctl) not found — this installer manages Magma as a systemd service"

CNAME="$SERVICE"                       # container name == service name
SECRETS_DIR="$CONFIG_DIR/$DOMAIN"      # host path; mounted read-only at /etc/magma in the container
UNIT="/etc/systemd/system/$SERVICE.service"
ADMIN_SERVICE="$SERVICE-admin"         # the /admin web panel runs as its own unit
ADMIN_UNIT="/etc/systemd/system/$ADMIN_SERVICE.service"

# distro / package manager
PKG=""; for p in dnf apt-get yum zypper apk; do command -v "$p" >/dev/null 2>&1 && { PKG="$p"; break; }; done

cat <<BANNER

  ${c_blue}Magma${c_0} — host installer (systemd-managed container)
  ------------------------------------------------
  A real mail-server service, started on boot, firewall opened, re-runnable.
  service: $SERVICE    image: $IMAGE    config: $CONFIG_DIR

BANNER

# ----------------------------------------------------------- gather inputs ---
[ -n "$DOMAIN" ] || tty_read DOMAIN 'Primary mail domain (e.g. example.com)' ''
[ -n "$DOMAIN" ] || die "a domain is required (--domain or MAGMA_DOMAIN)"
case "$DOMAIN" in *.*) :;; *) die "'$DOMAIN' does not look like a domain";; esac
SECRETS_DIR="$CONFIG_DIR/$DOMAIN"
[ -n "$HOSTNAME_FQDN" ] || tty_read HOSTNAME_FQDN 'Server hostname (FQDN)' "mail.$DOMAIN"
[ -n "$ADMIN_USER" ]    || tty_read ADMIN_USER 'Admin account (local part)' 'admin'
if [ -z "$ADMIN_PASS" ] && [ ! -f "$SECRETS_DIR/.admin-minted" ]; then
  tty_read ADMIN_PASS "Password for ${ADMIN_USER}@${DOMAIN}" '' secret
fi

# ----------------------------------------------------- 1. prerequisites ------
say "installing prerequisites (podman + tools)"
PKGS_COMMON="podman git openssl curl python3"   # python3 runs the /admin panel
case "$PKG" in
  dnf|yum)   run "$PKG" -y install $PKGS_COMMON certbot bind-utils      || warn "some packages failed to install";;
  apt-get)   run env DEBIAN_FRONTEND=noninteractive "$PKG" update -qq || true
             run env DEBIAN_FRONTEND=noninteractive "$PKG" -y install $PKGS_COMMON certbot dnsutils uidmap || warn "some packages failed to install";;
  zypper)    run "$PKG" -n install $PKGS_COMMON certbot bind-utils      || warn "some packages failed to install";;
  apk)       run "$PKG" add --no-cache $PKGS_COMMON certbot bind-tools  || warn "some packages failed to install";;
  *)         warn "unknown package manager — ensure podman, git, openssl, curl are installed";;
esac
command -v podman >/dev/null 2>&1 || [ "$DRY" = yes ] || die "podman is required but not installed"
PODMAN="$(command -v podman 2>/dev/null || echo /usr/bin/podman)"
ok "prerequisites ready ($PODMAN)"

# --------------------------------------------------- 2. fetch the source -----
# The scripts (gen-secrets.sh, magma-tls.sh, magma-status.sh) and, for a build,
# the full tree come from here.
if [ -d "$INSTALL_DIR/src/.git" ]; then
  say "updating source in $INSTALL_DIR/src"
  run git -C "$INSTALL_DIR/src" fetch --depth 1 origin "$REF" || warn "git fetch failed (using existing checkout)"
  run git -C "$INSTALL_DIR/src" checkout -q "$REF" || true
  run git -C "$INSTALL_DIR/src" reset --hard "origin/$REF" 2>/dev/null || true
else
  say "cloning $REPO ($REF) -> $INSTALL_DIR/src"
  run mkdir -p "$INSTALL_DIR"
  run git clone --depth 1 -b "$REF" "$REPO" "$INSTALL_DIR/src" || die "git clone failed"
fi
SRC="$INSTALL_DIR/src"

# --------------------------------------------------- 3. build the image ------
image_exists() { "$PODMAN" image exists "$IMAGE" 2>/dev/null; }
if [ "$DO_BUILD" = yes ] && ! { [ "$DRY" = no ] && image_exists; }; then
  say "building $IMAGE from $SRC (first build takes ~15-25 min)"
  run "$PODMAN" build -t "$IMAGE" --build-arg MAGMA_REF="$REF" -f "$SRC/Containerfile" "$SRC" \
    || die "image build failed"
  ok "image built"
elif [ "$DO_BUILD" = no ] && [ "$DRY" = no ] && ! image_exists; then
  die "--no-build given but image '$IMAGE' does not exist"
else
  ok "reusing image $IMAGE"
fi

# ------------------------------------------------- 4. render real secrets ----
if [ -f "$SECRETS_DIR/magma.$DOMAIN.config" ] || [ -f "$SECRETS_DIR/grant.sql" ]; then
  ok "reusing existing secrets in $SECRETS_DIR (delete it to regenerate)"
else
  say "generating secrets for $DOMAIN -> $SECRETS_DIR"
  run mkdir -p "$SECRETS_DIR"; run chmod 700 "$SECRETS_DIR"
  run "$PODMAN" run --rm -v "$SECRETS_DIR:/out:z" --entrypoint /bin/bash "$IMAGE" -lc \
    "cd /root/magma && ./gen-secrets.sh --domain '$DOMAIN' --out /out --force --dime \
       --config-prefix /etc/magma --install-root /root/magma --data-root /var/lib/magma \
       --db-socket /var/lib/mysql/mysql.sock" \
    || die "secret generation failed"
  run "$PODMAN" unshare chown -R 0:0 "$SECRETS_DIR" 2>/dev/null || true
  ok "secrets written"
fi

# ------------------------------------------------- 5. systemd unit -----------
# Run the container in the foreground under systemd (works on every podman
# version; no Quadlet dependency). --replace + ExecStartPre make restarts clean.
say "writing systemd unit $UNIT"
# Persist the database, the mail store and the logs on the HOST — the container
# runs with --rm, so without these bind mounts every restart/reboot would wipe
# all accounts and mail. The log dir also feeds fail2ban's [magma] jail.
for d in "$DB_DIR" "$DATA_DIR" "$LOG_DIR"; do run mkdir -p "$d"; done
run chmod 700 "$DB_DIR" "$DATA_DIR"
PUBLISH=""; for m in "${PORT_MAP[@]}"; do PUBLISH="$PUBLISH -p $m"; done
UNIT_CONTENT="[Unit]
Description=Magma mail server ($DOMAIN) — podman container
Documentation=https://github.com/brokep/magma-modern
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=10
TimeoutStartSec=900
ExecStartPre=-$PODMAN rm -f $CNAME
ExecStart=$PODMAN run --name $CNAME --replace --rm \\
  --ulimit memlock=-1:-1 --ulimit nofile=65536:65536 \\
  --hostname $HOSTNAME_FQDN \\
  -e MAGMA_SEED_DEMO=0 \\
  -v $SECRETS_DIR:/etc/magma:ro,z \\
  -v $DB_DIR:/var/lib/mysql:z \\
  -v $DATA_DIR:/var/lib/magma:z \\
  -v $LOG_DIR:/var/log/magma:z \\
 $PUBLISH \\
  $IMAGE
ExecStop=$PODMAN stop -t 30 $CNAME

[Install]
WantedBy=multi-user.target
"
if [ "$DRY" = yes ]; then printf '   %s[dry-run]%s would write %s:\n%s\n' "$c_yel" "$c_0" "$UNIT" "$UNIT_CONTENT"
else printf '%s' "$UNIT_CONTENT" > "$UNIT"; fi
run systemctl daemon-reload
run systemctl enable "$SERVICE" >/dev/null 2>&1 || true
if [ "$DO_START" = yes ]; then
  run systemctl restart "$SERVICE" || die "failed to start $SERVICE — see: journalctl -u $SERVICE"
  ok "service $SERVICE started (enabled on boot)"
else
  ok "unit installed (not started; --no-start)"
fi

# ------------------------------------------------- 6. firewall ---------------
open_firewall() {
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    for p in "${FW_PORTS[@]}"; do run firewall-cmd --permanent --add-port="$p/tcp" >/dev/null || true; done
    run firewall-cmd --reload >/dev/null || true
    ok "firewalld: opened ${FW_PORTS[*]}"
  elif command -v ufw >/dev/null 2>&1; then
    for p in "${FW_PORTS[@]}"; do run ufw allow "$p/tcp" >/dev/null || true; done
    ok "ufw: allowed ${FW_PORTS[*]} (ufw not force-enabled; enable it yourself if desired)"
  else
    warn "no firewalld/ufw detected — open these TCP ports yourself: ${FW_PORTS[*]}"
  fi
}
if [ "$DO_FIREWALL" = yes ]; then say "opening firewall ports"; open_firewall
else warn "firewall skipped (--no-firewall) — open TCP ${FW_PORTS[*]} yourself"; fi

# ------------------------------------------------- 6b. hardening --------------
# fail2ban (brute-force protection on SSH + Magma's mail auth) and automatic
# security updates — the baseline every internet-facing mail server wants.
harden() {
  # --- automatic security updates (best-effort, per distro) ---
  case "$PKG" in
    dnf|yum)
      run "$PKG" -y install dnf-automatic >/dev/null 2>&1 || warn "could not install dnf-automatic"
      if [ "$DRY" = no ] && [ -f /etc/dnf/automatic.conf ]; then
        sed -i 's/^apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf 2>/dev/null || true
        sed -i 's/^upgrade_type = default/upgrade_type = security/' /etc/dnf/automatic.conf 2>/dev/null || true
      fi
      run systemctl enable --now dnf-automatic.timer >/dev/null 2>&1 || true
      ok "automatic security updates: dnf-automatic.timer";;
    apt)
      run env DEBIAN_FRONTEND=noninteractive "$PKG" -y install unattended-upgrades >/dev/null 2>&1 || warn "could not install unattended-upgrades"
      if [ "$DRY" = no ]; then printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null || true; fi
      run systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
      ok "automatic security updates: unattended-upgrades";;
    zypper)
      run systemctl enable --now transactional-update.timer >/dev/null 2>&1 \
        || warn "enable automatic updates yourself (zypper)";;
    apk)
      warn "Alpine: schedule 'apk upgrade' via cron yourself";;
  esac

  # --- fail2ban ---
  case "$PKG" in
    dnf|yum)  run "$PKG" -y install fail2ban >/dev/null 2>&1 || true;;
    apt)      run env DEBIAN_FRONTEND=noninteractive "$PKG" -y install fail2ban >/dev/null 2>&1 || true;;
    zypper)   run "$PKG" -n install fail2ban >/dev/null 2>&1 || true;;
    apk)      run "$PKG" add --no-cache fail2ban >/dev/null 2>&1 || true;;
  esac
  if ! command -v fail2ban-server >/dev/null 2>&1 && [ "$DRY" = no ]; then
    warn "fail2ban not available on this distro — skipping (install it yourself to enable the jails)"
    return 0
  fi
  if [ "$DRY" = no ]; then
    mkdir -p /etc/fail2ban/filter.d /etc/fail2ban/jail.d
    # the Magma filter ships in the source tree
    if [ -f "$SRC/res/fail2ban/magma.conf" ]; then
      install -m 0644 "$SRC/res/fail2ban/magma.conf" /etc/fail2ban/filter.d/magma.conf
    else
      warn "res/fail2ban/magma.conf missing from $SRC — the [magma] jail filter won't be installed"
    fi
    # jails: SSH (universal) + Magma mail auth (reads the host-mounted log dir)
    cat > /etc/fail2ban/jail.d/magma.local <<JAIL
# Installed by magma-host-install.sh
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = auto

[sshd]
enabled = true

[magma]
enabled  = true
filter   = magma
logpath  = $LOG_DIR/magmad.*.log
port     = 25,465,587,110,995,143,993
maxretry = 5
bantime  = 1h
JAIL
  else
    printf '   %s[dry-run]%s would write /etc/fail2ban/filter.d/magma.conf + jail.d/magma.local\n' "$c_yel" "$c_0"
  fi
  run systemctl enable fail2ban >/dev/null 2>&1 || true
  run systemctl restart fail2ban >/dev/null 2>&1 || warn "fail2ban did not restart — check: journalctl -u fail2ban"
  ok "fail2ban: sshd + magma jails (ban 5 failures/10m for 1h)"
}
if [ "$DO_HARDEN" = yes ]; then say "hardening the host (fail2ban + auto-updates)"; harden
else warn "hardening skipped (--no-harden)"; fi

# ------------------------------------------------- 7. wait + mint admin ------
if [ "$DO_START" = yes ] && [ "$DRY" = no ]; then
  say "waiting for Magma to come up (first-boot schema load can take a few minutes)…"
  ready=no
  for i in $(seq 1 180); do
    code=$("$PODMAN" exec "$CNAME" curl -s --max-time 4 -o /dev/null -w '%{http_code}' http://127.0.0.1:10000/ 2>/dev/null || true)
    case "$code" in 2*|3*|4*) ready=yes; break;; esac
    sleep 2
  done
  [ "$ready" = yes ] || warn "portal did not answer in time; check: journalctl -u $SERVICE"
  if [ "$ready" = yes ] && [ ! -f "$SECRETS_DIR/.admin-minted" ] && [ -n "$ADMIN_PASS" ]; then
    say "creating admin account ${ADMIN_USER}@${DOMAIN}"
    json=$(printf '{"jsonrpc":"2.0","method":"register","id":1,"params":{"username":"%s","password":"%s","password_verification":"%s","plan":"PREMIER"}}' \
           "$(json_escape "$ADMIN_USER")" "$(json_escape "$ADMIN_PASS")" "$(json_escape "$ADMIN_PASS")")
    RESP=$(printf '%s' "$json" | "$PODMAN" exec -i "$CNAME" curl -s --max-time 15 \
           -H 'Content-Type: application/json' --data-binary @- http://127.0.0.1:10000/json 2>/dev/null || true)
    if printf '%s' "$RESP" | grep -q '"result"'; then
      : > "$SECRETS_DIR/.admin-minted"; ok "admin account created"
    elif printf '%s' "$RESP" | grep -qiE 'already|exists|duplicate'; then
      : > "$SECRETS_DIR/.admin-minted"; ok "admin account already present"
    else
      warn "could not confirm admin creation; response: ${RESP:-<empty>}"
    fi
  elif [ -f "$SECRETS_DIR/.admin-minted" ]; then
    ok "admin account already minted (skipping)"
  fi
fi

# ------------------------------------------------- 8. record state -----------
say "recording configuration in $CONFIG_DIR/magma.conf"
CONF_CONTENT="# magma host install — written by magma-host-install.sh
MAGMA_DOMAIN=$DOMAIN
MAGMA_ADMIN_USER=$ADMIN_USER
MAGMA_HOSTNAME=$HOSTNAME_FQDN
MAGMA_SECRETS_DIR=$SECRETS_DIR
MAGMA_SERVICE=$SERVICE
MAGMA_CONTAINER=$CNAME
MAGMA_IMAGE=$IMAGE
MAGMA_INSTALL_DIR=$INSTALL_DIR
MAGMA_PODMAN=$PODMAN
MAGMA_ADMIN_SERVICE=$ADMIN_SERVICE
MAGMA_ADMIN_BIND=$ADMIN_BIND
MAGMA_ADMIN_PORT=$ADMIN_PORT
MAGMA_DATA_DIR=$DATA_DIR
MAGMA_DB_DIR=$DB_DIR
MAGMA_LOG_DIR=$LOG_DIR
MAGMA_BACKUP_DIR=$BACKUP_DIR
"
if [ "$DRY" = yes ]; then printf '   %s[dry-run]%s would write %s/magma.conf\n' "$c_yel" "$c_0" "$CONFIG_DIR"
else printf '%s' "$CONF_CONTENT" > "$CONFIG_DIR/magma.conf"; chmod 600 "$CONFIG_DIR/magma.conf"; fi

# ------------------------------------------------- 9. `magma` control cmd -----
if [ -f "$SRC/magma-ctl.sh" ]; then
  say "installing the 'magma' command -> /usr/local/sbin/magma"
  run install -m 0755 "$SRC/magma-ctl.sh" /usr/local/sbin/magma
  ok "run 'magma status' / 'magma restart' / 'magma logs' anytime"
else
  warn "magma-ctl.sh not found in $SRC — skipping the 'magma' command"
fi

# ------------------------------------------------- 9b. /admin web panel ------
# A single-file Python (stdlib) control panel, run as its own systemd unit.
# Loopback-bound by default — reach it over an SSH tunnel.
if [ "$DO_ADMIN" = yes ] && [ -f "$SRC/magma-admin.py" ]; then
  PYTHON="$(command -v python3 2>/dev/null || echo /usr/bin/python3)"
  say "installing the /admin web panel ($ADMIN_SERVICE on $ADMIN_BIND:$ADMIN_PORT)"
  ADMIN_CONTENT="[Unit]
Description=Magma /admin web panel ($DOMAIN)
After=$SERVICE.service network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PYTHON $SRC/magma-admin.py --config $CONFIG_DIR/magma.conf --bind $ADMIN_BIND --port $ADMIN_PORT
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectHome=yes

[Install]
WantedBy=multi-user.target
"
  if [ "$DRY" = yes ]; then printf '   %s[dry-run]%s would write %s:\n%s\n' "$c_yel" "$c_0" "$ADMIN_UNIT" "$ADMIN_CONTENT"
  else printf '%s' "$ADMIN_CONTENT" > "$ADMIN_UNIT"; fi
  run systemctl daemon-reload
  run systemctl enable "$ADMIN_SERVICE" >/dev/null 2>&1 || true
  if [ "$DO_START" = yes ]; then
    run systemctl restart "$ADMIN_SERVICE" || warn "admin panel did not start — see: journalctl -u $ADMIN_SERVICE"
    ok "admin panel on http://$ADMIN_BIND:$ADMIN_PORT  (tunnel:  ssh -L $ADMIN_PORT:$ADMIN_BIND:$ADMIN_PORT root@this-host)"
  else
    ok "admin panel unit installed (not started; --no-start)"
  fi
elif [ "$DO_ADMIN" = yes ]; then
  warn "magma-admin.py not found in $SRC — skipping the /admin panel"
else
  warn "/admin panel skipped (--no-admin)"
fi

# ------------------------------------------------- 9c. scheduled backups -----
# A systemd timer that runs magma-backup.sh (encrypted DB + secrets + mail
# store, rotated, optional offsite). The passphrase is minted on the first run.
if [ "$DO_BACKUP" = yes ] && [ -f "$SRC/magma-backup.sh" ]; then
  say "installing the backup timer ($SERVICE-backup.timer @ '$BACKUP_SCHEDULE')"
  run install -m 0755 "$SRC/magma-backup.sh" /usr/local/sbin/magma-backup
  BK_SVC="/etc/systemd/system/$SERVICE-backup.service"
  BK_TMR="/etc/systemd/system/$SERVICE-backup.timer"
  BK_SVC_CONTENT="[Unit]
Description=Magma encrypted backup ($DOMAIN)
After=$SERVICE.service
Wants=$SERVICE.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/magma-backup backup --config $CONFIG_DIR/magma.conf
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
"
  BK_TMR_CONTENT="[Unit]
Description=Run the Magma backup on a schedule

[Timer]
OnCalendar=$BACKUP_SCHEDULE
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
"
  if [ "$DRY" = yes ]; then
    printf '   %s[dry-run]%s would write %s + %s\n' "$c_yel" "$c_0" "$BK_SVC" "$BK_TMR"
  else
    printf '%s' "$BK_SVC_CONTENT" > "$BK_SVC"
    printf '%s' "$BK_TMR_CONTENT" > "$BK_TMR"
  fi
  run systemctl daemon-reload
  run systemctl enable --now "$SERVICE-backup.timer" >/dev/null 2>&1 || warn "could not enable the backup timer"
  ok "backups: '$SERVICE-backup' nightly -> $BACKUP_DIR  (run now: magma-backup backup)"
elif [ "$DO_BACKUP" = yes ]; then
  warn "magma-backup.sh not found in $SRC — skipping the backup timer"
else
  warn "scheduled backups skipped (--no-backup)"
fi

# ------------------------------------------------- 9d. dns + autoconfig ------
# Install the DNS-push and mail-client autoconfig helpers as commands, and
# generate the client autoconfig profiles now (so they're ready to serve/hand out).
for tool in magma-dns.sh magma-autoconfig.sh; do
  [ -f "$SRC/$tool" ] && run install -m 0755 "$SRC/$tool" "/usr/local/sbin/${tool%.sh}"
done
if [ -f "$SRC/magma-autoconfig.sh" ] && [ "$DRY" = no ]; then
  "$SRC/magma-autoconfig.sh" --config "$CONFIG_DIR/magma.conf" >/dev/null 2>&1 \
    && ok "mail-client autoconfig generated in $SECRETS_DIR/autoconfig/" \
    || warn "could not generate autoconfig (run: magma-autoconfig later)"
fi

# ------------------------------------------------- 10. Let's Encrypt ---------
if [ -n "$LE_EMAIL" ] && [ "$DRY" = no ]; then
  if [ -x "$SRC/magma-tls.sh" ]; then
    say "requesting a Let's Encrypt certificate"
    # Pass --service so the renew hooks drive systemctl (a bare podman stop would
    # be auto-restarted by the unit and steal :80 back from certbot).
    le=( --hostname "$HOSTNAME_FQDN" --email "$LE_EMAIL" --domain "$DOMAIN"
         --secrets-dir "$SECRETS_DIR" --service "$SERVICE" --container "$CNAME" --engine "$PODMAN" --yes )
    [ "$HOSTNAME_FQDN" != "$DOMAIN" ] && le+=( --extra-domain "$DOMAIN" )
    "$SRC/magma-tls.sh" "${le[@]}" \
      || warn "Let's Encrypt step did not complete; run 'magma tls $LE_EMAIL' later"
  else warn "magma-tls.sh not found — skipping Let's Encrypt"; fi
fi

# ------------------------------------------------- 11. summary + status ------
cat <<DONE

${c_grn}============================================================${c_0}
${c_grn} Magma is installed as a systemd service.${c_0}
${c_grn}============================================================${c_0}

  Service:   systemctl status $SERVICE     (enabled on boot)
  Control:   magma status | restart | stop | start | logs | tls <email> | admin
  Webmail:   https://$HOSTNAME_FQDN/
  Admin:     ${ADMIN_USER}@${DOMAIN}$( [ "$DO_ADMIN" = yes ] && printf '\n  Panel:     http://%s:%s/  (loopback — tunnel: ssh -L %s:%s:%s root@this-host)' "$ADMIN_BIND" "$ADMIN_PORT" "$ADMIN_PORT" "$ADMIN_BIND" "$ADMIN_PORT" )
  Secrets:   $SECRETS_DIR   (DNS records in dns-records.txt)
  Data:      db=$DB_DIR  mail=$DATA_DIR  logs=$LOG_DIR  (persist across restarts)
$( [ "$DO_BACKUP" = yes ] && printf '  Backups:   magma-backup list | backup | restore <f>   (nightly -> %s)\n' "$BACKUP_DIR" )$( [ "$DO_HARDEN" = yes ] && printf '  Hardening: fail2ban (sshd + magma) + automatic security updates\n' )
  DNS/mail:  magma-dns push --provider cloudflare   |   magma-autoconfig

  ${c_yel}Still yours to do${c_0} (any mail server needs these):
    1. DNS:  either run  magma-dns push --provider cloudflare|route53  (auto),
             or publish by hand:  MX $DOMAIN -> $HOSTNAME_FQDN ;  A $HOSTNAME_FQDN -> this IP ;
             SPF/DKIM/DMARC from $SECRETS_DIR/dns-records.txt ;  and a PTR for the IP
    2. Ensure outbound :25 isn't blocked by your host/ISP
$( [ -z "$LE_EMAIL" ] && printf '    3. For a real TLS cert:  magma tls you@%s\n' "$DOMAIN" )$( [ -n "$BACKUP_DIR" ] && [ "$DO_BACKUP" = yes ] && printf '    4. Copy the backup passphrase ('"$CONFIG_DIR"'/.backup-pass) OFF this box\n' )

DONE

if [ "$DRY" = no ] && [ -x "$SRC/magma-status.sh" ] && [ "$DO_START" = yes ]; then
  say "running deliverability checks (magma status)"
  "$SRC/magma-status.sh" --domain "$DOMAIN" --hostname "$HOSTNAME_FQDN" --secrets-dir "$SECRETS_DIR" || true
fi
ok "done"
