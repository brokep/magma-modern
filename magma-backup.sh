#!/usr/bin/env bash
# =============================================================================
# magma-backup.sh — encrypted, rotated backups of a Magma host install.
# (Operational parity with Mail-in-a-Box's backup system, Magma edition.)
#
# What it captures (everything needed to rebuild the server from nothing):
#   1. The database        — a consistent mysqldump of the Magma schema
#                            (accounts, mailboxes, aliases, folders, messages
#                            metadata, DKIM/domain routing, …).
#   2. The mail storage    — the on-disk message store + spool
#                            ($MAGMA_DATA_DIR, the container's /var/lib/magma).
#   3. The secrets         — $MAGMA_SECRETS_DIR: the TLS, DKIM and DIME/PRIME
#                            keys and the rendered config. WITHOUT THESE THE
#                            STORED MAIL CANNOT BE DECRYPTED — Magma is
#                            zero-access, so the keys ARE the data.
#
# The three are tarred together and encrypted with gpg (AES-256, symmetric)
# using a passphrase kept at $CONFIG_DIR/.backup-pass (mode 600). That
# passphrase is generated on first run — COPY IT SOMEWHERE OFF THE BOX, because
# a backup you can't decrypt is not a backup.
#
# Offsite: if MAGMA_BACKUP_REMOTE is set (an rclone remote like "b2:my-bucket"
# or "s3:bucket/magma"), each new archive is uploaded with `rclone copy`.
#
# Usage:
#   magma-backup.sh                      # make a backup (what the timer runs)
#   magma-backup.sh backup               # same
#   magma-backup.sh list                 # list local backups
#   magma-backup.sh restore <archive>    # restore a backup (DESTRUCTIVE)
#   magma-backup.sh --help
#
# Options (override magma.conf / env):
#   --config <f>     magma.conf (default /etc/magma/magma.conf)
#   --backup-dir <d> where archives live (default /var/backups/magma)
#   --keep <n>       how many local archives to retain (default 14)
#   --remote <r>     rclone remote for offsite copy (default MAGMA_BACKUP_REMOTE)
#   --no-storage     back up DB + secrets only (skip the message store)
#   --yes            don't prompt on restore
# =============================================================================
set -uo pipefail

CONFIG="/etc/magma/magma.conf"
BACKUP_DIR="" KEEP="14" REMOTE="" WANT_STORAGE="yes" ASSUME_YES="no"
ACTION="backup" ARG=""

if [ -t 1 ]; then
  c_grn=$'\033[1;32m'; c_yel=$'\033[1;33m'; c_red=$'\033[1;31m'; c_b=$'\033[1m'; c_0=$'\033[0m'
else c_grn="" c_yel="" c_red="" c_b="" c_0=""; fi
say()  { printf '%s>>%s %s\n' "$c_b"   "$c_0" "$*"; }
ok()   { printf '%s ✓%s %s\n' "$c_grn" "$c_0" "$*"; }
warn() { printf '%s !!%s %s\n' "$c_yel" "$c_0" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$c_red" "$c_0" "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    backup|list|restore) ACTION="$1"; shift; if [ "$ACTION" = restore ]; then ARG="${1:-}"; [ -n "$ARG" ] && shift || true; fi;;
    --config)     CONFIG="$2"; shift 2;;
    --backup-dir) BACKUP_DIR="$2"; shift 2;;
    --keep)       KEEP="$2"; shift 2;;
    --remote)     REMOTE="$2"; shift 2;;
    --no-storage) WANT_STORAGE="no"; shift;;
    --yes|-y)     ASSUME_YES="yes"; shift;;
    -h|--help)    sed -n '2,46p' "$0"; exit 0;;
    *)            die "unknown argument: $1 (try --help)";;
  esac
done

# ------------------------------------------------------------ load config ----
[ -r "$CONFIG" ] || die "cannot read $CONFIG (is Magma installed? pass --config)"
# shellcheck disable=SC1090
cfg() { sed -n "s/^$1=//p" "$CONFIG" | head -n1 | sed 's/^["'\'']//;s/["'\'']$//'; }
PODMAN="$(cfg MAGMA_PODMAN)";      PODMAN="${PODMAN:-podman}"
CONTAINER="$(cfg MAGMA_CONTAINER)"; CONTAINER="${CONTAINER:-magma}"
SECRETS_DIR="$(cfg MAGMA_SECRETS_DIR)"
DATA_DIR="$(cfg MAGMA_DATA_DIR)"
CONFIG_DIR="$(dirname "$CONFIG")"
DOMAIN="$(cfg MAGMA_DOMAIN)"
SERVICE="$(cfg MAGMA_SERVICE)"; SERVICE="${SERVICE:-magma}"
[ -n "$BACKUP_DIR" ] || BACKUP_DIR="$(cfg MAGMA_BACKUP_DIR)"; BACKUP_DIR="${BACKUP_DIR:-/var/backups/magma}"
[ -n "$REMOTE" ]     || REMOTE="$(cfg MAGMA_BACKUP_REMOTE)"

# schema name lives in the rendered magma.<domain>.config
SCHEMA="Magma"
RC="$SECRETS_DIR/magma.$DOMAIN.config"
[ -r "$RC" ] && SCHEMA="$(sed -n 's/^magma\.iface\.database\.schema[[:space:]]*=[[:space:]]*//p' "$RC" | head -n1)"
SCHEMA="${SCHEMA:-Magma}"
DB_SOCK="/var/lib/mysql/mysql.sock"

running() { [ "$("$PODMAN" inspect -f '{{.State.Status}}' "$CONTAINER" 2>/dev/null)" = running ]; }

# ---------------------------------------------------------- passphrase --------
PASS_FILE="$CONFIG_DIR/.backup-pass"
ensure_passphrase() {
  if [ ! -s "$PASS_FILE" ]; then
    ( umask 077; openssl rand -base64 33 > "$PASS_FILE" )
    chmod 600 "$PASS_FILE"
    warn "generated a new backup passphrase at $PASS_FILE"
    warn "COPY IT OFF THIS MACHINE NOW — without it these backups cannot be restored:"
    printf '      %s%s%s\n' "$c_b" "$(cat "$PASS_FILE")" "$c_0" >&2
  fi
}

# ============================================================== actions =======
do_list() {
  say "backups in $BACKUP_DIR"
  if ! ls "$BACKUP_DIR"/magma-*.tar.gz.gpg >/dev/null 2>&1; then
    echo "   (none yet)"; return 0
  fi
  ls -lh --time-style=+'%Y-%m-%d %H:%M' "$BACKUP_DIR"/magma-*.tar.gz.gpg | awk '{printf "   %-7s  %s %s  %s\n",$5,$6,$7,$NF}'
  [ -n "$REMOTE" ] && echo "   offsite remote: $REMOTE"
  return 0
}

do_backup() {
  command -v gpg  >/dev/null 2>&1 || die "gpg is required for encrypted backups (install gnupg)"
  running || die "container '$CONTAINER' is not running — start it before backing up (systemctl start $SERVICE)"
  ensure_passphrase
  mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"

  local stamp staging base
  stamp="$(date +%Y%m%d-%H%M%S)"
  base="magma-$stamp"
  staging="$(mktemp -d "${TMPDIR:-/tmp}/magma-backup.XXXXXX")" || die "mktemp failed"
  trap 'rm -rf "$staging"' EXIT

  # 1. database (consistent dump, as root over the container socket)
  say "dumping database '$SCHEMA'"
  if ! "$PODMAN" exec "$CONTAINER" mysqldump --socket="$DB_SOCK" \
        --single-transaction --quick --routines --events --triggers \
        --default-character-set=latin1 "$SCHEMA" > "$staging/database.sql" 2>"$staging/.dumperr"; then
    cat "$staging/.dumperr" >&2; die "mysqldump failed"
  fi
  rm -f "$staging/.dumperr"
  ok "database dumped ($(du -h "$staging/database.sql" | cut -f1))"

  # 2. secrets (keys + rendered config) — the part that makes the mail readable
  say "capturing secrets ($SECRETS_DIR)"
  tar -C "$(dirname "$SECRETS_DIR")" -cf "$staging/secrets.tar" "$(basename "$SECRETS_DIR")" \
    || die "could not archive secrets"
  ok "secrets captured"

  # 3. message store + spool (the actual mail on disk)
  if [ "$WANT_STORAGE" = yes ] && [ -n "$DATA_DIR" ] && [ -d "$DATA_DIR" ]; then
    say "capturing mail storage ($DATA_DIR)"
    tar -C "$(dirname "$DATA_DIR")" -cf "$staging/storage.tar" "$(basename "$DATA_DIR")" \
      || warn "storage archive incomplete (continuing)"
    ok "storage captured ($(du -sh "$DATA_DIR" 2>/dev/null | cut -f1))"
  else
    [ "$WANT_STORAGE" = yes ] && warn "no data dir at '$DATA_DIR' — skipping message store (DB+secrets only)"
  fi

  # manifest
  { echo "magma-backup 1"; echo "created=$(date -Is)"; echo "domain=$DOMAIN"; echo "schema=$SCHEMA";
    echo "host=$(hostname -f 2>/dev/null || hostname)"; echo "storage=$([ -f "$staging/storage.tar" ] && echo yes || echo no)";
  } > "$staging/MANIFEST"

  # bundle + encrypt
  say "encrypting archive"
  local out="$BACKUP_DIR/$base.tar.gz.gpg"
  if ! tar -C "$staging" -czf - MANIFEST database.sql secrets.tar $( [ -f "$staging/storage.tar" ] && echo storage.tar ) \
       | gpg --batch --yes --cipher-algo AES256 --symmetric \
             --passphrase-file "$PASS_FILE" -o "$out" 2>"$staging/.gpgerr"; then
    cat "$staging/.gpgerr" >&2; rm -f "$out"; die "encryption failed"
  fi
  chmod 600 "$out"
  ok "backup written: $out ($(du -h "$out" | cut -f1))"

  # rotate
  local n
  n="$(ls -1t "$BACKUP_DIR"/magma-*.tar.gz.gpg 2>/dev/null | wc -l | tr -d ' ')"
  if [ "$n" -gt "$KEEP" ]; then
    say "rotating: keeping newest $KEEP of $n"
    ls -1t "$BACKUP_DIR"/magma-*.tar.gz.gpg | tail -n +"$((KEEP+1))" | while read -r old; do rm -f "$old" && echo "   removed $(basename "$old")"; done
  fi

  # offsite
  if [ -n "$REMOTE" ]; then
    if command -v rclone >/dev/null 2>&1; then
      say "uploading to offsite remote $REMOTE"
      if rclone copy "$out" "$REMOTE" 2>/dev/null; then ok "offsite copy complete"; else warn "rclone upload failed"; fi
    else
      warn "MAGMA_BACKUP_REMOTE set but rclone is not installed — skipping offsite copy"
    fi
  fi

  rm -rf "$staging"; trap - EXIT
  ok "done"
}

do_restore() {
  local archive="$ARG"
  [ -n "$archive" ] || die "usage: magma-backup.sh restore <archive.tar.gz.gpg>"
  [ -f "$archive" ] || archive="$BACKUP_DIR/$archive"
  [ -f "$archive" ] || die "no such archive: $ARG"
  command -v gpg >/dev/null 2>&1 || die "gpg is required to decrypt backups"
  [ -s "$PASS_FILE" ] || die "no backup passphrase at $PASS_FILE — restore it from your offsite copy first"

  printf '%sThis will OVERWRITE the current database, secrets and mail storage from:%s\n' "$c_yel" "$c_0" >&2
  printf '   %s\n' "$archive" >&2
  if [ "$ASSUME_YES" != yes ]; then
    printf 'Type the domain (%s) to confirm: ' "$DOMAIN" >&2
    read -r confirm </dev/tty || true
    [ "$confirm" = "$DOMAIN" ] || die "aborted"
  fi

  local staging; staging="$(mktemp -d "${TMPDIR:-/tmp}/magma-restore.XXXXXX")" || die "mktemp failed"
  trap 'rm -rf "$staging"' EXIT

  say "decrypting"
  gpg --batch --yes --quiet --passphrase-file "$PASS_FILE" -o "$staging/bundle.tar.gz" -d "$archive" || die "decryption failed (wrong passphrase?)"
  tar -C "$staging" -xzf "$staging/bundle.tar.gz" || die "corrupt archive"
  [ -f "$staging/database.sql" ] || die "archive missing database.sql"
  say "restoring from backup created $(sed -n 's/^created=//p' "$staging/MANIFEST" 2>/dev/null)"

  # secrets first (the container needs them to come up)
  if [ -f "$staging/secrets.tar" ] && [ -n "$SECRETS_DIR" ]; then
    say "restoring secrets -> $SECRETS_DIR"
    rm -rf "$SECRETS_DIR"
    tar -C "$(dirname "$SECRETS_DIR")" -xf "$staging/secrets.tar" || die "secrets restore failed"
  fi

  # storage
  if [ -f "$staging/storage.tar" ] && [ -n "$DATA_DIR" ]; then
    say "restoring mail storage -> $DATA_DIR"
    rm -rf "$DATA_DIR"
    tar -C "$(dirname "$DATA_DIR")" -xf "$staging/storage.tar" || warn "storage restore incomplete"
  fi

  # database: ensure the container (hence MariaDB) is up, then load the dump
  say "starting $SERVICE to load the database"
  systemctl start "$SERVICE" 2>/dev/null || true
  local up=no i
  for i in $(seq 1 60); do "$PODMAN" exec "$CONTAINER" mysqladmin --socket="$DB_SOCK" ping >/dev/null 2>&1 && { up=yes; break; }; sleep 2; done
  [ "$up" = yes ] || die "database did not come up; cannot load the dump"
  say "loading database '$SCHEMA'"
  "$PODMAN" exec "$CONTAINER" mysql --socket="$DB_SOCK" -e "CREATE DATABASE IF NOT EXISTS \`$SCHEMA\`;" 2>/dev/null || true
  if "$PODMAN" exec -i "$CONTAINER" mysql --socket="$DB_SOCK" "$SCHEMA" < "$staging/database.sql"; then
    ok "database restored"
  else
    die "database load failed"
  fi

  say "restarting $SERVICE"
  systemctl restart "$SERVICE" 2>/dev/null || warn "could not restart $SERVICE — do it manually"
  rm -rf "$staging"; trap - EXIT
  ok "restore complete"
}

case "$ACTION" in
  backup)  do_backup;;
  list)    do_list;;
  restore) do_restore;;
  *)       die "unknown action: $ACTION";;
esac
