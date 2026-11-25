#!/usr/bin/env bash
# =============================================================================
# magma-domain.sh — host mail for more than one domain on a single Magma box.
#
# Magma routes inbound mail by looking the recipient's domain up in the Domains
# table and the full address up in Mailboxes, both read live from the DB. So
# adding a domain is a DB operation — no rebuild, no restart:
#
#   magma-domain.sh list
#   magma-domain.sh add    <domain> [--catch-all <user>] [--no-spf]
#   magma-domain.sh remove <domain>
#
# `add` registers the domain for receiving + hosting mailboxes (mailboxes=1,
# spf=1). Create addresses in it afterwards with the Aliases tab / an extra
# Mailboxes row, or register users whose address is in it. `--catch-all <user>`
# turns on the wildcard flag and points unmatched mail at <user>'s mailbox.
#
#   DKIM note: Magma signs outbound mail with ONE key/selector from magma.config
#   (your primary domain). Secondary domains are added with dkim=0 — they
#   receive fine and can send, but won't carry a valid DKIM signature of their
#   own. For per-domain DKIM you'd need a key per domain (not yet wired here);
#   publish SPF + DMARC for the secondary domain and relay accordingly.
#
# Options:  --config <f>   magma.conf (default /etc/magma/magma.conf)
#           --dry-run      print the SQL instead of running it
# =============================================================================
set -uo pipefail

CONFIG="/etc/magma/magma.conf" DRY="no" ACTION="" DOM="" CATCHALL="" WANT_SPF="yes"
if [ -t 1 ]; then c_grn=$'\033[1;32m'; c_yel=$'\033[1;33m'; c_red=$'\033[1;31m'; c_0=$'\033[0m'
else c_grn="" c_yel="" c_red="" c_0=""; fi
ok()   { printf '%s ✓%s %s\n' "$c_grn" "$c_0" "$*"; }
warn() { printf '%s !!%s %s\n' "$c_yel" "$c_0" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$c_red" "$c_0" "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    list|add|remove) ACTION="$1"; shift;;
    --config)    CONFIG="$2"; shift 2;;
    --catch-all) CATCHALL="$2"; shift 2;;
    --no-spf)    WANT_SPF="no"; shift;;
    --dry-run)   DRY="yes"; shift;;
    -h|--help)   sed -n '2,33p' "$0"; exit 0;;
    -*)          die "unknown option: $1";;
    *)           [ -z "$DOM" ] && DOM="$1" || die "unexpected argument: $1"; shift;;
  esac
done
[ -n "$ACTION" ] || die "usage: magma-domain.sh list|add|remove <domain> (try --help)"

[ -r "$CONFIG" ] || die "cannot read $CONFIG"
cfg() { sed -n "s/^$1=//p" "$CONFIG" | head -n1 | sed 's/^["'\'']//;s/["'\'']$//'; }
PODMAN="$(cfg MAGMA_PODMAN)"; PODMAN="${PODMAN:-podman}"
CNAME="$(cfg MAGMA_CONTAINER)"; CNAME="${CNAME:-magma}"
DOMAIN="$(cfg MAGMA_DOMAIN)"
SECRETS_DIR="$(cfg MAGMA_SECRETS_DIR)"
SCHEMA="Magma"; RC="$SECRETS_DIR/magma.$DOMAIN.config"
[ -r "$RC" ] && SCHEMA="$(sed -n 's/^magma\.iface\.database\.schema[[:space:]]*=[[:space:]]*//p' "$RC" | head -n1)"
SCHEMA="${SCHEMA:-Magma}"
SOCK="/var/lib/mysql/mysql.sock"

sql() {  # run SQL in the container's MariaDB (root over the socket)
  if [ "$DRY" = yes ]; then printf '   [dry-run] %s\n' "$1" >&2; return 0; fi
  "$PODMAN" exec -i "$CNAME" mysql --socket="$SOCK" -N -B "$SCHEMA" -e "$1"
}
valid_domain() { case "$1" in *.*) [ -z "${1//[A-Za-z0-9.-]/}" ];; *) return 1;; esac; }

case "$ACTION" in
  list)
    printf '%-32s %-9s %-4s %-4s %-9s\n' DOMAIN MAILBOXES SPF DKIM WILDCARD
    sql "SELECT domain, mailboxes, spf, dkim, wildcard FROM Domains ORDER BY domain;" \
      | while IFS=$'\t' read -r d m s k w; do printf '%-32s %-9s %-4s %-4s %-9s\n' "$d" "$m" "$s" "$k" "$w"; done
    ;;
  add)
    [ -n "$DOM" ] || die "usage: magma-domain.sh add <domain>"
    valid_domain "$DOM" || die "'$DOM' does not look like a domain"
    exists="$(sql "SELECT COUNT(*) FROM Domains WHERE domain='$DOM';" | tr -d '[:space:]')"
    [ "$exists" = 0 ] || die "domain '$DOM' already present (use remove first to change it)"
    spf=1; [ "$WANT_SPF" = yes ] || spf=0
    wild=0
    if [ -n "$CATCHALL" ]; then
      unum="$(sql "SELECT usernum FROM Users WHERE userid='$CATCHALL';" | tr -d '[:space:]')"
      [ -n "$unum" ] || die "catch-all user '$CATCHALL' not found"
      wild=1
    fi
    sql "INSERT INTO Domains (domain, restricted, mailboxes, wildcard, dkim, spf, created) VALUES ('$DOM', 0, 1, $wild, 0, $spf, NOW());"
    ok "added domain '$DOM' (receiving + mailboxes; spf=$spf, dkim=0)"
    if [ -n "$CATCHALL" ]; then
      # a wildcard/catch-all address for the domain, delivering to the chosen user
      sql "INSERT IGNORE INTO Mailboxes (address, usernum) VALUES ('@$DOM', $unum);" || true
      ok "catch-all: unmatched @$DOM -> $CATCHALL"
    fi
    echo
    warn "Publish DNS for $DOM:  MX -> $(cfg MAGMA_HOSTNAME) ;  TXT \"v=spf1 mx -all\" ;  _dmarc TXT \"v=DMARC1; p=quarantine\""
    warn "DKIM for $DOM is not signed (single-key limitation) — see --help."
    ;;
  remove)
    [ -n "$DOM" ] || die "usage: magma-domain.sh remove <domain>"
    [ "$DOM" != "$DOMAIN" ] || die "refusing to remove the primary domain '$DOMAIN'"
    n="$(sql "SELECT COUNT(*) FROM Mailboxes WHERE address LIKE '%@$DOM';" | tr -d '[:space:]')"
    [ "${n:-0}" = 0 ] || die "$n mailbox address(es) still use @$DOM — remove them first"
    sql "DELETE FROM Mailboxes WHERE address='@$DOM';" || true
    sql "DELETE FROM Domains WHERE domain='$DOM';"
    ok "removed domain '$DOM'"
    ;;
esac
