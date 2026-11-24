#!/usr/bin/env bash
# =============================================================================
# magma-status.sh — deliverability status checks for a modernized Magma. (Phase 3)
#
# The Mail-in-a-Box "System Status Checks" equivalent: one command tells you
# whether the outside world will actually accept mail from this server. It checks
# the public DNS surface (A / MX / PTR / SPF / DKIM / DMARC), that outbound :25
# isn't blocked, that Magma is answering locally, that TLS is CA-signed and
# current, and that the sending IP isn't on common blacklists.
#
# It compares what's PUBLISHED against what Magma actually EXPECTS: the DKIM check
# recomputes the public key from dkim.<domain>.pem in the secrets dir and verifies
# the DNS record matches, so a stale or wrong selector is caught.
#
# Read-only. Safe to run anytime. Exit status is non-zero if any check FAILs
# (warnings don't fail), so it drops into cron / the host installer cleanly.
#
# Usage:
#   ./magma-status.sh --domain example.com
#   ./magma-status.sh --domain example.com --hostname mail.example.com \
#       --secrets-dir ./secrets/example.com
#
# Options:
#   --domain <d>        mail domain to check.                       [required]
#   --hostname <h>      the mail server's FQDN (default mail.<domain>)
#   --selector <s>      DKIM selector (default: read from secrets, else 'mail')
#   --secrets-dir <p>   dir with dkim.<domain>.pem (default ./secrets/<domain>);
#                       enables the published-vs-expected DKIM key comparison
#   --ip <addr>         this host's public IP (default: autodetect)
#   --local-host <a>    where Magma listens locally for service probes (def 127.0.0.1)
#   --smtp-probe <h>    outbound-:25 test target (default aspmx.l.google.com)
#   --no-install        don't try to install 'dig' if it's missing
#   --no-color          plain output
#   -h | --help         this help
# =============================================================================
set -uo pipefail   # NB: no -e; checks must keep running after a failing probe

# --------------------------------------------------------------- defaults ----
DOMAIN="" HOSTNAME_FQDN="" SELECTOR="" SECRETS_DIR="" PUBIP=""
LOCAL_HOST="127.0.0.1" SMTP_PROBE="aspmx.l.google.com"
WANT_INSTALL="yes" USE_COLOR="yes"
HERE="$(cd "$(dirname "$0")" && pwd)"

# ----------------------------------------------------------------- parse -----
while [ $# -gt 0 ]; do
  case "$1" in
    --domain)      DOMAIN="$2"; shift 2;;
    --hostname)    HOSTNAME_FQDN="$2"; shift 2;;
    --selector)    SELECTOR="$2"; shift 2;;
    --secrets-dir) SECRETS_DIR="$2"; shift 2;;
    --ip)          PUBIP="$2"; shift 2;;
    --local-host)  LOCAL_HOST="$2"; shift 2;;
    --smtp-probe)  SMTP_PROBE="$2"; shift 2;;
    --no-install)  WANT_INSTALL="no"; shift;;
    --no-color)    USE_COLOR="no"; shift;;
    -h|--help)     sed -n '2,39p' "$0"; exit 0;;
    *)             printf 'unknown option: %s (try --help)\n' "$1" >&2; exit 2;;
  esac
done
[ -n "$DOMAIN" ] || { printf 'error: --domain is required\n' >&2; exit 2; }
case "$DOMAIN" in *.*) :;; *) printf "error: '%s' is not a domain\n" "$DOMAIN" >&2; exit 2;; esac
[ -n "$HOSTNAME_FQDN" ] || HOSTNAME_FQDN="mail.$DOMAIN"
[ -n "$SECRETS_DIR" ]   || SECRETS_DIR="$HERE/secrets/$DOMAIN"

# ---------------------------------------------------------------- colors -----
if [ "$USE_COLOR" = yes ] && [ -t 1 ]; then
  c_grn=$'\033[1;32m'; c_yel=$'\033[1;33m'; c_red=$'\033[1;31m'; c_dim=$'\033[2m'; c_b=$'\033[1m'; c_0=$'\033[0m'
else c_grn="" c_yel="" c_red="" c_dim="" c_b="" c_0=""; fi

PASS=0 WARN=0 FAIL=0
row() { # row <pass|warn|fail|skip> <label> [detail]
  local s=$1 label=$2 detail="${3:-}"
  case "$s" in
    pass) printf '  %s✓%s  %-26s %s\n' "$c_grn" "$c_0" "$label" "$detail"; PASS=$((PASS+1));;
    warn) printf '  %s!%s  %-26s %s\n' "$c_yel" "$c_0" "$label" "$detail"; WARN=$((WARN+1));;
    fail) printf '  %s✗%s  %-26s %s\n' "$c_red" "$c_0" "$label" "$detail"; FAIL=$((FAIL+1));;
    skip) printf '  %s·%s  %-26s %s%s%s\n' "$c_dim" "$c_0" "$label" "$c_dim" "$detail" "$c_0";;
  esac
}
hint() { printf '       %s↳ %s%s\n' "$c_dim" "$*" "$c_0"; }

# ------------------------------------------------------------- ensure dig -----
if ! command -v dig >/dev/null 2>&1; then
  if [ "$WANT_INSTALL" = yes ] && [ "$(id -u)" = 0 ]; then
    if   command -v dnf    >/dev/null 2>&1; then dnf -y install bind-utils  >/dev/null 2>&1 || true
    elif command -v apt-get>/dev/null 2>&1; then apt-get update -qq >/dev/null 2>&1; apt-get -y install dnsutils >/dev/null 2>&1 || true
    elif command -v yum    >/dev/null 2>&1; then yum -y install bind-utils  >/dev/null 2>&1 || true
    elif command -v apk    >/dev/null 2>&1; then apk add --no-cache bind-tools >/dev/null 2>&1 || true
    elif command -v zypper >/dev/null 2>&1; then zypper -n install bind-utils >/dev/null 2>&1 || true
    fi
  fi
fi
HAVE_DIG=no; command -v dig >/dev/null 2>&1 && HAVE_DIG=yes

# --------------------------------------------------------- DNS helpers --------
dns_a()   { if [ "$HAVE_DIG" = yes ]; then dig +short A "$1" 2>/dev/null | grep -E '^[0-9.]+$'; else getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | sort -u; fi; }
dns_mx()  { [ "$HAVE_DIG" = yes ] && dig +short MX   "$1" 2>/dev/null; }
dns_txt() { [ "$HAVE_DIG" = yes ] && dig +short TXT  "$1" 2>/dev/null; }
dns_ptr() { [ "$HAVE_DIG" = yes ] && dig +short -x   "$1" 2>/dev/null; }
# Join a TXT record's 255-char quoted chunks into one logical string (keeps inner spaces).
txt_join() { sed -e 's/" "//g' -e 's/^[[:space:]]*"//' -e 's/"[[:space:]]*$//'; }
lower()   { tr 'A-Z' 'a-z'; }
stripdot(){ sed 's/\.$//'; }

# TCP probes (bash /dev/tcp, bounded by timeout so a filtered port can't hang us).
tcp_connect() { timeout "${3:-8}" bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1; }
tcp_banner()  { timeout "${3:-8}" bash -c "exec 3<>/dev/tcp/$1/$2; IFS= read -r -t $(( ${3:-8} - 2 )) l <&3; printf '%s' \"\$l\"" 2>/dev/null; }

printf '\n%sMagma deliverability status%s  —  %s  (mail server: %s)\n' "$c_b" "$c_0" "$DOMAIN" "$HOSTNAME_FQDN"
printf '%s%s%s\n' "$c_dim" '--------------------------------------------------------------------' "$c_0"
[ "$HAVE_DIG" = yes ] || row warn "DNS tooling" "'dig' not found — DNS checks limited (install bind-utils/dnsutils)"

# -------------------------------------------------------- public IP -----------
if [ -z "$PUBIP" ]; then
  PUBIP="$(curl -fsS --max-time 6 https://api.ipify.org 2>/dev/null || true)"
  [ -n "$PUBIP" ] || PUBIP="$(curl -fsS --max-time 6 https://ifconfig.me 2>/dev/null || true)"
fi
if [ -n "$PUBIP" ]; then row pass "Public IP" "$PUBIP"
else row warn "Public IP" "could not determine (pass --ip <addr>); PTR and blacklist checks will be skipped"; fi

# -------------------------------------------------------- hostname A ----------
HOST_A="$(dns_a "$HOSTNAME_FQDN" | head -n1)"
if [ -z "$HOST_A" ]; then
  row fail "Hostname A record" "$HOSTNAME_FQDN does not resolve"
  hint "publish:  $HOSTNAME_FQDN.  IN A  ${PUBIP:-<your public IP>}"
elif [ -n "$PUBIP" ] && [ "$HOST_A" = "$PUBIP" ]; then
  row pass "Hostname A record" "$HOSTNAME_FQDN -> $HOST_A"
else
  row warn "Hostname A record" "$HOSTNAME_FQDN -> $HOST_A (host public IP is ${PUBIP:-unknown})"
  hint "if this host sends mail directly, point the A record at $PUBIP"
fi

# -------------------------------------------------------- MX ------------------
MX_RAW="$(dns_mx "$DOMAIN")"
if [ -z "$MX_RAW" ]; then
  row fail "MX record" "$DOMAIN has no MX"
  hint "publish:  $DOMAIN.  IN MX  10 $HOSTNAME_FQDN."
else
  MX_HOST="$(printf '%s\n' "$MX_RAW" | sort -n | head -n1 | awk '{print $2}')"
  MX_TARGET="$(printf '%s' "$MX_HOST" | stripdot | lower)"
  if [ "$MX_HOST" = "." ] || [ -z "$MX_TARGET" ]; then
    row warn "MX record" "$DOMAIN publishes a null MX (declares it accepts no mail)"
    hint "for a mail server, publish:  $DOMAIN.  IN MX  10 $HOSTNAME_FQDN."
  elif [ "$MX_TARGET" = "$(printf '%s' "$HOSTNAME_FQDN" | lower)" ]; then
    row pass "MX record" "$DOMAIN -> $MX_TARGET"
  else
    row warn "MX record" "$DOMAIN -> $MX_TARGET (expected $HOSTNAME_FQDN)"
    hint "lowest-priority MX should be this server for inbound mail to arrive here"
  fi
fi

# -------------------------------------------------------- PTR / rDNS ----------
if [ -n "$PUBIP" ] && [ "$HAVE_DIG" = yes ]; then
  PTR="$(dns_ptr "$PUBIP" | head -n1 | stripdot | lower)"
  if [ -z "$PTR" ]; then
    row fail "Reverse DNS (PTR)" "$PUBIP has no PTR"
    hint "set at your hosting/ISP provider:  $PUBIP -> $HOSTNAME_FQDN  (major receivers reject mail without it)"
  elif [ "$PTR" = "$(printf '%s' "$HOSTNAME_FQDN" | lower)" ]; then
    row pass "Reverse DNS (PTR)" "$PUBIP -> $PTR"
  else
    row warn "Reverse DNS (PTR)" "$PUBIP -> $PTR (expected $HOSTNAME_FQDN)"
    hint "forward/reverse DNS should match; many receivers reject on mismatch"
  fi
else
  row skip "Reverse DNS (PTR)" "skipped (need public IP + dig)"
fi

# -------------------------------------------------------- SPF -----------------
SPF="$(dns_txt "$DOMAIN" | txt_join | grep -i '^v=spf1' | head -n1)"
if [ -z "$SPF" ]; then
  row fail "SPF" "$DOMAIN publishes no v=spf1 record"
  hint 'publish:  '"$DOMAIN"'.  IN TXT  "v=spf1 mx -all"'
else
  case "$SPF" in
    *" mx"*|*":a "*|*" a "*|*"ip4:$PUBIP"*|*"+all"*|*" all")
      row pass "SPF" "$SPF";;
    *)
      row warn "SPF" "$SPF"
      hint "record doesn't obviously authorize this host (no mx/a/ip4:$PUBIP) — verify senders are covered";;
  esac
  case "$SPF" in *"+all"*) hint "'+all' allows anyone to send as you — use '-all' or '~all'";; esac
fi

# -------------------------------------------------------- DKIM ----------------
# Expected public key: recompute from the local private key (authoritative).
[ -n "$SELECTOR" ] || SELECTOR="$(awk -F= '/_domainkey/{print $0}' "$SECRETS_DIR/dns-records.txt" 2>/dev/null | sed -n 's/\([^.]*\)\._domainkey.*/\1/p' | head -n1)"
[ -n "$SELECTOR" ] || SELECTOR="mail"
EXP_P=""
if [ -f "$SECRETS_DIR/dkim.$DOMAIN.pem" ]; then
  EXP_P="$(openssl rsa -in "$SECRETS_DIR/dkim.$DOMAIN.pem" -pubout -outform DER 2>/dev/null | openssl base64 -A 2>/dev/null)"
fi
DKIM_TXT="$(dns_txt "$SELECTOR._domainkey.$DOMAIN" | sed -e 's/" "//g' -e 's/"//g' | tr -d '\n ' )"
if [ -z "$DKIM_TXT" ]; then
  row fail "DKIM ($SELECTOR)" "no key published at $SELECTOR._domainkey.$DOMAIN"
  [ -f "$SECRETS_DIR/dns-records.txt" ] && hint "publish the DKIM line from $SECRETS_DIR/dns-records.txt"
elif ! printf '%s' "$DKIM_TXT" | grep -q 'p='; then
  row warn "DKIM ($SELECTOR)" "a TXT record exists but has no p= key"
else
  PUB_P="${DKIM_TXT#*p=}"; PUB_P="${PUB_P%%;*}"
  if [ -z "$PUB_P" ]; then
    row warn "DKIM ($SELECTOR)" "key is revoked or empty (p=)"
  elif [ -n "$EXP_P" ] && [ "$PUB_P" = "$EXP_P" ]; then
    row pass "DKIM ($SELECTOR)" "published key matches this server's key"
  elif [ -n "$EXP_P" ]; then
    row fail "DKIM ($SELECTOR)" "published key does NOT match dkim.$DOMAIN.pem"
    hint "re-publish the DKIM record from $SECRETS_DIR/dns-records.txt (selector or key is stale)"
  else
    row pass "DKIM ($SELECTOR)" "key published (pass --secrets-dir to verify it matches this server)"
  fi
fi

# -------------------------------------------------------- DMARC ---------------
DMARC="$(dns_txt "_dmarc.$DOMAIN" | txt_join | grep -i '^v=DMARC1' | head -n1)"
if [ -z "$DMARC" ]; then
  row fail "DMARC" "_dmarc.$DOMAIN publishes no v=DMARC1 record"
  hint 'publish:  _dmarc.'"$DOMAIN"'.  IN TXT  "v=DMARC1; p=quarantine; rua=mailto:abuse@'"$DOMAIN"'"'
else
  POLICY="$(printf '%s' "$DMARC" | sed -n 's/.*p=\([a-z]*\).*/\1/p')"
  case "$POLICY" in
    quarantine|reject) row pass "DMARC" "policy p=$POLICY";;
    none)              row warn "DMARC" "policy p=none (monitoring only — tighten to quarantine/reject when ready)";;
    *)                 row warn "DMARC" "$DMARC";;
  esac
fi

# -------------------------------------------------- outbound :25 --------------
if tcp_connect "$SMTP_PROBE" 25 10; then
  B="$(tcp_banner "$SMTP_PROBE" 25 10)"
  case "$B" in 220*) row pass "Outbound port 25" "can reach $SMTP_PROBE:25 (banner ok)";;
               *)    row pass "Outbound port 25" "TCP to $SMTP_PROBE:25 open";; esac
else
  row fail "Outbound port 25" "cannot open :25 to $SMTP_PROBE"
  hint "your host/ISP likely blocks outbound 25 — you cannot deliver mail directly; use a smarthost or ask them to unblock"
fi

# -------------------------------------------------- local SMTP (inbound) ------
if tcp_connect "$LOCAL_HOST" 25 6; then
  B="$(tcp_banner "$LOCAL_HOST" 25 6)"
  case "$B" in 220*) row pass "Magma SMTP (local)" "listening on $LOCAL_HOST:25 — ${B%%$'\r'*}";;
               *)    row warn "Magma SMTP (local)" "port open but no 220 banner (still starting?)";; esac
else
  row fail "Magma SMTP (local)" "nothing listening on $LOCAL_HOST:25 — is Magma running?"
fi

# -------------------------------------------------- TLS certificate -----------
LEAF="$(printf '' | timeout 10 openssl s_client -connect "$LOCAL_HOST:443" -servername "$HOSTNAME_FQDN" 2>/dev/null | openssl x509 2>/dev/null)"
if [ -z "$LEAF" ]; then
  row warn "TLS certificate" "could not read a cert from $LOCAL_HOST:443"
else
  ISS="$(printf '%s' "$LEAF" | openssl x509 -noout -issuer 2>/dev/null | sed 's/^issuer=//')"
  SUB="$(printf '%s' "$LEAF" | openssl x509 -noout -subject 2>/dev/null | sed 's/^subject=//')"
  END="$(printf '%s' "$LEAF" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')"
  SELF=no; [ "$ISS" = "$SUB" ] && SELF=yes
  NAME_OK=no; printf '%s' "$LEAF" | openssl x509 -noout -checkhost "$HOSTNAME_FQDN" >/dev/null 2>&1 && NAME_OK=yes
  EXPIRING=no; printf '%s' "$LEAF" | openssl x509 -noout -checkend $((15*86400)) >/dev/null 2>&1 || EXPIRING=yes
  if [ "$SELF" = yes ]; then
    row warn "TLS certificate" "self-signed — run magma-tls.sh for a Let's Encrypt cert"
  elif [ "$NAME_OK" = no ]; then
    row warn "TLS certificate" "CA-signed but does not cover $HOSTNAME_FQDN (subject: $SUB)"
  elif [ "$EXPIRING" = yes ]; then
    row warn "TLS certificate" "expires soon ($END) — check certbot renewal"
  else
    row pass "TLS certificate" "CA-signed, covers $HOSTNAME_FQDN, valid until $END"
  fi
fi

# -------------------------------------------------- DNS blacklists ------------
if [ -n "$PUBIP" ] && [ "$HAVE_DIG" = yes ] && printf '%s' "$PUBIP" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
  REV="$(printf '%s' "$PUBIP" | awk -F. '{print $4"."$3"."$2"."$1}')"
  LISTED="" ; CLEAN=0
  for BL in zen.spamhaus.org bl.spamcop.net b.barracudacentral.org; do
    ANS="$(dns_a "$REV.$BL" | head -n1)"
    case "$ANS" in
      "")               CLEAN=$((CLEAN+1));;                         # NXDOMAIN = not listed
      127.255.255.*)    : ;;                                         # resolver blocked by the DNSBL — inconclusive, ignore
      127.0.0.*)        LISTED="$LISTED $BL";;                        # genuine listing
      *)                CLEAN=$((CLEAN+1));;
    esac
  done
  if [ -n "$LISTED" ]; then
    row fail "Blacklists (DNSBL)" "$PUBIP listed on:$LISTED"
    hint "request delisting at the listing provider; new IPs are sometimes pre-listed"
  else
    row pass "Blacklists (DNSBL)" "$PUBIP not listed on $CLEAN checked list(s)"
  fi
else
  row skip "Blacklists (DNSBL)" "skipped (need public IPv4 + dig)"
fi

# ------------------------------------------------------------- summary --------
printf '%s%s%s\n' "$c_dim" '--------------------------------------------------------------------' "$c_0"
printf '  %s%d passed%s   %s%d warning(s)%s   %s%d failed%s\n\n' \
  "$c_grn" "$PASS" "$c_0" "$c_yel" "$WARN" "$c_0" "$c_red" "$FAIL" "$c_0"
if [ "$FAIL" -gt 0 ]; then
  printf '  %sMail delivery will likely be impaired until the ✗ items are fixed.%s\n\n' "$c_yel" "$c_0"
  exit 1
fi
[ "$WARN" -gt 0 ] && printf '  Review the warnings above; none are hard blockers.\n\n'
exit 0
