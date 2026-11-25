#!/usr/bin/env bash
# =============================================================================
# magma-dns.sh — publish Magma's DNS records to your provider automatically.
# (Mail-in-a-Box hosts its own DNS; this instead *pushes* the record set into
#  an existing provider zone — Cloudflare or Route 53 — so you don't hand-copy.)
#
# It assembles the complete mail record set for your domain from magma.conf and
# $SECRETS_DIR/dns-records.txt (the DKIM/SPF/DMARC values Magma generated):
#
#     <host>.                 A      <public-ip>        (the mail server)
#     <domain>.               MX  10 <host>.            (inbound routing)
#     <domain>.               TXT    "v=spf1 mx -all"   (SPF)
#     <sel>._domainkey.<dom>. TXT    "v=DKIM1; …"       (DKIM, from secrets)
#     _dmarc.<domain>.        TXT    "v=DMARC1; …"      (DMARC)
#     autoconfig.<domain>.    CNAME  <host>.            (Thunderbird autoconfig)
#     autodiscover.<domain>.  CNAME  <host>.            (Outlook autodiscover)
#
# Each record is UPSERTED (created, or updated in place) — it never deletes
# records it doesn't manage, so an existing website on the apex is untouched.
#
# Usage:
#   magma-dns.sh plan                       # show the record set (no changes)
#   magma-dns.sh push --provider cloudflare # create/update via Cloudflare API
#   magma-dns.sh push --provider route53    # … via the AWS CLI
#   magma-dns.sh push --provider manual     # print a BIND zone snippet to paste
#
# Credentials (env or flag):
#   Cloudflare:  MAGMA_CF_TOKEN   (API token, Zone:DNS:Edit)   or --cf-token
#   Route 53:    standard AWS CLI credentials (aws configure / env / role)
#
# Options:
#   --config <f>    magma.conf (default /etc/magma/magma.conf)
#   --ip <addr>     public IP for the A record (default: auto-detect)
#   --provider <p>  cloudflare | route53 | manual
#   --no-autoconfig don't emit the autoconfig/autodiscover CNAMEs
#   --dry-run       print the API calls instead of making them
# =============================================================================
set -uo pipefail

CONFIG="/etc/magma/magma.conf"
PROVIDER="" PUBLIC_IP="" CF_TOKEN="" DRY="no" WANT_AUTOCONF="yes"
ACTION="plan"

if [ -t 1 ]; then
  c_grn=$'\033[1;32m'; c_yel=$'\033[1;33m'; c_red=$'\033[1;31m'; c_b=$'\033[1m'; c_dim=$'\033[2m'; c_0=$'\033[0m'
else c_grn="" c_yel="" c_red="" c_b="" c_dim="" c_0=""; fi
say()  { printf '%s>>%s %s\n' "$c_b"   "$c_0" "$*"; }
ok()   { printf '%s ✓%s %s\n' "$c_grn" "$c_0" "$*"; }
warn() { printf '%s !!%s %s\n' "$c_yel" "$c_0" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$c_red" "$c_0" "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    plan|push)       ACTION="$1"; shift;;
    --config)        CONFIG="$2"; shift 2;;
    --provider)      PROVIDER="$2"; shift 2;;
    --ip)            PUBLIC_IP="$2"; shift 2;;
    --cf-token)      CF_TOKEN="$2"; shift 2;;
    --no-autoconfig) WANT_AUTOCONF="no"; shift;;
    --dry-run)       DRY="yes"; shift;;
    -h|--help)       sed -n '2,50p' "$0"; exit 0;;
    *)               die "unknown argument: $1 (try --help)";;
  esac
done

[ -r "$CONFIG" ] || die "cannot read $CONFIG (pass --config)"
cfg() { sed -n "s/^$1=//p" "$CONFIG" | head -n1 | sed 's/^["'\'']//;s/["'\'']$//'; }
DOMAIN="$(cfg MAGMA_DOMAIN)";       [ -n "$DOMAIN" ]   || die "MAGMA_DOMAIN missing from $CONFIG"
HOST="$(cfg MAGMA_HOSTNAME)";       [ -n "$HOST" ]     || HOST="mail.$DOMAIN"
SECRETS_DIR="$(cfg MAGMA_SECRETS_DIR)"
[ -n "$CF_TOKEN" ] || CF_TOKEN="${MAGMA_CF_TOKEN:-$(cfg MAGMA_CF_TOKEN)}"
DNSFILE="$SECRETS_DIR/dns-records.txt"
[ -r "$DNSFILE" ] || die "no DNS records at $DNSFILE (run the installer / gen-secrets first)"

# --- pull the generated TXT values out of dns-records.txt (BIND format) ------
# lines look like:  name. IN TXT "value"
txt_value() { # txt_value <name-prefix-regex>
  sed -n "s/^$1[[:space:]]*IN[[:space:]]*TXT[[:space:]]*\"\(.*\)\"[[:space:]]*$/\1/p" "$DNSFILE" | head -n1
}
SPF="$(txt_value "${DOMAIN}\\.")"
DMARC="$(txt_value "_dmarc\\.${DOMAIN}\\.")"
DKIM_LINE="$(grep -E "_domainkey\\.${DOMAIN}\\." "$DNSFILE" | head -n1)"
DKIM_NAME="$(printf '%s' "$DKIM_LINE" | sed -n 's/^\([^ ]*\)\.[[:space:]].*$/\1/p')"
DKIM_VALUE="$(printf '%s' "$DKIM_LINE" | sed -n 's/^.*IN[[:space:]]*TXT[[:space:]]*"\(.*\)"[[:space:]]*$/\1/p')"
[ -n "$SPF" ]        || SPF="v=spf1 mx -all"
[ -n "$DMARC" ]      || DMARC="v=DMARC1; p=quarantine; rua=mailto:abuse@$DOMAIN"
[ -n "$DKIM_NAME" ]  || die "could not parse the DKIM record from $DNSFILE"

# --- public IP for the A record ---------------------------------------------
detect_ip() {
  local ip=""
  for u in "https://api.ipify.org" "https://ifconfig.me/ip" "https://ipv4.icanhazip.com"; do
    ip="$(curl -s --max-time 6 "$u" 2>/dev/null | tr -dc '0-9.')"
    case "$ip" in [0-9]*.[0-9]*.[0-9]*.[0-9]*) printf '%s' "$ip"; return 0;; esac
  done
  return 1
}
if [ -z "$PUBLIC_IP" ]; then PUBLIC_IP="$(detect_ip || true)"; fi

# --- the desired record set (TYPE<TAB>NAME<TAB>VALUE, NAME is fqdn w/o trailing dot) ---
RECORDS=""
add() { RECORDS="$RECORDS$1	$2	$3
"; }
[ -n "$PUBLIC_IP" ] && add A     "$HOST"                  "$PUBLIC_IP"
add MX    "$DOMAIN"                "10 $HOST"
add TXT   "$DOMAIN"                "$SPF"
add TXT   "$DKIM_NAME"             "$DKIM_VALUE"
add TXT   "_dmarc.$DOMAIN"         "$DMARC"
if [ "$WANT_AUTOCONF" = yes ]; then
  add CNAME "autoconfig.$DOMAIN"   "$HOST"
  add CNAME "autodiscover.$DOMAIN" "$HOST"
fi

print_plan() {
  say "DNS record set for $DOMAIN (host $HOST)"
  [ -n "$PUBLIC_IP" ] || warn "no public IP detected — the A record is omitted (pass --ip)"
  printf '%s' "$RECORDS" | while IFS=$'\t' read -r t n v; do
    [ -n "$t" ] || continue
    printf '   %-6s %-34s %s%s%s\n' "$t" "$n" "$c_dim" "$v" "$c_0"
  done
}

# ----------------------------------------------------------- manual ----------
push_manual() {
  echo "; ---- paste into your DNS provider's zone for $DOMAIN ----"
  printf '%s' "$RECORDS" | while IFS=$'\t' read -r t n v; do
    [ -n "$t" ] || continue
    case "$t" in
      TXT)   printf '%s.\tIN\t%s\t"%s"\n' "$n" "$t" "$v";;
      MX)    printf '%s.\tIN\t%s\t%s.\n'  "$n" "$t" "$v";;
      CNAME) printf '%s.\tIN\t%s\t%s.\n'  "$n" "$t" "$v";;
      A)     printf '%s.\tIN\t%s\t%s\n'   "$n" "$t" "$v";;
    esac
  done
}

# ----------------------------------------------------------- cloudflare ------
cf() { # cf <method> <path> [data]
  local m="$1" p="$2" d="${3:-}"
  if [ -n "$d" ]; then
    curl -s --max-time 20 -X "$m" "https://api.cloudflare.com/client/v4$p" \
      -H "Authorization: Bearer $CF_TOKEN" -H "Content-Type: application/json" --data "$d"
  else
    curl -s --max-time 20 -X "$m" "https://api.cloudflare.com/client/v4$p" \
      -H "Authorization: Bearer $CF_TOKEN" -H "Content-Type: application/json"
  fi
}
jget() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" | head -n1; }   # tiny JSON string field reader

push_cloudflare() {
  command -v curl >/dev/null 2>&1 || die "curl is required for the Cloudflare provider"
  [ -n "$CF_TOKEN" ] || die "set MAGMA_CF_TOKEN (a Zone:DNS:Edit API token) or pass --cf-token"
  say "looking up Cloudflare zone for $DOMAIN"
  local zresp zid
  zresp="$(cf GET "/zones?name=$DOMAIN&status=active")"
  printf '%s' "$zresp" | grep -q '"success":true' || die "Cloudflare API error: $(printf '%s' "$zresp" | sed -n 's/.*"message":"\([^"]*\)".*/\1/p' | head -n1)"
  zid="$(printf '%s' "$zresp" | sed -n 's/.*"result":\[{"id":"\([a-f0-9]*\)".*/\1/p' | head -n1)"
  [ -n "$zid" ] || die "no active Cloudflare zone named '$DOMAIN' on this account"
  ok "zone $zid"

  printf '%s' "$RECORDS" | while IFS=$'\t' read -r t n v; do
    [ -n "$t" ] || continue
    # existing record of this type+name?
    local cur recid prio content body esc_v
    cur="$(cf GET "/zones/$zid/dns_records?type=$t&name=$n")"
    recid="$(printf '%s' "$cur" | sed -n 's/.*"result":\[{"id":"\([a-f0-9]*\)".*/\1/p' | head -n1)"
    # build the record body
    if [ "$t" = MX ]; then
      prio="${v%% *}"; content="${v#* }"; content="${content%.}"
      esc_v="$content"
      body="{\"type\":\"MX\",\"name\":\"$n\",\"content\":\"$content\",\"priority\":$prio,\"ttl\":3600}"
    elif [ "$t" = CNAME ]; then
      esc_v="${v%.}"
      body="{\"type\":\"CNAME\",\"name\":\"$n\",\"content\":\"$esc_v\",\"ttl\":3600,\"proxied\":false}"
    elif [ "$t" = TXT ]; then
      esc_v="$(printf '%s' "$v" | sed 's/\\/\\\\/g; s/"/\\"/g')"
      body="{\"type\":\"TXT\",\"name\":\"$n\",\"content\":\"$esc_v\",\"ttl\":3600}"
    else # A
      esc_v="$v"
      body="{\"type\":\"A\",\"name\":\"$n\",\"content\":\"$v\",\"ttl\":3600,\"proxied\":false}"
    fi
    if [ "$DRY" = yes ]; then
      printf '   %s[dry-run]%s %s %-5s %-30s %s\n' "$c_yel" "$c_0" "$([ -n "$recid" ] && echo PUT || echo POST)" "$t" "$n" "$esc_v"
      continue
    fi
    local resp
    if [ -n "$recid" ]; then resp="$(cf PUT "/zones/$zid/dns_records/$recid" "$body")"
    else                     resp="$(cf POST "/zones/$zid/dns_records" "$body")"; fi
    if printf '%s' "$resp" | grep -q '"success":true'; then
      printf '   %s✓%s %-5s %-30s %s\n' "$c_grn" "$c_0" "$t" "$n" "updated"
    else
      printf '   %s!!%s %-5s %-30s %s\n' "$c_yel" "$c_0" "$t" "$n" "$(printf '%s' "$resp" | sed -n 's/.*"message":"\([^"]*\)".*/\1/p' | head -n1)" >&2
    fi
  done
  ok "Cloudflare sync complete"
}

# ----------------------------------------------------------- route53 ---------
push_route53() {
  command -v aws >/dev/null 2>&1 || die "the AWS CLI (aws) is required for the route53 provider"
  say "looking up Route 53 hosted zone for $DOMAIN"
  local zid
  zid="$(aws route53 list-hosted-zones-by-name --dns-name "$DOMAIN." --max-items 1 \
         --query 'HostedZones[0].Id' --output text 2>/dev/null | sed 's#/hostedzone/##')"
  [ -n "$zid" ] && [ "$zid" != None ] || die "no Route 53 hosted zone for '$DOMAIN'"
  ok "zone $zid"

  # build one change batch (UPSERT each)
  local changes="" first=1
  while IFS=$'\t' read -r t n v; do
    [ -n "$t" ] || continue
    local rr prio content
    case "$t" in
      MX)    prio="${v%% *}"; content="${v#* }"; content="${content%.}"; rr="{\"Value\":\"$prio $content.\"}";;
      CNAME) rr="{\"Value\":\"${v%.}.\"}";;
      TXT)   rr="{\"Value\":\"\\\"$(printf '%s' "$v" | sed 's/"/\\\\\\"/g')\\\"\"}";;
      A)     rr="{\"Value\":\"$v\"}";;
    esac
    [ $first -eq 1 ] || changes="$changes,"; first=0
    changes="$changes{\"Action\":\"UPSERT\",\"ResourceRecordSet\":{\"Name\":\"$n.\",\"Type\":\"$t\",\"TTL\":3600,\"ResourceRecords\":[$rr]}}"
  done <<EOF
$(printf '%s' "$RECORDS")
EOF
  local batch="{\"Comment\":\"magma-dns\",\"Changes\":[$changes]}"
  if [ "$DRY" = yes ]; then printf '   %s[dry-run]%s change batch:\n%s\n' "$c_yel" "$c_0" "$batch"; return 0; fi
  if aws route53 change-resource-record-sets --hosted-zone-id "$zid" --change-batch "$batch" >/dev/null 2>&1; then
    ok "Route 53 sync submitted"
  else
    die "Route 53 change failed (check credentials / zone)"
  fi
}

case "$ACTION" in
  plan) print_plan;;
  push)
    [ -n "$PROVIDER" ] || die "push needs --provider cloudflare|route53|manual"
    print_plan; echo
    case "$PROVIDER" in
      cloudflare) push_cloudflare;;
      route53)    push_route53;;
      manual)     push_manual;;
      *)          die "unknown provider: $PROVIDER";;
    esac;;
esac
