#!/usr/bin/env bash
# =============================================================================
# gen-secrets.sh — render a real Magma config + all secrets from the template.
#
# Produces, into an output directory, everything that must NOT be baked into
# an image: the TLS keypair, the DKIM key (+ DNS record), optionally the DIME
# org signet, fresh session/salt secrets, a scoped DB user grant, a domain
# seed, and a fully-rendered magma.<domain>.config.
#
# Usage:
#   ./gen-secrets.sh --domain example.com [options]
#
# Common options (all have sane prod defaults):
#   --domain <d>           (required) primary mail domain
#   --out <dir>            output dir            (default: ./secrets/<domain>)
#   --config-prefix <p>    where key files live on the server
#                                               (default: /etc/magma)
#   --selector <s>         DKIM selector        (default: mail)
#   --csr                  emit a CSR for a real CA instead of self-signing TLS
#   --dime                 mint the DIME org signet with the tree's signet CLI (NOTE: some
#                          magmad builds reject its output; see the warning it prints)
#   --dime-copy-from <d>   reuse an existing org key+signet pair from dir/file <d> instead
#                          (e.g. sandbox/etc/dime.* for a bootable demo) — most reliable
#   --install-root <p>     magmad.so + res/ assets (default: /opt/magma)
#   --data-root <p>        spool/storage/virus    (default: /var/lib/magma)
#   --log-path <p>         log dir                (default: /var/log/magma/)
#   --db-host <h>          (default: localhost)
#   --db-user <u>          (default: magma)
#   --db-schema <s>        (default: Magma)
#   --db-socket <p>        (default: /var/lib/mysql/mysql.sock)
#   --db-grant-host <h>    host part of the DB grant (default: localhost)
#   --cache-host <h>       memcached host         (default: 127.0.0.1)
#   --cache-port <n>       memcached port         (default: 11211)
#   --relay-host <h>       outbound relay host    (default: 127.0.0.1)
#   --relay-port <n>       outbound relay port    (default: 2525)
#   --template <path>      (default: ./magma.prod.config.template)
#   --force                overwrite an existing output dir
# =============================================================================
set -euo pipefail

# --- defaults ---------------------------------------------------------------
DOMAIN=""
OUT=""
CONFIG_PREFIX="/etc/magma"
SELECTOR="mail"
TLS_MODE="self-signed"
DO_DIME="no"
DIME_COPY_FROM=""
INSTALL_ROOT="/opt/magma"
DATA_ROOT="/var/lib/magma"
LOG_PATH="/var/log/magma/"
DB_HOST="localhost"
DB_USER="magma"
DB_SCHEMA="Magma"
DB_SOCKET="/var/lib/mysql/mysql.sock"
DB_GRANT_HOST="localhost"
CACHE_HOST="127.0.0.1"
CACHE_PORT="11211"
RELAY_HOST="127.0.0.1"
RELAY_PORT="2525"
TEMPLATE="./magma.prod.config.template"
FORCE="no"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# --- args -------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --domain)        DOMAIN="$2"; shift 2;;
    --out)           OUT="$2"; shift 2;;
    --config-prefix) CONFIG_PREFIX="$2"; shift 2;;
    --selector)      SELECTOR="$2"; shift 2;;
    --csr)           TLS_MODE="csr"; shift;;
    --dime)          DO_DIME="yes"; shift;;
    --dime-copy-from) DIME_COPY_FROM="$2"; shift 2;;
    --install-root)  INSTALL_ROOT="$2"; shift 2;;
    --data-root)     DATA_ROOT="$2"; shift 2;;
    --log-path)      LOG_PATH="$2"; shift 2;;
    --db-host)       DB_HOST="$2"; shift 2;;
    --db-user)       DB_USER="$2"; shift 2;;
    --db-schema)     DB_SCHEMA="$2"; shift 2;;
    --db-socket)     DB_SOCKET="$2"; shift 2;;
    --db-grant-host) DB_GRANT_HOST="$2"; shift 2;;
    --cache-host)    CACHE_HOST="$2"; shift 2;;
    --cache-port)    CACHE_PORT="$2"; shift 2;;
    --relay-host)    RELAY_HOST="$2"; shift 2;;
    --relay-port)    RELAY_PORT="$2"; shift 2;;
    --template)      TEMPLATE="$2"; shift 2;;
    --force)         FORCE="yes"; shift;;
    -h|--help)       sed -n '2,40p' "$0"; exit 0;;
    *)               die "unknown option: $1";;
  esac
done

[ -n "$DOMAIN" ] || die "--domain is required"
command -v openssl >/dev/null || die "openssl not found"
[ -f "$TEMPLATE" ] || die "template not found: $TEMPLATE"
# cheap domain sanity check
case "$DOMAIN" in *.*) :;; *) die "domain '$DOMAIN' doesn't look like a FQDN";; esac

[ -n "$OUT" ] || OUT="./secrets/$DOMAIN"
if [ -e "$OUT" ] && [ "$FORCE" != "yes" ]; then
  die "output dir '$OUT' exists (use --force to overwrite)"
fi
mkdir -p "$OUT"
chmod 700 "$OUT"

echo ">> generating Magma secrets for '$DOMAIN' into $OUT"

# --- file names (as they will be referenced in the rendered config) ---------
TLS_PEM="tls.$DOMAIN.pem"
DKIM_PEM="dkim.$DOMAIN.pem"
DIME_KEY="dime.$DOMAIN.key"
DIME_SIGNET="dime.$DOMAIN.signet"

# --- secrets: two DISTINCT secrets + DB password ----------------------------
# hex keeps the values free of any character the config parser or SQL might
# choke on; distinctness fixes the sandbox's reuse of one string for both.
SECURE_SALT="$(openssl rand -hex 32)"
SECURE_SESSIONS="$(openssl rand -hex 32)"
DB_PASSWORD="$(openssl rand -base64 48 | LC_ALL=C tr -dc 'A-Za-z0-9' | cut -c1-28)"

# --- TLS --------------------------------------------------------------------
if [ "$TLS_MODE" = "self-signed" ]; then
  echo ">> TLS: self-signed cert for $DOMAIN (replace with a CA-signed cert for real use)"
  openssl req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes \
    -keyout "$OUT/_tls.key" -out "$OUT/_tls.crt" \
    -subj "/CN=$DOMAIN" \
    -addext "subjectAltName=DNS:$DOMAIN,DNS:mail.$DOMAIN" >/dev/null 2>&1
  cat "$OUT/_tls.key" "$OUT/_tls.crt" > "$OUT/$TLS_PEM"
  rm -f "$OUT/_tls.key" "$OUT/_tls.crt"
  chmod 600 "$OUT/$TLS_PEM"
else
  echo ">> TLS: generating key + CSR (get it signed, then: cat key signed.crt > $TLS_PEM)"
  openssl req -newkey rsa:4096 -sha256 -nodes \
    -keyout "$OUT/tls.$DOMAIN.key" -out "$OUT/tls.$DOMAIN.csr" \
    -subj "/CN=$DOMAIN" \
    -addext "subjectAltName=DNS:$DOMAIN,DNS:mail.$DOMAIN" >/dev/null 2>&1
  chmod 600 "$OUT/tls.$DOMAIN.key"
  # placeholder pem so the config path exists; operator concatenates real cert
  cp "$OUT/tls.$DOMAIN.key" "$OUT/$TLS_PEM"
fi

# --- DKIM (2048-bit) + DNS record -------------------------------------------
echo ">> DKIM: 2048-bit key, selector '$SELECTOR'"
openssl genrsa -out "$OUT/$DKIM_PEM" 2048 >/dev/null 2>&1
chmod 600 "$OUT/$DKIM_PEM"
DKIM_P="$(openssl rsa -in "$OUT/$DKIM_PEM" -pubout -outform DER 2>/dev/null | openssl base64 -A)"

# --- DIME org signet (optional, interactive wizard) -------------------------
if [ -n "$DIME_COPY_FROM" ]; then
  # Reuse a known-good org key + signet pair (e.g. a properly-minted one, or the sandbox pair
  # for a bootable demo). Accepts a directory or the key file's path.
  if [ -d "$DIME_COPY_FROM" ]; then
    SRC_KEY="$(ls "$DIME_COPY_FROM"/*.key 2>/dev/null | head -n1)"
    SRC_SIG="$(ls "$DIME_COPY_FROM"/*.signet 2>/dev/null | head -n1)"
  else
    SRC_KEY="$DIME_COPY_FROM"; SRC_SIG="${DIME_COPY_FROM%.key}.signet"
  fi
  if [ -f "$SRC_KEY" ] && [ -f "$SRC_SIG" ]; then
    echo ">> DIME: copying existing org pair from $SRC_KEY / $SRC_SIG"
    cp -f "$SRC_KEY" "$OUT/$DIME_KEY"; cp -f "$SRC_SIG" "$OUT/$DIME_SIGNET"; chmod 600 "$OUT/$DIME_KEY"
  else
    echo "   !! --dime-copy-from: could not find a *.key and *.signet pair at $DIME_COPY_FROM"
  fi
elif [ "$DO_DIME" = "yes" ]; then
  SIGNET_BIN=""
  for c in ./signet ./tools/signet/signet tools/signet/signet; do
    [ -x "$c" ] && SIGNET_BIN="$c" && break
  done
  if [ -n "$SIGNET_BIN" ]; then
    echo ">> DIME: $SIGNET_BIN -g $DOMAIN"
    printf '\n\n\n\n\n\n\n\n' | "$SIGNET_BIN" -g "$DOMAIN" -o "$OUT/$DIME_SIGNET" -k "$OUT/$DIME_KEY" >/dev/null 2>&1 || \
      "$SIGNET_BIN" -g "$DOMAIN" -o "$OUT/$DIME_SIGNET" -k "$OUT/$DIME_KEY" || \
      echo "   !! signet generation failed"
    [ -f "$OUT/$DIME_KEY" ] && chmod 600 "$OUT/$DIME_KEY"
    echo "   !! WARNING: this tree's 'signet' CLI emits an org signet some magmad builds REJECT"
    echo "      (PRIME field-length drift: field 1 is 33 bytes, magmad wants 32). If magmad logs"
    echo "      'Unable to parse the PRIME organizational signing key', supply a known-good pair"
    echo "      with --dime-copy-from <dir> instead (sandbox/etc/dime.* works for a demo)."
  else
    echo ">> DIME: no built signet binary found (looked for ./signet, ./tools/signet/signet) — skipping."
  fi
else
  echo ">> DIME: skipped (pass --dime to mint, or --dime-copy-from <dir> to reuse a known-good pair)"
fi

# --- render the config from the template ------------------------------------
echo ">> rendering config from $TEMPLATE"
content="$(cat "$TEMPLATE")"
subst() { content="${content//$1/$2}"; }

subst "__DOMAIN__"          "$DOMAIN"
subst "__TLS_CERT__"        "$CONFIG_PREFIX/$TLS_PEM"
subst "__DIME_KEY__"        "$CONFIG_PREFIX/$DIME_KEY"
subst "__DIME_SIGNET__"     "$CONFIG_PREFIX/$DIME_SIGNET"
subst "__DKIM_SELECTOR__"   "$SELECTOR"
subst "__DKIM_KEY__"        "$CONFIG_PREFIX/$DKIM_PEM"
subst "__SECURE_SALT__"     "$SECURE_SALT"
subst "__SECURE_SESSIONS__" "$SECURE_SESSIONS"
subst "__ADMIN_CONTACT__"   "contact@$DOMAIN"
subst "__ADMIN_ABUSE__"     "abuse@$DOMAIN"
subst "__CACHE_HOST__"      "$CACHE_HOST"
subst "__CACHE_PORT__"      "$CACHE_PORT"
subst "__DB_HOST__"         "$DB_HOST"
subst "__DB_PASSWORD__"     "$DB_PASSWORD"
subst "__DB_SCHEMA__"       "$DB_SCHEMA"
subst "__DB_SOCKET__"       "$DB_SOCKET"
subst "__DB_USER__"         "$DB_USER"
subst "__LIBRARY_FILE__"    "$INSTALL_ROOT/magmad.so"
subst "__PAGES__"           "$INSTALL_ROOT/res/pages/"
subst "__TEMPLATES__"       "$INSTALL_ROOT/res/templates/"
subst "__FONTS__"           "$INSTALL_ROOT/res/fonts/"
subst "__SPOOL__"           "$DATA_ROOT/spool/"
subst "__STORAGE_TANK__"    "$DATA_ROOT/storage/tanks/"
subst "__STORAGE_ROOT__"    "$DATA_ROOT/storage/"
subst "__VIRUS_SIGS__"      "$DATA_ROOT/virus/"
subst "__LOG_PATH__"        "$LOG_PATH"
subst "__RELAY_HOST__"      "$RELAY_HOST"
subst "__RELAY_PORT__"      "$RELAY_PORT"
subst "__TLS_REDIRECT__"    "127.0.0.1:10500"

# fail loudly if any token survived
if printf '%s' "$content" | grep -q '__[A-Z_]*__'; then
  printf '%s' "$content" | grep -o '__[A-Z_]*__' | sort -u >&2
  die "unsubstituted tokens remain in the rendered config (see above)"
fi
printf '%s\n' "$content" > "$OUT/magma.$DOMAIN.config"
chmod 600 "$OUT/magma.$DOMAIN.config"

# --- scoped DB grant --------------------------------------------------------
cat > "$OUT/grant.sql" <<SQL
-- Scoped runtime user for Magma — NOT "ALL PRIVILEGES ... WITH GRANT OPTION".
-- The schema itself is created once by a privileged admin (scheme.reset);
-- this user only needs DML + temp/lock/exec on the one schema.
CREATE USER IF NOT EXISTS '$DB_USER'@'$DB_GRANT_HOST' IDENTIFIED BY '$DB_PASSWORD';
ALTER USER '$DB_USER'@'$DB_GRANT_HOST' IDENTIFIED BY '$DB_PASSWORD';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE
  ON \`$DB_SCHEMA\`.* TO '$DB_USER'@'$DB_GRANT_HOST';
FLUSH PRIVILEGES;
SQL
chmod 600 "$OUT/grant.sql"

# --- domain seed ------------------------------------------------------------
cat > "$OUT/domains.sql" <<SQL
-- Seed your real domain into the Domains table (acceptance is DB-driven,
-- the config's magma.system.domain is only the default).
INSERT INTO \`Domains\` (\`domain\`,\`restricted\`,\`mailboxes\`,\`wildcard\`,\`dkim\`,\`spf\`,\`updated\`,\`created\`)
VALUES ('$DOMAIN',1,1,0,1,1,NOW(),NOW())
ON DUPLICATE KEY UPDATE \`dkim\`=1,\`spf\`=1,\`updated\`=NOW();

-- Point the single Hosts row at this machine's hostname (run on the host):
-- UPDATE \`Hosts\` SET \`hostname\` = @@hostname WHERE hostnum = 1;
SQL
chmod 600 "$OUT/domains.sql"

# --- DNS records ------------------------------------------------------------
{
  echo "; ---- DNS records for $DOMAIN ----"
  echo "; DKIM (if your provider rejects the long value, split p= into 255-char quoted strings)"
  echo "$SELECTOR._domainkey.$DOMAIN. IN TXT \"v=DKIM1; k=rsa; p=$DKIM_P\""
  echo
  echo "; SPF — adjust if you send through a smarthost"
  echo "$DOMAIN. IN TXT \"v=spf1 mx -all\""
  echo
  echo "; DMARC"
  echo "_dmarc.$DOMAIN. IN TXT \"v=DMARC1; p=quarantine; rua=mailto:abuse@$DOMAIN\""
  echo
  echo "; Also required (set to your host): an MX record and a reverse-DNS (PTR) for the sending IP."
} > "$OUT/dns-records.txt"

# --- secrets.env (quick reference, keep out of VCS) -------------------------
cat > "$OUT/secrets.env" <<ENV
# Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) — keep private, do not commit.
MAGMA_SECURE_SALT=$SECURE_SALT
MAGMA_SECURE_SESSIONS=$SECURE_SESSIONS
MAGMA_DB_USER=$DB_USER
MAGMA_DB_PASSWORD=$DB_PASSWORD
MAGMA_DB_SCHEMA=$DB_SCHEMA
ENV
chmod 600 "$OUT/secrets.env"

# --- summary ----------------------------------------------------------------
cat <<DONE

>> done. Generated in $OUT:
   magma.$DOMAIN.config   rendered config (paths point at $CONFIG_PREFIX/)
   $TLS_PEM   TLS keypair$( [ "$TLS_MODE" = csr ] && echo " (+ tls.$DOMAIN.csr to get signed)" )
   $DKIM_PEM   DKIM private key
   dns-records.txt        DKIM + SPF + DMARC to publish
   grant.sql              scoped DB user (run as admin)
   domains.sql            Domains-table seed
   secrets.env            salt/sessions/db-password reference
$( [ "$DO_DIME" = yes ] && [ -f "$OUT/$DIME_SIGNET" ] && echo "   $DIME_SIGNET / $DIME_KEY   DIME org signet + key" )

Deploy:
   1. Copy tls/dkim/dime key files to $CONFIG_PREFIX/ on the server (mode 600).
   2. Mount/copy magma.$DOMAIN.config to the server; point magmad at it.
   3. mysql < grant.sql   (as a privileged admin)
   4. mysql $DB_SCHEMA < domains.sql
   5. Publish the records in dns-records.txt.
   6. NEVER bake $OUT into a container image — mount it or use secrets.

Reminder: TLS here is $TLS_MODE. For real mail, use a CA-signed cert.
DONE
