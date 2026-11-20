#!/bin/bash
# magma-start.sh - bring up Magma's backing services (MariaDB, memcached, Postfix) and run magmad.
# Idempotent container entrypoint (magmad runs in the foreground as the main process).
#
# Config selection:
#   * If a config is mounted at /etc/magma/*.config  -> PROD mode, that config wins.
#       - DB user/password/schema/socket are read FROM that config.
#       - /etc/magma/grant.sql (if mounted) provisions the DB user; else a scoped user is created.
#       - /etc/magma/domains.sql / seed.sql (if mounted) are applied after the schema loads.
#       - Demo accounts/domains (magma/password, lavabit.com...) load only when MAGMA_SEED_DEMO=1
#         (default 1 so it boots out of the box; set 0 and supply your own seed for real use).
#   * Otherwise                                      -> SANDBOX mode (unchanged legacy behavior).
#       Webmail portal: http://localhost:10000  (user: magma / password)
set -uo pipefail
MAGMA_DIR="${MAGMA_DIR:-/root/magma}"
cd "$MAGMA_DIR"
export TERM="${TERM:-dumb}" NSS_DISABLE_HW_AES=1
log(){ echo "[magma-start $(date +%H:%M:%S)] $*"; }

# --- pick the config: a mounted prod config beats the baked sandbox one ---
MOUNTED_CONFIG="$(ls /etc/magma/*.config 2>/dev/null | head -n1 || true)"
if [ -n "$MOUNTED_CONFIG" ]; then
  MODE=mounted; SRC_CONFIG="$MOUNTED_CONFIG"
  log "PROD mode: using mounted config $SRC_CONFIG"
else
  MODE=sandbox; SRC_CONFIG="sandbox/etc/magma.sandbox.config"
  log "SANDBOX mode: no /etc/magma/*.config mounted, using $SRC_CONFIG"
fi

# read a value out of the active config (first match)
cfg(){ sed -n "s/^$1[[:space:]]*=[[:space:]]*//p" "$SRC_CONFIG" 2>/dev/null | head -n1; }
DB_USER="$(cfg magma.iface.database.user)";        DB_USER="${DB_USER:-mytool}"
DB_PASS="$(cfg magma.iface.database.password)";    DB_PASS="${DB_PASS:-aComplex1}"
DB_SCHEMA="$(cfg magma.iface.database.schema)";    DB_SCHEMA="${DB_SCHEMA:-Sandbox}"
DB_SOCK="$(cfg magma.iface.database.socket_path)"; DB_SOCK="${DB_SOCK:-/var/lib/mysql/mysql.sock}"

# --- MariaDB ---
mkdir -p /run/mysqld; chown -R mysql:mysql /run/mysqld /var/lib/mysql 2>/dev/null || true
if [ ! -d /var/lib/mysql/mysql ]; then
  log "initializing MariaDB datadir"
  mariadb-install-db --user=mysql --datadir=/var/lib/mysql --auth-root-authentication-method=normal >/tmp/mariadb-install.log 2>&1 || true
fi
# Ping (not just "does the socket file exist") so a stale socket left by a previous run on
# a container restart doesn't fool us into skipping the start -> restart-safe.
if ! mysqladmin --socket="$DB_SOCK" ping >/dev/null 2>&1; then
  rm -f "$DB_SOCK"
  log "starting mariadbd"
  nohup mariadbd --user=mysql --datadir=/var/lib/mysql --socket="$DB_SOCK" --sql-mode=ALLOW_INVALID_DATES >/tmp/mariadbd.log 2>&1 &
  for i in $(seq 1 60); do mysqladmin --socket="$DB_SOCK" ping >/dev/null 2>&1 && break; sleep 1; done
fi
mysqladmin --socket="$DB_SOCK" ping >/dev/null 2>&1 || { log "FATAL: MariaDB did not start"; tail -20 /tmp/mariadbd.log 2>/dev/null; exit 1; }

# --- DB user provisioning ---
if [ "$MODE" = sandbox ]; then
  mysql --socket="$DB_SOCK" -e "CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS'; GRANT ALL PRIVILEGES ON *.* TO '$DB_USER'@'localhost' WITH GRANT OPTION; FLUSH PRIVILEGES;" 2>/dev/null || true
else
  mysql --socket="$DB_SOCK" -e "CREATE DATABASE IF NOT EXISTS \`$DB_SCHEMA\`;" 2>/dev/null || true
  if [ -f /etc/magma/grant.sql ]; then
    log "applying mounted /etc/magma/grant.sql"
    mysql --socket="$DB_SOCK" < /etc/magma/grant.sql 2>/tmp/grant.log || { log "grant.sql failed"; tail -5 /tmp/grant.log 2>/dev/null; }
  else
    log "creating scoped DB user '$DB_USER' on \`$DB_SCHEMA\`"
    mysql --socket="$DB_SOCK" -e "CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS'; GRANT SELECT,INSERT,UPDATE,DELETE,CREATE TEMPORARY TABLES,LOCK TABLES,EXECUTE ON \`$DB_SCHEMA\`.* TO '$DB_USER'@'localhost'; FLUSH PRIVILEGES;" 2>/dev/null || true
  fi
fi

# --- memcached ---
pgrep -x memcached >/dev/null 2>&1 || { log "starting memcached"; nohup memcached -u nobody -l 127.0.0.1 -p 11211 >/tmp/memcached.log 2>&1 & }

# --- Postfix relay on 127.0.0.1:2525 ---
if command -v postfix >/dev/null 2>&1; then
  pgrep -x master >/dev/null 2>&1 || { log "starting postfix"; postfix start >/dev/null 2>&1 || true; }
fi

# --- Bundled virus signatures (needed for the AV iface in both modes) ---
cp -f dev/virus/*.cvd sandbox/virus/ 2>/dev/null || true

# --- Schema load (only when the schema has no Hosts table yet) ---
if ! mysql --socket="$DB_SOCK" -e "USE \`$DB_SCHEMA\`; SELECT 1 FROM Hosts LIMIT 1;" >/dev/null 2>&1; then
  if [ "$MODE" = sandbox ]; then
    log "loading $DB_SCHEMA schema (schema.reset)"
    MYSQL_USER="$DB_USER" MYSQL_PASSWORD="$DB_PASS" MYSQL_SCHEMA="$DB_SCHEMA" \
      dev/scripts/database/schema.reset.sh "$DB_USER" "$DB_PASS" "$DB_SCHEMA" >/tmp/schema.log 2>&1 \
      || { log "schema reset failed"; tail -10 /tmp/schema.log 2>/dev/null; }
  else
    # Build the schema as root (the scoped runtime user has no DDL rights), in the exact file
    # order schema.reset.sh uses: Schema -> Migration (adds columns Data needs) -> Hosts/Version
    # row seeds -> [Data, demo only] -> Finish. FK/unique checks are disabled during the load.
    SEED="${MAGMA_SEED_DEMO:-1}"
    log "loading schema into \`$DB_SCHEMA\` as root (demo data: $SEED)"
    VER=$(grep -E '^PACKAGE_VERSION' Makefile | awk -F= '{print $2}' | awk -F. '{print $1}' | tr -d '[:blank:]')
    {
      echo "USE \`$DB_SCHEMA\`;"
      echo "SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;"
      echo "SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;"
      echo "SET SESSION sql_mode='ALLOW_INVALID_DATES';"
      cat res/sql/Schema.sql res/sql/Migration.sql
      echo "INSERT INTO \`Hosts\` (\`hostnum\`,\`hostname\`,\`timestamp\`) VALUES (1,'$(hostname)',NOW());"
      echo "INSERT INTO \`Host_Config\` (\`hostnum\`,\`application\`,\`name\`,\`value\`,\`timestamp\`) VALUES (NULL,'magmad','magma.version','$VER',NOW());"
      [ "$SEED" = 1 ] && cat res/sql/Data.sql
      cat res/sql/Finish.sql
    } | mysql --socket="$DB_SOCK" >/tmp/schema.log 2>&1 || { log "schema load failed"; tail -10 /tmp/schema.log 2>/dev/null; }
    [ "$SEED" = 1 ] \
      && log "NOTE: demo accounts/domains loaded (magma/password, lavabit.com...). For real use set MAGMA_SEED_DEMO=0 and mount your own /etc/magma/seed.sql." \
      || log "MAGMA_SEED_DEMO=0: schema only, Hosts row seeded. Add your domain/users via /etc/magma/seed.sql or domains.sql."
  fi
fi

# --- Apply operator SQL seeds mounted alongside the config (prod only) ---
if [ "$MODE" = mounted ]; then
  for f in /etc/magma/seed.sql /etc/magma/domains.sql; do
    [ -f "$f" ] && { log "applying $f"; mysql --socket="$DB_SOCK" "$DB_SCHEMA" < "$f" 2>/dev/null || true; }
  done
fi

# magmad resolves its stored config by hostname; align the Hosts row to THIS container's
# hostname so one image works no matter what hostname the container is given.
mysql --socket="$DB_SOCK" "$DB_SCHEMA" -e "UPDATE \`Hosts\` SET \`hostname\` = @@hostname WHERE hostnum = 1;" 2>/dev/null || true

# --- Run magmad in the foreground (daemonize off). The mount is read-only, so in prod we
#     flip daemonize on a writable copy; the key files stay referenced at /etc/magma. ---
if [ "$MODE" = mounted ]; then
  # magmad requires its TLS cert/key files to be READ-WRITE (file_readwritable()), but the secrets
  # mount is read-only. Copy the key material to a writable tmpfs dir and repoint the config at it;
  # the operator's secrets stay mounted :ro, magmad works against the ephemeral copy.
  WETC=/run/magma-etc
  mkdir -p "$WETC"
  for f in /etc/magma/*.pem /etc/magma/*.key /etc/magma/*.signet /etc/magma/*.crt; do
    [ -e "$f" ] && cp -f "$f" "$WETC/"
  done
  chmod 600 "$WETC"/* 2>/dev/null || true
  RUN_CONFIG=/run/magma.config
  sed -e 's/^magma.system.daemonize = true/magma.system.daemonize = false/' \
      -e "s|/etc/magma/|$WETC/|g" "$SRC_CONFIG" > "$RUN_CONFIG"
  # Create any runtime directories the config references (log/spool/storage/virus).
  for key in magma.output.path magma.spool magma.storage.root magma.storage.tank magma.iface.virus.signatures; do
    d=$(sed -n "s/^$key[[:space:]]*=[[:space:]]*//p" "$RUN_CONFIG" | head -n1)
    [ -n "$d" ] && mkdir -p "$d" 2>/dev/null || true
  done
  SROOT=$(sed -n 's/^magma.storage.root[[:space:]]*=[[:space:]]*//p' "$RUN_CONFIG" | head -n1)
  [ -n "$SROOT" ] && mkdir -p "${SROOT}local/0" 2>/dev/null || true
  VSIG=$(sed -n 's/^magma.iface.virus.signatures[[:space:]]*=[[:space:]]*//p' "$RUN_CONFIG" | head -n1)
  [ -n "$VSIG" ] && cp -f dev/virus/*.cvd "$VSIG" 2>/dev/null || true
else
  RUN_CONFIG="$SRC_CONFIG"
  sed -i -e 's/^magma.system.daemonize = true/magma.system.daemonize = false/' "$SRC_CONFIG" 2>/dev/null || true
fi

log "launching magmad ($MODE) with $RUN_CONFIG -> portal on :10000"
exec ./magmad "$RUN_CONFIG"
