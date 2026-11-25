#!/usr/bin/env bash
# =============================================================================
# magma — day-2 control command for a Magma host install.  (Phase 4)
#
# Installed as /usr/local/sbin/magma by magma-host-install.sh. Reads the install
# state from /etc/magma/magma.conf and wraps the systemd service + the Phase 1-3
# scripts so operators don't have to remember podman/systemctl incantations.
#
#   magma status [args]   run the deliverability checks (magma-status.sh)
#   magma restart|start|stop
#   magma logs            follow the server logs
#   magma tls <email>     obtain / renew a Let's Encrypt certificate
#   magma admin [sub]     /admin panel: url|status|restart|start|stop|logs
#   magma backup [sub]    encrypted backups: backup|list|restore <file>
#   magma dns [sub]       publish DNS records: plan|push --provider <p>
#   magma autoconfig      (re)generate mail-client autoconfig profiles
#   magma exec <cmd...>   run a command inside the container
#   magma version | help
# =============================================================================
set -euo pipefail

CONF="${MAGMA_CONF:-/etc/magma/magma.conf}"
[ -r "$CONF" ] || { echo "magma: $CONF not found — run magma-host-install.sh first" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONF"
SRC="${MAGMA_INSTALL_DIR:-/opt/magma}/src"
PODMAN="${MAGMA_PODMAN:-podman}"
SVC="${MAGMA_SERVICE:-magma}"
CNAME="${MAGMA_CONTAINER:-$SVC}"

need() { [ -x "$1" ] || { echo "magma: $1 not found (reinstall?)" >&2; exit 1; }; }

cmd="${1:-status}"; shift || true
case "$cmd" in
  status)
    need "$SRC/magma-status.sh"
    exec "$SRC/magma-status.sh" --domain "$MAGMA_DOMAIN" --hostname "$MAGMA_HOSTNAME" \
         --secrets-dir "$MAGMA_SECRETS_DIR" "$@";;
  restart|start|stop)
    exec systemctl "$cmd" "$SVC";;
  logs)
    "$PODMAN" logs -f "$CNAME" 2>/dev/null || exec journalctl -u "$SVC" -f;;
  tls)
    need "$SRC/magma-tls.sh"
    email="${1:-${MAGMA_LE_EMAIL:-}}"
    [ -n "$email" ] || { echo "usage: magma tls <email>" >&2; exit 2; }
    exec "$SRC/magma-tls.sh" --hostname "$MAGMA_HOSTNAME" --email "$email" \
         --domain "$MAGMA_DOMAIN" --secrets-dir "$MAGMA_SECRETS_DIR" \
         --service "$SVC" --container "$CNAME" --yes;;
  admin)
    ASVC="${MAGMA_ADMIN_SERVICE:-$SVC-admin}"
    sub="${1:-url}"
    case "$sub" in
      url|"")  echo "http://${MAGMA_ADMIN_BIND:-127.0.0.1}:${MAGMA_ADMIN_PORT:-8080}/"
               echo "tunnel:  ssh -L ${MAGMA_ADMIN_PORT:-8080}:${MAGMA_ADMIN_BIND:-127.0.0.1}:${MAGMA_ADMIN_PORT:-8080} root@$(hostname)";;
      status)  exec systemctl status "$ASVC";;
      restart|start|stop) exec systemctl "$sub" "$ASVC";;
      logs)    exec journalctl -u "$ASVC" -f;;
      *)       echo "usage: magma admin [url|status|restart|start|stop|logs]" >&2; exit 2;;
    esac;;
  backup)
    # magma backup [list|backup|restore <f>] — defaults to making a backup
    BK="$(command -v magma-backup || echo "$SRC/magma-backup.sh")"
    need "$BK"
    exec "$BK" "${@:-backup}" --config "$CONF";;
  dns)
    # magma dns [plan|push] [args] — publish the DNS records to your provider
    DNSC="$(command -v magma-dns || echo "$SRC/magma-dns.sh")"
    need "$DNSC"
    exec "$DNSC" "$@" --config "$CONF";;
  autoconfig)
    # magma autoconfig — (re)generate the mail-client autoconfig profiles
    AC="$(command -v magma-autoconfig || echo "$SRC/magma-autoconfig.sh")"
    need "$AC"
    exec "$AC" --config "$CONF" "$@";;
  exec)
    [ $# -gt 0 ] || { echo "usage: magma exec <command...>" >&2; exit 2; }
    exec "$PODMAN" exec -it "$CNAME" "$@";;
  version|--version|-V)
    echo "magma control — service $SVC, image ${MAGMA_IMAGE:-?}, domain ${MAGMA_DOMAIN:-?}";;
  help|-h|--help)
    sed -n '8,19p' "$0" | sed 's/^# \{0,1\}//';;
  *)
    echo "magma: unknown command '$cmd' (try: magma help)" >&2; exit 2;;
esac
