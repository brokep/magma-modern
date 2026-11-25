#!/usr/bin/env bash
# =============================================================================
# magma-autoconfig.sh — generate mail-client autoconfiguration for Magma.
# (So users set up mail with just their address + password, Mail-in-a-Box style.)
#
# It writes three artefacts into $SECRETS_DIR/autoconfig/ :
#
#   mail/config-v1.1.xml            Mozilla Thunderbird autoconfig
#   autodiscover/autodiscover.xml   Microsoft Outlook autodiscover (POP/IMAP)
#   magma-<domain>.mobileconfig     Apple profile (iOS/macOS Mail) — install by hand
#
# …plus ready nginx and Caddy snippets to serve the first two over HTTPS on
# autoconfig.<domain> and autodiscover.<domain>. Magma itself holds :443 for its
# webmail, so true auto-fetch needs a reverse proxy (or those two vhosts) in
# front — the snippets do exactly that. The .mobileconfig works today with no
# server: hand it to the user (AirDrop/email) and they tap to install.
#
# Client settings advertised (the standard public ports the installer maps):
#   IMAP  993 SSL   (or 143 STARTTLS)      SMTP submission 465 SSL (or 587 STARTTLS)
#   POP   995 SSL   (or 110 STARTTLS)      Login = full email address
#
# Usage:  magma-autoconfig.sh [--config /etc/magma/magma.conf] [--out <dir>]
# =============================================================================
set -uo pipefail

CONFIG="/etc/magma/magma.conf" OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --config) CONFIG="$2"; shift 2;;
    --out)    OUT="$2"; shift 2;;
    -h|--help) sed -n '2,27p' "$0"; exit 0;;
    *) printf 'error: unknown argument: %s\n' "$1" >&2; exit 2;;
  esac
done
[ -r "$CONFIG" ] || { printf 'error: cannot read %s\n' "$CONFIG" >&2; exit 1; }
cfg() { sed -n "s/^$1=//p" "$CONFIG" | head -n1 | sed 's/^["'\'']//;s/["'\'']$//'; }
DOMAIN="$(cfg MAGMA_DOMAIN)";   [ -n "$DOMAIN" ] || { echo "error: MAGMA_DOMAIN missing" >&2; exit 1; }
HOST="$(cfg MAGMA_HOSTNAME)";   [ -n "$HOST" ]   || HOST="mail.$DOMAIN"
[ -n "$OUT" ] || OUT="$(cfg MAGMA_SECRETS_DIR)/autoconfig"
mkdir -p "$OUT/mail" "$OUT/autodiscover" || { echo "error: cannot create $OUT" >&2; exit 1; }

# A stable (per-host) UUID for the Apple profile so re-installs replace cleanly.
uuid_from() { printf '%s' "$1" | { md5sum 2>/dev/null || md5; } | sed -E 's/(........)(....)(....)(....)(............).*/\1-\2-\3-\4-\5/' | tr 'a-f' 'A-F'; }
PUUID="$(uuid_from "magma-profile-$DOMAIN")"
IUUID="$(uuid_from "magma-imap-$DOMAIN")"
SUUID="$(uuid_from "magma-smtp-$DOMAIN")"

# -------------------------------------------------- Mozilla (Thunderbird) ----
cat > "$OUT/mail/config-v1.1.xml" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="$DOMAIN">
    <domain>$DOMAIN</domain>
    <displayName>$DOMAIN Mail</displayName>
    <displayShortName>$DOMAIN</displayShortName>
    <incomingServer type="imap">
      <hostname>$HOST</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <incomingServer type="pop3">
      <hostname>$HOST</hostname>
      <port>995</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>$HOST</hostname>
      <port>465</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
  </emailProvider>
</clientConfig>
XML

# -------------------------------------------------- Microsoft (Outlook) ------
# Static autodiscover response. Outlook POSTs a request; most servers reply with
# a fixed document — this one advertises IMAP + SMTP over SSL.
cat > "$OUT/autodiscover/autodiscover.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
      <Protocol>
        <Type>IMAP</Type>
        <Server>$HOST</Server>
        <Port>993</Port>
        <SSL>on</SSL>
        <SPA>off</SPA>
        <AuthRequired>on</AuthRequired>
      </Protocol>
      <Protocol>
        <Type>SMTP</Type>
        <Server>$HOST</Server>
        <Port>465</Port>
        <SSL>on</SSL>
        <SPA>off</SPA>
        <AuthRequired>on</AuthRequired>
      </Protocol>
    </Account>
  </Response>
</Autodiscover>
XML

# -------------------------------------------------- Apple (.mobileconfig) -----
cat > "$OUT/magma-$DOMAIN.mobileconfig" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.mail.managed</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>com.magma.$DOMAIN.mail</string>
      <key>PayloadUUID</key><string>$IUUID</string>
      <key>PayloadDisplayName</key><string>$DOMAIN Mail</string>
      <key>EmailAccountType</key><string>EmailTypeIMAP</string>
      <key>EmailAccountName</key><string>$DOMAIN</string>
      <key>EmailAccountDescription</key><string>$DOMAIN</string>
      <key>EmailAddress</key><string></string>
      <key>IncomingMailServerHostName</key><string>$HOST</string>
      <key>IncomingMailServerPortNumber</key><integer>993</integer>
      <key>IncomingMailServerUseSSL</key><true/>
      <key>IncomingMailServerAuthentication</key><string>EmailAuthPassword</string>
      <key>IncomingMailServerUsername</key><string></string>
      <key>OutgoingMailServerHostName</key><string>$HOST</string>
      <key>OutgoingMailServerPortNumber</key><integer>465</integer>
      <key>OutgoingMailServerUseSSL</key><true/>
      <key>OutgoingMailServerAuthentication</key><string>EmailAuthPassword</string>
      <key>OutgoingMailServerUsername</key><string></string>
      <key>OutgoingPasswordSameAsIncomingPassword</key><true/>
      <key>SMTPEnablePerMessageSignature</key><false/>
    </dict>
  </array>
  <key>PayloadDisplayName</key><string>$DOMAIN Mail</string>
  <key>PayloadIdentifier</key><string>com.magma.$DOMAIN</string>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>$PUUID</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadDescription</key><string>Configures Mail for $DOMAIN (enter your address and password on install).</string>
</dict>
</plist>
PLIST

# -------------------------------------------------- serving snippets ---------
cat > "$OUT/nginx-autoconfig.conf" <<NGINX
# Serve mail autoconfig/autodiscover for $DOMAIN. Point autoconfig.$DOMAIN and
# autodiscover.$DOMAIN (A/CNAME) at this host, give them a TLS cert, and reload.
server {
    listen 443 ssl;
    server_name autoconfig.$DOMAIN autodiscover.$DOMAIN;
    # ssl_certificate     /path/to/fullchain.pem;
    # ssl_certificate_key /path/to/privkey.pem;
    root $OUT;
    location = /mail/config-v1.1.xml        { default_type application/xml; }
    location = /autodiscover/autodiscover.xml { default_type application/xml; }
    location = /Autodiscover/Autodiscover.xml { alias $OUT/autodiscover/autodiscover.xml; default_type application/xml; }
}
NGINX

cat > "$OUT/Caddyfile.autoconfig" <<CADDY
# Caddy auto-provisions TLS. Point autoconfig.$DOMAIN / autodiscover.$DOMAIN here.
autoconfig.$DOMAIN, autodiscover.$DOMAIN {
    root * $OUT
    file_server
    @ad path /Autodiscover/Autodiscover.xml /autodiscover/Autodiscover.xml
    rewrite @ad /autodiscover/autodiscover.xml
}
CADDY

printf 'autoconfig written to %s\n' "$OUT"
printf '  mozilla:   %s/mail/config-v1.1.xml\n' "$OUT"
printf '  outlook:   %s/autodiscover/autodiscover.xml\n' "$OUT"
printf '  apple:     %s/magma-%s.mobileconfig  (install directly, no server needed)\n' "$OUT" "$DOMAIN"
printf '  serve via: %s/nginx-autoconfig.conf  or  %s/Caddyfile.autoconfig\n' "$OUT" "$OUT"
printf '  DNS:       autoconfig.%s + autodiscover.%s -> %s  (magma-dns.sh adds these)\n' "$DOMAIN" "$DOMAIN" "$HOST"
