#!/bin/bash
#
# .github/ci/build-and-test.sh
#
# Build Magma's vendored dependency stack and run the full unit suite, from a clean
# checkout, inside a Rocky 9 container. Invoked by .github/workflows/ci.yml, but it is
# a plain script and can be run by hand in a rockylinux:9 container the same way:
#
#   docker run --rm --ulimit memlock=-1:-1 --ulimit nofile=65536:65536 \
#       -v "$PWD":/src -w /src quay.io/rockylinux/rockylinux:9 \
#       bash .github/ci/build-and-test.sh
#
# The --ulimit memlock=-1:-1 is required: Magma's secure-memory (mlock) reallocation
# test fails under the container default (~8 MB) locked-memory limit.
#
set -euo pipefail

echo "::group::Dependencies"
# EPEL + CRB (CodeReady Builder), then the build/runtime packages. This mirrors the
# Containerfile; keep the two in sync. clamav* is needed because this branch links the
# platform's libclamav rather than vendoring it.
dnf -y install epel-release || dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
dnf -y install dnf-plugins-core
dnf config-manager --set-enabled crb || dnf config-manager --set-enabled powertools || true
dnf -y install \
  autoconf automake bison byacc cmake cpp cscope ctags diffstat elfutils expect flex gcc gcc-c++ gdb \
  gettext glibc-devel glibc-headers indent intltool jq kernel-headers libarchive libbsd libbsd-devel \
  libtool libtool-ltdl-devel libzstd libzstd-devel make mpfr ncurses-devel patch patchutils \
  perl perl-Digest perl-Digest-CRC perl-Digest-HMAC perl-Digest-MD5 perl-Digest-SHA \
  perl-Module-Pluggable perl-Pod-Escapes perl-Pod-Simple perl-Time-HiRes perl-libs perl-version \
  pkgconfig procps python3 swig texinfo unzip valgrind valgrind-devel wget zip zlib-devel m4 rsync git \
  inotify-tools haveged mariadb-server mariadb memcached postfix \
  libnsl2-devel libwebp-devel json-c-devel brotli-devel \
  clamav clamav-lib clamav-devel clamav-freshclam
dnf clean all
printf "[client]\nsocket=/var/lib/mysql/mysql.sock\n" > /etc/my.cnf.d/zz-client.cnf
# git refuses to operate in a directory owned by another uid (the checkout's).
git config --global --add safe.directory "$(pwd)" || true
echo "::endgroup::"

echo "::group::Build (build.lib.sh all)"
NSS_DISABLE_HW_AES=1 QUICK=yes M_JOBS="$(nproc)" dev/scripts/builders/build.lib.sh all
echo "OpenSSL linked into magmad.so: $(strings magmad.so | grep -m1 -oE 'OpenSSL [0-9][^ ]*' || echo '??')"
echo "::endgroup::"

echo "::group::Build (make all)"
NSS_DISABLE_HW_AES=1 make -j"$(nproc)" all
ls -l magmad magmad.check
echo "::endgroup::"

echo "::group::Start services (MariaDB, memcached, Postfix)"
if [ ! -d /var/lib/mysql/mysql ]; then
  mariadb-install-db --user=mysql --datadir=/var/lib/mysql >/dev/null
fi
chown -R mysql:mysql /var/lib/mysql
/usr/libexec/mariadbd --user=mysql --datadir=/var/lib/mysql \
  --socket=/var/lib/mysql/mysql.sock --sql-mode=ALLOW_INVALID_DATES &
for _ in $(seq 1 30); do
  mysqladmin --socket=/var/lib/mysql/mysql.sock ping >/dev/null 2>&1 && break
  sleep 1
done
mysql --socket=/var/lib/mysql/mysql.sock <<'SQL'
CREATE USER IF NOT EXISTS 'mytool'@'localhost' IDENTIFIED BY 'aComplex1';
GRANT ALL PRIVILEGES ON *.* TO 'mytool'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
SQL

memcached -u nobody -l 127.0.0.1 -p 11211 &

# Postfix as Magma's outbound relay on 127.0.0.1:2525 (otherwise the SMTP send-path
# tests fail with no relay listening).
printf "\ninet_interfaces = localhost\ninet_protocols = ipv4\nmyhostname = relay.magma.localdomain\nmyorigin = magma.localdomain\nmessage_size_limit = 134217728\ntransport_maps = hash:/etc/postfix/transport\nsmtp_tls_security_level = may\n" >> /etc/postfix/main.cf
sed -i -e 's/^smtp\([ ]*inet\)/127.0.0.1:2525\1/' /etc/postfix/master.cf
touch /etc/postfix/transport && postmap /etc/postfix/transport
postfix start || true
sleep 2
echo "::endgroup::"

echo "::group::Reset schema + seed AV signatures"
MYSQL_USER=mytool MYSQL_PASSWORD=aComplex1 MYSQL_SCHEMA=Sandbox dev/scripts/database/schema.reset.sh
# sandbox/virus/ ships empty; without signatures ClamAV init aborts the VIRUS checks.
cp -f dev/virus/*.cvd sandbox/virus/ 2>/dev/null || true
echo "::endgroup::"

echo "::group::Unit suite (magmad.check)"
NSS_DISABLE_HW_AES=1 dev/scripts/launch/check.run.sh
echo "::endgroup::"
