# Containerfile - reproducible Magma (lavabit) build + runtime on Rocky 9.
#
#   podman build -t magma:dev -f Containerfile .
#
# One image, two run modes (magma-start.sh picks based on what's mounted at /etc/magma):
#
#   # SANDBOX (demo): baked config, login magma / password
#   podman run -d --name magma --ulimit memlock=-1:-1 --ulimit nofile=65536:65536 magma:dev
#
#   # PROD: mount a rendered config + secrets (see gen-secrets.sh) read-only at /etc/magma.
#   #   ./gen-secrets.sh --domain example.com --config-prefix /etc/magma \
#   #       --install-root /root/magma --data-root /root/magma/sandbox
#   podman run -d --name magma --ulimit memlock=-1:-1 --ulimit nofile=65536:65536 \
#       -v ./secrets/example.com:/etc/magma:ro magma:dev
#   # Any /etc/magma/*.config wins over the baked sandbox config; grant.sql / domains.sql /
#   # seed.sql there are applied too. Set -e MAGMA_SEED_DEMO=0 to skip the demo accounts.
#
# Then tunnel to :10000 from your workstation and log in.
#
# This builds the MODERNIZED stack: vendored OpenSSL 3.5.9 + refreshed EOL dependencies (see the
# `openssl3` branch). A clean `build.lib.sh all` + `make` reproduces to 143/143 unit tests.
#
# Rocky 9 (GCC 11) is used on purpose: Magma's vendored OpenSSL would not compile on a
# bleeding-edge toolchain (e.g. Fedora's GCC 16). See magma-start.sh for the runtime.
#
# MAGMA_REPO must point at a repo/fork that has the modernized branch (the tarballs are bundled in
# lib/archives, so no network fetch of sources is needed during the build).
FROM quay.io/rockylinux/rockylinux:9

ARG MAGMA_REPO=https://github.com/lavabit/magma.git
ARG MAGMA_REF=openssl3

# EPEL + CRB (CodeReady Builder) repositories.
RUN dnf -y install epel-release || dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
RUN dnf -y install dnf-plugins-core && (dnf config-manager --set-enabled crb || dnf config-manager --set-enabled powertools || true)

# Build + runtime dependencies. The libnsl2-devel/libwebp-devel/json-c-devel/brotli-devel line is the
# gap vs. robox's rocky9 list: without it the final magmad.so link fails with "ld: cannot find -lnsl /
# -lwebp / -ljson-c / -lbrotlidec". The clamav line supplies the virus scanner: magma no longer vendors
# ClamAV (modern ClamAV needs a Rust toolchain to build), so it links the platform's prebuilt libclamav
# instead -- clamav-devel provides clamav.h and libclamav.so for the build, clamav-lib the runtime
# library, and clamav-freshclam the signature updater used by dev/scripts/freshen/freshen.clamav.sh.
RUN dnf -y install \
      autoconf automake bison byacc cmake cpp cscope ctags diffstat elfutils expect flex gcc gcc-c++ gdb \
      gettext glibc-devel glibc-headers indent intltool jq kernel-headers libarchive libbsd libbsd-devel \
      libtool libtool-ltdl-devel libzstd libzstd-devel make mpfr ncurses-devel patch patchutils \
      perl perl-Digest perl-Digest-CRC perl-Digest-HMAC perl-Digest-MD5 perl-Digest-SHA \
      perl-Module-Pluggable perl-Pod-Escapes perl-Pod-Simple perl-Time-HiRes perl-libs perl-version \
      pkgconfig procps python3 swig texinfo unzip valgrind valgrind-devel wget zip zlib-devel m4 rsync git \
      inotify-tools haveged mariadb-server mariadb memcached postfix \
      libnsl2-devel libwebp-devel json-c-devel brotli-devel \
      clamav clamav-lib clamav-devel clamav-freshclam \
    && dnf clean all

# Point the MySQL client at the same socket Magma uses.
RUN printf "[client]\nsocket=/var/lib/mysql/mysql.sock\n" > /etc/my.cnf.d/zz-client.cnf

# Fetch Magma.
WORKDIR /root
RUN git clone --quiet "$MAGMA_REPO" magma && cd magma && git checkout "$MAGMA_REF"
WORKDIR /root/magma

# Build the vendored dependencies (-> magmad.so), then the daemon and tools.
RUN NSS_DISABLE_HW_AES=1 QUICK=yes M_JOBS="$(nproc)" dev/scripts/builders/build.lib.sh all
RUN NSS_DISABLE_HW_AES=1 make -j"$(nproc)" all

# Minimal AV signatures for the sandbox (and the ClamAV test corpus).
RUN cp -f dev/virus/*.cvd sandbox/virus/ 2>/dev/null || true

# Postfix as Magma's outbound relay on 127.0.0.1:2525 (robox-derived).
RUN printf "\ninet_interfaces = localhost\ninet_protocols = ipv4\nmyhostname = relay.magma.localdomain\nmyorigin = magma.localdomain\nmessage_size_limit = 134217728\ntransport_maps = hash:/etc/postfix/transport\nsmtp_tls_security_level = may\n" >> /etc/postfix/main.cf \
    && sed -i -e 's/^smtp\([ ]*inet\)/127.0.0.1:2525\1/' /etc/postfix/master.cf \
    && touch /etc/postfix/transport && postmap /etc/postfix/transport

# Mount target for a prod config + secrets (read-only). Empty in the sandbox image.
RUN mkdir -p /etc/magma

COPY magma-start.sh /usr/local/bin/magma-start.sh
RUN chmod +x /usr/local/bin/magma-start.sh

# Webmail portal, MOLTEN, SMTP, POP.
EXPOSE 10000 6000 7000 8000
CMD ["/usr/local/bin/magma-start.sh"]
