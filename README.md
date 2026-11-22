# Magma (modernized)

Magma is the encrypted mail server originally designed and developed by Ladar
Levison for lavabit.com. It speaks SMTP, POP and IMAP (mature), plus the DMTP,
DMAP and HTTP/JSON-RPC interfaces and the bundled webmail portal.

This fork is a **modernization** of the upstream [`lavabit/magma`](https://github.com/lavabit/magma)
`develop` branch. The goal is a server that builds, tests and runs cleanly on a
current, security-patched toolchain instead of the long-EOL dependency stack the
original pinned. The protocol behaviour, on-disk formats and wire formats are
unchanged; the suite is **143/143** on every supported branch.

## What's modernized

- **Vendored OpenSSL 1.0.2u → 3.5.9** (the 3.5 LTS series). The original pinned an
  OpenSSL that reached end-of-life in 2019. See the commit history and
  [lavabit/magma#164](https://github.com/lavabit/magma/pull/164) for the port.
- **Every other EOL dependency refreshed:** zlib 1.3.1, curl 8.11.1, libxml2
  2.13.5, pcre2 10.44, freetype 2.13.3, libpng 1.6.44, jpeg 9f, libgd 2.3.3,
  utf8proc 2.9.0, mariadb-connector-c 3.3.13, and **jansson 2.14** — the stack now
  carries no end-of-life libraries.
- **ClamAV is consumed from the platform's shared `libclamav`** rather than
  vendored. Modern ClamAV (0.105+) requires a Rust toolchain to build from source;
  linking the distribution package keeps the scanner security-patched through the
  normal system update channel and keeps Rust out of magma's build. (The
  `openssl3-port` PR branch still vendors ClamAV 0.103.6, the last pre-Rust
  release, so it builds with no system ClamAV.)
- **Legacy GeoIP dropped.** Nothing in magma ever called the discontinued legacy
  GeoIP API; it was dead weight linked into `magmad.so`.
- **A remotely-triggerable futex/alignment DoS fixed** (a packed `session_t` left
  its `pthread_mutex_t` on an odd offset; glibc 2.34 aborts the daemon on the
  contended `futex()`). Submitted upstream as
  [lavabit/magma#163](https://github.com/lavabit/magma/pull/163).
- **Continuous integration:** every push builds the full vendored stack and runs
  the complete 143-test unit suite in a Rocky 9 container (GitHub Actions).

## Quick start (container)

The fastest way to build and run magma is the bundled `Containerfile`, which
produces a reproducible Rocky 9 image with everything vendored — no network fetch
of sources at build time.

```shell
# Build the image (defaults to the modernized openssl3-port branch).
podman build -t magma:port -f Containerfile .

# Run the sandbox demo (login: magma / password). The memlock ulimit is
# required — magma's secure-memory (mlock) allocator needs it.
podman run -d --name magma \
    --ulimit memlock=-1:-1 --ulimit nofile=65536:65536 \
    magma:port
```

Then tunnel to the webmail portal and log in:

```shell
# from your workstation
ssh -L 10000:<container-ip>:10000 <docker-host>
# open http://localhost:10000  (magma / password)
```

For a real deployment, render a config and secrets with `gen-secrets.sh` and
mount them read-only at `/etc/magma` — see the header of `Containerfile` and
`magma-start.sh` for the one-image/two-modes (sandbox vs. prod) runtime.

> **Why Rocky 9 (GCC 11)?** Magma's vendored crypto will not compile on a
> bleeding-edge toolchain (e.g. Fedora's GCC 16). Rocky 9 is the known-good
> build environment; the container pins it so the host distribution doesn't
> matter.

## Building from source

Magma vendors and statically links its dependencies into `magmad.so`, resolving
each entry point via `dlsym` at runtime. A from-scratch build on **Rocky / RHEL 9**
(or a `rockylinux:9` container) looks like this:

```shell
# Enable EPEL + CRB (CodeReady Builder), which carry several of the -devel packages.
dnf -y install epel-release dnf-plugins-core
dnf config-manager --set-enabled crb

# Install the build + runtime dependencies. The Containerfile's dnf line is the
# complete, tested list; the non-obvious pieces beyond a typical toolchain are:
#   libnsl2-devel libwebp-devel json-c-devel brotli-devel  (final magmad.so link)
#   libtool-ltdl-devel                                      (vendored libltdl users)
#   clamav clamav-lib clamav-devel                          (system libclamav, see above)
#   mariadb-server mariadb memcached postfix                (to run the test suite)

# Build the vendored dependencies (-> magmad.so), then the daemon and tools.
NSS_DISABLE_HW_AES=1 QUICK=yes M_JOBS="$(nproc)" dev/scripts/builders/build.lib.sh all
NSS_DISABLE_HW_AES=1 make -j"$(nproc)" all
```

`build.lib.sh` run without arguments lists its sub-targets (`extract`, `prep`,
`build`, `combine`, `keys`, `all`, per-library targets, …). The bundled `Makefile`
builds `magmad` and `magmad.check`; it will run the dependency step automatically
if the expected headers are missing.

### Running the unit tests

The suite needs MariaDB, memcached and (for the SMTP send-path tests) a Postfix
relay on `127.0.0.1:2525`:

```shell
# MariaDB: user 'mytool' / password 'aComplex1', socket /var/lib/mysql/mysql.sock,
#          started with --sql-mode=ALLOW_INVALID_DATES
# Then load the sandbox schema and seed the AV signatures:
MYSQL_USER=mytool MYSQL_PASSWORD=aComplex1 MYSQL_SCHEMA=Sandbox \
    dev/scripts/database/schema.reset.sh
cp -f dev/virus/*.cvd sandbox/virus/     # sandbox/virus/ ships empty

NSS_DISABLE_HW_AES=1 dev/scripts/launch/check.run.sh
```

`.github/ci/build-and-test.sh` performs exactly this sequence end-to-end and is
runnable by hand in a `rockylinux:9` container; it is the authoritative build +
test recipe.

## Credits

Magma was created by Ladar Levison and the Lavabit team, with contributions from
Greg Brown, Ivan Tolkachev, Princess Levison, Ryan Crites, Sean Benson, Stephen
Watt and Jacob Adkins — and the army of Kickstarter supporters who funded the
project. This fork builds on their work; all original copyright and licensing
(see `LICENSE` and `COPYRIGHT`) is unchanged.

## Development

The best way to get an issue fixed is a pull request with a unit test in the
`check/` folder that reproduces it. Please run the Valgrind harnesses
(`check.vg`, `magma.vg`) before submitting, to catch memory leaks and invalid
memory operations.

## Webmail

A compiled copy of the webmail portal lives in `res/pages/webmail`. Set
`magma.portalUrl = false` in its `script.js` to use the hard-coded test
request/response fixtures (useful for developing the portal without a running
server). The static files are compiled from the sources in `web/` — see
`web/WORKFLOW.md`.
