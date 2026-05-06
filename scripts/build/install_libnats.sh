#!/bin/sh
# scripts/build/install_libnats.sh -- install the libnats C client SDK.
#
# OpenSIPS's three NATS modules (event_nats, cachedb_nats, nats_consumer)
# and lib/nats depend on the libnats C client SDK.  Ubuntu < 22.04 does
# not ship libnats-dev in apt, and the package is universe-only on
# 22.04+, so rather than maintain split logic we always build from a
# pinned source tarball.  Output is staged at $LIBNATS_PREFIX (default
# /usr/local) so the in-tree Makefile.nats pkg-config probe finds it.
#
# Idempotent: if libnats is already installed (e.g. a CI cache hit
# restored /usr/local before this script ran), the build is skipped.
#
# Soft dep: the Makefiles gate themselves on libnats availability, so
# if this script fails the build still proceeds with the NATS modules
# silently absent.  We still 'set -e' so a real failure surfaces in
# CI logs rather than masquerading as a successful build with no
# NATS coverage.

set -e

LIBNATS_VERSION="${LIBNATS_VERSION:-3.12.0}"
LIBNATS_PREFIX="${LIBNATS_PREFIX:-/usr/local}"

# Skip if a working install is already in place (cache hit, prior run,
# or a host-level libnats from apt).
if command -v pkg-config >/dev/null 2>&1 && \
   pkg-config --exists libnats 2>/dev/null; then
    installed=$(pkg-config --modversion libnats 2>/dev/null || echo unknown)
    echo "libnats already installed (version ${installed}); skipping build"
    exit 0
fi
if [ -f "${LIBNATS_PREFIX}/include/nats/nats.h" ] && \
   ls "${LIBNATS_PREFIX}/lib"/libnats.so* >/dev/null 2>&1; then
    echo "libnats present at ${LIBNATS_PREFIX}; skipping build"
    exit 0
fi

# Build deps.  cmake is not in apt_requirements.txt because it is
# only needed by this one optional dep -- install inline.
${SUDO} env DEBIAN_FRONTEND=noninteractive apt-get -y \
    --no-install-recommends install \
    cmake build-essential libssl-dev ca-certificates wget

tmp=$(mktemp -d)
cd "$tmp"

wget -q "https://github.com/nats-io/nats.c/archive/refs/tags/v${LIBNATS_VERSION}.tar.gz" \
    -O "nats.c-v${LIBNATS_VERSION}.tar.gz"
tar xzf "nats.c-v${LIBNATS_VERSION}.tar.gz"
cd "nats.c-${LIBNATS_VERSION}"

mkdir build
cd build
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="${LIBNATS_PREFIX}" \
    -DNATS_BUILD_STREAMING=OFF \
    -DNATS_BUILD_EXAMPLES=OFF \
    -DNATS_BUILD_USE_SODIUM=OFF
make -j"$(nproc 2>/dev/null || echo 2)"
${SUDO} make install

# Refresh the dynamic linker cache so the freshly-installed
# libnats.so.<n> is reachable without a full env reset.
${SUDO} ldconfig 2>/dev/null || true

# Drop the build tree -- the cache only needs the install artefacts.
cd /
rm -rf "$tmp"

echo "libnats ${LIBNATS_VERSION} installed at ${LIBNATS_PREFIX}"
