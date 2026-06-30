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

# nats-io/nats.c ref to build. Uses main (nats.c's default branch): per-key KV
# TTL (PR #1000 -- kvConfig.LimitMarkerTTL + kvStore_*WithTTL) is merged on main
# but not yet in a tagged release, and cachedb_nats's per-key-TTL path requires it.
LIBNATS_VERSION="${LIBNATS_VERSION:-main}"
LIBNATS_PREFIX="${LIBNATS_PREFIX:-/usr/local}"

# Skip on cross-compile builds.  The multiarch CI uses *-cross
# compilers (gcc-mips64-cross, clang-arm32-qemu-cross, etc.) running
# inside an older Ubuntu 18.04 container with cmake 3.10, which
# can't build libnats >= 3.10 (CMake 3.13+ required).  Even if we
# upgraded cmake there, the resulting libnats would target the
# build host's architecture and link-fail against the cross-built
# OpenSIPS modules.  The Makefile gate in lib/nats/Makefile.nats
# handles the no-libnats case cleanly: NATS modules silently skip,
# the rest of the build proceeds.
case "${COMPILER:-}" in
    *cross*)
        echo "skipping libnats install: cross-compile build (COMPILER=${COMPILER})"
        exit 0
        ;;
esac

# Skip on uncommon architectures.  rtp.io's Docker buildx matrix runs
# native-in-QEMU on mips64le, ppc64le, s390x, riscv64, arm/v7 and 386,
# none of which match *cross* above.  libnats's CMake FindOpenSSL fails
# to locate libcrypto.so across multiarch sysroots there even with
# libssl-dev:<arch> installed, and these targets aren't a real NATS
# deployment surface.  The Makefile gate covers the absent-libnats case.
case "$(uname -m)" in
    x86_64|amd64|aarch64|arm64)
        ;;
    *)
        echo "skipping libnats install: uncommon arch $(uname -m)"
        exit 0
        ;;
esac

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

wget -q "https://github.com/nats-io/nats.c/archive/refs/heads/${LIBNATS_VERSION}.tar.gz" \
    -O "nats.c-${LIBNATS_VERSION}.tar.gz"
tar xzf "nats.c-${LIBNATS_VERSION}.tar.gz"
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
