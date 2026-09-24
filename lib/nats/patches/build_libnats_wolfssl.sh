#!/bin/sh
# build_libnats_wolfssl.sh -- build wolfSSL and a wolfSSL-backed libnats.
#
# Builds, under $PREFIX (default /opt/nats-wolfssl):
#   $PREFIX/wolfssl        wolfSSL with its OpenSSL compatibility layer
#   $PREFIX/libnats        libnats from the same nats.c commit CI pins in
#                          scripts/build/install_libnats.sh, with
#                          nats.c-wolfssl.patch applied
# Nothing is installed system-wide.  Point OpenSIPS at the result with
#   NATS_DL_LIBNATS_PATH=$PREFIX/libnats/lib/libnats.so.<major.minor>
# (the library has an rpath to $PREFIX/wolfssl/lib).
#
# Environment:
#   PREFIX           install root (default /opt/nats-wolfssl)
#   WOLFSSL_VERSION  wolfSSL tag (default: the tls_wolfssl module's version)
#   LIBNATS_VERSION  nats.c ref (default: the pin in install_libnats.sh)
#   WORKDIR          build directory (default: a mktemp dir, removed after)
#
# Needs: git, cmake, make, a C compiler, autoconf/automake/libtool.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
TREE=$(cd "$HERE/../../.." && pwd)
PREFIX="${PREFIX:-/opt/nats-wolfssl}"
WOLFSSL_VERSION="${WOLFSSL_VERSION:-v5.9.1-stable}"
if [ -z "${LIBNATS_VERSION:-}" ]; then
	LIBNATS_VERSION=$(sed -n 's/^LIBNATS_VERSION="\${LIBNATS_VERSION:-\([^}]*\)}"$/\1/p' \
		"$TREE/scripts/build/install_libnats.sh")
fi
[ -n "$LIBNATS_VERSION" ] || { echo "cannot read the nats.c pin" >&2; exit 1; }
PATCH="$HERE/nats.c-wolfssl.patch"
JOBS=$(nproc 2>/dev/null || echo 2)

own_workdir=0
if [ -z "${WORKDIR:-}" ]; then
	WORKDIR=$(mktemp -d)
	own_workdir=1
fi
cleanup() { [ "$own_workdir" = 1 ] && rm -rf "$WORKDIR"; }
trap cleanup EXIT

# AES-NI is x86-only
case "$(uname -m)" in
	x86_64|amd64) aesni=--enable-aesni ;;
	*)            aesni= ;;
esac

echo "== wolfSSL $WOLFSSL_VERSION -> $PREFIX/wolfssl"
git clone -q --depth 1 --branch "$WOLFSSL_VERSION" \
	https://github.com/wolfSSL/wolfssl.git "$WORKDIR/wolfssl"
cd "$WORKDIR/wolfssl"
./autogen.sh >/dev/null
# opensslextra/opensslall: the OpenSSL compatibility layer libnats uses;
# crl/ocsp/sni: symbols libnats' TLS code references.
./configure --prefix="$PREFIX/wolfssl" --enable-opensslextra \
	--enable-opensslall --enable-tls13 --enable-curve25519 \
	--enable-ed25519 --enable-crl --enable-ocsp --enable-sni \
	$aesni >/dev/null
make -j"$JOBS" >/dev/null
make install >/dev/null

echo "== libnats $LIBNATS_VERSION + wolfSSL patch -> $PREFIX/libnats"
git clone -q https://github.com/nats-io/nats.c.git "$WORKDIR/nats.c"
cd "$WORKDIR/nats.c"
git checkout -q "$LIBNATS_VERSION"
git apply "$PATCH"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_INSTALL_PREFIX="$PREFIX/libnats" \
	-DCMAKE_INSTALL_LIBDIR=lib \
	-DCMAKE_INSTALL_RPATH="$PREFIX/wolfssl/lib" \
	-DNATS_BUILD_STREAMING=OFF -DNATS_BUILD_EXAMPLES=OFF \
	-DNATS_BUILD_USE_SODIUM=OFF -DBUILD_TESTING=OFF \
	-DNATS_BUILD_WITH_TLS=OFF -DNATS_BUILD_WITH_WOLFSSL=ON \
	-DNATS_WOLFSSL_DIR="$PREFIX/wolfssl" >/dev/null
cmake --build build -j"$JOBS" --target nats >/dev/null
cmake --install build >/dev/null 2>&1 || true   # static/test targets may be absent
lib=$(ls "$PREFIX"/libnats/lib/libnats.so.* 2>/dev/null | grep -E '\.so\.[0-9]+\.[0-9]+$' | head -1)
[ -n "$lib" ] || { echo "libnats was not installed" >&2; exit 1; }
if ! ldd "$lib" | grep -q "$PREFIX/wolfssl/lib/libwolfssl"; then
	echo "$lib does not resolve libwolfssl from $PREFIX/wolfssl" >&2
	exit 1
fi
echo "built $lib"
echo "use: NATS_DL_LIBNATS_PATH=$lib"
