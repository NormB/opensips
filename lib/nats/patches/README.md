# Patches for libnats

## nats.c-wolfssl-v3.12.0.patch

Adds a wolfSSL TLS backend to libnats ([nats.c](https://github.com/nats-io/nats.c)):
a `NATS_BUILD_WITH_WOLFSSL` CMake option, plus the include-order and
source guards needed to build libnats against wolfSSL's OpenSSL
compatibility layer instead of OpenSSL.

> [!WARNING]
> The patch applies to nats.c **v3.12.0** only. The NATS modules need
> libnats 3.14 or later, and the patch does not apply to those versions,
> so a wolfSSL-backed libnats cannot currently be used with them. It is
> kept here as the starting point for a rebase.

### Provenance

The patch is a rebase of
[nats-io/nats.c#867](https://github.com/nats-io/nats.c/pull/867) by
[@kerbert101](https://github.com/kerbert101) onto the v3.12.0 tag. The
upstream pull request was closed without merge on 2025-09-10; the nats.c
maintainers chose not to support a second TLS backend. The patch should
be dropped if upstream nats.c ever gains native wolfSSL support.

It touches four files:

- `CMakeLists.txt`: the option, the wolfSSL lookup and the define;
- `src/CMakeLists.txt`: linking the wolfSSL libraries;
- `src/conn.c`: the `SSL_verify_cb` typedef, and excluding
  `SSL_set_hostflags` / `SSL_set1_host` under wolfSSL;
- `src/natsp.h`: including `<wolfssl/options.h>` before the OpenSSL
  headers so the compatibility macros take effect.

### Building (v3.12.0)

```bash title="wolfSSL, then a wolfSSL-backed libnats"
# wolfSSL >= 5.6.0 with the OpenSSL compatibility layer.
# --enable-crl/ocsp/sni provide symbols libnats uses; --enable-aesni is x86-only.
git clone --depth 1 --branch v5.6.4-stable https://github.com/wolfSSL/wolfssl
cd wolfssl && ./autogen.sh
./configure --prefix=/opt/wolfssl \
            --enable-opensslextra --enable-opensslall \
            --enable-tls13 --enable-aesni \
            --enable-curve25519 --enable-ed25519 \
            --enable-crl --enable-ocsp --enable-sni
make -j"$(nproc)" && sudo make install && cd ..

git clone --depth 1 --branch v3.12.0 https://github.com/nats-io/nats.c
cd nats.c && git apply /path/to/opensips/lib/nats/patches/nats.c-wolfssl-v3.12.0.patch
cmake -B build -DCMAKE_INSTALL_PREFIX=/opt/libnats-wolfssl \
      -DCMAKE_INSTALL_LIBDIR=lib \
      -DNATS_BUILD_WITH_TLS=OFF \
      -DNATS_BUILD_WITH_WOLFSSL=ON \
      -DNATS_WOLFSSL_DIR=/opt/wolfssl
cmake --build build -j"$(nproc)" && sudo cmake --install build

echo /opt/wolfssl/lib | sudo tee /etc/ld.so.conf.d/wolfssl.conf && sudo ldconfig
ldd /opt/libnats-wolfssl/lib/libnats.so | grep wolfssl
```

OpenSIPS would then load it through `NATS_DL_LIBNATS_PATH` (see
[TLS](../README.md#tls)), once the patch is rebased onto a supported
libnats version.

### Rebasing

1. Check out the target nats.c tag.
2. Run `git apply --check` with this patch. If it applies, rename the file
   to the new version.
3. Otherwise resolve the conflicts by hand, regenerate the patch with
   `git diff`, and rename it.
4. Build with the recipe above and run
   `lib/nats/tests/test_tls_mgm_smoke.sh` against the result
   (`NATS_DL_LIBNATS_PATH` pointing at it).
