# nats_tls_wolfssl — wolfSSL preload selector for libnats

Operator-facing module that declares the NATS-client TLS backend
should be wolfSSL.  Required companion module for `event_nats`,
`cachedb_nats`, and `nats_consumer` when explicit wolfSSL selection
is desired.  Mirrors the SIP-side `tls_wolfssl` pattern at the
operator UX level.

- **Language:** C
- **Target:** OpenSIPS 4.0+
- **Companion of:** `event_nats`, `cachedb_nats`, `nats_consumer`
- **Mutually exclusive with:** `nats_tls_openssl`
- **Requires:** a wolfSSL-built libnats sidecar install (default
  prefix `/opt/libnats-wolfssl/`)

## How it works

Same preload pattern as `nats_tls_openssl`: `mod_init` performs an
explicit `dlopen` of a wolfSSL-flavoured libnats build with
`RTLD_NOW | RTLD_GLOBAL`, ensuring subsequent NATS user-module
`DT_NEEDED libnats.so.3.x` resolution matches the wolfSSL build
by SONAME.  See `modules/nats_tls_openssl/README.md` for the full
architectural rationale.

## Sidecar libnats build (required)

wolfSSL is not the default TLS backend for any distro's libnats
package, so a sidecar build is required.  The recipe:

### Step 1 — wolfSSL ≥ 5.6.0 with OpenSSL-compat layer

```
git clone --depth 1 --branch v5.6.4-stable https://github.com/wolfSSL/wolfssl
cd wolfssl
./autogen.sh
./configure --prefix=/opt/wolfssl \
            --enable-opensslextra \
            --enable-opensslall \
            --enable-tls13 \
            --enable-aesni \
            --enable-curve25519 \
            --enable-ed25519 \
            --enable-crl \
            --enable-ocsp \
            --enable-sni
# --enable-crl/ocsp/sni are required for the symbol set libnats's
# TLS code uses (e.g. wolfSSL_X509_STORE_add_crl).  --enable-aesni
# is x86-only; drop it on aarch64.
make -j
sudo make install
```

`--enable-opensslextra` provides the OpenSSL API names that
libnats's TLS code calls (cert-chain walk, hostname verify, etc.).
wolfSSL < 5.6.0 stubs out a couple of cert helpers libnats
depends on, hence the version pin.

### Step 2 — libnats with the vendored wolfSSL patch

Native wolfSSL support isn't part of upstream nats.c yet.  The
relevant PR
([nats-io/nats.c#867](https://github.com/nats-io/nats.c/pull/867)
by @kerbert101) closed without merge on 2025-09-10; the upstream
maintainers weighed the cost of a second TLS backend and decided
to hold for now.  Until that conversation reopens, we ship a
rebased version of that patch under
`docs/patches/nats.c-wolfssl-v3.12.0.patch` so this build recipe
produces a working library.  See `docs/patches/README.md` for full
provenance and the wider rationale.  If you deploy this in
production, a friendly note on upstream PR #867 describing your
use case helps the upstream maintainers see concrete adoption
context for the next time they revisit it.  Apply the patch
before cmake:

```
git clone --depth 1 --branch v3.12.0 https://github.com/nats-io/nats.c
cd nats.c
git apply /path/to/opensips/docs/patches/nats.c-wolfssl-v3.12.0.patch
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/opt/libnats-wolfssl \
      -DCMAKE_INSTALL_LIBDIR=lib \
      -DNATS_BUILD_WITH_TLS=OFF \
      -DNATS_BUILD_WITH_WOLFSSL=ON \
      -DNATS_WOLFSSL_DIR=/opt/wolfssl \
      ..
make -j
sudo make install
```

### Step 3 — register `/opt/wolfssl/lib` with the dynamic linker

The wolfSSL-backed libnats has `DT_NEEDED libwolfssl.so.NN`.  For
that to resolve at module-dlopen time, `/opt/wolfssl/lib` needs to
be on the linker's search path.  Once per host:

```
echo "/opt/wolfssl/lib" | sudo tee /etc/ld.so.conf.d/wolfssl.conf
sudo ldconfig
```

Verify:

```
ldd /opt/libnats-wolfssl/lib/libnats.so | grep wolfssl
# libwolfssl.so.NN => /opt/wolfssl/lib/libwolfssl.so.NN
```

After step 2 the install layout is:

```
/opt/libnats-wolfssl/
├── include/nats/...
└── lib/
    ├── libnats.so          -> libnats.so.3.12.0
    ├── libnats.so.3.12     -> libnats.so.3.12.0
    └── libnats.so.3.12.0
```

`ldd /opt/libnats-wolfssl/lib/libnats.so` should show
`libwolfssl.so.X => /opt/wolfssl/lib/libwolfssl.so.X` confirming
the build.

## When to load

Load `nats_tls_wolfssl.so` **before** any of `event_nats.so`,
`cachedb_nats.so`, or `nats_consumer.so`:

```
loadmodule "nats_tls_wolfssl.so"
modparam("nats_tls_wolfssl", "libnats_path",
         "/opt/libnats-wolfssl/lib/libnats.so.3.12")
loadmodule "event_nats.so"
loadmodule "cachedb_nats.so"
loadmodule "nats_consumer.so"
```

If both `nats_tls_openssl` and `nats_tls_wolfssl` appear in
`opensips.cfg`, the second wrapper's `mod_init` refuses with an
`LM_ERR` and OpenSIPS exits at config-parse time.

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `libnats_path` | string | `/opt/libnats-wolfssl/`<br>`lib/libnats.so.3.12` | Path to the wolfSSL-flavoured libnats install.  An absolute path is recommended — the sidecar wolfSSL libnats is not on any standard system search path.  Use the exact SONAME the user modules will `DT_NEEDED` (typically `libnats.so.3.12` for upstream nats.c v3.12.x). |

## Diagnostics

At successful `mod_init`:

```
INFO:nats_tls_wolfssl:mod_init: nats_tls_wolfssl: loaded '/opt/libnats-wolfssl/lib/libnats.so.3.12' (TLS backend = wolfSSL)
```

The companion user modules each emit one confirming line at their
own `mod_init`:

```
INFO:core:nats_pool_log_tls_backend: event_nats: NATS TLS backend = wolfssl (via nats_tls_wolfssl)
```

Common failure modes:

| Error | Cause |
|-------|-------|
| `dlopen('…') failed: No such file or directory` | sidecar libnats not installed at the configured path |
| `sanity-check failed -- loaded '…' does not export natsConnection_Connect` | configured path points at a stub, wrong SONAME, or an OpenSSL-only libnats variant that mis-resolved |
| `nats_tls_openssl is also loaded; load exactly one TLS-backend wrapper module` | both wrappers in `opensips.cfg` — remove one |

## Verifying the loaded backend at runtime

After OpenSIPS is running, confirm wolfSSL is actually in use:

```
lsof -p $(pidof opensips) | grep -E 'libssl|libwolfssl'
```

You should see `libwolfssl.so.X` mapped and **no** `libssl.so.X`
(unless an unrelated module like `tls_openssl` for SIP-side TLS
is also loaded — that's independent of the NATS-side backend).

## License

GPLv2-or-later — same as OpenSIPS.
