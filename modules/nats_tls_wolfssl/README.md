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
            --enable-ed25519
make -j
sudo make install
```

`--enable-opensslextra` provides the OpenSSL API names that
libnats's TLS code calls (cert-chain walk, hostname verify, etc.).
wolfSSL < 5.6.0 stubs out a couple of cert helpers libnats
depends on, hence the version pin.

### Step 2 — libnats with the vendored wolfSSL patch

Upstream nats.c does **not** support wolfSSL natively
([PR #867](https://github.com/nats-io/nats.c/pull/867) was closed
without merge on 2025-09-10).  We ship a rebased version of that
patch under `docs/patches/nats.c-wolfssl-v3.12.0.patch` (see
`docs/patches/README.md` for provenance).  Apply it before cmake:

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
| `libnats_path` | string | `/opt/libnats-wolfssl/`<br>`lib/libnats.so.3.12` | Path to the wolfSSL-flavoured libnats install.  Must be an absolute path — wolfSSL libnats is not on any standard search path.  Use the exact SONAME the user modules will `DT_NEEDED` (typically `libnats.so.3.12` for upstream nats.c 3.13.x). |

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
