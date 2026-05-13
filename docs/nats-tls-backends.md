# NATS TLS configuration

> **Status (v4.0-nats-rc1):** TLS for the OpenSIPS NATS modules is
> routed through the central `tls_mgm` module, using a client
> domain named `nats`.  This replaces the earlier
> `nats_tls_openssl` / `nats_tls_wolfssl` wrapper-module preload
> pattern, which has been removed.  CI coverage lives in
> [`.github/workflows/nats-tls-backends.yml`](../.github/workflows/nats-tls-backends.yml);
> the canonical smoke is
> [`lib/nats/tests/test_tls_mgm_smoke.sh`](../lib/nats/tests/test_tls_mgm_smoke.sh)
> (real broker, real handshake, four negative-path scenarios).

This document covers operator-facing TLS configuration for the
libnats C client used by OpenSIPS's NATS modules (`event_nats`,
`cachedb_nats`, `nats_consumer`).

OpenSIPS's SIP-side TLS configuration goes through the same
`tls_mgm` module as the NATS side, but uses different client / server
domains.  The NATS side reads only the domain named `"nats"`; SIP-side
TLS settings under other domain names are independent.

## Quick start

```
loadmodule "tls_mgm.so"
modparam("tls_mgm", "client_domain", "nats")
modparam("tls_mgm", "tls_method",          "[nats]TLSv1.2+")
modparam("tls_mgm", "verify_cert",         "[nats]1")
modparam("tls_mgm", "require_cert",        "[nats]1")
modparam("tls_mgm", "certificate",         "[nats]/etc/opensips/tls/client.pem")
modparam("tls_mgm", "private_key",         "[nats]/etc/opensips/tls/client.key")
modparam("tls_mgm", "ca_list",             "[nats]/etc/opensips/tls/ca.pem")
# or:
modparam("tls_mgm", "ca_directory",        "[nats]/etc/opensips/tls/ca.d/")

loadmodule "event_nats.so"
modparam("event_nats", "nats_url", "tls://nats-1:4222,tls://nats-2:4222")

# cachedb_nats and nats_consumer are optional; they share the pool
# established by the first NATS user module to register.
loadmodule "cachedb_nats.so"
modparam("cachedb_nats", "cachedb_url", "nats://localhost:4222/")
loadmodule "nats_consumer.so"
```

A `tls://` URL on `nats_url` flips the pool to TLS at connect
time; with `nats://` the `nats` client domain is ignored.

## How TLS gets applied

`lib/nats/nats_pool.c::apply_tls_from_mgm()` runs at connect time,
not at module load:

1. Each NATS user module's `mod_init` binds the `tls_mgm` API via
   `load_tls_mgm_api()` and hands the bind table to `lib/nats` via
   `nats_pool_set_tls_api()`.
2. When the pool actually opens a NATS connection
   (`nats_pool_get`), it looks up the `tls_mgm` client domain named
   `"nats"` and copies cert / CA / key / verify / cipher settings
   onto the libnats `natsOptions` struct.
3. If the URL is `tls://...` but `tls_mgm` isn't loaded or the
   `"nats"` domain isn't defined, the pool errors out at connect
   time with an operator-friendly diagnostic pointing at the
   missing configuration.  Plaintext `nats://` URLs continue to
   work without `tls_mgm`.

For `ca_directory`, `lib/nats/nats_ca_dir.c` reads every `.pem`
file in the directory and concatenates them in lexicographic order,
then passes the resulting PEM string to libnats via
`natsOptions_SetCATrustedCertificates`.  This mirrors OpenSSL's
`SSL_CTX_load_verify_locations(NULL, dir)` semantics without
requiring a libnats change.

## libnats backend selection

The libnats TLS backend (OpenSSL vs wolfSSL) is **implicit**:
whichever TLS library OpenSIPS itself was built against — as
reported by `tls_mgm`'s `get_tls_library_used()` API — is logged
at startup, but the actual choice is made by whichever
`libnats.so.3.x` the dynamic linker resolves when `lib/nats`
dlopens it.

Two ways to control which libnats variant gets loaded:

1. **Default ld.so search.**  If `libnats.so.3.x` is installed
   somewhere on the system search path (e.g.
   `/usr/local/lib/libnats.so.3.x`), it's used as-is.
2. **Environment override.**  Setting
   `NATS_DL_LIBNATS_PATH=/opt/libnats-wolfssl/lib/libnats.so.3.12`
   in OpenSIPS's environment forces `lib/nats/nats_dl.c` to dlopen
   exactly that path.  This is the right knob for operators who
   want to ship a sidecar libnats build with an unusual SONAME or
   in a non-default location.

OpenSIPS does **not** ship libnats.  Distros ship an OpenSSL-backed
libnats; operators who need a wolfSSL-backed libnats build it from
source per the recipe in the next section.

## Building a wolfSSL-backed libnats (optional)

Native wolfSSL support is not part of upstream nats.c.  The
upstream PR
([nats-io/nats.c#867](https://github.com/nats-io/nats.c/pull/867)
by @kerbert101) closed without merge on 2025-09-10 — the
maintainers weighed the cost of a second TLS backend and decided
to hold for now, which is a reasonable call from where they sit.
In the meantime this repository carries a rebased version of that
patch at
[`docs/patches/nats.c-wolfssl-v3.12.0.patch`](patches/nats.c-wolfssl-v3.12.0.patch)
so operators who need wolfSSL on the NATS side have a working
build path.  See [`docs/patches/README.md`](patches/README.md) for
provenance and the rationale.

> **If you deploy this in production** and your context is something
> you'd be comfortable sharing, a friendly note on
> [upstream PR #867](https://github.com/nats-io/nats.c/pull/867)
> describing your use case (FIPS audit, footprint, embedded target,
> license review — whatever drove the wolfSSL choice) is genuinely
> helpful.  It gives the upstream maintainers concrete adoption data
> if and when they revisit the question.

```
# Step 1 — wolfSSL >= 5.6.0 with OpenSSL-compat layer
git clone --depth 1 --branch v5.6.4-stable https://github.com/wolfSSL/wolfssl
cd wolfssl
./autogen.sh
# --enable-crl/ocsp/sni are required for the symbol set libnats's
# TLS code uses (e.g. wolfSSL_X509_STORE_add_crl).  --enable-aesni
# is x86-only; drop it on aarch64.
./configure --prefix=/opt/wolfssl \
            --enable-opensslextra --enable-opensslall \
            --enable-tls13 --enable-aesni \
            --enable-curve25519 --enable-ed25519 \
            --enable-crl --enable-ocsp --enable-sni
make -j && sudo make install
cd ..

# Step 2 — libnats with the vendored wolfSSL patch
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
make -j && sudo make install

# Register /opt/wolfssl/lib with the dynamic linker so libnats's
# DT_NEEDED libwolfssl.so.NN resolves at runtime.
echo "/opt/wolfssl/lib" | sudo tee /etc/ld.so.conf.d/wolfssl.conf
sudo ldconfig

# Verify
ldd /opt/libnats-wolfssl/lib/libnats.so | grep wolfssl
# Expected: libwolfssl.so.NN => /opt/wolfssl/lib/libwolfssl.so.NN
```

To make OpenSIPS use that variant, point `NATS_DL_LIBNATS_PATH` at
the resulting `libnats.so.3.12` (typically via the OpenSIPS unit
file's `Environment=`).  When nats.c bumps versions, the patch may
need rebasing — see `docs/patches/README.md`'s maintenance section.

## Operator verification

At startup, `lib/nats/nats_pool.c` logs the resolved libnats path
and the `tls_mgm` library identifier:

```
INFO:lib/nats:nats_dl_load: dlopen'd /usr/local/lib/libnats.so.3.12
INFO:lib/nats:nats_pool_get: TLS via tls_mgm domain 'nats' (library=openssl)
```

At runtime, confirm via `lsof`:

```
lsof -p $(pidof opensips) | grep -E 'libssl|libwolfssl|libnats'
```

A wolfSSL-backed deployment will show `libwolfssl.so.X` and the
`libnats.so` from `/opt/libnats-wolfssl/lib`; an OpenSSL-backed
deployment shows `libssl.so.X` and the distro `libnats.so`.

## FAQ

**Q: Can I run different TLS backends on different NATS connections
in the same OpenSIPS process?**
No.  The libnats variant is process-global, resolved once by
`lib/nats/nats_dl_load` at the first NATS user module's
`child_init`.  Two OpenSIPS instances on one host can pick
different libnats variants via per-instance
`NATS_DL_LIBNATS_PATH`; within one instance every NATS connection
uses the same libnats.

**Q: Does the SIP-side TLS backend affect NATS-side TLS?**
The TLS backend choice in OpenSIPS (`tls_openssl` vs
`tls_wolfssl`) is global to the OpenSIPS process and is reported
to NATS via `tls_mgm`'s `get_tls_library_used()` API.  It does not
constrain which libnats variant is loaded, but for operators
running wolfSSL on the SIP side it's typically natural to also
pick the wolfSSL-flavored libnats so the process maps only one TLS
library.  This is a deployment preference, not a hard requirement.

**Q: What happens if `tls_mgm` isn't loaded but the URL is `tls://`?**
`nats_pool_get` errors out at connect time with a diagnostic
message that names the missing configuration (either load
`tls_mgm` and define a `nats` client domain, or change the URL
back to `nats://`).  OpenSIPS does not start the affected NATS
modules.

**Q: What happens if `tls_mgm` is loaded but the `nats` client
domain isn't defined?**
Same as above — the pool refuses to connect over TLS without
explicit configuration, rather than silently falling back to a
default trust store.

**Q: Can I switch TLS settings without restarting OpenSIPS?**
`tls_mgm` supports certificate rotation through its own reload
mechanism; the NATS pool re-reads on the next reconnect.
Switching the libnats variant (OpenSSL → wolfSSL) requires an
OpenSIPS restart.

## See also

- [`lib/nats/README.md`](../lib/nats/README.md) — pool, TLS, disconnect
  semantics, test suite layout
- `modules/event_nats/README.md`, `modules/cachedb_nats/README.md`,
  `modules/nats_consumer/README.md` — per-module config and usage
- [`docs/patches/README.md`](patches/README.md) — wolfSSL patch
  provenance and maintenance
