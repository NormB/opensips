# NATS TLS backend selection

This document covers operator-facing TLS backend selection for the
libnats C client used by OpenSIPS's NATS modules (`event_nats`,
`cachedb_nats`, `nats_consumer`).

OpenSIPS's own SIP-side TLS abstraction (`tls_mgm` plus the
backend modules `tls_openssl` / `tls_wolfssl`) is **independent** of
the choice covered here.  You can mix SIP-side `tls_wolfssl` with
NATS-side OpenSSL, or vice versa, or pick the same backend on both
sides — they don't coordinate at runtime.

## Quick start

```
# Pick exactly one:
loadmodule "nats_tls_openssl.so"     # use system-default libnats (OpenSSL)
# loadmodule "nats_tls_wolfssl.so"   # use a wolfSSL-built libnats sidecar

# Then the usual NATS user modules:
loadmodule "event_nats.so"
loadmodule "cachedb_nats.so"
loadmodule "nats_consumer.so"
```

If neither wrapper is loaded, the user modules fall back to whatever
libnats the dynamic linker resolves — almost always the distro's
OpenSSL-backed `libnats.so.3.x`.  Loading a wrapper just makes the
choice explicit, validated, and grep-able in `opensips.cfg`.

## Architecture (preload pattern)

The wrapper modules don't link against libnats at compile time.
Each wrapper's `mod_init` does an explicit
`dlopen("libnats.so.3.13", RTLD_NOW | RTLD_GLOBAL)`.  When the NATS
user modules load later in the OpenSIPS startup sequence, their
`DT_NEEDED libnats.so.3.x` reference is resolved by SONAME match
against the already-loaded copy — no re-dlopen, no rpath
override, no `LD_LIBRARY_PATH` magic.

This pattern is cheaper than the "vtable abstraction over libnats's
~90 C entry points" approach because no call sites in `lib/nats` or
the user modules need to change.  It gives operators the same
declarative-in-opensips.cfg UX as the SIP-side `tls_mgm` pattern
without the corresponding implementation cost.

## When you'd want wolfSSL

The default OpenSSL backend is appropriate for the vast majority
of deployments.  Consider wolfSSL only if:

- **FIPS 140-2/140-3 compliance** is required and your audit
  treats wolfSSL's FIPS-validated build as preferable to OpenSSL
  FIPS provider.
- **Embedded / footprint-sensitive** OpenSIPS deployments where
  the wolfSSL footprint (~600 KB) is materially smaller than
  OpenSSL (~5 MB).
- **License audit** requires the OpenSSL Apache-2.0 dependency to
  be replaced by a GPL-friendly GPLv2-licensed TLS implementation.

If none of these apply, stay on OpenSSL.

## Building wolfSSL-backed libnats

Upstream nats.c does **not** support wolfSSL natively yet
([PR #867](https://github.com/nats-io/nats.c/pull/867) was closed
without merge on 2025-09-10; upstream's stance is "not at this
time", not "never").  This repository carries a rebased version
of that patch at
[`docs/patches/nats.c-wolfssl-v3.12.0.patch`](patches/nats.c-wolfssl-v3.12.0.patch);
see [`docs/patches/README.md`](patches/README.md) for the full
provenance and the rationale for shipping it despite upstream's
current "no".  The recipe below applies the patch before cmake so
the wolfSSL backend logic exists in libnats's CMake.

> **If you deploy this in production**, please consider commenting
> on [upstream PR #867](https://github.com/nats-io/nats.c/pull/867)
> with your use case (FIPS audit, footprint, license review,
> whatever made you pick wolfSSL).  Concrete downstream adoption
> signals are what we expect to change the upstream calculus over
> time — every additional voice with a specific deployment makes
> a reopened PR more persuasive than a closed one with a single
> contributor.

```
# Step 1 — wolfSSL ≥ 5.6.0 with OpenSSL-compat layer
git clone --depth 1 --branch v5.6.4-stable https://github.com/wolfSSL/wolfssl
cd wolfssl
./autogen.sh
./configure --prefix=/opt/wolfssl \
            --enable-opensslextra --enable-opensslall \
            --enable-tls13 --enable-aesni \
            --enable-curve25519 --enable-ed25519
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

# Verify
ldd /opt/libnats-wolfssl/lib/libnats.so | grep wolfssl
```

You should see `libwolfssl.so.X => /opt/wolfssl/lib/libwolfssl.so.X`.

When nats.c bumps versions, the patch may need rebasing — see
`docs/patches/README.md`'s maintenance section.

## Packaging guidance

The wrapper modules ship in the normal OpenSIPS distribution tree.
The libnats variants do **not** ship with OpenSIPS — operators or
distros build them via the recipe above.  For long-lived
deployments, package the wolfSSL build as
`/opt/libnats-wolfssl/lib/libnats.so.3.13.0` (and the symlink
chain) into a vendor-specific `.deb` or `.rpm`.

If you ship both backends as packages on the same host, neither
needs to be on the system `ld.so.cache` path — the wrapper modules'
explicit `dlopen` is independent of system search paths.

## Operator verification

At OpenSIPS startup the wrapper logs its selection:

```
INFO:nats_tls_wolfssl:mod_init: nats_tls_wolfssl: loaded
    '/opt/libnats-wolfssl/lib/libnats.so.3.13' (TLS backend = wolfSSL)
```

Each NATS user module echoes the resolved backend at its own init:

```
INFO:core:nats_pool_log_tls_backend: event_nats: NATS TLS backend = wolfssl (via nats_tls_wolfssl)
INFO:core:nats_pool_log_tls_backend: cachedb_nats: NATS TLS backend = wolfssl (via nats_tls_wolfssl)
INFO:core:nats_pool_log_tls_backend: nats_consumer: NATS TLS backend = wolfssl (via nats_tls_wolfssl)
```

At runtime, confirm via `lsof`:

```
lsof -p $(pidof opensips) | grep -E 'libssl|libwolfssl'
```

A wolfSSL-backed deployment will show `libwolfssl.so.X` mapped and
no `libssl.so.X` (unless the SIP-side `tls_openssl` is also loaded
for unrelated SIP-TLS handling).

## FAQ

**Q: Can I run different TLS backends on different NATS connections
in the same OpenSIPS process?**
No.  The backend choice is process-global, baked in at the
`dlopen` step in the wrapper module's `mod_init`.  Two OpenSIPS
instances on one host can run different backends (via separate
`loadmodule` choices in each instance's `opensips.cfg`); within
one instance every NATS connection uses the same backend.

**Q: Does the SIP-side TLS backend (`tls_openssl` vs
`tls_wolfssl`) constrain the NATS-side choice?**
No.  `tls_mgm` and the `nats_tls_*` wrappers are completely
independent.  You can run SIP-side wolfSSL and NATS-side OpenSSL,
or any combination.  In a mixed deployment, the process will map
both `libssl.so` and `libwolfssl.so`; this works because the
SONAMEs are distinct.

**Q: What happens if both `nats_tls_openssl` and `nats_tls_wolfssl`
are listed in `opensips.cfg`?**
The second one to load detects the conflict via
`module_loaded()`, emits an `LM_ERR`, and OpenSIPS exits at
config-parse time.  This mirrors `tls_mgm`'s
"multiple TLS library modules loaded" rejection.

**Q: What happens if neither wrapper is loaded?**
The user modules use whatever libnats the dynamic linker resolves
via `DT_NEEDED libnats.so.3.x` and the standard search path.  This
is the historical behaviour pre-wrapper-modules and remains
supported.  The diagnostic line reads
`NATS TLS backend = system default (no nats_tls_* wrapper loaded)`.

**Q: Does this affect `skip_openssl_init` / `skip_tls_init`?**
The new backend-neutral modparam is `skip_tls_init`; the old
`skip_openssl_init` name is retained for one release cycle as a
deprecated alias that emits a one-time `LM_WARN`.  Both modparams
write to the same internal storage, so behaviour is identical.

**Q: Can I switch backends without restarting OpenSIPS?**
No.  The backend choice is fixed at the wrapper module's
`mod_init`.  Switching requires editing `opensips.cfg` and
restarting OpenSIPS.

## See also

- `modules/nats_tls_openssl/README.md`
- `modules/nats_tls_wolfssl/README.md`
- `modules/event_nats/README.md` — `skip_tls_init` modparam
- `modules/cachedb_nats/README.md` — same
- `modules/cachedb_nats/doc/PERF_NOTES.md` — async / RPC architecture
