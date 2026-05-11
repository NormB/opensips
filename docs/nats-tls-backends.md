# NATS TLS backend selection

> **Status (2026-05-11):** validated end-to-end on aarch64 Linux
> and amd64 Ubuntu CI.  The
> [`NATS TLS Backends`](../.github/workflows/nats-tls-backends.yml)
> workflow runs four jobs every push that touches NATS modules,
> wrapper modules, the vendored patch, or the workflow itself:
>
> | Job | What it tests |
> |---|---|
> | `openssl` | wrapper loads system libnats, diagnostic confirms OpenSSL backend |
> | `wolfssl` | wrapper loads wolfSSL-built libnats (vendored patch applied), diagnostic confirms wolfSSL backend |
> | `mismatch` | both wrappers loaded → mutual-exclusion `LM_ERR` fires, OpenSIPS exits non-zero |
> | `none` | no wrapper loaded → user modules fall back, "system default" diagnostic fires |
>
> Plus a local end-to-end rebuild on the development host
> (wolfSSL 5.9.1-stable + nats.c v3.12.0 + patch + OpenSIPS
> feature/nats) with `/proc/<pid>/maps` confirming each backend
> loads **only** its target libnats variant (no parallel loading).

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
Each wrapper's `mod_load` callback does an explicit
`dlopen(<path>, RTLD_NOW | RTLD_GLOBAL)` on its target libnats
variant.  `mod_load` fires immediately after OpenSIPS dlopens the
wrapper module itself — **before** the next `loadmodule` directive
runs — so the dlopen registers libnats's SONAME in the global
dynamic-linker namespace before any NATS user module tries to
resolve it.  When `event_nats`, `cachedb_nats`, or `nats_consumer`
load later in the startup sequence, their
`DT_NEEDED libnats.so.3.x` reference is resolved by SONAME match
against the already-loaded copy — no re-dlopen, no rpath
override, no `LD_LIBRARY_PATH` magic.

The path each wrapper dlopens:

| Wrapper | Source | Default |
|---|---|---|
| `nats_tls_openssl` | `$NATS_TLS_LIBNATS_PATH` env var, else first match from a 9-candidate SONAME search list | `libnats.so.3.13` → ... → `libnats.so.3.7` → `libnats.so.3` → `libnats.so` |
| `nats_tls_wolfssl` | `$NATS_TLS_LIBNATS_PATH` env var, else compiled-in default | `/opt/libnats-wolfssl/lib/libnats.so.3.12` |

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

Native wolfSSL support isn't part of upstream nats.c yet.  The
upstream PR ([nats-io/nats.c#867](https://github.com/nats-io/nats.c/pull/867)
by @kerbert101) closed without merge on 2025-09-10 — the
maintainers weighed the cost of a second TLS backend and decided
to hold for now, which is a reasonable call from where they sit.
In the meantime this repository carries a rebased version of that
patch at
[`docs/patches/nats.c-wolfssl-v3.12.0.patch`](patches/nats.c-wolfssl-v3.12.0.patch)
so operators who need wolfSSL on the NATS side have a working
build path.  See [`docs/patches/README.md`](patches/README.md) for
provenance and the rationale.  The recipe below applies the patch
before cmake so the wolfSSL backend logic is available in libnats's
CMake.

> **If you deploy this in production** and your context is something
> you'd be comfortable sharing, a friendly note on
> [upstream PR #867](https://github.com/nats-io/nats.c/pull/867)
> describing your use case (FIPS audit, footprint, embedded target,
> license review — whatever drove the wolfSSL choice) is genuinely
> helpful.  It gives the upstream maintainers concrete adoption data
> if and when they revisit the question.

```
# Step 1 — wolfSSL ≥ 5.6.0 with OpenSSL-compat layer
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
INFO:nats_tls_wolfssl:mod_load: nats_tls_wolfssl: loaded
    '/opt/libnats-wolfssl/lib/libnats.so.3.12' (TLS backend = wolfSSL)
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
`dlopen` step in the wrapper module's `mod_load`.  Two OpenSIPS
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
Both wrappers' `mod_load` runs successfully in `loadmodule` order
(each dlopens its own libnats), so the log will briefly show both
"TLS backend = ..." lines.  Then OpenSIPS iterates module `mod_init`
callbacks; the first wrapper's `mod_init` detects the other via
`module_loaded()`, emits an `LM_ERR`
("`load exactly one TLS-backend wrapper module`"), and OpenSIPS
aborts before any traffic flows.  This mirrors `tls_mgm`'s
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
`mod_load` (which runs during `opensips.cfg` parse).  Switching
requires editing `opensips.cfg` and restarting OpenSIPS.

## See also

- `modules/nats_tls_openssl/README.md`
- `modules/nats_tls_wolfssl/README.md`
- `modules/event_nats/README.md` — `skip_tls_init` modparam
- `modules/cachedb_nats/README.md` — same
- `modules/cachedb_nats/doc/PERF_NOTES.md` — async / RPC architecture

## Implementation notes (for future maintainers)

A handful of non-obvious constraints surfaced during the
end-to-end validation.  They're called out here so the next
person to touch this code doesn't have to rediscover them.

### Timing: `mod_load`, not `mod_init`

The wrapper modules' libnats `dlopen()` happens in `mod_load`,
not `mod_init`.  `mod_load` runs immediately after OpenSIPS
dlopens the wrapper module itself, **before the next
loadmodule directive** in `opensips.cfg`.  This timing is
load-bearing for the preload pattern:

```
loadmodule "nats_tls_wolfssl.so"   # ← mod_load runs here,
                                   #   dlopens wolfssl libnats,
                                   #   RTLD_GLOBAL.
loadmodule "event_nats.so"         # ← DT_NEEDED libnats.so.3.x
                                   #   resolves against the
                                   #   already-loaded wolfssl libnats
                                   #   by SONAME match.
```

If the dlopen were in `mod_init` (which runs after all loadmodule
directives), `event_nats` would have already resolved its
`DT_NEEDED libnats.so.3.x` via the standard search path —
typically finding `/usr/local/lib/libnats.so.3.x` (OpenSSL flavor)
before the wrapper's wolfssl variant could win the SONAME race.
The wrapper's diagnostic log line would still say
"TLS backend = wolfSSL" because the dlopen succeeds, but the user
modules would actually be using the OpenSSL libnats.
Operationally undetectable, dangerously wrong.

This is why the `libnats_path` setting is an **environment
variable** (`NATS_TLS_LIBNATS_PATH`) rather than a modparam:
modparams aren't parsed until after `mod_load`.

The mutual-exclusion check stays in `mod_init` (after both
wrappers' `mod_load` runs), which is correct — by that point
OpenSIPS knows what modules are loaded and can reject the
conflict before any RPC fires.

### wolfSSL OpenSSL-compat header path

wolfSSL's OpenSSL compatibility layer ships its `openssl/`
headers under `${WOLFSSL_INCLUDE_DIR}/wolfssl/openssl/`, not
`${WOLFSSL_INCLUDE_DIR}/openssl/`.  For libnats's existing
`#include <openssl/ssl.h>` lines to resolve to wolfSSL's
compat shim (which renames `SSL_get_error` → `wolfSSL_get_error`
at preprocess time), the include path must contain
`${WOLFSSL_INCLUDE_DIR}/wolfssl` AS WELL AS
`${WOLFSSL_INCLUDE_DIR}` (the latter so `<wolfssl/options.h>`
in `natsp.h` resolves).

Order matters: the `wolfssl` subdir must come first via
`include_directories(BEFORE ...)` so `<openssl/ssl.h>` finds
the wolfSSL compat header before the system OpenSSL header.

Also: this `include_directories` belongs at the **top-level**
`CMakeLists.txt`, not in `src/CMakeLists.txt`.  CMake scopes
`include_directories` to the current directory and below; if
it's in `src/`, then `test/`, `examples/`, and any other
subdir won't see it, and any file that includes `natsp.h`
fails to compile.

### Required wolfSSL configure flags

`--enable-opensslextra` / `--enable-opensslall` are necessary
but not sufficient for the symbol set libnats's TLS code
references.  In addition, you need at minimum:

- `--enable-crl`   — provides `wolfSSL_X509_STORE_add_crl`
- `--enable-ocsp`  — provides OCSP-related compat symbols
- `--enable-sni`   — provides SNI-related compat symbols

There may be more depending on which libnats functions you
exercise.  `--enable-session-certs` is referenced by some
libnats test/example targets but not by the shipped library;
the CI workflow simply skips test/example builds rather than
chasing every additional flag.

### ldconfig registration

The wolfSSL-built libnats has `DT_NEEDED libwolfssl.so.NN`
where `NN` is the wolfSSL ABI version (currently 44 for
wolfSSL 5.9.x, 41 for 5.6.x).  For that to resolve at dlopen
time, `/opt/wolfssl/lib` must be on the dynamic linker's
search path.  Once per host:

```
echo "/opt/wolfssl/lib" | sudo tee /etc/ld.so.conf.d/wolfssl.conf
sudo ldconfig
```

The CI workflow does this on every run (`ldconfig`-style
registration is host state, not part of the cached build
artifacts) — see the "Register /opt/wolfssl/lib with the
dynamic linker" step.

### Cache invalidation

The CI workflow caches the wolfSSL + libnats-wolfssl build
under a key derived from `WOLFSSL_VERSION` + `NATS_C_VERSION`
plus a suffix (currently `-v2-crl`).  Bump the suffix whenever
the wolfSSL configure flags or the libnats patch change so old
cached artifacts don't mask the new behaviour.  The cache
mostly exists to keep wolfSSL's from-source build (3-5 min on
the runner) out of the critical path; once a key combination
has been cached, subsequent runs save that time.

### Skipping libnats tests/examples

The CI workflow builds wolfSSL-libnats with
`-DNATS_BUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF`.  Without
these, libnats's `test/` and `examples/` source uses wolfSSL
APIs gated by `SESSION_CERTS` (`wolfSSL_get_peer_cert_chain`,
etc.) that aren't enabled in our `--enable-opensslextra`
build, and the build aborts at the link step.

Skipping these is safe — they're not part of what we ship.
The library itself builds and links correctly; operators
follow `sudo make install` to deploy `libnats.so.3.x` only.
