# nats_tls_openssl — OpenSSL preload selector for libnats

Operator-facing module that declares the NATS-client TLS backend
should be OpenSSL.  Required companion module for `event_nats`,
`cachedb_nats`, and `nats_consumer` when explicit backend selection
is desired.  Mirrors the SIP-side `tls_openssl` pattern at the
operator UX level.

- **Language:** C
- **Target:** OpenSIPS 4.0+
- **Companion of:** `event_nats`, `cachedb_nats`, `nats_consumer`
- **Mutually exclusive with:** `nats_tls_wolfssl`

## How it works

`nats_tls_openssl` does **not** link against libnats at compile
time.  Its `mod_init` performs an explicit
`dlopen("libnats.so.3.13", RTLD_NOW | RTLD_GLOBAL)`.  When the NATS
user modules (`event_nats`, etc.) load later in the OpenSIPS
startup sequence, their `DT_NEEDED libnats.so.3.13` reference is
resolved by SONAME match against the already-loaded copy — no
re-dlopen, no rpath gymnastics, no `LD_LIBRARY_PATH` override.

This pattern is the cheapest cross-module way to give the operator
explicit, audit-friendly TLS-backend selection without an
abstraction layer around libnats's ~90 C entry points.

## When to load

Load `nats_tls_openssl.so` **before** any of `event_nats.so`,
`cachedb_nats.so`, or `nats_consumer.so`:

```
loadmodule "nats_tls_openssl.so"
loadmodule "event_nats.so"
loadmodule "cachedb_nats.so"
loadmodule "nats_consumer.so"
```

Loading this module is **optional**.  If neither
`nats_tls_openssl` nor `nats_tls_wolfssl` is loaded, the NATS
user modules use whatever libnats the dynamic linker resolves
via the standard search path (typically the distro's
`libnats.so.3.x` shipped with `libnats-dev` or equivalent — almost
always OpenSSL-backed).  Loading this wrapper just makes that
choice explicit, validated, and logged.

`nats_tls_openssl` and `nats_tls_wolfssl` must NOT be loaded at
the same time.  If both appear in `opensips.cfg`, both `mod_load`
callbacks run (each dlopens its own libnats), then the first
wrapper's `mod_init` detects the other via `module_loaded()`,
emits an `LM_ERR`, and OpenSIPS aborts before any traffic flows.

## Parameters

This module exports **no modparams**.  Backend selection is driven
by the `loadmodule` directive itself; libnats path is overridable
via an environment variable (see below).

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `NATS_TLS_LIBNATS_PATH` | _(unset)_ | When set, the wrapper's `mod_load` dlopens this exact path/SONAME instead of walking the default search list.  Use when libnats is installed somewhere outside the standard linker search path, or to pin a specific minor version. |

When `NATS_TLS_LIBNATS_PATH` is unset, the wrapper tries the
following SONAMEs in order and uses the first one the dynamic
linker can resolve:

```
libnats.so.3.13
libnats.so.3.12
libnats.so.3.11
libnats.so.3.10
libnats.so.3.9
libnats.so.3.8
libnats.so.3.7
libnats.so.3       (hypothetical post-realign SONAME)
libnats.so         (dev-package symlink, last resort)
```

Each candidate is tried with `dlopen(name, RTLD_NOW | RTLD_GLOBAL)`;
misses fail fast (no disk I/O once ld.so determines the file is
absent), so startup-time cost is sub-millisecond even when the
last entry is the one that resolves.

### Why an environment variable rather than a modparam

The dlopen happens in `mod_load`, which fires immediately after
OpenSIPS dlopens the wrapper module — **before** the next
`loadmodule` directive in `opensips.cfg` runs.  This timing is
load-bearing for the preload pattern: it's what lets later NATS
user modules resolve their `DT_NEEDED libnats.so.3.x` against the
already-loaded wrapper variant by SONAME match.  Modparams are
parsed strictly after `mod_load`, so a modparam couldn't influence
the dlopen.  Setting the env var in the unit file
(`Environment=NATS_TLS_LIBNATS_PATH=…`) or shell rc works
correctly.

## Diagnostics

At successful `mod_load`:

```
INFO:nats_tls_openssl:mod_load: nats_tls_openssl: loaded 'libnats.so.3.12' (TLS backend = OpenSSL)
```

The companion user modules each emit one confirming line at their
own `mod_init`:

```
INFO:core:nats_pool_log_tls_backend: event_nats: NATS TLS backend = openssl (via nats_tls_openssl)
```

The post-dlopen sanity check verifies that
`natsConnection_Connect` resolves from the loaded library.  If it
does not (e.g. the configured path points at a stub or a wrong-
SONAME file), `mod_init` fails fast with a descriptive `LM_ERR`.

## License

GPLv2-or-later — same as OpenSIPS.
