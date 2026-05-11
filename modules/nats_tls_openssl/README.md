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
the same time.  If both appear in `opensips.cfg`, the second
wrapper's `mod_init` refuses with an `LM_ERR` and OpenSIPS exits
at config-parse time.

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `libnats_path` | string | _(empty — search defaults)_ | Optional override of the libnats SONAME / file path.  When empty, the module tries `libnats.so.3.13`, `libnats.so.3`, then `libnats.so` in order, resolved via the standard dynamic-linker search path.  Set this to an absolute path (e.g. `/opt/custom-libnats/lib/libnats.so.3.14`) only for non-default installs. |

## Diagnostics

At successful `mod_init`:

```
INFO:nats_tls_openssl:mod_init: nats_tls_openssl: loaded 'libnats.so.3.13' (TLS backend = OpenSSL)
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
