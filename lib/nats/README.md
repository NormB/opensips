# lib/nats — shared NATS connection pool

`lib/nats` is the common runtime layer that the three OpenSIPS NATS
modules share:

| Module           | Direction         | Uses pool for          |
| ---------------- | ----------------- | ---------------------- |
| `event_nats`     | OpenSIPS → NATS   | `natsConnection_Publish`, JetStream async publish |
| `cachedb_nats`   | OpenSIPS ↔ NATS KV | `kvStore_*` get/put/update/delete/watch |
| `nats_consumer`  | NATS → OpenSIPS   | JetStream pull subscriptions, ack IPC |

The library is built once (`libnats_pool.so` under
`$modules_dir`) and the three module `.so`s locate it via `$ORIGIN`
rpath so all loaded modules share a single copy of the pool's
process-local state (`pool_cfg`, `_nc`, `_js`).  Earlier history kept
this as a static `.a`, which gave each module its own copy — and
broke handle sharing between `nats_consumer_proc` and `event_nats`.

## What lives here

| File                | Purpose                                                |
| ------------------- | ------------------------------------------------------ |
| `nats_pool.c/.h`    | Connection pool + JetStream context + KV bucket cache  |
| `nats_rank.c`       | Per-process rank assignment for the pool registry     |
| `nats_redact.c`     | URL redaction for log lines (passwords, tokens)        |
| `nats_validate.c`   | Subject grammar validator used by every publish path  |
| `Makefile.nats`     | pkg-config probe; gates module builds on libnats availability |

## Registration contract

Each NATS module calls `nats_pool_register(url, tls_opts, name, …)`
during `mod_init`.  The first registrant wins:

* Its `nats_url` and TLS settings become the pool's connection
  parameters.
* Subsequent registrants from other modules log a `WARN` if their
  proposed URL/TLS differs and then piggy-back on the already-registered
  connection.
* Workers later call `nats_pool_get()` (per-process) to retrieve the
  shared `natsConnection *`, and `nats_pool_get_js()` for a JetStream
  context.

A typical multi-module deployment loads `event_nats` first to set the
canonical NATS URL, then the others; or any single module alone, in
which case that module owns the registration.

> **Important:** `nats_consumer` does NOT call `nats_pool_register()`
> itself — it consumes the connection set up by another module
> (typically `event_nats`).  A standalone `nats_consumer` deployment
> will fail at child_init with `NATS pool: not registered (call
> nats_pool_register first)` and the consumer process will exit.
> Always load at least one of `event_nats` or `cachedb_nats` *before*
> `nats_consumer`.

## TLS handling

TLS configuration is sourced from OpenSIPS's central `tls_mgm` module
at connect time -- see `apply_tls_from_mgm()` in `nats_pool.c`.
NATS user modules bind `tls_mgm` via `load_tls_mgm_api()` in their
`mod_init` and pass the bind table to `lib/nats` via
`nats_pool_set_tls_api()`.  The pool then looks up the `tls_mgm`
client domain named `"nats"` for cert / CA / key / cipher / verify
settings.

When a `tls://` URL is configured but `tls_mgm` isn't loaded (or the
"nats" domain isn't defined), `nats_pool_get` errors out at connect
time with operator-friendly guidance pointing at the missing config.
Plaintext (`nats://`) URLs work without `tls_mgm`.

For CA directories (`tls_mgm`'s `ca_directory` field), `nats_pool`
reads every `.pem` in the directory and concatenates them in
lexicographic order, then passes the result to libnats via
`natsOptions_SetCATrustedCertificates` (PEM-string API).  This
mirrors OpenSSL's `SSL_CTX_load_verify_locations(NULL, dir)`
semantics without requiring a libnats change.

The libnats backend (OpenSSL vs wolfSSL) is implicit: whichever
backend `tls_mgm` reports via its `get_tls_library_used()` API is
the one operators chose by loading `tls_openssl.so` vs `tls_wolfssl.so`
for their SIP-side TLS.  `lib/nats` itself dlopens whatever libnats
the standard `ld.so` search resolves -- operators with multiple
variants installed override via `$NATS_DL_LIBNATS_PATH`.

## Disconnect / reconnect semantics

* Publish-side modules (`event_nats`, `cachedb_nats`) fast-fail any
  operation while the pool is in `DISCONNECTED` state rather than
  blocking the worker for the libnats internal-buffer timeout.  They
  return `-1` to the script.  The end-to-end behavior is pinned by
  `modules/event_nats/tests/test_publish_during_disconnect.sh`.
* `nats_consumer_proc` watches the connection epoch and resubscribes
  every binding after a reconnect.

## Tests

| Suite                           | Trigger                          |
| ------------------------------- | -------------------------------- |
| `lib/nats/tests/`               | `make -C lib/nats/tests check`   |
| `modules/event_nats/tests/`     | unit + `sip_e2e/run.sh` integration suite |
| `modules/cachedb_nats/tests/`   | unit + `sip_e2e/run.sh` + KV CRUD/watch shell tests |
| `modules/nats_consumer/tests/`  | unit + docker-compose functional & stress |
| `lib/nats/tests/test_three_module_e2e.sh` | shared-pool round-trip across all three modules |
| `lib/nats/tests/test_tls_mgm_smoke.sh` | TLS handshake via tls_mgm + negative-path scenarios |

The CI workflow `.github/workflows/nats-sanitizers.yml` runs every
unit suite under AddressSanitizer + UBSan and ThreadSanitizer.  Tests
that deliberately exercise UAF or `volatile`-vs-atomic races are
listed in each Makefile's `TESTS_TSAN_SAFE` and excluded from the
`check-tsan` target.
