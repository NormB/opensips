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

## TLS handling

`nats_pool` carries a single `natsTLS_t` view of the connection's TLS
state.  All three modules ship matching `tls_*` modparams whose values
must agree if all three are loaded; the registrant's values are
authoritative and a mismatch warns at load time.  The `tls_allow_downgrade`
flag is independent per-module (used to refuse a plaintext-only
server) and is checked locally before an operation.

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
| `modules/event_nats/tests/`     | unit + `test_nats_module.sh`     |
| `modules/cachedb_nats/tests/`   | unit + integration shell tests   |
| `modules/nats_consumer/tests/`  | unit + docker-compose integration |
| `lib/nats/tests/test_three_module_e2e.sh` | shared-pool round-trip across all three modules |

The CI workflow `.github/workflows/nats-sanitizers.yml` runs every
unit suite under AddressSanitizer + UBSan and ThreadSanitizer.  Tests
that deliberately exercise UAF or `volatile`-vs-atomic races are
listed in each Makefile's `TESTS_TSAN_SAFE` and excluded from the
`check-tsan` target.
