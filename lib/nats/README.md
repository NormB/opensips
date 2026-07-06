# lib/nats — shared NATS connection pool

`lib/nats` is the common runtime layer that the three OpenSIPS NATS
modules share:

| Module           | Direction         | Uses pool for          |
| ---------------- | ----------------- | ---------------------- |
| `event_nats`     | OpenSIPS → NATS   | `natsConnection_Publish`, JetStream async publish |
| `cachedb_nats`   | OpenSIPS ↔ NATS KV | `kvStore_*` get/put/update/delete/watch |
| `nats_consumer`  | NATS → OpenSIPS   | JetStream pull subscriptions, ack IPC |

The library is built once (`libnats_pool.so` under `$modules_dir`) and
the three module `.so`s locate it via `$ORIGIN` rpath so all loaded
modules share a single copy of the pool's process-local state
(`pool_cfg`, `_nc`, `_js`).  Earlier history kept this as a static
`.a`, which gave each module its own copy — and broke handle sharing
between `nats_consumer_proc` and `event_nats`.

## What lives here

| File                | Purpose                                                |
| ------------------- | ------------------------------------------------------ |
| `nats_pool.c/.h`    | Connection pool + JetStream context + KV bucket cache  |
| `nats_dl.c/.h` + `nats_dl_table.def` | The dlopen shim: every libnats symbol the tree uses is resolved through the `nats_dl` function-pointer table (one `NATS_DL_FN` line per symbol in the `.def`), so the modules carry no link-time libnats dependency |
| `nats_ca_dir.c/.h`  | CA-directory loader: concatenates every `.pem` in a `tls_mgm` `ca_directory` for `natsOptions_SetCATrustedCertificates` |
| `nats_epoch.h`      | The reconnect-epoch tag idiom (snapshot / current / adopt / lost) shared by every module that caches pool-owned handles |
| `nats_rank.c`       | `nats_pool_should_init()` — which OpenSIPS process ranks bring up a connection |
| `nats_redact.c/.h`  | URL redaction for log lines (passwords, tokens)        |
| `nats_rl.h`         | One-per-interval log gate behind the outage logging policy (rate-limited WARN + per-call DBG) |
| `nats_str.h`        | `str` → bounded NUL-terminated buffer conversion for the cnats C-string edge (keys/subjects; rejects embedded NUL) |
| `nats_validate.c/.h`| Subject grammar validator used by every publish path   |
| `Makefile.nats`     | pkg-config probe; gates module builds on libnats availability (compile-probes for the per-key-TTL API) |

> **Build note (dl-table layout):** adding or removing `NATS_DL_FN`
> entries changes the offset of every later member of
> `nats_dl_funcs_t`.  All consumers — including `nats_dl.o` itself —
> must recompile together; a stale `nats_dl.o` ships the old layout
> inside `libnats_pool.so` and every OpenSIPS child segfaults at boot.
> The `-MMD` depfiles track `nats_dl_table.def`, so a plain `make`
> handles it; if `nats_dl.o` predates its `.d` file, delete it first.

## Registration contract

Each NATS module calls
`nats_pool_register(const char *url, const char *module, int
reconnect_wait, int max_reconnect)` during `mod_init` (pre-fork).
Registrations **merge**:

* The pool keeps the **union of server URLs** across all registrants
  (duplicates skipped, overflow past the cap warn-skipped).
* Reconnect parameters merge too: the strictest/most-explicit value
  wins regardless of module load order.
* TLS material is *not* a parameter — it comes from `tls_mgm` via
  `nats_pool_bind_tls()` / `nats_pool_set_tls_api()` (see below).
* Workers later call `nats_pool_get()` (per-process, lazy) for the
  shared `natsConnection *`, and `nats_pool_get_js()` for a JetStream
  context.

All three modules **self-register** — including `nats_consumer`, which
contributes its own `nats_url` modparam and, when that is unset, falls
back to `nats://localhost:4222` *only if no other module has already
registered* (so it never injects a spurious localhost seed into a
configured pool).  Any single module loads and runs standalone; any
combination shares one connection per process.  Load order does not
matter.  The merge semantics are unit-locked by
`tests/test_pool_merge.c`.

## Handle lifetime and the reconnect epoch

`nats_pool_get_kv()` returns **pool-owned** handles that are destroyed
and re-created when a reconnect marks the cache stale — a cached
`kvStore *` held across a reconnect is a use-after-free.  Every module
that keeps one tags it with `nats_epoch_t` (`nats_epoch.h`) and
re-validates before use (snapshot → check `nats_epoch_current` →
re-acquire → `nats_epoch_adopt` only on success).  The
disconnect/reconnect callbacks bump the epoch and set the stale flag;
consumers pick it up on their next call.

## Allocator policy

Where memory for NATS-related code should come from (established by
the 2026-07 audits; the P3.5/P3.6 conversions moved the tree onto it):

* **pkg** for process-private, main-thread-owned, small/medium
  short-lived allocations — the JSON hot path, MI staging,
  consumer-config strings, async resume params.  Near-parity speed
  with glibc tcache; the wins are `-M` visibility, leak diagnostics
  (`pkg stats`/`DBG_MALLOC`), and fragmentation isolation from cnats's
  own heap traffic.
* **shm** ONLY for genuinely cross-process data: the search index,
  intern table, rings, RPC slots, stats blocks, IPC payloads.  It is
  the slowest allocator here (global/hashed locks contended by every
  SIP worker); converting private data to shm is a pessimization.
* **Foreign-thread handoff** (cnats callback → worker) is
  `shm_malloc` + `ipc_dispatch_rpc`: the shm lock is process-shared
  and the IPC pipe write is atomic, so this is safe from cnats
  threads — `event_nats_sub.c`'s message callback is the canonical
  pattern.  `pkg_malloc` and `LM_*` remain forbidden there (per-process
  / main-thread-only).
* **libc malloc stays** at four legitimate boundaries:
  1. memory OWNED by cnats (its API mandates `free()` — header key
     arrays, error strings);
  2. allocations made on cnats callback threads for thread-local use;
  3. large config-scaled buffers (msg-ref rows up to ~1.5 MB × 256
     handles, worst-case MI listings) — pkg pools are sized at fork,
     so forcing these into pkg makes operators over-provision every
     process: a net RAM regression;
  4. `lib/nats` files that deliberately compile standalone for unit
     tests (`nats_ca_dir.c`, `nats_redact.c`, `nats_validate.c`,
     `nats_str.h` helpers).

**Strings:** `str` at every OpenSIPS edge, NUL-terminated C strings at
the cnats edge (keys/subjects/bucket names via `nats_str_to_buf`,
which fails closed on embedded NUL), and `(ptr,len)` walkers inside
the JSON layer.  VALUES ride the length-aware `kvStore_Put/Create/
Update` — never the `*String` forms, which silently truncate at a NUL.
No tree-wide wrapper conversions; consolidate ad-hoc `memcpy`+`'\0'`
boundary code onto `nats_str.h` opportunistically when a file is
already open.

## TLS handling

TLS configuration is sourced from OpenSIPS's central `tls_mgm` module
at connect time — see `apply_tls_from_mgm()` in `nats_pool.c`.
NATS user modules bind `tls_mgm` via `nats_pool_bind_tls()` in their
`mod_init`; the pool then looks up the `tls_mgm` client domain named
`"nats"` for cert / CA / key / cipher / verify settings.

When a `tls://` URL is configured but `tls_mgm` isn't loaded (or the
"nats" domain isn't defined), `nats_pool_get` errors out at connect
time with operator-friendly guidance pointing at the missing config.
A libnats built without TLS fails hard the same way — there is no
silent plaintext downgrade.  Plaintext (`nats://`) URLs work without
`tls_mgm`.

For CA directories (`tls_mgm`'s `ca_directory` field), `nats_ca_dir.c`
reads every `.pem` in the directory and concatenates them in
lexicographic order, then passes the result to libnats via
`natsOptions_SetCATrustedCertificates` (PEM-string API).  This mirrors
OpenSSL's `SSL_CTX_load_verify_locations(NULL, dir)` semantics without
requiring a libnats change.

The libnats backend (OpenSSL vs wolfSSL) is implicit: whichever
backend `tls_mgm` reports via its `get_tls_library_used()` API is the
one operators chose by loading `tls_openssl.so` vs `tls_wolfssl.so`
for their SIP-side TLS.  `lib/nats` itself dlopens whatever libnats
the standard `ld.so` search resolves — operators with multiple
variants installed override via `$NATS_DL_LIBNATS_PATH`.

## Credential redaction in logs

NATS URLs may embed credentials as `scheme://user:pass@host` (or a
single bearer token, `scheme://token@host`).  To keep those secrets out
of the logs, **every** log line that prints a URL first passes it
through `nats_redact_url()` (`nats_redact.c`):

* The entire `userinfo` segment between `://` and `@` — username,
  password, or token — is replaced with the literal `[redacted]`.
  `nats://alice:s3cr3t@host:4222` is logged as
  `nats://[redacted]@host:4222`.
* Comma-separated seed lists are redacted per-URL; only the entries
  that actually carry credentials are masked.
* URLs without `userinfo` are logged verbatim.

This covers the startup `NATS URL: …` line, the pool's `connected to …`
and `reconnected to …` lines, and the `no valid NATS server URLs found
in …` parse error.  Redaction affects logging only — the unmodified URL
is still used for the connection itself.

> **Contributor rule:** any new log statement that includes a URL or
> server string MUST redact it via `nats_redact_url()` first — never log
> a raw `url`/server value.  The behavior is pinned by
> `lib/nats/tests/test_redact_url.c`.

## Disconnect / reconnect semantics

* Publish-side modules (`event_nats`, `cachedb_nats`) fast-fail any
  operation while the pool is in `DISCONNECTED` state rather than
  blocking the worker for the libnats internal-buffer timeout.  They
  return `-1` to the script.  The end-to-end behavior is pinned by
  `modules/event_nats/tests/test_publish_during_disconnect.sh`.
* Outage logging follows one policy tree-wide: rate-limited WARN
  (`nats_rl.h` gate, one line per interval per process) plus per-call
  DBG — never a per-request WARN flood, never DBG-only invisibility.
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

## Review history

- 2026-05-22 — static + semantic audit, ten correctness fixes
  landed in `c7b37eb27` (with revert in `230a6802e`); see
  [REVIEW.md](REVIEW.md) for the per-finding write-up, test tally,
  and items left for human review.
- 2026-07 — six-dimension maintainability/perf review; the P0–P3
  phases of `MAINTAINABILITY-PERF-SPEC.md` (design repo) landed
  through this tree.  This document was rewritten against the code in
  P4.1 and is truth-locked by `tests/test_doc_truth.c`.
