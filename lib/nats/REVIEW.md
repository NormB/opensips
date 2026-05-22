# feature/nats — static + semantic review (2026-05-22)

Independent code-review pass over the four NATS components on
`feature/nats`:

| Component               | LoC (.c + .h)  |
| ----------------------- | -------------- |
| `lib/nats/`             | 2,371          |
| `modules/event_nats/`   | 3,136          |
| `modules/cachedb_nats/` | 8,587          |
| `modules/nats_consumer/`| 12,438         |
| **Total**               | **26,532**     |

(plus ~9 kLoC of test code, not reviewed for correctness.)

## Method

- Default-warning build: clean, 0 warnings.
- Strict-warning sweep (`-Wextra -Wshadow -Wnull-dereference
  -Wformat=2 -Wlogical-op -Wuninitialized -Wstrict-overflow=2 …`):
  ~625 entries, all classifiable as OpenSIPS-wide patterns
  (codebase-global names like `str`/`user`/`log_level` shadowing,
  `cmd_function` casts, `void*` arithmetic).  No new defects beyond
  those identified by the manual review below.
- Per-module semantic review of: memory ownership (shm vs pkg),
  allocator error paths, libnats callback-thread invariants, ack /
  IPC slot lifecycles, ring-buffer ordering, reconnect handling,
  credential-redaction, modparam validation, and MI surface
  contracts.
- All four `.so` files were rebuilt clean after every change.

## Fixes landed (commit c7b37eb27, with revert in 230a6802e)

### lib/nats

| Severity | File              | Defect                                              |
| -------- | ----------------- | --------------------------------------------------- |
| **high** | `nats_pool.c`     | `kvStore` handles leaked on every reconnect (one per bucket per event); libnats public contract requires the caller to `kvStore_Destroy`.  Now destroyed in the stale-cache cleanup. |
| medium   | `nats_pool.c`     | `parse_urls()` leaked partially-populated SHM URL strings when `shm_malloc` failed on the Nth URL.  Added `err_free_partial:` cleanup. |
| low      | `nats_dl.c`       | The X-macro called `dlerror()` twice in a ternary; POSIX clears the error state after the first call, so the missing-symbol diagnostic always read "no error string".  Cached to a local. |

### modules/event_nats

| Severity | File             | Defect                                              |
| -------- | ---------------- | --------------------------------------------------- |
| **high** | `event_nats.c`   | `nats_evi_raise()` skipped the async `status_cb` on four early-failure paths (payload build, subject too long, subject validation, pool disconnected), leaving EVI subscribers that await async status to hang.  Single `out:` label runs the callback unconditionally. |
| medium   | `event_nats.c`<br>`nats_consumer.c` | A misleading comment claimed `procs[].no` was set dynamically; it was not (proc table is consumed before `mod_init`).  Corrected the comment.<br><br>An attempted optimisation (early-return in `nats_consumer_process()` when no subscriptions configured) was **reverted in 230a6802e** because returning from a `proc_export` entry triggers SIGCHLD in the attendant and shuts the whole instance down.  The sleep-forever behaviour is now documented inline. |
| low      | `nats_consumer.c`| Duplicate `subject=`/`event=`/`queue=` keys inside a single `subscribe` modparam silently took the last value.  Now rejected at config-load with a clear error. |

### modules/cachedb_nats

| Severity | File              | Defect                                              |
| -------- | ----------------- | --------------------------------------------------- |
| medium   | `cachedb_nats.c`  | Cachedb URL was logged raw at DEBUG; a `nats://user:pass@host` form leaked credentials into syslog.  Now passed through the existing `nats_redact_url()` helper. |

### modules/nats_consumer

| Severity | File                    | Defect                                              |
| -------- | ----------------------- | --------------------------------------------------- |
| **high** | `nats_mi.c`<br>`nats_consumer.c` | `nats_registry_bind()` rc=`-3` (handle-cap reached) was silently treated as success by both the MI and script wrappers, leaking the handle and returning 200/1 with an unusable id.  Both wrappers now branch explicitly and free the handle. |
| **high** | `nats_fetch.c`          | `w_nats_fetch_batch()` (sync path) didn't take a `pending_ops` reference; a concurrent unbind + reap could free `h->ring` mid-`pop` or mid-`wait`, producing a use-after-free.  Wrapped in `pending_inc`/`pending_dec` with a single `out:` label. |
| **high** | `nats_rpc_consumer.c`   | Five state stores (one in `on_inbox_reply`, four in `publish_cb`) used unconditional `atomic_store_explicit(state)`.  Between the acquire-load and the store, the worker could ABANDON + free + another caller could re-CLAIM the slot — the blind store then clobbered the new claimer's state and handed it a stale reply (silent cross-call data leak).  All five converted to `compare_exchange_strong_explicit` from `INFLIGHT`. |
| low      | `nats_consumer_proc.c`  | `parse_backoff_csv()` digit accumulator was unbounded; `v * mult * 1e6` could overflow `int64_t`.  Added per-digit clamp + post-multiply overflow check. |

## Findings left for human review (NOT patched)

| Component        | Defect                                                   |
| ---------------- | -------------------------------------------------------- |
| `lib/nats`       | `apply_tls_from_mgm()` calls `natsOptions_LoadCATrustedCertificates(filename)` with `dom->ca.s` — works for modparam-mode (file path) but tls_mgm DB-backed mode stores raw cert BLOBs there.  Fixing properly requires switching between `Load*` (file) and `Set*` (memory) APIs based on origin. |
| `nats_consumer`  | Persistence writer `pthread_t` is created in `mod_init` and so lives only in the attendant.  Workers calling `nats_persist_schedule_write` from `w_nats_consumer_bind` signal a private copy of the condvar that no one is waiting on.  Either route through OpenSIPS IPC, replace the pthread with a `proc_export`, or restrict bind to attendant. |
| `cachedb_nats`   | Possible refcount-ordering UAF in `_entry_remove_key` + `nats_intern_release` (decrement before chain validation).  Requires a model-checker pass before reordering. |

## Test state at commit `230a6802e`

Unit tests (host-local nats-server 2.10.27 with JetStream, nats CLI 0.1.6):

| Suite                           | Binaries | Assertions | Failed |
| ------------------------------- | -------- | ---------- | ------ |
| `lib/nats/tests`                | 5        | 112        | 0      |
| `modules/cachedb_nats/tests`    | 17       | 1,363      | 0      |
| `modules/event_nats/tests`      | 4        | 36         | 0      |
| `modules/nats_consumer/tests`   | 13       | 550        | 0      |
| **Total**                       | **39**   | **~2,061** | **0**  |

Shell integration tests (host-local broker, exit-77 ⇒ SKIP):

| Test                                                     | Verdict |
| -------------------------------------------------------- | ------- |
| `lib/nats/tests/test_three_module_e2e.sh`                | PASS    |
| `lib/nats/tests/test_tls_mgm_smoke.sh`                   | SKIP (no tls_mgm in build set) |
| `cachedb_nats/tests/test_kv_crud_e2e.sh`                 | PASS    |
| `cachedb_nats/tests/test_kv_watch_basic.sh`              | PASS    |
| `event_nats/tests/test_publish_during_disconnect.sh`     | PASS    |
| `nats_consumer/tests/test_async_request_dispatch.sh`     | PASS    |
| `nats_consumer/tests/test_consumer_proc_restart.sh`      | PASS    |
| `nats_consumer/tests/test_multi_instance_durable.sh`     | PASS    |
| `nats_consumer/tests/stress_3way.sh` (`DURATION_S=20`)   | PASS    |
| `nats_consumer/tests/test_tls_mgm_consumer_smoke.sh`     | SKIP (no tls_mgm in build set) |

End-to-end SIP suites (run `modules/<m>/tests/sip_e2e/run.sh`):

| Suite                                       | Cases | Failed |
| ------------------------------------------- | ----- | ------ |
| `modules/cachedb_nats/tests/sip_e2e/`       | 40    | 0      |
| `modules/event_nats/tests/sip_e2e/`         | 64    | 0      |
| **Total**                                   | **104** | **0** |

### Not exercised on the review host

15 tests under `modules/nats_consumer/tests/` that drive opensips
through `docker compose` (`test_batch.sh`, `test_ensure_backoff.sh`,
`test_ephemeral.sh`, `test_fetch_async.sh`, `test_fetch_sync.sh`,
`test_filter.sh`, `test_headers.sh`, `test_max_deliver.sh`,
`test_reconnect.sh`, `test_redelivery.sh`, `test_rpc.sh`,
`stress_ack_wait_expiry.sh`, `stress_churn.sh`,
`stress_multi_worker.sh`, plus `bench/`).  The compose-image build
failed inside the container at `apt-get update` (couldn't resolve
`deb.debian.org`) — an environmental issue, not a code defect.

## Reproducing

```sh
# C unit tests
make -C lib/nats/tests check
make -C modules/cachedb_nats/tests check
make -C modules/event_nats/tests check
make -C modules/nats_consumer/tests check

# Host-local-broker shell tests + sip_e2e
nats-server --jetstream --store_dir=/tmp/js --port=4222 &
export PATH="$(pwd):/usr/sbin:/usr/local/bin:$PATH"
./lib/nats/tests/test_three_module_e2e.sh
./modules/cachedb_nats/tests/sip_e2e/run.sh
./modules/event_nats/tests/sip_e2e/run.sh

# docker-compose suite (requires functional compose + network)
(cd modules/nats_consumer/tests && docker compose up -d)
make -C modules/nats_consumer/tests check
```
