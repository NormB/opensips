# NATS modules — adversarial audit & fixes

> **Engineering record.** A point-in-time record of the correctness/security
> audit of the OpenSIPS NATS modules (`cachedb_nats`, `event_nats`,
> `nats_consumer`, and their `lib/nats` client glue) and the fixes it drove.
> The living contract is the docbook (`doc/*.xml`) and the source comments;
> this file explains *what* was wrong and *how* it was fixed.

Every behavioural fix landed test-first: a failing test whose "buggy arm"
reproduces the defect (under AddressSanitizer or a deterministic
interleaving), then the fix to green. Unit suites stay green
(`cachedb_nats` 87, `nats_consumer`, `event_nats`); the risk-bearing fixes
were additionally exercised end-to-end against a real 3-node NATS ≥2.11
JetStream cluster (KV CRUD incl. CAS, and the KV watcher `E_NATS_KV_CHANGE`
path).

## Method

Seven independent read-only passes (one per coherent slice) surfaced
candidate findings; each was then re-verified against the source before a
fix was written, and cross-checked by a second pass. That cross-check
mattered: it caught a real use-after-free that the slice owner had marked
"clean". Plausible-but-guarded candidates (the lock-free ring/MPSC memory
ordering, the intern-table locking, the JSON DoS surface, the JetStream
object lifecycles) were verified sound and left alone.

## HIGH

- **`nats_consumer` — UAF acking a fetched `natsMsg` after its subscription
  was destroyed.** The reconnect-epoch refresh and the vanished/GC'd-consumer
  path destroyed the subscription without purging the process-local msg-ref
  row, so a later ack dereferenced `msg->sub` on a freed subscription —
  reachable on any broker reconnect with in-flight messages. Factored the
  walk into `purge_msg_ref_row()` and call it at all three destroy sites.
- **`cachedb_nats` — heap OOB in `raw_kv_bucket_info`.** The reply row was
  sized to a hardcoded 6 columns while the cachedb core frees
  `expected_kv_no` columns per row — OOB read + bad free when a script asked
  for > 6 output vars. Sized to `max(expected_kv_no, 6)`, mirroring
  `raw_kv_keys`.

## MED

- **`cachedb_nats` — UAF read in the counter op.** Logged
  `kvEntry_ValueString()` after `kvEntry_Destroy()`; snapshot the value first.
- **`cachedb_nats` — embedded-NUL document truncation.** The usrloc merge
  recomputed the doc length with `strlen` (vs the authoritative
  `kvEntry_ValueLen`), so a doc with an embedded NUL was truncated and
  CAS-written back short, dropping contacts. Fail closed when
  `strlen(json) != data_len`. `lib/nats/nats_str.h` (`nats_str_to_buf`) also
  now rejects an embedded NUL on the generic `*String` write paths (the KV
  C-string API would otherwise silently truncate on write while reads
  preserve the NUL).
- **`event_nats` — timer-raised events dropped.** `PROC_TIMER` was not
  NATS-initialised, so usrloc/dialog **expiry** events (and other
  timer-driven events) published from the timer process were dropped and
  mis-counted as failures. `nats_pool_should_init` now admits `PROC_TIMER`.
- **`cachedb_nats` — TTL tombstone mislabelled to EVI.** A MaxAge/TTL expiry
  surfaces as an empty-value Put; the index treats it as a REMOVE, but the
  `E_NATS_KV_CHANGE` event was raised as `operation="put"`. Remap an
  empty-value Put to `kvOp_Delete` for the event.
- **`nats_consumer` — async-RPC reply misdelivery under slot reuse.** The
  reply handler wrote `reply_*` + CAS'd `INFLIGHT→DELIVERED`, then re-checked
  the generation as a *separate* step; a worker that re-claimed the slot
  could consume another request's reply in that window. Added a `DELIVERING`
  pin state so claim-validation and reply-publish are atomic w.r.t. the
  worker (and fixed the at-deadline-drops-a-delivered-reply case).

## LOW (hardening)

- `cachedb_nats` json: negative-length guards on the `_lookup` /
  `_lookup_shard` fv-builders (parity with the other builders).
- `cachedb_nats` dbase: strict counter parse (`nats_counter_parse`) — reject
  a non-numeric / trailing-garbage / out-of-range stored value instead of
  silently resetting the counter to `delta`.
- `cachedb_nats` watch: poll the orphan watchdog (`getppid()==1`) at the loop
  top, not only in the `NATS_TIMEOUT` arm (a steady update stream never times
  out).
- `nats_consumer` persist: sanitize the JSON *key* (not just values) before
  splicing it into the `key=value;…` bind-config — blocks config-field
  injection from a tampered persist file.
- `nats_consumer` sub_config: fail the consumer build on a NULL required
  `stream` / `durable` cstr (OOM) rather than handing `nats.c` a NULL Stream.

## Follow-ups (all subsequently completed)

These were initially deferred as higher-risk, then landed via low-risk
in-tree solutions:

- **msg-ref generation epoch.** The 16-bit ack-token generation only
  disambiguated slot reuse within one row incarnation; a stale token could
  mis-ack a rebound handle index. Fix: persist a per-index generation seed
  (`g_row_gen_seed`) across the row free so a new incarnation's generations
  are strictly greater than any stale token's.
- **64-bit JetStream sequence in MI.** `nats_msg_get` / `nats_msg_delete`
  parsed `seq` as an `int`; `mi_get_seq_u64` now parses the full `uint64`
  (JSON string via `strtoull`, JSON-number int path retained).
- **orphan-reap TTL vs `ack_wait`.** The fixed 120 s orphan TTL could reap a
  slow-but-live worker under a large `ack_wait`; the per-row TTL is now
  `max(120 s, 2 × ack_wait)`.
- **`num_documents` stat drift.** Remove paths decremented unconditionally
  (going negative on a never-indexed key). `_entry_remove_key` now reports
  whether it removed the key, and the decrement is gated on actual removal.
- **CAS-error classification.** `nats_kv_update` returned -2 ("retry") for a
  generic `NATS_ERR`, so a script CAS loop could spin. It now routes the CAS
  through `nats_kv_put_row` (`js_PublishMsg` with `ExpectLastSubjectSeq` —
  byte-for-byte the same optimistic check `kvStore_UpdateString(rev)`
  performs), reading the numeric jsErrCode inline: 10071 → -2 (retry),
  anything else → -1. No new `nats.c` dependency.
- **Watcher `UpdatesOnly` snapshot gap.** The watcher rebuilt the index from a
  snapshot and *then* subscribed `UpdatesOnly`, dropping any mutation in the
  window. It now subscribes **before** the rebuild; the watcher's pending
  queue captures concurrent mutations and the consume loop applies them after
  the swap. The snapshot/live overlap is idempotent (`_entry_add_key` dedups
  on the interned key; the remove paths are membership-gated).

## Test-coverage deepening

A gcov pass over the unit-testable production TUs (compiled under `TEST_SHIM`
with real code linked) drove two new depth tests:

- **`test_parser_adversarial`** — drives the untrusted-input parser
  (`nats_handle_parse.c`) through every sub-parser branch and error path with
  adversarial values (all bool/ack/deliver/replay forms; every duration unit;
  RFC3339 `Z`/`±HH:MM`/fractional; uint/int bounds; missing/duplicate/empty
  keys; whitespace), asserting the *specific* error each time. Line coverage
  **84.6% → 96.3%**. It also surfaced a real gap now fixed: `parse_uint64`
  accepted a negative (`strtoull` wraps `-1` to `UINT64_MAX`); it now rejects a
  leading sign, so a typo'd/adversarial unsigned config value is refused rather
  than silently becoming a huge count.
- **`test_rpc_slot_lifecycle`** — drives the real async-RPC slot allocator
  (`nats_rpc_slot.c`) through its full lifecycle and edge paths: the init count
  clamp, double-init, pool exhaustion (claim on a full pool → NULL),
  publish-on-non-CLAIMED, lookup hit / out-of-range / freed, abandon → free →
  reuse, and the inflight/total counters. Line coverage **84.0% → 93.8%**.

The lock-free ring and MPSC were already exercised by existing 1M-message
multi-producer/multi-consumer stress tests (`test_ring.c` case 4,
`test_mpsc.c`), so no redundant stress tests were added. The remaining
`nats_handle_registry.c` gap (76%) is concentrated in SHM-OOM / lock-init
failure paths that require fault injection to reach.
