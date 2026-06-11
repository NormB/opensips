# NATS integration — improvement TODO

Analysis of `feature/nats` (lib/nats, cachedb_nats, event_nats, nats_consumer; ~27k LoC)
across four dimensions: maintainability, performance, security, survivability.
Date: 2026-06-11, branch head `c1429fea4`.

Tags: `[SEC]` security · `[PERF]` performance · `[MAINT]` maintainability · `[SURV]` survivability.
Items merged where multiple reviews found the same root cause.

**Status (2026-06-11):** P0 (1–8), P1 (9–27) and P2 (28–44) all done, plus P3
#53/#54 (folded into the ring/fetch-bounds work). Remaining: the rest of P3
(45–52, 55–74) — lower-severity correctness nits, hardening, docs, and tests.
Progress is tracked in git (`feature/nats`), not just these checkboxes.

---

## P0 — Fix before any further feature work (corruption, injection, server-wide outage)

- [x] **1. [SEC][MAINT] Remove the pointer-identity result cache in the subject validator.**
  `lib/nats/nats_validate.c:51-56` caches `(pointer,len)→verdict`; OpenSIPS reuses buffers
  at the same address, so refilled SIP-derived bytes containing `\r\n`/`*`/`>`/space skip the
  scan and reach the line-oriented `PUB` wire — NATS protocol injection. The O(len) scan it
  avoids is trivial. Delete the cache.

- [x] **2. [SEC] Make async-RPC reply inboxes unguessable.**
  `modules/nats_consumer/nats_rpc_consumer.c:304-306` uses `_INBOX.opensips.<pid>.<slot>.<gen>`
  (both guessable). The per-call UUIDv7 `corr_id` is only a header. Embed `corr_id` in the
  reply subject and validate it in `on_inbox_reply`.

- [x] **3. [SEC] Cap JSON depth/size before parsing broker-supplied values.**
  `modules/cachedb_nats/cachedb_nats_json.c:1666,1937` pass broker data to recursive cJSON
  with no nesting limit — deeply nested `[[[…]]]` crashes the worker (stack exhaustion).
  Pre-validate depth with the iterative `_skip_json_value`, cap `data_len`, and copy +
  NUL-terminate before parse (also covers the embedded-NUL truncation on the query path).

- [x] **4. [SEC] Fix cross-process eventfd confusion in nats_ring.**
  `modules/nats_consumer/nats_ring.c:317-321,195-198`: the eventfd int created in the MI-bind
  process is written/closed by *other* processes where the number maps to unrelated fds
  (libnats socket, timerfd). Drop the legacy eventfd (futex path already wakes cross-process)
  or guard all fd touches with a stored creator PID.

- [x] **5. [SEC] Close the registry lookup → pending_ops TOCTOU (use-after-free).**
  `modules/nats_consumer/nats_fetch.c:226-231` (and `:415-480,634-644,818-887`): handle can be
  retired+reaped between `nats_registry_lookup()` and `nats_handle_pending_inc()`. Add
  `nats_registry_lookup_ref()` that increments `pending_ops` under the bucket read lock and
  re-checks `retire`; use it on every fetch/ack path.

- [x] **6. [SURV] Apply fast-fail + stale-handle refresh to ALL cachedb operations.**
  `nats_con_refresh_kv` (`cachedb_nats_dbase.c:132-165`) guards only get/set/remove/counter
  paths. `nats_cache_query` (`cachedb_nats_json.c:1585`), `nats_cache_update` (`:2815`),
  raw query (`cachedb_nats_native.c:850`), map_get/set/remove (`:1208,1358,1485`) and the
  `w_nats_kv_*` wrappers bypass it — broker-down blocks SIP workers for the full JS timeout,
  and after reconnect they keep a **dangling** `ncon->kv` (free(): invalid pointer). Call the
  refresh at the top of every op, per the contract in `cachedb_nats.h:89`.

- [x] **7. [SURV] Stop event_nats from aborting the whole SIP server when the broker is down at boot.**
  `event_nats.c:376-388` child_init returns -1 after the ~2-min connect loop
  (`nats_pool.c:790-816`) → instance fails to start because an eventing sidecar is down.
  Log and return 0 (publish already fails cleanly on `!_nc`), enable
  `natsOptions_SetRetryOnFailedConnect`, and make the nats_consumer proc loop-retry instead
  of `return` (`nats_consumer_proc.c:1741-1752`).

- [x] **8. [SEC][SURV] Add generation checks to the async-RPC IPC path (double-publish).**
  Timeout frees the slot immediately (`nats_rpc_async.c:1188-1197`) while the consumer may
  still hold an undrained IPC entry that carries only `slot_idx` (`nats_rpc_ipc.h:68`);
  re-claimed slot → request published twice. Add `generation` to `nats_rpc_ipc_msg_t`,
  check it in `publish_cb` (`nats_rpc_consumer.c:284-299`), and re-verify generation after
  the INFLIGHT→DELIVERED CAS (`:190-195`).

---

## P1 — High (production blockers at scale, resource leaks, API conflicts)

- [x] **9. [SURV] Cap JetStream async publish pending (memory under slow-acking broker).**
  `lib/nats/nats_pool.c:869-871` leaves `PublishAsync.MaxPending` unset (= unlimited).
  Set it, use small/zero StallWait so the publish errors instead of blocking, count as drop.

- [x] **10. [SURV] Reap orphaned msg-ref slots (worker died mid-processing).**
  `nats_consumer_proc.c:295-330`: no TTL; a crashed worker leaks its slot forever and the
  handle eventually wedges (`:1404-1409`). Stamp claim time, reap slots older than ack_wait,
  add a stat. Pair `pending_ops` with owner-PID liveness so `nats_registry_reap` can't be
  blocked permanently by a dead worker.

- [x] **11. [PERF][SURV] Eliminate head-of-line blocking in the consumer main loop.**
  `nats_consumer_proc.c:1828-1832` runs serial blocking 1 s Fetches per handle; acks
  (`:1858-1877`) and async-RPC publishes (`:1888`) drain only after the full sweep. With N
  idle handles, ack latency ≈ N×fetch_timeout → ack_wait expiry → broker redelivery/double
  processing, and async RPCs can time out before being published. Drain ack/RPC eventfds
  between per-handle fetches and shrink the effective idle-fetch timeout (NoWait probing)
  when multiple handles or RPC slots are active. Also fixes the heartbeat false-stale
  (`:1790` vs 5000 ms threshold in `nats_mi.c:333`).

- [x] **12. [PERF][MAINT] Resolve the duplicate `nats_request` exports and route-safety conflict.**
  `cachedb_nats.c:308-314` exports a blocking sync `nats_request` to ALL_ROUTES (up to 30 s
  on a SIP worker — contradicts SCALING.md); `nats_consumer` exports a same-named, different-
  arity, route-restricted one. Keep one canonical version (nats_consumer's policy): rename
  cachedb's to `nats_cdb_request` (or remove) and apply the same route mask +
  `allow_sync_anywhere` opt-in.

- [x] **13. [MAINT] Fix the MI command name collision.**
  `event_nats.c:185-201` and `nats_consumer/nats_mi.c:356-381` both register
  `nats_consumer_list` (different semantics). Rename event_nats's JetStream-admin set to
  `nats_js_consumer_*` (mirrors its `nats_stream_*` family).

- [x] **14. [MAINT] Remove nats_consumer's hidden dependency on another module's pool registration.**
  `nats_consumer.c:495-513` never calls `nats_pool_register()`; loaded alone it fails at
  runtime (`nats_consumer_proc.c:1741`). Give it its own `nats_url`/reconnect modparams and
  register (the pool already merges), or add a real `dep_export_t` on event_nats.

- [x] **15. [MAINT][SURV] Make pool lifetime refcounted and fix shutdown ordering.**
  `nats_pool_destroy()` is called only by event_nats (`event_nats.c:404`) — wrong owner for a
  shared lib, never called when event_nats isn't loaded, and runs in the attendant where
  `_nc` is NULL so the drain knob is dead code. Refcount register/unregister in lib/nats,
  destroy on last unregister; call `js_PublishAsyncComplete()` (bounded) **before**
  `jsCtx_Destroy` (`nats_pool.c:1049-1066`); destroy stats **after** the pool
  (`event_nats.c:403`); wire or delete dead `nats_dl_unload()` (`nats_dl.c:169`).

- [x] **16. [SEC] Clamp the snprintf return before write() in the JS ack handler.**
  `lib/nats/nats_pool.c:391-396`: broker-controlled `ErrText` > ~219 bytes makes `len > 255`
  and `write()` leaks adjacent stack to the log. `if (len >= (int)sizeof(buf)) len = sizeof(buf)-1;`

- [x] **17. [SEC] Redact the URL returned by `nats_pool_get_server_info()`.**
  `nats_pool.c:1129-1133` returns the connected URL unredacted; surfaced to MI clients via
  `nats_stats.c:127`. Run `nats_redact_url()` over it.

- [x] **18. [SEC] Validate keys on ALL native/map/raw KV paths.**
  Map ops don't reject `:` (`cachedb_nats_native.c:67,1171-1173` — cross-map key aliasing);
  `w_nats_kv_*` and `raw_kv_purge` (`:888,1032`) forward unvalidated tokens — a wildcard
  reaching Purge is a mass delete. Run everything through `validate_kv_key`; explicitly
  reject wildcards on purge.

- [x] **19. [SEC] Validate RPC request/reply subjects.**
  `nats_rpc.c:883-893` and `nats_rpc_async.c:1259-1271` check only empty/length. Apply
  `nats_validate_publish_subject` to both paths and to `nats_reply`'s subject.

- [x] **20. [SEC] Fix counter overflow/truncation in `nats_cache_add`.**
  `cachedb_nats_dbase.c:595-622`: broker-set value near INT64_MAX → signed-overflow UB on
  `current += delta` and `(int)` truncation to script (limit-bypass). Range-check parsed
  int64 to INT range and detect overflow before adding (same in `get_counter` `:742`).

- [x] **21. [SEC][PERF] Bound and batch event_nats inbound message handling.**
  `modules/event_nats/nats_consumer.c:356-401`: per message, 3 separate shm_mallocs and an
  unbounded IPC dispatch — publish flood exhausts SHM. Single combined allocation (struct +
  subject + data), atomic in-flight counter with high-water drop + counter, reject oversized
  `data_len` explicitly.

- [x] **22. [SEC] Key consumer-side teardown on handle identity, not id string.**
  `nats_consumer_proc.c:675-677,1641-1650`: unbind+rebind of the same id before the teardown
  tick wedges delivery (old sub pushes into an unread ring) and leaks the retired handle.
  Use `h_ref`/`h->index` for teardown/reconcile matching.

- [x] **23. [SEC] Reap retired handles that never had a subscription.**
  `nats_consumer_proc.c:1637-1639` scans only `g_subs`; a handle bound+unbound before
  subscribe leaks ~2.3 MB SHM forever. Walk the retire list and mark `sub_torn_down=1` for
  retired handles with no matching `ss`.

- [x] **24. [SEC] Stop consuming handle indices on failed binds.**
  `nats_handle_registry.c:304-312`: index allocated before the duplicate check and never
  reclaimed — 256 failed/duplicate binds permanently disable binding. Allocate after the
  duplicate check; recycle indices via a free bitmap on reap.

- [x] **25. [SEC][PERF] Bound the nats_ring producer spin; lower the pop spin cap.**
  Push side has no spin cap (`nats_ring.c:243-254`) — a worker dead between tail-CAS and
  `consumed_gen` store livelocks the consumer at 100% CPU. Add a bounded push spin that
  bails as full; detect stalled `consumed_gen` and reclaim. Lower `NATS_RING_POP_SPIN_MAX`
  from 100k to ~1-4k (`:355,389-394`) — the futex re-arm fallback is cheap.

- [x] **26. [PERF] Replace the watcher delete path's O(buckets×entries) index removal.**
  `cachedb_nats_watch.c:523` → `nats_json_index_remove` (`cachedb_nats_json.c:1109-1131`)
  holds ALL shard locks for a full-index walk on every expiry/unregister — re-creates the
  21× p99 cliff PERF_NOTES fixed for updates. Maintain a doc-key→interned-fv reverse list
  (attach to the intern table) so deletes use `nats_json_index_remove_fields`; move the
  query-time stale eviction (`:1906`) to a background reap.

- [x] **27. [PERF] Make the intern table scale with the index.**
  `cachedb_nats_intern.c:25` hard-codes 1024 buckets — ~100-entry chains at 100k AoRs,
  walked under a shard lock twice per key op. Size from `index_buckets` (or own modparam)
  at init; store the FNV hash in the node for 4-byte pre-compare and to avoid re-hash in
  release.

---

## P2 — Medium (resilience hardening, hot-path efficiency, observability)

- [x] **28. [SURV] Fix the dead periodic index-resync timer.**
  `cachedb_nats.c:802-825` gates on process-local `_connected` in the timer process, which
  never connects → every tick silently skipped. Attempt `nats_pool_get()` first, or
  dispatch the rebuild to a NATS-initialized worker via `ipc_dispatch_rpc`.

- [x] **29. [SURV] Converge the search index after missed KV updates.**
  Watcher uses `UpdatesOnly` (`cachedb_nats_watch.c:419`); post-reconnect rebuild defaults
  off (`index_resync_on_reconnect=0`, `cachedb_nats.c:137`) — writes made during an outage
  never enter the index. Track last-delivered KV revision and rebuild on gap, or default
  the resync to 1 (after fixing #28).

- [x] **30. [SURV] Retry CAS loops only on actual conflicts.**
  `cachedb_nats_dbase.c:614-633` and `cachedb_nats_json.c:3048-3077` retry on ANY error —
  up to 10 × 2 × 5 s ≈ 100 s worker stall on a degraded broker. Continue only on
  mismatch/key-exists; bail immediately on timeout/connection errors; re-check
  connectivity per iteration.

- [x] **31. [SURV] Bound the inline publish path against black-holed brokers.**
  `nats_producer.c:88` publishes inline in SIP workers; options (`nats_pool.c:746-786`) set
  no write deadline/ping interval, so a no-RST black-hole blocks workers before cnats flips
  DISCONNECTED. Set a short ping interval / write deadline, or move publishing behind IPC
  to a producer proc.

- [x] **32. [SURV] Expose a `kv_op_timeout_ms` modparam.**
  `jsOpts.Wait` left 0 (`nats_pool.c:869-872`) = cnats default 5 s for every KV op — far
  above per-REGISTER budget and not operator-tunable. Plumb a modparam (500-1000 ms
  guidance for usrloc).

- [x] **33. [SURV] Poison-message and dead-inbox handling in nats_consumer.**
  Default `max_deliver=0` = unlimited broker-paced redelivery with no dead-letter
  (`nats_consumer_proc.c:797-798`, `nats_handle_parse.c:405-413`) — add consumer-side
  auto-Term + stat past a configurable cap. The async-RPC inbox subscribe is attempted
  exactly once (`:1773-1777`); on transient failure every async request for the process
  lifetime publishes to a deaf inbox — retry in the main loop, CAS slots to ABANDONED
  while down.

- [x] **34. [SURV] Close the ack-drop double-processing gap and export the counters.**
  Full ack queue drops the ack (`nats_ack_ipc.c:191-201`), script gets -2 with no retry
  guidance, and `dropped_total` (`:301-306`) is exported nowhere. Add MI stats:
  ring depth, ack/RPC IPC depth + drops, RPC slots in flight, fetch errors; fix the
  mislabeled `total_dropped_backpressure` (counts skips, `nats_consumer_proc.c:1250-1252`);
  add `fastfail_rejected`/`op_failed`/`watcher_restarts` to cachedb stats (rejection is
  currently LM_DBG-only, `cachedb_nats_dbase.c:144`); add consumer-side drop counters to
  event_nats (`nats_consumer.c:356-401`).

- [x] **35. [SURV] Add reconnect jitter.**
  `nats_pool.c:774-777,814`: fixed 2 s cadence × 32 workers = lockstep reconnect storm.
  `natsOptions_SetReconnectJitter` + randomized per-process startup sleep.

- [x] **36. [SURV] Watcher flap-leak and replay-flood polish.**
  One kvWatcher handle intentionally leaked per disconnect cycle — unbounded under flapping
  (`cachedb_nats_watch.c:539-551`); `nats_watch_stop()` from the attendant is a cross-process
  no-op (`cachedb_nats.c:785-786`); deleted-durable rebuild silently re-applies
  `deliver_policy=all` → full-stream replay (`nats_consumer_proc.c:1288-1300`) — WARN and
  bias recreate to last seen stream_seq.

- [x] **37. [PERF] Wake one waiter, not all, on the ring empty→non-empty edge.**
  `nats_ring.c:334-336` uses `FUTEX_WAKE INT_MAX` — 32 wakeups per message at low rate.
  Wake 1; producer issues additional single wakes while depth > 1.

- [x] **38. [PERF] Prefix-copy ring slots instead of full 17.9 KB struct assignment.**
  `nats_fetch.c:199,611,923` copy the whole `nats_ring_slot_t` 2-3× per message (~36-54 KB
  for a 100-byte payload). Add a prefix-copy helper (mirror of the pop side); have
  `nats_batch_select` store a pointer/index instead of copying.

- [x] **39. [PERF] Make async-RPC capacity and poll interval tunable.**
  `NATS_RPC_SLOT_COUNT 64` compile-time (`nats_rpc_slot.h:77-78`) caps system-wide async
  RPC at ~1.3k req/s @ 50 ms RTT; 1 ms per-call timerfd poll (`nats_rpc_async.c:1110`) adds
  a latency floor and 64k timer events/s at saturation. Promote both to modparams; consider
  per-slot eventfd wake or one shared timerfd per worker.

- [x] **40. [PERF] Stop full-bucket enumeration in map_get / prefix map_remove.**
  `cachedb_nats_native.c:1227,1243-1317,1520-1548`: O(total keys) enumeration + one serial
  RTT per match. Use filtered keys (subject-token encoding for subkeys) or a filtered
  watch-snapshot stream like `_drain_kv_snapshot` (`cachedb_nats_json.c:812`).

- [x] **41. [PERF] Take allocations out of the shard lock in non-PK queries.**
  `cachedb_nats_json.c:1779-1806` strdups the whole match set under `_idx_lock_shard`, then
  serial-fetches N documents (`:1893-1950`). Copy interned key pointers with a refcount
  bump (intern guarantees stability), release the lock before allocating, fetch with
  bounded concurrency.

- [x] **42. [PERF] De-serialize the ack/RPC IPC enqueue locks.**
  Single global `gen_lock_t` per queue shared by all workers (`nats_ack_ipc.c:57,184-200`;
  `nats_rpc_ipc.c:161-232`). Reuse the head/tail-CAS + per-slot generation scheme already
  proven in nats_ring.c, or shard per worker.

- [x] **43. [PERF] Use stack buffers on the PK fast path.**
  `cachedb_nats_json.c:1614-1653,2890-2931`: 2 mallocs + 2 frees per usrloc read/write for
  typically <100-byte keys. Encode into a 512 B stack buffer with heap fallback.

- [x] **44. [PERF] Document / gate per-process connection fan-out.**
  `nats_pool.c:119,672-689`: every touching process gets its own connection (~6 libnats
  threads each) — 32+ workers = 32+ broker connections, ~200 threads. Document in
  SCALING.md; optionally gate creation to ranks that serve cachedb traffic.

---

## P3 — Lower severity (correctness nits, hardening, code health, docs, tests)

- [ ] **45. [SEC] Redactor: use last `@` (`nats_redact.c:54-56`) and redact scheme-less
  `user:pass@host` URLs (`:39-47`).**
- [ ] **46. [SEC] `nats_cache_set`: add `val->len < 0` guard (`cachedb_nats_dbase.c:439-450`).**
- [ ] **47. [SEC] kv_history JSON escaping: escape control chars, not just `"`/`\`
  (`cachedb_nats_native.c:377-383`).**
- [ ] **48. [SEC] `_json_escape_len`: accumulate in size_t/int64 and bound `in_len`
  (`cachedb_nats_json.c:2102-2131`); fix the `\uXXXX` 6-vs-7-byte guard (`:2006-2010`).**
- [ ] **49. [SEC] persist rehydrate: reject/escape `;`/`=` in values (`nats_persist.c:803-834`).**
- [ ] **50. [SEC] `batch_parse_duration_ms`: per-digit overflow clamp (`nats_fetch.c:508-512`).**
- [ ] **51. [SEC] `nats_ring_pop`: clamp SHM-read `*_len` fields to their MAX before memcpy
  (`nats_ring.c:415-439`).**
- [ ] **52. [SEC] Rate-limit the per-message oversize WARN (`nats_consumer_proc.c:1448-1453`).**
- [x] **53. [SEC] Cap `ring_capacity` (e.g. 65536) — currently up to 2^31 ≈ 18 GB per bind
  (`nats_handle_parse.c:541-543`).**
- [x] **54. [SEC] Reject `timeout_ms <= 0` on async fetch — currently holds `pending_ops` and a
  1 ms timer forever (`nats_fetch.c:478`).**
- [ ] **55. [SEC] Check snprintf truncation in nats_ca_dir (`nats_ca_dir.c:125,159`); explicit
  `data_len` max reject in event_nats consumer (`nats_consumer.c:380-381`).**
- [ ] **56. [SEC] Intern release: locate node before dereferencing freed memory on double-release
  (`cachedb_nats_intern.c:200-214`).**
- [ ] **57. [SEC] Guard NULL `cb_h` before `&cb_h->acks` (`nats_consumer_proc.c:1511-1513`); force
  `data_len=0` when libnats returns NULL data (`:1411-1413`).**
- [ ] **58. [SEC][MAINT] Check natsStatus returns in `apply_tls_from_mgm` — silent mTLS/cipher
  downgrade on failure (`nats_pool.c:636-661,783`).**
- [ ] **59. [MAINT] Rename event_nats's internal `nats_consumer.c/.h` (e.g. `event_nats_sub.c`)
  and differentiate the two `"NATS consumer"` proc display names
  (`event_nats.c:235`, `nats_consumer/nats_consumer.c:449`).**
- [ ] **60. [MAINT] Split `cachedb_nats_json.c` (3087 lines → index / serializer / query+update
  TUs) and `nats_consumer_proc.c` (1960 lines → msg_ref, sub_config, proc loop); decompose
  the ~400-line functions.**
- [ ] **61. [MAINT] Factor the duplicated URL tokenizer in `nats_pool_register`
  (`nats_pool.c:489-546` vs `parse_urls` `:165-236`).**
- [ ] **62. [MAINT] Sweep stale docs/comments: nonexistent `@param tls`, `nats_OpenWithConfig`,
  `nats_pool_finalize` (`nats_pool.h:99,137,268`); "statically linked" comment
  (`cachedb_nats.c:466`); wrong `index_resync_on_reconnect` default claim
  (`cachedb_nats_watch.c:399`); stale "process-local index" header
  (`cachedb_nats_json.c:22-40`); unreachable spec reference (`nats_consumer.h:27-28`).**
- [ ] **63. [MAINT] Consolidate str→cstr/dup helpers into lib/nats (4+ duplicates:
  `cachedb_nats_dbase.c:234`, `cachedb_nats_native.c:100,208-223,564-578,638-651`,
  `nats_consumer_proc.c:423,436`).**
- [ ] **64. [MAINT] Consolidate the four subject/name validators into lib/nats with mode flags
  (publish / stream-name / kv-key / filter-subject) — also closes gaps behind #18/#19.**
- [ ] **65. [MAINT] Remove the `*timeout_ms = eff` write-back that contradicts its own comment
  (`cachedb_nats_native.c:176-193`).**
- [ ] **66. [MAINT] Extract `nats_publish_checked()` for the duplicated publish path
  (`event_nats.c:486-521` vs `:631-663`) and `subscribe_one()` for the duplicated subscribe
  (`modules/event_nats/nats_consumer.c:238-247` vs `:296-305`); name `NATS_MAX_SUBJECT_LEN`.**
- [ ] **67. [MAINT] MI param boilerplate helper + named jsErrCode constants in
  `nats_jetstream.c` (10× repeated block; raw 10059/10014/10037 literals).**
- [ ] **68. [MAINT] Reject over-long KV bucket names instead of snprintf-truncating them into a
  permanently-missing cache slot (`nats_pool.c:137-140,948-985`); name the 128/16 constants.**
- [ ] **69. [MAINT] lib/nats Makefile: add `-MMD -MP` dependency tracking (X-macro
  `nats_dl_table.def` edits currently don't rebuild), extend clean targets and .gitignore
  for test binaries.**
- [ ] **70. [MAINT] Honor `expected_kv_no` in raw_query (`cachedb_nats_native.c:925-1016,
  1061-1131`) — callers requesting more columns get OOB frees in the core's reply-free loop.**
- [ ] **71. [MAINT] Watcher hygiene: add `\n` to LM_INFO lines (`cachedb_nats_watch.c:625-627`),
  drop the unreachable `_num_patterns==0` branch (`:799-804`), use pkg_malloc not raw
  malloc (`:605,618`).**
- [ ] **72. [MAINT] Unify the aliased drain-timeout modparams (`nats_drain_timeout_ms` /
  `cdb_drain_timeout_ms` both write one global, last-writer-wins) — take the max across
  registrants like reconnect params.**
- [ ] **73. [MAINT] Move point-in-time review/bench artifacts (REVIEW.md,
  DEDICATED_WATCHER_REVIEW.md, PERF_NOTES.md) out of the tree or mark as historical;
  generate README from doc XML per OpenSIPS convention instead of hand-written README.md.**
- [ ] **74. [MAINT][SURV] Close test-coverage gaps for the riskiest untested surfaces:
  jetstream MI handlers, map/raw ops, `ensure_subscription_for_handle`/reconcile, pool
  register-merge; plus failure-mode tests for items 6, 7, 9, 10, 11 (ack latency vs
  ack_wait), 8 (slot-reuse double-publish), 28, 29, 30, 31, 33 (inbox-failure path),
  34 (ack-IPC overflow), 36 (per-flap watcher leak).**

---

## Verified-good (no action; confirmed by review)

- tls_mgm `verify_cert` defaults to 1; no insecure-skip backdoor.
- `nats_redact_url` core arithmetic, IPv6, truncation handling correct (modulo #45).
- `nats_dl_load` fails closed on missing symbols; RTLD_NOW.
- Main `json_escape` handles quotes, backslash, all control chars incl. embedded NUL.
- Stats counters: C11 `_Atomic` per-process slots, bounds-checked.
- kvEntry lifetimes on query/counter/history paths; watcher teardown single-owner
  (atomic_exchange + pthread_join).
- Sync RPC uses libnats random inboxes; UUIDv7 fails closed; IPC never passes pointers.
- Persist file write atomic (mkstemp + fchmod 0600 + fsync + rename), 10 MiB slurp cap.
- No format-string sinks; no infinite waits (all blocking calls bounded — see #31/#32 for
  the two practical exceptions).
