# cachedb_nats / NATS-modules performance notes

This file consolidates the perf series shipped on `feature/nats`
between `7232b5e18` (master merge) and the latest scale-tuning
group (PK fast path, runtime-tunable bucket count, optional index
for PK-only workloads).  Three layered passes (correctness →
tier-1/2/3 perf → 1MM/10MM scale tuning).

For day-to-day operator guidance, read
`cachedb_nats_usrloc_playbook.xml` first — it covers topology,
bucket sizing, MI counters, and the runtime recommendations.
This file is the engineering record: what changed, why, and what
the measurements showed.

## TL;DR

For production cachedb_nats deployments backing usrloc in
`cluster_mode = full-sharing-cachedb`:

1. **Launch opensips with `-s HP_MALLOC`** to use HP_MALLOC for the SHM
   allocator.  This is the single biggest tail-latency win.
2. **Set `enable_search_index=0`** for usrloc-only deployments.
   usrloc reads/writes are PK-only (`is_pk=1`); the in-memory
   JSON-FTS index is dead weight.  Disabling it saves the SHM
   footprint, the watcher CPU, and routes every read through
   the new PK fast path.  See SCALING.md for the threshold
   guidance at 1MM and 10MM endpoints.
3. **If the index is enabled**, tune `index_buckets` to keep
   average chain length ≤ ~5: 4096 (default) at ≤ 20k AoRs,
   16384 at 100k, 65536 at 1MM.  Power-of-two-rounded at init.
4. **Set `index_resync_on_reconnect=0`** (the new default since
   commit 05a695f8c).  The Phase-1.4 self-heal makes the bulk
   rebuild redundant for correctness, and saves a 5-10 s stall on
   every brief broker hiccup.
5. **Monitor `nats_cdb_stats`** counters via MI; alert on
   `cas_exhausted > 0` (lost writes) and watch `index_miss_kv`
   for a churn-rate signal across multi-instance deployments.
6. **Optionally bump `nats_cas_retries`** above the default 10
   if you see a steady non-zero `cas_exhausted` rate under burst
   contention; the Phase-1.3 jittered backoff bounds total per-
   call latency at ~50 ms.

## Bench summary

Single-instance, loopback NATS broker, aarch64.  All numbers from
`modules/cachedb_nats/tests/sip_e2e/bench_ul_register.sh`,
unpaced (RPS=0).  "Original" is the branch state at session
start; "Final" is `398c3e206` with `-s HP_MALLOC`.

| AoR count | Metric | Original | Final | Δ |
|-----------|-------|---------:|------:|--:|
| 1 000 | p50 | 15 ms | 15 ms | — |
| 1 000 | p99 | 18 ms | 18 ms | — |
| 10 000 | p50 | 37 ms | 21 ms | **−43%** |
| 10 000 | p99 | 96 ms | 54 ms | **−44%** |
| 20 000 | p50 | 54 ms | 25 ms | **−54%** |
| 20 000 | p99 | 383 ms | 142 ms | **−63%** |
| 20 000 | effective RPS | 391 | 448 | **+15%** |

CAS exhaustion was zero across every configuration.  Effective
RPS was bench-harness-bound (sipsak round-trip + `udp_workers=2`),
not opensips-bound, except at 20k where index pressure showed.

## Correctness fixes (Phase 1.1–1.4 + 1.5)

These commits (the first wave) were not perf work per se but
unblocked usrloc-on-NATS at all:

| SHA | Phase | What it fixed |
|-----|-------|---------------|
| `eaff7d0ec` | 1.1 | nested-dict + typed pairs + subkey + unset in `nats_cache_update` (was silently dropping every `CDB_DICT` pair) |
| `a98198fe4` | 1.2 | upsert-on-first-update via `kvStore_CreateString` seed (every initial REGISTER had been failing) |
| `536ee0b3f` | 1.3 | jittered CAS backoff + 4 SHM-atomic counters + `nats_cdb_stats` MI |
| `bf45eeb1a` | 1.4 | self-healing stale-index eviction in `nats_cache_query` |
| `f976ae18f` | 1.5 | KV-key encoding (`@` → `=40`) + sip_e2e harness + 4 integration cases |

Together these turned a spec-only "you can use NATS as your usrloc
store" into a configuration that actually persists REGISTERs.

## Tier-1 perf

**`856f25d90` — single-buffer JSON sink for nested-dict
serialization.**  `_serialize_cdb_dict` was building inner
contact dicts pair-by-pair, with each iteration calling the old
`_json_apply_pair`, re-parsing the growing buffer, and running 2-3
mallocs (`_render_leaf` / `_object_set` / `_splice`).  For a 14-
field contact dict that was ~30-40 malloc/free cycles per
serialization.  Replaced with a single growable `json_sink_t`
buffer that walks the cdb_dict_t once and appends each pair
directly.  ~5–10× reduction in malloc traffic on the inner-dict
hot path; correctness preserved across all 12+ unit tests.

**`742d83eb1` — single-pass pair-apply in `nats_cache_update`.**
The CAS loop's per-pair `_json_apply_pair` invocations re-parsed
the entire growing JSON document on every iteration: O(M·|doc|)
for M pairs.  Replaced with `_apply_pairs_one_pass`: classify the
pair list once (materialise any `CDB_DICT` subtrees up front),
then walk the input doc exactly once, copying through to a sink
while applying matching ops.  Pairs whose field is not present in
the input are appended at the end.  O(M + |doc|) instead of
O(M·|doc|), with one growable buffer rather than ~3M.

Tier-1 #3 (pre-built field list to skip post-CAS index reparse)
was evaluated and skipped — measured impact 10–40 µs/CAS write,
sub-1% of typical p50 latency, not worth ~150–200 lines of byte-
offset bookkeeping risk.

## Tier-2 perf

**`d48f6218a` — per-thread subject-validation cache.**
`nats_validate_publish_subject` is called on every publish.  The
script engine reuses stable str buffers for compiled string
constants, so the same bytes are validated repeatedly.  Cache
the last (pointer, length, result) tuple in `_Thread_local`
storage; pointer-equality is sufficient because the script
engine guarantees buffer stability.  5–15% CPU reduction on
bulk publish loops.

**`7dc360a88` — cold-start: stream snapshot via
`kvStore_WatchAll`.**  `nats_json_index_build` and
`nats_json_index_rebuild` both used a "Keys + N × Get" pattern:
one round-trip to enumerate, then N serial round-trips for
values.  At ~200 µs RTT and a 50k-entry bucket that's ~10 s of
serial waiting per process per cold start.  Replaced with a
single `kvStore_WatchAll` subscription opened with
`UpdatesOnly=false`, draining only the snapshot phase.  Expected
~5–10× cold-start speedup at large bucket sizes.

**`e7837b22f` — per-process counter slots, no cacheline ping-
pong.**  Both `nats_stats_t` (event_nats) and `nats_cdb_stats_t`
(cachedb_nats) were single SHM structs with `_Atomic` fields.
Every publish or CAS retry did `atomic_fetch_add` against the
same line, forcing cache-coherence traffic between cores.
Replaced with SHM arrays of `NATS_*_MAX_PROCS` (512) cacheline-
aligned slots, indexed by `process_no`.  Each worker writes
exclusively to its own line; MI handlers sum across slots on
read.  Expected 2–5% throughput at 16+ workers; measurable on
high-frequency publish workloads.

Tier-2 #8 (skip re-parse on no-op watcher events) was evaluated
and skipped — re-REGISTERs always change `cseq`/`last_modified`,
making the cache-hit rate near-zero on real workloads.

## Tier-2 #4 (deferred → done)

**`3865cdb93` — move the JSON-FTS index into shared memory.**
The largest architectural change.  Every worker had a private
`nats_search_idx` in pkg/heap memory: ~5 MB × M workers, M
concurrent cold-starts each making N kvStore requests, AND a
correctness gap (only rank-1 ran the watcher; non-rank-1 indexes
drifted until reconnect rebuild or query-time self-heal).
Promoted `g_idx`, every entry struct, every `field_value`
string, every `keys[]` array, and every key-string strdup into
SHM via `shm_malloc`.  The 16 sharded mutexes added in Tier-3
#10 swap from `pthread_mutex_t` to OpenSIPS's
`gen_lock_set_t`.  Init moves to `mod_init` pre-fork; only
rank 1 calls `nats_json_index_build`.  Watcher updates from
rank 1 are now visible to every reader through the shared
mapping.

## Tier-3 perf

**`05a695f8c` — flip `index_resync_on_reconnect` default 1 →
0.**  Phase 1.4's stale-entry self-heal makes the bulk rebuild
redundant for correctness; the lazy convergence avoids a 5-10 s
watcher stall on every brief broker hiccup.

**`5c6095a8f` — tunable shutdown drain timeout.**  `lib/nats/
nats_pool_finalize` had a hardcoded 5 s `kvStore_DrainTimeout`.
Expose `nats_pool_drain_timeout_ms` as a public extern int with
modparams in both event_nats (`nats_drain_timeout_ms`) and
cachedb_nats (`cdb_drain_timeout_ms`) so high-latency cross-DC
deployments can extend the budget.

**`78ea7ed78` — parse JSON outside the index mutex.**
`nats_json_index_add` held `g_idx->lock` for the entire
duration of `_parse_json_fields`, which is CPU-bound and scales
with document size.  Refactored into a two-phase pattern: parse
unlocked into a stack-backed `_idx_fv_list_t`, then take the
lock briefly to insert each collected pair.  Lock-hold time
goes from O(num_bytes) to O(num_fields).  ~10× lock-window
reduction for typical 500-byte AoR docs.

**`43ceca02b` — shard the index mutex (16 shards over 256
buckets).**  Single-bucket operations (lookup, single-key add)
take only their owning shard; whole-index operations (remove,
rebuild swap, destroy) acquire all 16 shards in order.
`num_documents` is `_Atomic int` so add/remove can update it
without holding any shard.  Concurrent queries on disjoint
shards now proceed in parallel.

**`34494d1a8` — per-shard locking in `nats_json_index_add`
Phase B.**  Inlined the per-field hash + lock + insert into the
loop so each iteration acquires/releases just the relevant
shard, instead of locking all shards once for the whole list.
Modest tail-tightening at the bench's 2-worker scale; bigger
relative gain on production-scale 32+ worker deployments where
multiple writers contend on disjoint shards.

## CI fix

**`ba059150a` — drop dead JSON helpers, refresh atomic-stats
source-grep, add CLAUDE.md.**  Three CI failures triggered by the
perf work:

  1. Tier-1 #1+#2 left the entire legacy `_json_apply_pair`/
     `_object_set`/`_render_leaf`/`_splice`/`_kv_token`/
     `_find_field` chain unreferenced.  Local `cc 13` allowed
     it; CI's `gcc-12 -Werror=unused-function` rejected it.
     Deleted ~330 lines of dead code.
  2. Tier-2 #6 replaced `atomic_fetch_add` direct calls with
     `NATS_STATS_BUMP`; `test_atomic_stats.c` source-greped for
     the OLD pattern and broke.  Updated the test to assert the
     new macro shape AND that the macro still expands to
     `atomic_fetch_add`.
  3. Added `CLAUDE.md` mandating the full-tree pre-push
     checklist (every NATS module's tests + `lib/nats/tests` +
     `make all -Werror`), since source-grep tests in sibling
     modules are exactly what local single-module testing
     misses.

## Final round (this commit's antecedents)

**`1b0694cfa` — targeted index_remove via the doc's old JSON.**
The biggest single tail-latency win.  `nats_json_index_remove`
walked all 256 buckets and every chained entry while holding all
16 shard locks for the whole walk.  At 20k entries that produced
super-linear p99 growth: p50 grew 3× from 1k → 20k, but p99 grew
21× because every other operation queued behind each remove.

`nats_cache_update` already had the doc's pre-write JSON in scope
(it's exactly what we just `kvStore_Get`'d for the CAS).  Add
`nats_json_index_remove_fields(key, json)` that parses that JSON
and visits only the (field:value) entries the key was actually
in, locking just the relevant shard one entry at a time.  Cost
goes from O(N) over the whole index to O(F) where F is the
indexed top-level string field count (typically 2-3 for usrloc).

The legacy O(N) `nats_json_index_remove` stays in place for the
lazy stale-index self-heal in `nats_cache_query` — that path
only learns the key is stale when a query hits it and doesn't
have the old JSON.

20k bench: p99 383 ms → 185 ms (−52%).

**`398c3e206` — recommend HP_MALLOC for SHM (single biggest p99
win).**  Diagnosed the residual p99 growth from 10k → 20k:
broker per-write latency is essentially flat (1k → 20k buckets:
15.5 → 16.4 ms, only +6%), ruling out NATS-side scaling.  The
bottleneck is OpenSIPS's default Q_MALLOC SHM allocator —
single-mutex, serialises every `shm_malloc`/`shm_free` across
all worker processes.  Each per-CAS path triggers 3-5 SHM
allocations to update the in-memory JSON-FTS index, and Q_MALLOC's
lock pinches every worker on every alloc.

`HP_MALLOC` ("optimized for shared memory multiprocessing")
gives:

  10k: p50 35 → 21 ms (−40%), p99 84 → 54 ms (−36%)
  20k: p50 41 → 25 ms (−39%), p99 185 → 142 ms (−23%)

No code changes — the allocator is selected at runtime via the
existing `-s HP_MALLOC` flag.  The bench harness now bakes it in by
default; the playbook calls it out as a production
recommendation; CLAUDE.md captures the finding so future
investigations reach for it directly.

Pkg memory (`-k`) is per-process and not contended; only the
SHM allocator (`-s`) needs the switch.

## Scale-tuning group (Items 1-3 of the 1MM / 10MM plan)

Three changes that together make cachedb_nats viable as a usrloc
backend at 1MM endpoints and credible at 10MM, by recognising
that usrloc's read/write path is PK-only and the JSON-FTS index
is therefore optional weight on the hot path.

**Item 1 — PK fast path in `nats_cache_query`.**  Added a single-
condition is_pk=1 short-circuit at the top of `nats_cache_query`
(mirroring the long-existing PK branch in `nats_cache_update`).
Encodes the filter value via `_kv_encode_key`, builds the prefixed
target_key, calls `kvStore_Get`, parses the returned JSON, and
returns one row.  No mutex acquired, no chain walk, no shard
locking.  Falls through to the index path for any non-PK or
multi-condition filter, so script-driven `cdb_query` still works.
For the canonical usrloc deployment (`cdb_load_urecord` always
sets `is_pk=1`) this turns every read into a single broker RTT
plus JSON parse.

**Item 2 — `index_buckets` modparam.**  Promoted the bucket count
from a 4096 `#define` to a runtime modparam (`index_buckets`,
default 4096, init-time power-of-two-rounded with a floor of
`NATS_IDX_SHARDS = 16`).  The buckets array moved from a fixed
inline `nats_idx_entry *buckets[NATS_IDX_BUCKETS]` to a
dynamically-allocated SHM array.  `_hash` switched from `% N` to
`& nats_idx_bucket_mask`.  Operators can now tune for their AoR
count without recompiling: 16384 at 100k AoRs (avg chain ≈ 6),
65536 at 1MM (avg chain ≈ 15).  Each doubling halves average
chain length for ~32 KB additional SHM.

**Item 3 — `enable_search_index` modparam.**  Default 1 preserves
legacy behaviour.  When set to 0:

  - `nats_json_index_init` is skipped in `mod_init`; `g_idx`
    stays NULL.
  - `nats_json_index_build` and the watcher are skipped in
    `child_init`.
  - The PK fast path (Item 1) handles every query;
    `nats_cache_update`'s existing PK branch handles every
    update.
  - Non-PK filters in either path are rejected with an explicit
    error message ("non-PK filter rejected because the search
    index is disabled") rather than crashing on a NULL `g_idx`.
  - `nats_json_index_add/remove/remove_fields` natural early-
    returns make the watcher callsites and CAS update path
    no-ops (zero JSON parse, zero SHM allocation).

For usrloc-only deployments this is a free win at every scale:
no SHM cost for the index (saves ~250 MB at 1MM, ~2.5 GB at
10MM), no watcher CPU (which would otherwise saturate at >100 %
of one core at 1MM), and no per-write index-update work in the
CAS loop.

Combined effect: usrloc-on-NATS at 1MM endpoints is now a single
modparam flip away from a full-sharing-cachedb deployment that
spends zero SHM and zero CPU on machinery it doesn't need.

## Item 4 — dedicated watcher process

Until Item 4, the KV watcher ran as a pthread inside the rank-1
SIP worker (`nats_watch_start` → `_watcher_thread_fn`).  At
≥ 100k AoRs the steady-state event rate (~1 700 events/sec,
~17% of one core, see SCALING.md) competes with SIP request
handling on the same scheduler — the SIP worker can be late
servicing INVITEs because its sibling thread is busy parsing JSON
and updating the index.

Item 4 adds an opt-in modparam, `dedicated_watcher_proc`, that
shifts the watcher into its own forked OpenSIPS child process via
the standard `proc_export_t` mechanism (same shape `event_routing`,
`pua_dialoginfo`, and `dialog` use).  The dedicated process owns
its own NATS connection and KV handle; it writes to the same
SHM-backed `g_idx` every SIP worker maps, using the per-shard
locks added in commit 43ceca02b — no new synchronisation.

Gating:
- `dedicated_watcher_proc=0` (default) — legacy rank-1 pthread.
- `dedicated_watcher_proc=1` — dedicated process, rank-1 pthread
  is skipped.  `destroy()` also skips `nats_watch_stop()` since
  there's no in-process pthread to join; SIGTERM from the core
  reaps the dedicated child cleanly.
- `enable_search_index=0` overrides both — the dedicated process
  is not declared and not forked, with an explicit "is meaningless"
  log line.  The watcher has nothing to update when the index
  doesn't exist.

The dedicated proc is also gated on `kv_watch_count > 0` (mirrors
the rank-1 child_init gate): if no `kv_watch` pattern is
configured, no fork — there's nothing to watch.

### Bench (10k AoRs, RPS=200, single-instance, loopback NATS, HP_MALLOC, aarch64)

| Mode | p50 ms | p95 ms | p99 ms | max ms | eff. RPS | RSS MB | CAS retry / exh |
|------|------:|------:|------:|------:|--------:|------:|----------------:|
| rank-1 pthread (default)         | 15.18 | 16.34 | 17.98 | 62.1 | 103.6 | 77.8 | 0 / 0 |
| dedicated watcher proc           | 15.21 | 16.41 | 18.21 | 63.2 | 103.6 | 84.4 | 0 / 0 |
| `enable_search_index=0` (regr.)  | 15.01 | 16.11 | 17.68 | 61.9 | 103.6 | 72.1 | 0 / 0 |

At 10k single-instance the dedicated mode is **noise-level** in
latency: p50 +0.03 ms, p95 +0.07 ms, p99 +0.23 ms — all well
inside run-to-run variance — and pays ~6.6 MB RSS for the second
process.  The expected payoff is at higher scale where the
watcher's CPU footprint stops being negligible: at 100k AoRs the
rank-1 pthread mode has ~17% of one core taken by watcher work,
which the SIP worker no longer competes for in the dedicated mode.
We don't have a 100k bench rig in tree to measure that directly;
the design rationale stands on the SCALING.md projection plus the
fact that at 10k there is no measurable regression from running
the watcher out-of-process.

### Functional verification

sip_e2e was extended to wire `DEDICATED_WATCHER` through
`opensips.cfg.in`, `run.sh`, `bench_ul_register.sh`, and
`cases/040_broker_bounce.sh`.  All 30 assertions pass in each of
three configurations:

- Default (rank-1 pthread) — log shows `_watcher_thread_fn: NATS
  KV watcher thread started`.
- `DEDICATED_WATCHER=1` — log shows a separate pid in
  `nats_watcher_proc_main: NATS watcher proc starting (pid=…)`
  and the rank-1 pthread is correctly skipped.
- `ENABLE_INDEX=0` — log shows the `is meaningless` message and
  neither watcher starts; PK fast path serves all reads/writes.

A structural test (`test_dedicated_watcher_proc.c`) asserts the
modparam, `proc_export_t`, gate sites in `mod_init` /
`child_init` / `destroy`, and the cross-file symbol declaration.
RED-proven: stripping the modparam string from `cachedb_nats.c`
flips the test red; restoring it flips it green.

## What's still on the table

Not pursued in this series, listed for the next session:

- **Async `nats_request` variant** (Item 5) — `nats_consumer/
  nats_rpc.c` currently blocks the SIP worker on the RPC call.
  Synchronous design is fine for non-request-route callers and
  modest RPS; a deployment running `nats_request` in
  `request_route` at 1MM-endpoint scale needs async.  Flagged in
  the original perf review (item #8); not pursued.

- **SHM allocator pressure at non-trivial bucket counts** — at
  20k AoRs / 256 buckets the residual p99 growth from 10k → 20k
  (54 → 142 ms) tracked SHM-alloc serialisation.  HP_MALLOC took
  the worst of it.  Item 2's bigger bucket arrays should narrow
  it further; re-bench at 100k once the deployment shape calls
  for it.
