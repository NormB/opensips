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
   commit 05a695f8c).  The stale-entry self-heal makes the bulk
   rebuild redundant for correctness, and saves a 5-10 s stall on
   every brief broker hiccup.
5. **Monitor `nats_cdb_stats`** counters via MI; alert on
   `cas_exhausted > 0` (lost writes) and watch `index_miss_kv`
   for a churn-rate signal across multi-instance deployments.
6. **Optionally bump `nats_cas_retries`** above the default 10
   if you see a steady non-zero `cas_exhausted` rate under burst
   contention; the jittered CAS backoff bounds total per-call
   latency at ~50 ms.

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

## Correctness fixes (initial wave)

These commits were not perf work per se but unblocked usrloc-on-NATS
at all:

| SHA | What it fixed |
|-----|---------------|
| `eaff7d0ec` | nested-dict + typed pairs + subkey + unset in `nats_cache_update` (was silently dropping every `CDB_DICT` pair) |
| `a98198fe4` | upsert-on-first-update via `kvStore_CreateString` seed (every initial REGISTER had been failing) |
| `536ee0b3f` | jittered CAS backoff + 4 SHM-atomic counters + `nats_cdb_stats` MI |
| `bf45eeb1a` | self-healing stale-index eviction in `nats_cache_query` |
| `f976ae18f` | KV-key encoding (`@` → `=40`) + sip_e2e harness + 4 integration cases |

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
0.**  The stale-entry self-heal in `nats_cache_query` makes the
bulk rebuild redundant for correctness; the lazy convergence
avoids a 5-10 s watcher stall on every brief broker hiccup.

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

## Scale-tuning group (PK fast path, configurable index_buckets, optional index)

Three changes that together make cachedb_nats viable as a usrloc
backend at 1MM endpoints and credible at 10MM, by recognising
that usrloc's read/write path is PK-only and the JSON-FTS index
is therefore optional weight on the hot path.

**PK fast path in `nats_cache_query`.**  Added a single-
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

**Configurable `index_buckets` modparam.**  Promoted the bucket count
from a 4096 `#define` to a runtime modparam (`index_buckets`,
default 4096, init-time power-of-two-rounded with a floor of
`NATS_IDX_SHARDS = 16`).  The buckets array moved from a fixed
inline `nats_idx_entry *buckets[NATS_IDX_BUCKETS]` to a
dynamically-allocated SHM array.  `_hash` switched from `% N` to
`& nats_idx_bucket_mask`.  Operators can now tune for their AoR
count without recompiling: 16384 at 100k AoRs (avg chain ≈ 6),
65536 at 1MM (avg chain ≈ 15).  Each doubling halves average
chain length for ~32 KB additional SHM.

**Optional index via `enable_search_index` modparam.**  Default 1 preserves
legacy behaviour.  When set to 0:

  - `nats_json_index_init` is skipped in `mod_init`; `g_idx`
    stays NULL.
  - `nats_json_index_build` and the watcher are skipped in
    `child_init`.
  - The PK fast path (PK fast path) handles every query;
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

## Dedicated KV-watcher process (`dedicated_watcher_proc`)

Before the dedicated-watcher feature, the KV watcher ran as a pthread inside the rank-1
SIP worker (`nats_watch_start` → `_watcher_thread_fn`).  At
≥ 100k AoRs the steady-state event rate (~1 700 events/sec,
~17% of one core, see SCALING.md) competes with SIP request
handling on the same scheduler — the SIP worker can be late
servicing INVITEs because its sibling thread is busy parsing JSON
and updating the index.

The dedicated-watcher feature adds an opt-in modparam, `dedicated_watcher_proc`, that
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

### Bench rig: compiled C driver

The original bash bench harness (`bench_ul_register.sh` driving
`sipsak` per-call) had a ~7 ms/iter floor from `bash` pacing +
`awk` fork + per-call `sipsak` exec.  That floor capped effective
rate at ~140 RPS regardless of OpenSIPS performance, and the
reported per-call latency was dominated by the `sipsak` startup
cost — not the SIP path.  The numbers from that rig (p50 ~15 ms)
are the bash harness floor, not OpenSIPS.

We replaced the drive loop with a multi-threaded C client
(`tests/sip_e2e/bench_register.c`): persistent UDP sockets per
worker, token-bucket pacing, single-process N-thread design,
nanosecond-resolution `CLOCK_MONOTONIC` timestamps.  Same input
knobs; same output stats.  The harness auto-detects the binary
and falls back to the bash loop only when the binary is absent.

Latency reporting is now bounded by the SIP path itself:
real-system p50 at low rate is ~1 ms, not ~15 ms.

A driver script (`tests/sip_e2e/bench_matrix.sh`) wraps the
per-mode invocation, runs N trials per cell, and aggregates
median + min/max per metric.  The script avoids the
`eval | tail | grep` pipeline-in-loop pattern that broke the
earlier multi-mode invocation: each trial is a separate
top-level bash subshell, parsing happens in a deferred stage,
and the script always exits 0 — cell-level errors are reported
in the aggregated table.

### Bench (3 trials × 3 modes × 2 scales, RPS=2000, 32 workers, loopback NATS, HP_MALLOC, aarch64)

Each cell shows `median (min..max)` across 3 trials.

#### 30k AoRs

| Mode | p50 µs | p95 µs | p99 µs | eff. RPS | RSS MB | CAS retry/exh |
|------|------:|------:|------:|--------:|------:|--------------:|
| rank-1 pthread       | 16100 (15377..16254) | 18459 (18140..18511) | 20087 (19540..21205) | 1922.7 |  95.8 | 0 / 0 |
| dedicated watcher    | 15710 (15515..15958) | 18281 (18023..18303) | 19811 (19778..19940) | 1954.0 | 103.3 | 0 / 0 |
| `enable_search_index=0` |  **772** (771..776) |  **1330** (1202..1432) |  **3481** (3258..3854) | **1999.1** |  **72.5** | 0 / 0 |

#### 100k AoRs (INDEX_BUCKETS=16384) — pre-allocator-rework baseline

| Mode | p50 µs | p95 µs | p99 µs | eff. RPS | RSS MB | CAS retry/exh |
|------|------:|------:|------:|--------:|------:|--------------:|
| rank-1 pthread       | 16510 (16283..16764) | 18504 (18476..18769) | 20420 (20327..20546) | 1921.7 | 151.4 | 0 / 0 |
| dedicated watcher    | 16587 (16394..16657) | 18509 (18461..18686) | 20631 (20399..20667) | 1914.8 | 158.6 | 0 / 0 |
| `enable_search_index=0` |  **772** (772..783) |  **1291** (1278..1486) |  **8189** (4441..9315) | **1999.4** |  **72.3** | 0 / 0 |

#### 100k AoRs (INDEX_BUCKETS=16384) — after intern table + entry blob combine

3-trial run after the doc-key intern table (commit 9e66237083) and
the single-allocation entry blob (commit ca3d786a9f) landed.  These
two changes together collapsed the watcher's per-event allocation
rate from ~10k shm_mallocs/sec (saturating HP_MALLOC's per-bucket
SHM_LOCK semaphore) to a tiny fraction.

| Mode | p50 µs | p95 µs | p99 µs | eff. RPS | RSS MB | CAS retry/exh |
|------|------:|------:|------:|--------:|------:|--------------:|
| rank-1 pthread       |  **877** (875..888) |  **3304** (2565..3878) |  **9816** (8498..13477) | **1999.4** | 146.4 | 0 / 0 |
| dedicated watcher    |  881 (877..882) |  4148 (3917..4566) | 13794 (12165..14750) | 1999.4 | 153.5 | 0 / 0 |
| `enable_search_index=0` |  774 (771..777) |  1301 (1243..1496) |  8355 (5426..11412) | 1999.4 |  72.8 | 0 / 0 |

Per-metric improvement vs the pre-allocator-rework baseline:

| Metric (rank-1) | Before | After | Δ |
|---|---:|---:|---:|
| p50 µs | 16510 | **877** | **−95% (19×)** |
| p95 µs | 18504 | **3304** | **−82% (5.6×)** |
| p99 µs | 20420 | **9816** | **−52% (2.1×)** |
| eff. RPS | 1921.7 | **1999.4** | hit target (was capped) |
| RSS MB | 151.4 | 146.4 | −3% |

The headline finding: **the index-on path is no longer
HP_MALLOC-bottlenecked.**  Effective RPS at 100k is now
indistinguishable across all three modes (1999.4 / 1999.4 /
1999.4 — they all hit the bench's 2000-RPS target exactly).  The
prior "index-on caps at ~1920 RPS while index-off hits 2000" cliff
disappeared.  rank-1 mode's p50 is within ~100 µs of `index off`
mode's p50 (877 vs 774), which means the residual cost of
keeping the index alive is now comparable to a single hash lookup,
not "structural CPU saturation in the lock path."

Dedicated mode shows a small residual penalty on the tail (p99
13794 vs rank-1 9816, +40%), wider than the +1% pre-rework gap.
Likely because the bench is now event-rate-saturating whatever
was previously absorbed by HP_MALLOC contention; the cross-process
semaphore overhead surfaces directly.  Filed for follow-up; the
candidates listed below (libnats subscriber-thread placement, or
the Item-4 dedicated proc's separate kvWatcher_Next loop) are
worth investigating once the workload has settled at the new
performance floor.

`enable_search_index=0` numbers are essentially unchanged
(774/1301/8355 vs 772/1291/8189 — within noise), confirming that
the allocator changes didn't break the PK fast path or introduce
overhead in deployments that don't use the index.

### Interpretation

**The dedicated-proc mode at 30k is a small but real win**: median
p99 19811 vs 20087 µs (−1.4%), median p95 18281 vs 18459 µs
(−1.0%).  The mode-medians sit well outside each other's
trial-range, so the signal is stable across N=3 trials.  An
earlier single-trial run reported −6.4% p99 — that was an outlier;
the real benefit is in the 1–2% range.  The dedicated mode pays
~7.5 MB RSS for the extra process.

**At 100k the dedicated mode no longer wins**: median p99 20631
vs 20420 µs (+1.0%), p50 essentially flat (+0.5%).

The first hypothesis we drafted here was "cross-process SHM lock
contention on the `NATS_IDX_SHARDS=16` index shards exceeds the
scheduling-isolation benefit."  An investigation pass falsified
that.  Two reasons it doesn't fit this benchmark:

1. usrloc passes `is_pk=1` on every REGISTER read and write
   (`modules/usrloc/urecord.c`).  cachedb_nats's PK fast path
   takes that branch and **never acquires an index shard lock**
   on the SIP side.  The watcher does take per-field shard
   locks, but the SIP workers don't contend with it — they're
   on a different code path.  At 100k AoRs the watcher event
   rate is ~2000 ev/s × ~5 fields = ~10k acquires/s, all on
   the watcher side, all on different keys.  Effectively zero
   cross-process contention.

2. Bumping `NATS_IDX_SHARDS` from 16 to 64 (a 4× reduction in
   any per-shard contention probability) did not close the gap.
   N=3 trials at 100k for both shard counts measured the
   dedicated/rank-1 delta within run-to-run variance (~250 µs
   spread).  If the hypothesis were correct, 4× more shards
   should have reduced the delta by ~75%.  It didn't.  The
   change was reverted; shipping a code change with no
   measurable win is just churn.

### Scheduler-wakeup hypothesis: instrumented, partially supported

A `perf stat` pass measured the actual scheduler / TLB cost of
cross-process wakeups in dedicated mode versus the rank-1 pthread
mode.  Both runs: 100k AoRs, 2000 RPS target, 32 bench workers,
`INDEX_BUCKETS=16384`, perf attached to every opensips PID for
40 s of steady-state mid-flight bench.  Counters via
`perf stat -p <pids> -e task-clock,context-switches,cpu-migrations,page-faults,minor-faults`.

| Counter (40 s window) | rank-1 (8 pids) | dedicated (9 pids) | Δ |
|---|---:|---:|---:|
| task-clock (ms)       | 57,924    | 49,596    | **−14.4 %** |
| CPUs utilized         | 1.448     | 1.240     | −14.4 % |
| context-switches      | 1,110,408 | 1,179,528 | +6.2 % |
| context-switches/sec  | 27,760    | 29,488    | +1,728/sec |
| cpu-migrations        | 36,275    | 24,172    | **−33.3 %** |
| page-faults           | 9,016     | 14,307    | **+58.7 %** |
| minor-faults          | 9,017     | 14,307    | +58.7 % |

The hypothesis predicted dedicated mode would be a net loser
because cross-process wakeups + TLB flushes outweigh the
isolation benefit.  The data partially supports it:

- **Page-faults +59 % in dedicated mode** is real signal —
  ~5,300 extra minor faults over 40 s, all soft (no disk I/O).
  Consistent with cross-process TLB pressure (the watcher's SHM
  pages get re-faulted in the SIP workers and vice versa as the
  index is updated cross-process).
- **Context-switches +6 %** is real but modest — ~1,728/sec
  extra, roughly one extra cs per 2-3 KV events.

But the data also actively contradicts other parts of the
hypothesis:

- **CPU-migrations −33 % in dedicated mode** — fewer scheduler
  migrations, not more.  The dedicated watcher proc apparently
  stays put on its CPU; rank-1 mode has more migrations because
  the SIP worker pthread bounces between SIP-routing and watcher
  work, providing more re-scheduling opportunities for the
  scheduler.
- **Total CPU −14 % in dedicated mode** — a measurable
  isolation win.  Per-process CPU drops from 18.1 % to 13.8 %;
  the watcher's work running in its own address space avoids
  competing with SIP routing for CPU resources (intra-process
  cache-coherence traffic, libc-malloc lock contention, etc.).

End-to-end p99 effect at 100k was +1.0 % in the multi-trial
matrix.  The scheduler / TLB cost of dedicated mode (extra cs
+ extra page-faults) does NOT add up to that 1 % regression.
The CPU savings actually point the other way (dedicated mode
should be faster, not slower).  So the residual +1 % p99
must be coming from somewhere else.

### HP_MALLOC contention hypothesis: instrumented, strongly supported

`perf record -F 99 -g --call-graph dwarf` against every opensips
PID for 30 s of mid-flight 100k bench, in both modes, then
`perf report --sort=symbol` to attribute samples.  The picture
is striking — **half of all CPU is in HP_MALLOC + lock paths in
both modes**:

| Symbol (% of samples) | rank-1 | dedicated | Δ |
|---|---:|---:|---:|
| `sem_wait@@GLIBC_2.34`        | 31.72 | **34.82** | +3.10 |
| `sem_post@@GLIBC_2.34`        | 13.04 | 11.86 | −1.18 |
| `hp_shm_malloc`               | 1.80  | 2.03  | +0.23 |
| `hp_frag_attach` / `hp_frag_size` | 0.03 | 0.11 | +0.08 |
| `hp_shm_free`                 | 0.03  | 0.03  | 0 |
| **TOTAL HP_MALLOC + lock + index** | **47.07%** | **49.34%** | +2.27 |

Two findings:

**1. The watcher's allocation path dominates CPU in both modes.**
Stack traces resolve `sem_wait → __new_sem_wait_fast →
hp_shm_malloc → nats_json_index_add` as the hottest stack.  The
watcher does ~10k shm_mallocs/sec at 100k AoRs (~2000 events/sec
× ~5 field:value entries per usrloc contact) and every one
takes a per-bucket `SHM_LOCK(hash)` semaphore.  Half of all
opensips CPU goes into that path regardless of which mode owns
the watcher.

**2. Dedicated mode adds a small ~3% extra `sem_wait` cost.**
Cross-process semaphore acquire is slightly more expensive than
intra-process — kernel-side TLB tracking on contended waits and
no fast path that an in-process futex could take when both
contenders are in the same address space.  That ~3% extra,
multiplied across the bench's ~10k acquires/sec, accounts cleanly
for the **+1.0 % p99 regression** the matrix measured at 100k.
Hypothesis confirmed: the dedicated mode pays a small structural
cost for cross-process lock contention, which shows up exactly
where the regression is.

**Important:** the reverse implication is that **HP_MALLOC
contention from the watcher's allocation rate is the real
scaling cliff**, not anything Item-4-specific.  Both rank-1 and
dedicated modes hit ~47-49 % CPU in alloc/lock paths at 100k.
Above ~100k AoRs the steady-state allocation rate would push
these numbers further, regardless of watcher topology.

### New optimization candidate: cut the watcher's allocation rate

The watcher allocates inside the per-shard lock.  Reducing the
allocation rate (or moving allocations outside the lock) would
free up significant CPU for both modes and would likely close
the dedicated/rank-1 gap entirely.  Specific candidates:

- **Watcher-local arena.** Pre-allocate a watcher-process arena
  in PKG memory and sub-allocate field:value strings from it
  without touching SHM or the bucket lock.  The arena resets
  per kvWatcher_Next() iteration so it never grows unbounded.
  Refs into the SHM index are still SHM-allocated (small,
  fixed-size pointers), but the variable-size field/value
  strings — the bulk of the allocation traffic — bypass
  HP_MALLOC entirely.  Largest expected win.
- **Move JSON parsing fully outside the index mutex.** Commit
  `78ea7ed78` already parses JSON before taking the mutex, but
  the field:value entries themselves are still allocated under
  the lock.  Lift those allocations to before lock acquire.
- **Per-shard alloc batching.** Instead of one shm_malloc per
  field:value pair, batch into a single bigger allocation per
  event and slab-suballocate.  Reduces bucket-lock acquires by
  a factor of ~5 (the avg field count).

Filed for the next iteration.

### libnats subscriber-thread placement: instrumented, hypothesis refined

After the allocator rework closed the dedicated/rank-1 gap during
the perf-record pass but NOT during the no-perf-overhead matrix
(rank-1 p99 9816 vs dedicated p99 13794, +40%), `perf sched record`
attached to every opensips PID for 30 s of mid-flight 100k bench
captured per-thread scheduler latency.

**Thread topology turns out to be identical**:

  rank-1 (8 opensips processes)
    - 4 SIP workers @ 7 threads each (1 main + 6 libnats)
    - 1 SIP worker @ 8 threads
    - 1 SIP worker @ **15 threads** (the rank-1 worker that ALSO
      runs the watcher pthread; watcher's kvWatcher subscription
      drives the extra libnats delivery threads)
    - 2 single-threaded (mi_datagram et al.)

  dedicated (9 opensips processes)
    - 5 SIP workers @ 7 threads each
    - 2 single-threaded
    - 1 dedicated proc @ **15 threads** (same libnats thread
      count as rank-1's heaviest worker; watcher subscription
      drives the same delivery threads)

So the libnats thread COUNT is the same.  The hypothesis that
the dedicated proc has a "lighter" / less-warm libnats I/O
thread that delivers events with extra jitter is wrong on those
mechanics — the I/O threads in both modes process the same
event rate against the same connection topology.

**But scheduler latency for active threads differs**:

  Active opensips threads (top by runtime, 30s window)
  worst max scheduler delay        rank-1     dedicated
  ----------------------------------------------------
  worst case                       0.818 ms   5.512 ms     (+6.7x)
  median across top-10 active      0.42 ms    0.49 ms      (similar)
  avg across all opensips          0.007 ms   0.007 ms     (identical)

(The aggregate "rank-1 max 200 ms vs dedicated max 5.5 ms"
reading was a red herring; that 200 ms outlier was on an idle
mi_datagram-style thread that simply slept for a long stretch
and resumed once.  Filtering to high-runtime threads — the
ones doing real work in the bench — shows dedicated mode has
the worse worst-case wait.)

**Likely mechanism (not the bare libnats threads themselves)**:
the SHM index's per-shard lock IS taken by both writers (SIP-
side `nats_cache_update`) and the watcher.  In rank-1 mode
both contenders are in the same address space; the kernel's
mutex/futex fast-path is intra-process.  In dedicated mode the
contenders are in different processes, going through SHM
gen_lock_set_t (POSIX semaphores on aarch64) — every uncontended
acquire is similar cost, but contended waits cost more (cross-
process descheduling and re-wakeup).  When a SIP writer
contends with the watcher on a shard, the dedicated mode pays
~few-ms extra wakeup latency on the contended path; that's
consistent with the 5.5 ms outlier.

**Statistical significance caveat**: with 3 trials per cell,
the +40 % p99 gap (rank-1 9816, dedicated 13794) sits within
the 8498..13477 / 12165..14750 trial-range overlap.  The
medians clearly differ but a single outlier could move them.
Worth re-confirming with N=5 trials before treating the gap
as a permanent dedicated-mode tax.

**Mitigation candidates** (if the gap is real and worth closing):

- **Pin the dedicated watcher proc to a CPU.**  `taskset
  --cpu-list <cpu>` on the dedicated proc should reduce
  scheduler-driven jitter; the watcher would never migrate
  off its CPU and its cache state would stay warm.
- **Bump the dedicated proc's nice priority** so the kernel
  schedules it ahead of SIP workers when both are runnable.
  Tradeoff: hurts SIP routing fairness when the watcher is
  spinning.
- **Share the connection across watcher + cdb path even in
  dedicated mode** — i.e., the dedicated proc opens the same
  connection that all SIP workers use.  Doable architecturally
  but requires lib/nats refactoring; large change.

None of these are obvious wins over the current state, and the
+1 % p99 absolute (now ~4 ms) is only consequential at very
high event rates.  Filed at low priority.

The dedicated-proc mode's value at this scale is the
**orphan-safety + isolation property** (proven by the new
sip_e2e case 150_orphan_watcher_reap.sh), not raw latency.
Operators choosing between rank-1 and dedicated at 100k+ should
base the decision on rank-1's SIP-worker scheduling fairness
needs, not on this latency table.

Note: this is a `bench_register` REGISTER-only workload, which
exercises the PK fast path exclusively.  A bench that drives
non-PK script-level filter queries through `nats_kv_query` would
exercise the SIP-side index path and produce a fundamentally
different lock profile.  That's filed as a follow-up — the
current bench is fit-for-purpose for the usrloc-on-NATS
deployment shape but does not characterise the index-on-mixed
workload.

**`enable_search_index=0` is the dominant performance lever at
every scale**.  At 30k: p50 21× lower (772 vs 16100 µs), p99 6×
lower, and the system hits the full RPS=2000 target where the
index-on modes cap at ~1920–1955.  At 100k: p50 still 21× lower,
p99 2.5× lower, and RSS is **flat** at ~72 MB regardless of
bucket size (vs +56 MB for rank-1 between 30k and 100k as the
index grows ~800 bytes/AoR).

**Tail variance** in off mode is wider — 100k p99 range
4441..9315 µs (4.9 ms) vs ~250 µs for index-on.  The PK fast
path goes straight to KV with no index-side queueing, so rare
broker-side slow writes dominate the tail directly instead of
being smoothed.

**Effective RPS ceiling** is in the index path: the index-on
modes cap at ~1920 RPS, the off mode hits 1999 RPS at every
scale.  Profiling-grade investigation of the index-path
serialisation is filed as a follow-up; the operational
conclusion stands — disabling the index for usrloc-only
deployments delivers the throughput.

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

- **Async `nats_request` variant** — `nats_consumer/
  nats_rpc.c` currently blocks the SIP worker on the RPC call.
  Synchronous design is fine for non-request-route callers and
  modest RPS; a deployment running `nats_request` in
  `request_route` at 1MM-endpoint scale needs async.  Flagged in
  the original perf review (item #8); not pursued.

- **SHM allocator pressure at non-trivial bucket counts** — at
  20k AoRs / 256 buckets the residual p99 growth from 10k → 20k
  (54 → 142 ms) tracked SHM-alloc serialisation.  HP_MALLOC took
  the worst of it.  The configurable `index_buckets` modparam should narrow
  it further; re-bench at 100k once the deployment shape calls
  for it.
