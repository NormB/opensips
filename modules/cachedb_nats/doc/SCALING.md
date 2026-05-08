# cachedb_nats scaling notes — 1MM and 10MM endpoints

This file extends `PERF_NOTES.md` with sizing analysis and
architectural recommendations for usrloc-on-NATS deployments well
beyond what the bench harness exercises.

The bench data informing this doc was at 20k AoRs / single
instance / `udp_workers=2`.  At that scale, the cachedb_nats
hot path is broker-RTT-bound (~15-16 ms per CAS) and SHM
allocator pressure dominates the residual tail.  As we scale by
50× to 1MM and 500× to 10MM endpoints, **different bottlenecks
take over** and the right answer is structural, not parametric.

## Quick reference

| Scale | Per-instance memory | Bucket count | Watcher | Architecture |
|-------|--------------------:|-------------:|---------|--------------|
| ≤ 20k AoRs | ~10 MB | 4 096 | rank-1 | single instance, current code |
| 100k AoRs | ~30 MB | 16 384 | rank-1 | single instance, current code |
| 1 MM AoRs | ~250 MB | 65 536 | dedicated proc | shard recommended (10 instances × 100k) |
| 10 MM AoRs | ~2.5 GB | n/a | n/a | **drop the index entirely**; PK-direct lookups; or shard heavily |

## What's in the index, exactly

usrloc in `cluster_mode = full-sharing-cachedb` writes one JSON
document per AoR via `cdb_flush_urecord` (modules/usrloc/urecord.c).
The seed document built on first-insert contains a single
top-level string field — the filter identity, typically the AoR
itself.  All other fields are either non-strings (`aorhash` is
`CDB_INT32`) or nested objects (`contacts` is a `CDB_DICT` whose
top-level value is `{...}`, which the indexer skips).

So the JSON-FTS index holds **one entry per AoR doc**, not three:

| AoRs | Index entries (typical) |
|-----:|------------------------:|
|   1k |                    ~1 k |
|  20k |                   ~20 k |
| 100k |                  ~100 k |
|  1 M |                   ~1 M  |
| 10 M |                  ~10 M  |

The keys[] array per entry has length 1 in the steady state — each
AoR's filter identity is unique to that AoR.  No popular
"field:value" combos pile up as they would on a more general
filterable workload.

## Memory math

Per-entry footprint:

| Component | Bytes |
|---|---:|
| `nats_idx_entry` struct | 64 |
| `field_value` string ("aor:alice@host" + nul) | ~30-50 |
| `keys[]` array (initial 8 ptrs × 8 bytes) | 64 |
| Doc-key strdup ("json_alice=40host") | ~30-50 |
| SHM allocator overhead per allocation | ~16 |
| **Total per entry** | **~250** |

Plus the bucket array itself: `NATS_IDX_BUCKETS × sizeof(ptr)`.

| Scale | Entries | Bucket bytes (4096 buckets) | Entry bytes | **Total SHM** |
|------:|--------:|----------------------------:|------------:|--------------:|
|   1 k |   1 000 |                       32 KB |       250 KB|       ~280 KB |
|  20 k |  20 000 |                       32 KB |       5.0 MB|        ~5 MB  |
| 100 k | 100 000 |                       32 KB |       25 MB |       ~25 MB  |
|   1 M | 1 000 000|                      32 KB |       250 MB|      **~250 MB** |
|  10 M |10 000 000|                      32 KB |       2.5 GB|      **~2.5 GB** |

OpenSIPS ships with a default SHM size of 64 MB.  Operators
commonly raise it via `-m 256` or `-m 512` for non-trivial
deployments.

- **At 1MM**: feasible on a single beefy instance with `-m 1024`.
  ~250 MB SHM for the index is real but tractable.
- **At 10MM**: a 2.5 GB SHM block per instance is past what most
  OpenSIPS deployments are sized for.  Multiple instances of the
  same magnitude × replication factor is cluster-grade memory
  budget.  At this scale, **don't keep all of it in RAM per
  instance**.

## Bucket count sizing

Already bumped to **4 096** in this branch (was 256).  The hash
distributes via djb2 + bitmask; powers of two keep `% buckets`
compiled to AND.  Each doubling halves average chain length for
~32 KB more SHM.

| Scale | Recommended `NATS_IDX_BUCKETS` | Avg chain | Bucket SHM |
|------:|-------------------------------:|----------:|-----------:|
|   1 k |                          4 096 |       0.2 |       32 KB|
|  20 k |                          4 096 |         5 |       32 KB|
| 100 k |                         16 384 |         6 |      128 KB|
|   1 M |                         65 536 |        15 |      512 KB|
|  10 M | n/a — drop the index (see below) |          |             |

Today this is a `#define` requiring rebuild.  At 100k+ scale
operators need to be able to tune without recompiling — promote
`NATS_IDX_BUCKETS` to a modparam (`index_buckets`, default 4 096,
power-of-two-rounded at init).  Implementation: ~30 lines, change
`buckets[NATS_IDX_BUCKETS]` to a runtime-allocated pointer.  Filed
as a follow-up.

## Watcher CPU at scale

The KV watcher (rank-1 only today) processes one event per
KV-change.  With re-REGISTER every 60 s, the steady-state event
rate is `AoRs / 60`:

| Scale | Steady event rate | Per-event cost | Watcher CPU |
|------:|-----------------:|---------------:|------------:|
|   1 k |    17 events/s | ~100 µs | ~0.2 % |
|  20 k |   333 events/s | ~100 µs | ~3 %   |
| 100 k | 1 667 events/s | ~100 µs | ~17 %  |
|   1 M |16 667 events/s | ~100 µs | **>100 % — single watcher saturates** |
|  10 M |166 667 events/s| ~100 µs | unreachable on any single watcher |

Per-event cost ≈ JSON parse + `index_remove_fields` (targeted)
+ `index_add` (parse again, see Tier-1 #3 deferred fix).
Optimistic 100 µs at moderate load; can grow to 200 µs as the
index size pushes cache pressure.

- **At 100k**: single rank-1 watcher uses ~17 % of one core.
  Fine, but rank-1 is also a SIP worker; if its REGISTER
  workload competes for CPU with the watcher, propagation
  latency stretches.  This is where the dedicated-watcher
  process (Option B from the previous discussion) earns its
  keep — isolate the watcher from SIP-worker scheduling.
- **At 1MM**: a single watcher can't keep up.  Period.  Even
  Option B doesn't help because the bottleneck is per-event
  CPU, not scheduling jitter.  Need parallelism.
- **At 10MM**: hopeless under the current architecture.

## Architectural recommendations

### Up to 100k AoRs

- Bucket count: bump `NATS_IDX_BUCKETS` to 16 384 (4× current).
  Either patch the `#define` or wait for the modparam follow-up.
- SHM size: `-m 256`.
- Allocator: `-s HP` (already in the playbook).
- Watcher: rank-1 only is fine; consider Option B (dedicated
  process) if rank-1's SIP load is heavy.
- Index resync: `index_resync_on_reconnect=0` (default since
  this branch).
- Single instance is OK.

### 100k – 1MM AoRs

- Bucket count: 65 536 (16× current).
- SHM size: `-m 1024` or higher.
- **Sharded deployment**: split AoRs across multiple OpenSIPS
  instances by AoR-prefix or hash.  10 instances × 100k AoRs
  apiece keeps each instance in the comfortable single-instance
  regime.  Add a SIP-layer load balancer (eg. `dispatcher` or
  `permissions` modules) routing REGISTERs to the right shard.
- **Watcher**: dedicated process per instance (Option B from
  the prior write-up).  At 100k AoRs per shard, ~17 % CPU is
  fine for an isolated process; rank-1 stays focused on SIP
  routing.
- Each instance has its own NATS bucket, OR one shared bucket
  with each instance subscribing only to its prefix slice.

### 10MM AoRs — drop the index, go PK-direct

The architecture changes substantively:

1. **Don't index everything**.  The JSON-FTS index exists to
   accelerate non-PK filter queries (script-driven `nats_kv_query`
   etc.).  usrloc's hot path is **PK-only** — both reads
   (`cdb_load_urecord` at `udomain.c:937`) and writes
   (`cdb_flush_urecord` at `urecord.c:600`) construct
   `cdb_filter_t` with `is_pk = 1`.

   Today, `nats_cache_query` walks the index regardless of
   `is_pk`.  Adding a PK fast path that skips the index entirely
   for `is_pk=1` filters lets reads bypass the bucket walk and go
   straight to `kvStore_Get(prefix + encode(filter_value))`.
   The KV store handles the lookup in O(1) broker-side.

   **Filed as a follow-up commit**: PK fast path in
   `nats_cache_query`.  Mirror the existing PK branch in
   `nats_cache_update`.

2. **Make the in-memory index optional**.  Add a modparam
   `enable_search_index` (default 1 for backwards compat).  When
   set to 0, skip `nats_json_index_init`, skip the watcher, and
   route every query through the PK fast path.  Non-PK queries
   from script error out with a clear message.  For
   usrloc-only deployments this saves the entire 2.5 GB index
   memory footprint and the watcher's >100 % CPU.

3. **Shard regardless**.  At 10MM total endpoints, even with
   the index disabled, a single OpenSIPS instance holding the
   AoR routing for all of them is impractical for SIP-side
   reasons (UDP port queues, transaction tables, etc.).
   Sharding remains required.

4. **NATS topology**.  A single 10MM-key bucket holds ~5 GB of
   data on each broker replica.  JetStream replication carries
   every write to every replica.  At ~167k writes/sec steady
   state across a 3-replica cluster, that's ~500k×size cross-
   broker writes/sec.  Real concerns:
   - Stream replication bandwidth.
   - Disk write throughput (JetStream writes to disk).
   - Compaction / snapshot cost.

   **Bucket-per-shard** topology aligns with the OpenSIPS
   instance shards and keeps individual streams sized for the
   broker's comfort zone.  Cross-shard reads become a routing
   layer concern, not a NATS-side replication concern.

### 100MM and beyond

NATS-KV is not the right primary store at this scale.  Consider
distributed KV stores designed for it (FoundationDB, Cassandra
with appropriate keyspace, distributed Redis cluster).
cachedb_nats can stay in the picture as a fast-path cache or
event bus, but the authoritative usrloc storage should move to
something replicated and sharded by design.

## Re-examining option 2 (watcher) and option 3 (async RPC) at scale

### Watcher trade-off — revised

- **≤ 100k**: Option A (rank-1 only) is fine.
- **100k – 1MM**: Option B (dedicated watcher process) becomes
  the right choice — it isolates the watcher from SIP-worker
  scheduling and the index it maintains is still tractable.
- **1MM+**: parallel watchers become necessary, but **only if
  the index is still maintained**.  The architectural answer
  at this scale is to drop the index for usrloc (recommendation
  above), at which point the watcher becomes a no-op too.
  Option C (one watcher per worker) was always wrong for this
  shape; it just multiplies broker delivery cost without solving
  the per-event-cost problem.

### Async RPC — revised

- **At any scale where `nats_request` is in `request_route`**
  and the request rate is non-trivial, async is mandatory.  The
  blocking variant turns one SIP worker into one in-flight
  request × `udp_workers` total concurrency.  At 1MM endpoints
  with 16 667 REGs/sec and even 1 ms RPC latency, that's 17
  workers fully blocked steady-state — and 833 at 50 ms cross-DC
  RPC.
- **At 10MM**: 167 µs RPC budget per worker even at 1000 workers.
  Synchronous RPC isn't physically possible.

For deployments not using `nats_request` from request_route, the
blocking design is fine at any scale.  The investment to add
async RPC is worth making before committing to a deployment
that depends on it in the registration path.

## Concrete next steps from this analysis

1. **PK fast path in `nats_cache_query`** — biggest immediate
   win for usrloc workloads of any size, and unblocks the
   "drop the index" architecture at 10MM scale.  ~50 lines.
2. **`index_buckets` modparam** — replace the `#define` with a
   runtime-tunable bucket count, default 4 096, init-time
   power-of-two-rounded.  ~30 lines.
3. **`enable_search_index` modparam** — default 1 for backwards
   compat; when 0 skips index init, watcher, and routes all
   queries through the PK fast path.  ~50 lines.
4. **Dedicated watcher process** (Option B) — only meaningful
   above ~100k AoRs.  ~150 lines.
5. **Async `nats_request`** — only meaningful for
   request-route-blocking deployments at non-trivial RPS.
   ~300-500 lines.

In rough priority for the next session: **(1) → (2) → (3) →
benchmark at 100k → (4) if needed → (5) when the deployment
shape calls for it**.
