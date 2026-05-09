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

The four modparams introduced by the scale-tuning group of this
branch (`index_buckets`, `enable_search_index`, `nats_cas_retries`,
`dedicated_watcher_proc`) are the levers operators reach for
first.  Their relationship to the AoR-count thresholds below is
the central thread of this document.

## Quick reference

For pure usrloc-as-store deployments, the simplest answer at every
scale is **`enable_search_index=0`**.  The PK fast path handles
every read; `nats_cache_update`'s PK branch handles every write;
no watcher runs; no SHM index is allocated.  The table below is
relevant only when the index is left on (e.g. mixed deployments
that also run script-driven non-PK queries).

| Scale | `enable_search_index=0` (recommended) | `enable_search_index=1` (mixed workloads) |
|-------|-----------------------------------------|---------------------------------------------|
| ≤ 20k AoRs | single instance, ~0 MB index, no watcher | `index_buckets=4096`, ~10 MB index, rank-1 watcher (`dedicated_watcher_proc=0`) |
| 100k AoRs | single instance, ~0 MB index, no watcher | `index_buckets=16384`, ~30 MB index, `dedicated_watcher_proc=1` (~17 % CPU) |
| 1 MM AoRs | single beefy instance OR shard for SIP-side reasons; no watcher | `index_buckets=65536`, ~250 MB index, `dedicated_watcher_proc=1` required |
| 10 MM AoRs | shard for SIP-side reasons; no index ever; PK-direct only | **not viable** — index would be ~2.5 GB and watcher unreachable |

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

(Only relevant when `enable_search_index=1`.  PK-only deployments
should set `enable_search_index=0` and skip the index entirely.)

Default is **4 096** (was 256 before this branch).  Tunable at
runtime via `modparam("cachedb_nats", "index_buckets", N)`; the
init code rounds N up to the next power of two with a floor of
`NATS_IDX_SHARDS = 16`.  The hash distributes via djb2 + bitmask;
powers of two keep `% buckets` compiled to AND.  Each doubling
halves average chain length for ~32 KB more SHM.

| Scale | Recommended `index_buckets` | Avg chain | Bucket SHM |
|------:|----------------------------:|----------:|-----------:|
|   1 k |                       4 096 |       0.2 |       32 KB|
|  20 k |                       4 096 |         5 |       32 KB|
| 100 k |                      16 384 |         6 |      128 KB|
|   1 M |                      65 536 |        15 |      512 KB|
|  10 M | n/a — `enable_search_index=0` (see below) |          |             |

## Watcher CPU at scale

The KV watcher processes one event per KV-change.  By default it
runs as a pthread inside the rank-1 SIP worker; setting
`dedicated_watcher_proc=1` moves it into its own forked
OpenSIPS child process so it stops competing with SIP request
handling on rank 1.  With re-REGISTER every 60 s, the steady-
state event rate is `AoRs / 60`:

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
  latency stretches.  Set `dedicated_watcher_proc=1`
  to fork a dedicated OpenSIPS child process that owns the
  watcher loop and lets rank 1 stay focused on SIP routing.
- **At 1MM**: a single watcher can't keep up.  Period.  Even
  the dedicated-process flavour doesn't help because the
  bottleneck is per-event CPU, not scheduling jitter.  Need
  parallelism — and at this scale the architectural answer is
  to drop the index for usrloc (`enable_search_index=0`),
  which makes the watcher a no-op.
- **At 10MM**: hopeless under the current architecture.

## Architectural recommendations

### Up to 100k AoRs

- For pure usrloc: `enable_search_index=0` and stop reading.
  No index, no watcher, no per-write index update.  All reads
  go through the PK fast path.
- For mixed workloads (script-driven non-PK queries also in
  play): leave `enable_search_index=1`, set `index_buckets`
  to 16384 (4× the default 4096).
- SHM size: `-m 256`.
- Allocator: `-s HP_MALLOC` (always; see playbook).
- Watcher (only relevant if index enabled): rank-1 only is
  fine.  Set `dedicated_watcher_proc=1` if rank-1's SIP load
  is heavy and the propagation-latency floor matters.
- Index resync: `index_resync_on_reconnect=0` (default since
  this branch).
- Single instance is OK.

### 100k – 1MM AoRs

- For pure usrloc: `enable_search_index=0`.  Single beefy
  instance is viable up to ~1MM endpoints from the cachedb_nats
  side; the SHM cost of running with the index on (~250 MB at
  1MM) is what makes "off" the obvious answer here.
- For mixed workloads with the index on: `index_buckets=65536`
  and `-m 1024`.  Set `dedicated_watcher_proc=1` to
  keep the rank-1 worker focused on SIP routing.
- **Sharded deployment** is recommended above ~500k AoRs even
  with the index off, but for SIP-side reasons (UDP port
  queues, transaction tables, REGISTER fan-out): split AoRs
  across multiple OpenSIPS instances by AoR-prefix or hash.
  10 instances × 100k AoRs each keeps every instance in the
  comfortable single-instance regime.  Add a SIP-layer load
  balancer (eg. `dispatcher` or `permissions`) routing
  REGISTERs to the right shard.
- Each instance has its own NATS bucket, OR one shared bucket
  with each instance subscribing only to its prefix slice.

### 10MM AoRs — index off, shard hard

The architecture changes substantively:

1. **The index is off**.  `enable_search_index=0` is mandatory
   here.  The JSON-FTS index exists to accelerate non-PK filter
   queries (script-driven `nats_kv_query` etc.).  usrloc's hot
   path is **PK-only** — both reads (`cdb_load_urecord` and `cdb_flush_urecord` in `modules/usrloc/`) construct `cdb_filter_t` with `is_pk = 1`.
   The PK fast path in `nats_cache_query` (introduced in this
   branch) handles those reads in O(1) broker-side via
   `kvStore_Get(prefix + encode(filter_value))`, bypassing the
   bucket walk entirely.  At 10MM scale, the index would cost
   ~2.5 GB of SHM and a watcher rate of ~167k events/sec that
   no single thread can keep up with.

2. **Shard regardless**.  At 10MM total endpoints, even with
   the index disabled, a single OpenSIPS instance holding the
   AoR routing for all of them is impractical for SIP-side
   reasons (UDP port queues, transaction tables, etc.).
   Sharding remains required.

3. **NATS topology**.  A single 10MM-key bucket holds ~5 GB of
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

## Status of the action items in this analysis

1. **PK fast path in `nats_cache_query`** — **landed**.  Single-
   condition is_pk=1 short-circuit at the top of
   `nats_cache_query`; falls through to the index path for
   non-PK or multi-condition filters.  Mirrors the long-existing
   PK branch in `nats_cache_update`.
2. **`index_buckets` modparam** — **landed**.  Default 4 096,
   init-time power-of-two-rounded with a floor of 16
   (`NATS_IDX_SHARDS`).  The buckets array is now SHM-allocated
   dynamically; `_hash` uses a bitmask AND on
   `nats_idx_bucket_mask`.
3. **`enable_search_index` modparam** — **landed**.  Default 1
   for backwards compatibility.  When 0 skips
   `nats_json_index_init`, the index build, and the watcher;
   non-PK filters in query/update are rejected with an explicit
   error message rather than crashing on a NULL `g_idx`.  For
   pure usrloc deployments this is the canonical setting.
4. **Dedicated watcher process** — **landed; default off** (legacy rank-1 pthread). Set `dedicated_watcher_proc=1` to opt in. See PERF_NOTES.md §"Dedicated KV-watcher process" for the design and a 30k/100k three-mode bench table.
   With `enable_search_index=0` making the watcher optional, this is now only
   meaningful for mixed-workload deployments that keep the
   index on at ≥ 100k AoRs.  ~150 lines.
5. **Async `nats_request`** — **pending**.  Only meaningful
   for request-route-blocking deployments at non-trivial RPS.
   ~300-500 lines.

The PK fast path, configurable index_buckets, and optional index turn cachedb_nats from "works to about 100k AoRs with
care" into "1MM is a single modparam flip from a working 100k
config".  Items 4-5 are deployment-shape dependent.
