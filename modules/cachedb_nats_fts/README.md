# cachedb_nats_fts

Optional full-text-search / secondary-index module for `cachedb_nats`
(the P1.2 split).  **Loading this module is the enable switch** — it
replaces the former `enable_search_index` modparam.

When loaded, `cachedb_nats` binds it at startup and:

- feeds the SHM-backed `field:value -> doc keys` hash index from its
  write path and KV-watcher process;
- routes non-PK `cache_query()` / `update()` filters through the index
  (including `"search:term"` raw queries);
- rebuilds the index on reconnect / periodic resync (knobs stay on
  `cachedb_nats`, which owns the watcher and timers).

Without this module `cachedb_nats` is PK-only — the flagship
usrloc-over-NATS deployment never needs it and saves the index SHM,
the watcher-feed CPU and the per-write lock traffic.

## Parameters

| Name | Type | Default | Purpose |
|---|---|---|---|
| `index_buckets` | int | 4096 | Hash bucket count for the SHM index (rounded to a multiple of 16 shards). |
| `fts_max_results` | int | 100 | Cap on keys returned to a single non-PK query. |

## Example

```
loadmodule "cachedb_nats.so"
loadmodule "cachedb_nats_fts.so"
modparam("cachedb_nats_fts", "index_buckets", 8192)
```

> Load order: `cachedb_nats_fts` must be loaded **after** `cachedb_nats`
> (it links the JSON walkers cachedb_nats exports).
