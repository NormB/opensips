# cachedb_nats — OpenSIPS CacheDB Engine backed by NATS KV

A cachedb engine module that stores key-value data in [NATS JetStream KV](https://docs.nats.io/nats-concepts/jetstream/key-value-store),
with an in-process JSON full-text search index and live KV change watching.

- **Language:** C
- **NATS client:** [nats.c](https://github.com/nats-io/nats.c) v3.13+
- **Target:** OpenSIPS 4.0+

## Dependencies

- `nats_connection.so` — must be loaded first (provides the shared connection pool)

## Features

- Standard cachedb operations: get, set, remove, add (atomic increment), sub, get_counter
- Atomic counter operations using CAS (compare-and-swap) with configurable retry
- JSON document storage with in-process full-text search index
- Live index updates via KV watcher thread (no polling)
- `nats_request()` — synchronous NATS request/reply (RPC pattern)
- `nats_kv_history()` — retrieve key version history as JSON array
- Raw query commands: `KV KEYS`, `KV PURGE <key>`, `KV BUCKET INFO`
- Map operations: get/set/remove with composite `key:subkey` addressing

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `cachedb_url` | string (func) | -- | OpenSIPS cachedb URL (e.g., `nats://127.0.0.1:4222/`) |
| `nats_url` | string | `nats://127.0.0.1:4222` | NATS server seed list. Use DNS hostnames for cluster resilience. |
| `kv_bucket` | string | `opensips` | JetStream KV bucket name |
| `kv_replicas` | int | 3 | Replication factor (only used when creating a new bucket) |
| `kv_history` | int | 5 | Version history depth per key |
| `kv_ttl` | int | 0 | Bucket-level TTL in seconds (0 = no expiry). Per-key TTL is not supported by NATS KV. |
| `fts_json_prefix` | string | `json:` | Key prefix for JSON documents included in the search index |
| `fts_max_results` | int | 100 | Maximum results returned by `cache_query` |
| `kv_watch` | string | NULL | Key pattern to watch (e.g., `usrloc.>` for wildcard). NULL = watch all keys. |
| `tls_*`, `reconnect_*`, `max_reconnect` | -- | -- | Same TLS and reconnect params as event_nats |

## Script Functions

### `nats_request(subject, payload, timeout_ms, result_pvar)`

Synchronous NATS request/reply. Sends `payload` to `subject`, waits up to `timeout_ms`
for a reply, stores it in `result_pvar`.

Returns: 1 (success), -1 (error), -2 (timeout)

```
nats_request("auth.check", "$var(json)", 2000, $var(reply));
if ($retcode == 1) {
    xlog("reply: $var(reply)\n");
}
```

### `nats_kv_history(key, result_pvar)`

Retrieve version history of a KV key as a JSON array.

Returns: 1 (success), -1 (error), -2 (not found)

```
nats_kv_history("usrloc.alice", $var(history));
# $var(history) = [{"rev":1,"value":"..."},{"rev":2,"value":"..."}]
```

## CacheDB Operations

```
# Standard KV operations
cache_store("nats", "call:$ci", "$fu|$tu");
cache_fetch("nats", "call:$ci", $var(val));
cache_remove("nats", "call:$ci");

# Atomic counters (CAS-based, 3 retries)
cache_add("nats", "counter:calls", 1, 0);
cache_counter_fetch("nats", "counter:calls", $var(count));

# JSON document storage (indexed if key starts with fts_json_prefix)
cache_store("nats", "json:user:alice", "{\"name\":\"alice\",\"domain\":\"example.com\"}");
```

## JSON Search Index

Keys starting with `fts_json_prefix` (default: `json:`) are automatically parsed and
indexed. The index supports equality queries via `cache_query`:

```
# Find all documents where domain=example.com
cache_query("nats", "domain", "example.com", $var(results));
```

The index is:
- Built at startup from existing KV data
- Updated in real-time by the KV watcher thread
- Rebuilt automatically on NATS reconnection
- Thread-safe (pthread mutex protects the index; heap `malloc`/`free` used instead of
  `pkg_malloc` because the watcher pthread and SIP worker share the same process and
  `pkg_malloc` is not thread-safe)

## KV Watcher

Each worker process spawns a pthread that watches the KV bucket for changes. On each
put/delete/purge event, the watcher:
1. Updates the in-process search index
2. Raises an `E_NATS_KV_CHANGE` EVI event (if compiled with `HAVE_EVI`)

On reconnection, the watcher stops, the index is rebuilt from a full KV scan, and the
watcher restarts.

## Cluster Configuration

```
loadmodule "nats_connection.so"
loadmodule "cachedb_nats.so"

modparam("cachedb_nats", "cachedb_url", "nats://localhost:4222/")
modparam("cachedb_nats", "nats_url", "nats://nats-1:4222,nats://nats-2:4222,nats://nats-3:4222")
modparam("cachedb_nats", "kv_bucket", "opensips")
modparam("cachedb_nats", "kv_replicas", 3)
```

The `nats_url` is a seed list — see the `nats_connection` README for cluster topology
and resilience details. Use DNS hostnames for automatic discovery of topology changes.

The `kv_replicas` setting only takes effect when the bucket is first created. To change
replication on an existing bucket, use the NATS CLI: `nats kv update <bucket> --replicas=N`.

## Raw Query Commands

```
cache_raw_query("nats", "KV KEYS", $var(keys));
cache_raw_query("nats", "KV PURGE mykey");
cache_raw_query("nats", "KV BUCKET INFO", $var(info));
```

## MI Commands

| Command | Description |
|---------|-------------|
| `nats_kv_status` | Bucket name, replicas, history, TTL, connection state |

## License

GPL-2.0 (matching OpenSIPS)
