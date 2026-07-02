# cachedb_nats — OpenSIPS CacheDB Engine backed by NATS KV

A cachedb engine module that stores key-value data in [NATS JetStream KV](https://docs.nats.io/nats-concepts/jetstream/key-value-store),
with an in-process JSON full-text search index and live KV change watching.

- **Language:** C
- **NATS client:** [nats.c](https://github.com/nats-io/nats.c) v3.13+
- **Target:** OpenSIPS 4.0+

## Dependencies

- `lib/nats/libnats_pool.so` — built once and located by every NATS module via `$ORIGIN` rpath; provides the shared connection pool. No `loadmodule` line needed.
- `tls_mgm` — required only when `nats_url` starts with `tls://`. See [`docs/nats-tls-backends.md`](../../docs/nats-tls-backends.md) for the `nats` client-domain pattern.

## Features

- Standard cachedb operations: get, set, remove, add (atomic increment), sub, get_counter
- Atomic counter operations using CAS (compare-and-swap) with configurable retry
- JSON document storage with in-process full-text search index
- Live index updates via KV watcher thread (no polling)
- `nats_cdb_request()` — synchronous NATS request/reply (RPC pattern)
- `nats_kv_history()` — retrieve key version history as JSON array
- Raw query commands: `KV KEYS`, `KV PURGE <key>`, `KV BUCKET INFO`
- Map operations: get/set/remove with composite `key:subkey` addressing

## Parameters

The `Default` column wraps multi-line values so its rendered width
is bounded by the longest single-line value rather than the longest
full string.  Long defaults split across `<br>` breaks.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `cachedb_url` | string (func) | -- | OpenSIPS cachedb URL (e.g., `nats://127.0.0.1:4222/`) |
| `nats_url` | string | `nats://`<br>`127.0.0.1:`<br>`4222` | NATS server seed list. Use DNS hostnames for cluster resilience. Embedded credentials (`nats://user:pass@host`) are masked as `[redacted]` in all log output — see [Credential redaction in logs](../../lib/nats/README.md#credential-redaction-in-logs). |
| `kv_bucket` | string | `opensips` | JetStream KV bucket name |
| `kv_replicas` | int | 3 | Replication factor (only used when creating a new bucket) |
| `kv_history` | int | 1 | Version history depth per key. **Keep at 1 for registration buckets**: server-side auto-expiry only works when no old versions are kept — on a history-keeping bucket an expired key rolls back to an older revision instead of disappearing, so the module disables native TTL there (cleanup-scan-only expiry, see `nats_ttl_allow_history`). Raise only if your script uses `nats_kv_history()`. |
| `kv_ttl` | int | 0 | Bucket-wide TTL in seconds (0 = no expiry); applies to the generic `cache_store`/`cache_add` paths. **Must stay 0 for registration buckets** (a whole-bucket max age would silently delete permanent contacts; the module refuses to start otherwise). Per-key expiry for usrloc rows is handled separately (per-message `Nats-TTL` on NATS 2.11+ via the row-write path, plus the reaper). |
| `kv_marker_ttl` | int | 30 | Lifetime (seconds) of the "this was deleted" note the server leaves when it auto-deletes a record, so sibling instances observe the deletion. Applied at bucket creation. Raise if instances can be disconnected longer than 30 s; a value below `nats_reap_grace` warns at startup. |
| `nats_expired_linger` | int | 0 | How long (seconds, 0–86400) an **expired** registration record stays physically stored after it stops being served. `0` = delete as promptly as possible (~1 s, the server minimum); `30` = keep it readable for troubleshooting (`nats kv get`, `nats_kv_history()`) and to damp delete/re-create churn. Never affects call routing — expired contacts are never served. |
| `nats_native_ttl` | int | 1 | Master switch for server-side auto-expiry. `0` = never set message TTLs; rely solely on the periodic cleanup scan (expired records then persist up to ~`nats_reap_interval` longer). A diagnostic/emergency lever — leave at 1 for normal operation. Cannot be 0 with the cleanup scan also disabled (startup refused). |
| `nats_ttl_allow_history` | int | 0 | Advanced: use server-side auto-expiry on a bucket that keeps old versions (`kv_history` > 1) anyway. On tested servers (2.11.x) expiry is then **late** (up to `kv_marker_ttl` s) and older record versions can transiently resurface. Only set after verifying your NATS server version; the default scan-only fallback is always correct, just less prompt. |
| `fts_json_prefix` | string | `json_` | Key prefix for JSON documents included in the search index |
| `fts_max_results` | int | 100 | Maximum results returned by `cache_query` |
| `kv_watch` | string | NULL | Key pattern to watch (e.g., `usrloc.>` for wildcard). NULL = watch all keys. |
| `tls_*`, `reconnect_*`, `max_reconnect` | -- | -- | Same TLS and reconnect params as event_nats |

## Script Functions

### `nats_cdb_request(subject, payload, timeout_ms, result_pvar)`

Synchronous NATS request/reply. Sends `payload` to `subject`, waits up to `timeout_ms`
for a reply, stores it in `result_pvar`.  It blocks the worker for the full RTT/timeout,
so it is callable only off the SIP request path (onreply/local/startup/timer/event routes).

Returns: 1 (success), -1 (error), -2 (timeout)

```
nats_cdb_request("auth.check", "$var(json)", 2000, $var(reply));
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
cache_store("nats", "call.$ci", "$fu|$tu");
cache_fetch("nats", "call.$ci", $var(val));
cache_remove("nats", "call.$ci");

# Atomic counters (CAS-based, configurable via nats_cas_retries, default 10)
cache_add("nats", "counter.calls", 1, 0);
cache_counter_fetch("nats", "counter.calls", $var(count));

# JSON document storage (indexed if key starts with fts_json_prefix)
cache_store("nats", "json.user.alice", "{\"name\":\"alice\",\"domain\":\"example.com\"}");
```

## JSON Search Index

Keys starting with `fts_json_prefix` (default: `json_`) are automatically parsed and
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

A single watcher pthread is started in the rank-1 SIP worker (or, when
`dedicated_watcher_proc=1`, in a forked OpenSIPS child process — see
`PERF_NOTES.md` §"Dedicated KV-watcher process"). The watcher subscribes to
the KV bucket and on each put/delete/purge event:

1. Updates the SHM-backed search index that every worker reads
2. Raises an `E_NATS_KV_CHANGE` EVI event (if compiled with `HAVE_EVI`)

By default (`index_resync_on_reconnect=1`) the watcher rebuilds the index in
full on every reconnect. This is required for correctness: the watcher
subscribes with `UpdatesOnly`, so writes made by sibling instances while this
process was disconnected are never delivered live, and the lazy self-heal path
in `nats_cache_query` only *evicts* stale entries it already has — it cannot
discover a key it never indexed. Set `index_resync_on_reconnect=0` only for
large-index / hot-reconnect deployments that cannot afford the O(N) rebuild,
and rely instead on `index_resync_interval_secs` (the periodic resync timer)
to bound how long a missed write can stay invisible.

## Cluster Configuration

```
loadmodule "cachedb_nats.so"

modparam("cachedb_nats", "cachedb_url", "nats://localhost:4222/")
modparam("cachedb_nats", "nats_url", "nats://nats-1:4222,nats://nats-2:4222,nats://nats-3:4222")
modparam("cachedb_nats", "kv_bucket", "opensips")
modparam("cachedb_nats", "kv_replicas", 3)
```

The `nats_url` is a seed list — see [`lib/nats/README.md`](../../lib/nats/README.md) for
the shared-pool registration contract and reconnect semantics. Use DNS hostnames for
automatic discovery of topology changes.

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
| `nats_cdb_stats` | Snapshot of the counter set (`cas_retry`, `cas_exhausted`, `create_doc`, `index_miss_kv`, `rows_reaped`, `contacts_pruned`, ...) plus the `reap_last_*` gauges — bucket-wide registration totals (keys/AoRs/contacts/active/permanent/due + pass timestamp/duration) recorded by every reaper pass at zero extra broker cost. Poll THIS for registration-count monitoring. Alerting: `cas_exhausted > 0` = lost writes; sustained `index_miss_kv > 0` = cross-instance churn. |
| `nats_reg_summary [domains=1]` | High-level registration totals from a bucket scan: AoRs, contacts by state (active = would be served / expired-but-stored / permanent), soonest expiry, optional per-domain table. One round-trip per AoR — interactive use; monitoring should poll the `reap_last_*` gauges instead. |
| `nats_reg_list [filter]` | Per-AoR listing. Filter = `;`-separated `key=value`: `aor=<glob>`, `domain=<host>` (case-insensitive), `ua=`/`contact=` (substring), `state=active|expired|permanent|all`, `expiring_within=<s>`, `min_contacts=<n>`, `sort=aor|expiry|contacts|last_mod`, `desc=1`, `limit` (≤200), `offset`. Unknown keys refuse the command. Ties always break by AoR, so pagination is deterministic. |
| `nats_reg_show <aor>` | Everything stored for one AoR: each contact with all attributes + computed state/expires_in, and the row's KV metadata (revision, created, row_exp, schema_version). |
| `nats_stream_list [filter]` | JetStream streams on the connected server: name, messages, bytes, subjects, consumers, storage; KV backing streams also report their derived bucket name. Filter: `name=<glob>`, `kv=1` (KV buckets only), `limit`/`offset`. |
| `nats_stream_info <stream>` | One stream's full config + state — the direct operator check of the TTL preconditions on a bucket's backing stream (`allow_msg_ttl`, `max_msgs_per_subject`, `subject_delete_marker_ttl_s`, `max_age_s`) plus messages/bytes/seqs/consumers. |
| `nats_kv_keys [filter]` | LIVE keys of any KV bucket (delete markers never listed). Filter: `bucket=<name>` (default: the module's), `key=<glob>`, `detail=1` (revision/created/size for the returned page), `limit` (≤200)/`offset`. Read-only: buckets are bound, never created — a typo'd name errors instead of materializing a stream. |

Why here and not `ul_dump`: in full-sharing-cachedb mode usrloc frees its
in-memory records after every flush, so usrloc's own MI is empty by design —
the KV bucket is the only truth, and these commands read it directly (no
search index required).

**Output formats:** every command above defaults to structured JSON. Add
`format=csv` (RFC 4180, CRLF, header record) or `format=txt` (TAB-separated,
`# `-prefixed header) — as a filter key on the list commands, or as a
trailing parameter on `nats_reg_summary`/`nats_reg_show`/`nats_stream_info`
(`nats_reg_show alice@example.com csv`). Options: `eol=lf`, `header=0`. The
table rides as one `data` string inside the usual JSON-RPC envelope
(`jq -r '.result.data'` yields clean CSV/text; counts stay as JSON
siblings). Unknown format values are refused, never silently ignored.

## License

GPL-2.0 (matching OpenSIPS)
