# NATS integration — fault model and failure-path test coverage

How the OpenSIPS NATS stack (`lib/nats`, `cachedb_nats`, `event_nats`,
`nats_consumer`) behaves under broker faults, the contracts each surface
guarantees on failure, and the tests that pin every class.  Companion to
`NATS_TODO.md` ("Fault-class hardening follow-up").

Date: 2026-06-12, branch `feature/nats`.

---

## 1. Fault classes

The broker lifecycle produces five distinct fault classes.  They are NOT
interchangeable for testing: a docker pause (clean TCP close) exercises
different code than a SIGKILL (dead socket, no close), and a crash is not
a restart (restart adds reconnect + handle-refresh + watcher-resume +
subscription-rebuild paths).

| # | Class | What happens | Handling |
|---|-------|--------------|----------|
| 1 | **Down at boot** | Broker unreachable while every process runs `child_init` | Async first connect: `natsConnection_Connect` returns `NATS_NOT_YET_CONNECTED` immediately (`SetRetryOnFailedConnect`); the process continues **degraded** and cnats dials in the background. `_pool_reconnected_cb` doubles as the first-connect callback (sets `_connected`, bumps the reconnect epoch, marks KV handles stale). Boot completes in seconds; no SIP outage window. |
| 2 | **Crash mid-operation** | TCP dies while a fetch/publish/RPC is in flight | Bounded by the per-op timeout; the next op hits class 3. `NATS_CONNECTION_CLOSED` from a Fetch marks the sub dirty for rebuild. |
| 3 | **Down at op time** | Pool already disconnected when an op starts | Fast-fail everywhere — see §2. No op may block a SIP/timer/event process for a JetStream timeout while the broker is known-dead. |
| 4 | **Restart during traffic** | Broker comes back (same or fresh state) | Reconnect epoch bump → KV handles refreshed (`nats_con_refresh_kv`), consumer subscriptions destroyed + rebuilt (durable resumes past `last_stream_seq`), KV watcher re-watches, async-RPC inbox re-subscribed. No process restart needed. |
| 5 | **Deleted server-side** | Stream/consumer/bucket removed while bound | Ephemeral consumers recreate automatically (`NATS_NOT_FOUND` → dirty → rebuild). Durable on a **deleted stream** wedges by design — see §5. |

## 2. Fast-fail return codes (class 3)

Every script-reachable op checks `nats_pool_is_connected()` (or the
KV-handle equivalent) before doing broker work:

| Surface | Disconnected return | Notes |
|---|---|---|
| `cachedb_nats` ops (kv/cache/map/raw/query/update) | `-1` | via `nats_con_refresh_kv` gate; also refreshes a stale KV handle post-reconnect |
| `nats_fetch` / `nats_fetch_batch` | `-2` | checked before AND after the blocking wait |
| `nats_request` (sync) | `-3` | guard added 2026-06-12: previously blocked the calling (timer/event!) process for the full `timeout_ms` |
| `nats_request` (async submit) | `-2` | guard added 2026-06-12: previously burned a bounded RPC slot per call for the full timeout |
| `nats_publish` (event_nats) | `-1` | bumps the `failed` counter |
| ack family (`nats_ack`/`nak`/...) | `-2` | ack IPC still enqueued where meaningful |

## 3. Out-param contracts on failure returns

Core callers (usrloc, b2b, dlist, script engine) free or read
caller-owned out-params after a backend failure.  The backend therefore
guarantees, on **every** failure return:

| Function | Guarantee | Why |
|---|---|---|
| `query(con, filter, res)` | `cdb_res_init(res)` runs before any failure return | usrloc `cdb_load_urecord` calls `cdb_free_rows(&res)` on ANY rc≠0 with an uninitialized stack `res` — violating this was a live SIGSEGV (sip_e2e `040_broker_bounce`) |
| `map_get(con, key, res)` | same | b2b callers do the same |
| `raw_query(..., reply, ..., reply_no)` | `*reply = NULL`, `*reply_no = 0` at entry | contract does not require callers to pre-init |
| `get(con, attr, val)` | `*val = {NULL, 0}` at entry | callers only free on rc==0, but a deterministic NULL beats a garbage pointer if one ever doesn't |
| `get_counter` | `-2` = key absent (val untouched), `-1` = error | distinguishes miss from failure |
| `add`/`sub` | `new_val` may be NULL; only written on success | dlg_profile passes NULL |
| `set`/`remove`/`update`/`map_set`/`map_remove` | no out-params | inherently safe |

Pinned by: `cachedb_nats/tests/test_query_res_init.c`,
`test_outparam_contracts.c`.

## 4. Test coverage matrix

Local-broker e2e tests run against a **private disposable nats-server**
(needs `nats-server` in PATH — often `/usr/sbin`) so the operator's
broker is never disturbed.  SIGKILL is used for the kill phases (dead
TCP, no clean close).

| Fault class | cachedb_nats | nats_consumer | event_nats / lib |
|---|---|---|---|
| 1 boot-down | (via lib test cfg) | `test_boot_degraded_e2e.sh` (consumer subscribes after late broker) | `lib/nats/tests/test_boot_degraded_e2e.sh` + `test_async_first_connect.c` |
| 2 crash mid-op | `sip_e2e/cases/040_broker_bounce.sh` | `test_outage_rpc_fetch_e2e.sh` | `event_nats/tests/test_publish_during_disconnect.sh` |
| 3 down at op | `test_outage_matrix_e2e.sh` (9 ops, whole failing phase < 12 s) | `test_outage_rpc_fetch_e2e.sh` (fetch −2, request −3) + `test_request_fastfail.c` | publish fast-fail in the same tests |
| 4 restart | `test_outage_matrix_e2e.sh` phase 3 + **watcher resume** check; sip_e2e 040 post-bounce REGISTER | `test_outage_rpc_fetch_e2e.sh` phase 3 (durable resumes); compose `test_reconnect.sh` | `test_publish_during_disconnect.sh` recovery beats |
| 5 deleted server-side | — (see §5) | compose `test_ephemeral.sh` (ephemeral GC only) | — |
| out-param contracts | `test_query_res_init.c`, `test_outparam_contracts.c` | — | — |

Higher tiers: `sip_e2e/run.sh` (11 usrloc cases, 40 checks, two-instance),
the docker-compose integration suite under `nats_consumer/tests/`, and
`stress_3way.sh` (multi-hour soak; run on demand).

## 5. Known-untested, by decision

- **Durable bound to a deleted stream**: fetch returns "not found"
  forever; recovery is operational — `nats_consumer_unbind` the handle
  (MI) and rebind after recreating the stream.  Auto-recreate would mask
  operator data-loss mistakes.
- **Reconnect racing an in-flight async RPC reply**: the reply can land
  on the torn-down inbox; the caller sees the normal timeout (−1).
  Request-once semantics — the script layer owns the retry decision.
- **Broker-side `max_ack_pending` saturation under slow acks**: delivery
  pauses until acks catch up or the orphan reap (120 s TTL) releases
  slots; stress-tier behavior covered conceptually by
  `stress_ack_wait_expiry.sh` (compose).

## 6. Operator log signatures

| Log line | Meaning |
|---|---|
| `NATS pool: broker unreachable at startup; continuing degraded with background connect retries` | class 1 — boot proceeded; expect `NATS pool: reconnected to <url>` when the broker appears |
| `NATS pool: disconnected` | class 2/3 entered — ops fast-fail from here |
| `NATS pool: reconnected to <url>` | class 4 — handles refresh on next use; consumer rebuilds subs; watcher re-watches |
| `nats_request: NATS disconnected; failing fast instead of blocking <n> ms` | a timer/event route attempted a sync RPC during an outage |
| `watcher: disconnect detected, stopping watcher to prevent use-after-free` | KV watcher paused; resumes automatically post-reconnect |
| `consumer for <id> vanished (...); will recreate` | class 5 ephemeral GC (normal) or deleted durable (investigate) |
