# nats_consumer — OpenSIPS JetStream Pull Consumer

A pull-mode [NATS JetStream](https://nats.io/) consumer module for
[OpenSIPS](https://opensips.org/).  Binds JetStream stream/consumer pairs at
runtime, stages deliveries in per-handle SHM rings, and exposes them to
routing scripts through `nats_fetch()` + an explicit ack family.

- **Language:** C
- **NATS client:** [nats.c](https://github.com/nats-io/nats.c) v3.13+
- **Broker:** JetStream-enabled NATS server (v2.9+)
- **Target:** OpenSIPS 4.0+

`nats_consumer` is the receive-side counterpart to `event_nats` (publish) and
`cachedb_nats` (KV).  All three modules share the `lib/nats` connection pool,
so a single OpenSIPS instance opens one NATS connection per worker regardless
of which NATS modules are loaded.

## Use cases

- **Work queue.** Multiple OpenSIPS instances share the same durable name and
  load-balance deliveries.  `ack_wait` + `max_deliver` give at-least-once
  semantics with a bounded retry budget.
- **Replay.** An ephemeral consumer with `deliver_policy=by_start_seq` can
  replay arbitrary historical ranges without touching the durable state.
- **RPC.** `nats_request()` + `nats_reply()` pair to drive synchronous
  request/reply loops from a `timer_route`.
- **Dead-letter / advisory.** Subscribe to
  `$JS.EVENT.ADVISORY.MAX_DELIVERIES.>` through an ephemeral consumer to
  react to exhausted redelivery budgets.

## Dependencies

- `event_nats` (optional, but typically loaded for publishing and for the
  shared transport modparams)
- `tls_openssl` (only when connecting to NATS over TLS)
- `nats.c` 3.13+ at `libnats.so`

## Parameters

| Parameter           | Type   | Default                                               | Description |
|---------------------|--------|-------------------------------------------------------|-------------|
| `persist_handles`   | int    | `0`                                                   | Opt-in JSON snapshot of the handle registry.  Write-on-change, debounced 500 ms, rehydrated at mod_init. |
| `persist_path`      | string | `/var/lib/opensips/nats_consumer/handles.json`        | Destination path.  Parent directory must exist at init time. |
| `fetch_batch`       | int    | `10`                                                  | Module-global default for the JetStream pull-Fetch batch size on the consumer process.  Per-handle `fetch_batch=` bind key overrides this for individual handles.  Range: 1..4096.  See `Tuning fetch_batch and fetch_timeout_ms` below for guidance. |
| `fetch_timeout_ms`  | int    | `1000`                                                | Module-global default for the per-Fetch wait timeout (ms).  Per-handle `fetch_timeout_ms=` bind key overrides this for individual handles.  Range: 1..60000.  Lower values reduce shutdown latency; higher values reduce idle CPU on quiet streams. |
| `request_id_header` | string | `X-Request-Id`                            | Outbound header name used to carry the per-call UUIDv7 correlation id minted by both the sync and async `nats_request` start paths.  The id is also exposed to the script via `$nats_request_id` and persists across an `async()` yield so it is readable from the resume route.  Auto-stage skips the header iff the script already set the same name via `nats_hdr_set()`.  Set to `""` to mint without staging.  Per-call cost ≈ 200 ns (one `clock_gettime` + one `getrandom` of 10 bytes). |
| `allow_sync_anywhere` | int | `0`                                          | Opt-in switch that widens the route mask of the sync `nats_request` so it may be called from `REQUEST_ROUTE` / `FAILURE_ROUTE` / `BRANCH_ROUTE` / `ERROR_ROUTE`.  Default 0 keeps the parser rejecting bare `nats_request(...)` from those contexts.  Each route has its own blocking blast radius (REQUEST/BRANCH/ERROR block one SIP worker; FAILURE via negative-reply trigger blocks one SIP worker; FAILURE via `fr_timer`/`fr_inv_timer` expiry blocks the single-threaded **timer ticker** process, which queues every other module's tick callback — significantly worse).  The setter emits a multi-line `LM_WARN` at config-parse time detailing each route's consequences, and the DocBook admin guide carries the verified source-path references; read both before opting in.  The recommended pattern from any reactor-backed route is `async(nats_request(...), rt)`, which yields on an eventfd and is accepted regardless of this modparam — async works from `request_route` / `branch_route` / `error_route` / `timer_route` / `event_route` / `onreply_route` and reply-triggered `failure_route`.  The one remaining gap is `fr_timer`-triggered `failure_route`, which runs on the reactor-less timer ticker; lifting that requires an upstream TM change to dispatch fr_timer expiry through a Timer-handler process. |

NATS transport parameters (`nats_url`, `tls_*`, `reconnect_wait`,
`max_reconnect`, `skip_openssl_init`) are set on the `event_nats` module;
`nats_consumer` reads the same connection pool via `lib/nats`.

## Bind configuration

Handles are bound at runtime.  The config string is a `;`-separated list of
`k=v` pairs.

### Required

| Key       | Description |
|-----------|-------------|
| `id`      | Per-instance handle name used by script / MI. |
| `stream`  | JetStream stream name. |
| `durable` OR `ephemeral=1` | Exactly one must be set. |

### Optional

| Key                   | Description |
|-----------------------|-------------|
| `filter`              | Single subject filter. |
| `filters`             | CSV of subject filters (requires nats.c 3.13 FilterSubjects). |
| `deliver_policy`      | `all` (default), `last`, `new`, `last_per_subject`, `by_start_seq`, `by_start_time`. |
| `start_seq`           | Required when `deliver_policy=by_start_seq`. |
| `start_time`          | RFC3339 timestamp; required when `deliver_policy=by_start_time`. |
| `replay_policy`       | `instant` (default) or `original`. |
| `ack_policy`          | `explicit` (default), `none`, `all`. |
| `ack_wait`            | Duration (e.g. `30s`, `500ms`). |
| `max_deliver`         | Integer redelivery cap. |
| `backoff`             | CSV of durations for explicit redelivery schedule. |
| `max_ack_pending`     | Flow-control cap on un-acked messages. |
| `headers_only`        | `1` = drop payload, headers only. |
| `sample_freq`         | `0..100` (percent) sampled ack advisory. |
| `rate_limit`          | Bits/sec delivery rate cap. |
| `inactive_threshold`  | Ephemeral GC timeout. |
| `js_domain`           | JetStream multi-domain prefix. |
| `api_prefix`          | Custom `$JS.API` prefix. |
| `ring_capacity`       | Power-of-two ring size override (default module-wide).  When the consumer process Fetches a batch larger than the ring can hold, the surplus is dropped and the broker redelivers after `ack_wait`; size `ring_capacity >= 2 * fetch_batch` to avoid this. |
| `fetch_batch`         | Per-handle override of the `fetch_batch` modparam.  `0` means "use module default".  Range: 1..4096.  Useful when a single OpenSIPS hosts handles with very different rate profiles. |
| `fetch_timeout_ms`    | Per-handle override of the `fetch_timeout_ms` modparam.  `0` means "use module default".  Range: 1..60000.  Latency-sensitive low-rate handles benefit from a short timeout; throughput-bound durables typically want the module default. |

Unknown keys are preserved in `extra_json` for forward-compat and survive
persistence round-trips.

## Script functions

| Function                                    | Routes    | Description |
|---------------------------------------------|-----------|-------------|
| `nats_fetch(id, [timeout_ms])`              | any       | Pull one message; populates `$nats_*`. |
| `async nats_fetch(id, [timeout_ms])`        | async ctx | Non-blocking fetch; worker yields until message or timeout. |
| `nats_fetch_batch(id, [opts])`              | any       | Drain up to `count` (default 16) messages. |
| `nats_batch_select(idx)`                    | any       | Activate the `idx`-th message of the current batch. |
| `nats_ack()`                                | any       | Ack the current message. |
| `nats_ack_next()`                           | any       | Ack + ask for another delivery. |
| `nats_ack_progress()`                       | any       | Refresh `ack_wait` without terminating. |
| `nats_nak([delay_ms])`                      | any       | NAK current message; optional redelivery delay. |
| `nats_term()`                               | any       | Terminate delivery (no retry). |
| `nats_hdr_set(name, value)`                 | any       | Stage outgoing header on the worker buffer. |
| `nats_reply(payload)`                       | any       | Publish to the current message's `reply_to`. |
| `nats_request(subject, payload, timeout_ms)`| sync: onreply / local / startup / timer / event (widen with `allow_sync_anywhere`); async: any reactor-backed route | NATS request/reply.  Sync blocks the worker; `async(nats_request(...), rt)` yields on a per-call eventfd until the reply arrives or the timer expires. |

### Return codes

**Unified grammar.**  No `nats_*` script function returns 0 — a 0
return from a script-callable cmd triggers `ACT_FL_EXIT` in
`run_action_list` (core/action.c:196) and silently terminates the
calling route, which is never the right behaviour for an RPC /
fetch result.  Every result is therefore either a positive count
or a negative code:

| Code | Meaning |
|---|---|
| `>0` | success — for `nats_fetch_batch`, the message count.  For everything else, `1`. |
| `-1` | expected non-result: timeout for `nats_request` / `nats_fetch`, empty batch for `nats_fetch_batch`.  Pool is healthy; script can retry. |
| `-2` | connection/transport error.  Broker is down or the connection was lost mid-flight (for async `nats_request`).  Distinct from `-1`: treat as broker-down (alert, circuit-break) rather than retry-with-longer-tmo. |
| `-3` | configuration error: handle id not found, pool not initialised, handle retiring. |
| `-4` | request error: bad opts, subject empty / too long, msg create failed, publish/request failed. |
| `-5` | capacity: per-worker in-flight cap reached (async `nats_request` only).  Default 4096. |
| `-6` | internal error: oom, missing eventfd, format failure. |

**Latency note for `-2` on `async nats_request`:** the resume
function discovers the lost-connection state when the async-core
timer next wakes it, so the worst-case time to surface `-2` is
bounded by the script's `timeout_ms`.  Sub-second proactive
reaping requires either a periodic-poll route or a `lib/nats`
disconnect-callback chain; both are tracked for a later phase.

**Script-side idiom for `nats_fetch_batch`:** because the
function returns `-1` on empty (not 0), always assign and branch
on `> 0`:

```opensips
$var(n) = nats_fetch_batch("jobs", "count=64;expires=500");
if ($var(n) > 0) {
    for ($var(i) = 0; $var(i) < $var(n); $var(i) = $var(i) + 1) {
        nats_batch_select($var(i));
        # ... process the slot
        nats_ack();
    }
}
```

## Pseudo-variables

| Variable              | Description |
|-----------------------|-------------|
| `$nats_subject`       | Delivery subject. |
| `$nats_data`          | Payload. |
| `$nats_reply_to`      | Reply subject (empty if none). |
| `$nats_seq`           | Stream sequence. |
| `$nats_consumer_seq`  | Consumer-side sequence. |
| `$nats_delivered`     | Delivery count (1 = first). |
| `$nats_pending`       | Broker-side pending estimate. |
| `$nats_token`         | Opaque ack token. |
| `$nats_hdr(Name)`     | Header read; case-insensitive name match. |
| `$nats_request_id`    | **Read/write.** UUIDv7 of the most recent `nats_request` issued by this worker.  Auto-minted at call time; persists across `async()` yields so the resume route can read it for log/trace correlation.  Auto-staged as the `X-Request-Id` outbound header by default (configurable via `request_id_header`).  **Assigning** before a `nats_request` call substitutes a script-supplied value (consume-once) — useful to propagate an inbound `$hdr(X-Trace-Id)` end-to-end.  Both `$nats_request_id = NULL;` and `$nats_request_id = "";` clear the pending override and the stash.  Validation: 1..63 bytes, no CR/LF; rejected assignments log `LM_WARN` and the call falls back to minting fresh. |

## MI commands

| Command                  | Parameters          | Description |
|--------------------------|---------------------|-------------|
| `nats_consumer_bind`     | `config` (kv string)| Add / replace a handle. |
| `nats_consumer_unbind`   | `id`                | Retire a handle (deferred free). |
| `nats_consumer_list`     | —                   | JSON array of all handles with counters. |
| `nats_handle_reload`     | —                   | Additive reload from `persist_path`. |

## Usage

### Minimum end-to-end setup

The smallest config that exercises every part of the module from scratch.
Run on the same host as a JetStream-enabled NATS broker on `127.0.0.1:4222`.

**1. Create the stream and seed a few messages (broker-side, before
opensips starts):**

```sh
nats stream add WORK --subjects 'work.jobs' --storage memory --defaults
nats pub work.jobs --count 5 'job-{{Count}}'
```

**2. Minimum opensips.cfg:**

```
log_level=3
xlog_level=3
stderror_enabled=yes
udp_workers=1
socket=udp:127.0.0.1:5060

mpath="/usr/local/lib64/opensips/modules/"
loadmodule "proto_udp.so"
loadmodule "mi_datagram.so"
modparam("mi_datagram", "socket_name", "udp:127.0.0.1:8888")

loadmodule "event_nats.so"
modparam("event_nats", "nats_url", "nats://127.0.0.1:4222")
loadmodule "nats_consumer.so"
modparam("nats_consumer", "persist_handles", 1)

startup_route {
    # Single-line bind string -- OpenSIPS cfg syntax does NOT
    # auto-concatenate adjacent string literals.  Keep all k=v
    # pairs on one line.
    nats_consumer_bind("id=jobs;stream=WORK;durable=jobs_worker;filter=work.jobs;ack_wait=30s;max_deliver=5");
}

timer_route[drain, 1] {
    while (nats_fetch("jobs", 250) > 0) {
        xlog("L_INFO", "job $nats_seq subj=$nats_subject body=$nats_data\n");
        nats_ack();
    }
}

route { exit; }
```

**3. Verify after opensips starts:**

```sh
# The 5 seeded messages should appear in stderr / syslog as
# "job 1 ... job 5".  Confirm the consumer's ack count is 5:
echo '{"jsonrpc":"2.0","id":1,"method":"nats_consumer:nats_consumer_list"}' \
  | nc -u -w 2 127.0.0.1 8888
# {"id":"jobs", ..., "msgs_delivered":5,"acks":5,"naks":0}
```

### Simple work-queue consumer

```
timer_route[drain, 1] {
    while (nats_fetch("jobs", 250) > 0) {
        xlog("L_INFO", "job $nats_seq: $nats_data\n");
        nats_ack_next();
    }
}
```

### Batch drain

```
timer_route[bulk, 5] {
    $var(n) = nats_fetch_batch("jobs", "count=50;expires=2s");
    $var(i) = 0;
    while ($var(i) < $var(n)) {
        nats_batch_select($var(i));
        process_job("$nats_data");
        nats_ack();
        $var(i) = $var(i) + 1;
    }
}
```

### RPC responder

```
startup_route {
    nats_consumer_bind(
        "id=rpc_srv;stream=RPC;durable=srv;filter=rpc.call;ack_wait=5s");
}

timer_route[rpc_srv, 1] {
    while (nats_fetch("rpc_srv", 100) > 0) {
        nats_hdr_set("X-Trace-Id", "$nats_hdr(X-Trace-Id)");
        if (nats_reply("echo: $nats_data"))
            nats_ack();
        else
            nats_nak();
    }
}
```

### RPC caller (sync-only)

```
# nats_request blocks the worker; only call from timer / startup.
timer_route[rpc_cli, 5] {
    if (nats_request("rpc.call", "ping", 2000))
        xlog("L_INFO", "reply: $nats_data\n");
    else
        xlog("L_WARN", "rpc failed rc=$retcode\n");
}
```

### Dead-letter via advisory

```
startup_route {
    nats_consumer_bind(
        "id=dlq;stream=_SYS_JS;ephemeral=1;"
        "filter=$JS.EVENT.ADVISORY.MAX_DELIVERIES.>;"
        "inactive_threshold=5m");
}

timer_route[check_dlq, 5] {
    while (nats_fetch("dlq", 100) > 0) {
        xlog("L_ALERT", "dead letter: $nats_subject $nats_data\n");
        nats_ack();
    }
}
```

## Deployment patterns

These are the four shapes of operator config the test suite + the docs
optimise for.  Pick the one that matches your workload; they're not
mutually exclusive (one opensips can run several at once, each with
its own bound handle).

| Pattern | Stream / consumer config | OpenSIPS-side script |
|---|---|---|
| **Durable work queue** -- N opensips instances share work; explicit ack; bounded retry. | `durable=<name>; filter=work.>; ack_wait=30s; max_deliver=5; max_ack_pending=1000` | `timer_route { while (nats_fetch...) { ... nats_ack(); } }` |
| **Replay from sequence** -- one-shot historical scan. | `ephemeral=1; deliver_policy=by_start_seq; start_seq=12345; inactive_threshold=5m` | same as above; consumer auto-GCs after `inactive_threshold` of no activity. |
| **Sync RPC server** -- fan in JSON requests, reply on the embedded reply-to subject. | `durable=rpc; filter=rpc.call; ack_wait=5s` | `timer_route { while (nats_fetch...) { nats_reply("..."); nats_ack(); } }` |
| **Dead-letter listener** -- watch JetStream advisories for max-redelivery exhaustion. | `ephemeral=1; filter=$JS.EVENT.ADVISORY.MAX_DELIVERIES.>; inactive_threshold=5m` | `timer_route { while (nats_fetch...) { xlog("L_ALERT", "dlq: ...\n"); nats_ack(); } }` |

Detailed examples for each pattern are in `### Usage` above.

## Benchmarks

A bench harness lives at `tests/bench/bench_consumer.sh`.  It
pre-publishes N messages to a JetStream stream, starts an opensips
with a tight `timer_route` drain loop, and times how long until N
messages are acknowledged at the broker.  Drain-completion is read
from the JetStream consumer's "Acknowledgment Floor" -- the
authoritative broker-side count of acks confirmed.  The opensips
side mirrors the broker via the per-handle MI counters
(`pulls_requested`, `msgs_delivered`, `acks`, `naks`, `terms`,
`redeliveries`); the harness writes the final snapshot to
`$OUT/handle_metrics.json` for cross-check.

```sh
OPENSIPS_MODULES=/path/to/_modules \
  N=10000 \
  bash modules/nats_consumer/tests/bench/bench_consumer.sh
```

Env knobs: `N` (msg count, default 10000), `DEADLINE_S` (drain
deadline, default 60), `STREAM`, `STREAM_SUBJECTS` (default
`bench.>`), `PUB_SUBJECT` (default `bench.in`), `FILTER` (default
`bench.>`), `HANDLE`, `MI_PORT`, `NATS_URL`, `OUT`, plus
`FETCH_BATCH` / `FETCH_TIMEOUT_MS` / `RING_CAPACITY` to exercise
the tuning knobs.

### Reference numbers

Single-instance, loopback NATS, aarch64, defaults (`fetch_batch=10`,
`fetch_timeout_ms=1000`, default 1 s timer route).  Drain pattern
matters more than the module knobs; both rows are at N=100 000:

| Drain pattern                          | msgs/sec | Drain elapsed | redeliveries |
|----------------------------------------|---------:|--------------:|-------------:|
| `nats_fetch` + `nats_ack` (single)     |    2 058 |        48.5 s |          206 |
| `nats_fetch_batch` (`fetch_batch=10`)  |    9 630 |       10.4 s |            0 |
| `nats_fetch_batch` (`fetch_batch=64`)  |   56 211 |         1.8 s |            0 |
| `nats_fetch_batch` (`fetch_batch=128`) |   55 897 |         1.8 s |            0 |
| `nats_fetch_batch` (`fetch_batch=256`) | **89 286** | **1.1 s**   |        **0** |

The 43x speedup over the original single-drain baseline lands via
five fixes that compound:

1. `nats_fetch_batch`'s opts parser now accepts `expires_ms=` (was
   silently ignored before; only `expires=` was wired up).
2. `nats_fetch_batch`'s wait loop no longer relies on the ring's
   per-process eventfd (which never wakes on the worker side).
   It uses a SHM-resident `wake_seq` + Linux `FUTEX_WAIT` /
   `FUTEX_WAKE` against an address inside the ring struct, so the
   producer can wake every worker across fork boundaries in
   sub-millisecond time.  This replaced both the original "block
   the full `expires_ms`" collapse and the 5 ms usleep-tick
   stop-gap that shipped in the interim.  Visible mostly at
   mid-range `fetch_batch=64` (now 56 k msgs/sec vs. 37 k on the
   5 ms tick).
3. The consumer process's per-handle msg-ref table is now sized
   from `max(ring_capacity, max_ack_pending)`.  With the previous
   size = ring_capacity, any handle with `max_ack_pending` larger
   than the ring saw the broker fill the ref table mid-flight,
   trigger drops, and watch the broker redeliver after `ack_wait`
   --- which stalled the broker-side ack floor.
4. The consumer process's `pull_one_batch` now clamps the Fetch
   batch size to the ring's free slots before calling
   `natsSubscription_Fetch`.  Prior to this clamp, a static
   `fetch_batch` larger than the worker's transient drain rate
   would push messages past the ring's capacity, get defer-dropped
   on push, never be acked, expire `ack_wait`, and trigger a
   redelivery cascade whose stale-consumer-seq acks could never
   advance the broker's ack floor --- which is what stalled
   `fetch_batch` in (16..64) at zero broker-confirmed acks despite
   tens of thousands of locally-applied acks.
5. The consumer process's idle cycle is a blocking `select()` on
   `(ack_fd, retry_timerfd)` rather than a `usleep(50ms)` spin, so
   empty subscriptions drop to ~0% CPU and worker acks wake the
   process immediately.

### Choosing a drain pattern

| Pattern | Code shape | Use it when |
|---------|------------|-------------|
| **single** | `while (nats_fetch(...)) { nats_ack(); }` | Per-message latency matters more than throughput; rate ≤ ~2 k msgs/sec; simple. |
| **batch**  | `nats_fetch_batch(...)` then iterate `nats_batch_select(i)` + `nats_ack()` | Sustained throughput > 2 k msgs/sec; willing to pay batch-fill latency. |

Recommended batch drain template:

```
timer_route[drain, 1] {
    $var(b) = 0;
    while ($var(b) < 5000) {
        nats_fetch_batch("ingest", "count=10;expires_ms=100");
        $var(rc) = $retcode;
        if ($var(rc) <= 0) { break; }
        $var(i) = 0;
        while ($var(i) < $var(rc)) {
            nats_batch_select($var(i));
            nats_ack();
            $var(i) = $var(i) + 1;
        }
        $var(b) = $var(b) + 1;
    }
}
```

Throughput now scales linearly with `count` up to the
`max_ack_pending` cap.  Pick `count` to match the worker's
batch-iteration budget under your timer interval (a count=256
batch takes ~13 ms of script time per drain pass on aarch64).
Pair it with `ring_capacity >= 4 * count` and
`max_ack_pending >= ring_capacity` so the consumer-process Fetch
clamp has room to deliver full batches.

### Tuning `fetch_batch` and `fetch_timeout_ms`

**`fetch_batch`** -- consumer-process pulls/sec scale inversely
with batch size.  At `fetch_batch=10` the consumer issues ~10 000
`Fetch` calls to drain 100 k messages; at `fetch_batch=128` it
issues ~800.  Fewer broker round-trips = lower per-message broker
CPU.  In single-drain mode, throughput is gated by the worker's
script-interpreter overhead, so larger batches do not help (and
can hurt by hitting `max_ack_pending` faster); in batch-drain mode
they amortize the script overhead and DO scale, until the
per-batch script iteration cost crosses the `ack_wait` deadline
on the trailing messages.

**`fetch_timeout_ms`** -- per-Fetch upper-bound when the broker
has nothing to send.  Quiet streams pay this in CPU on every wake;
latency-sensitive shutdown pays it as worst-case shutdown delay.
Drop to 100 ms for short-lived ephemeral consumers; raise to
5 000 ms for high-volume durables that wake into useful work every
iteration.

**Recommended starting points** -- keep the module-global defaults
(`fetch_batch=10`, `fetch_timeout_ms=1000`) and override per-handle
when a specific consumer's profile justifies it:

```
# Latency-sensitive RPC responder; small batch, short timeout.
nats_consumer_bind("id=rpc;stream=API;durable=rpc;
  fetch_batch=4; fetch_timeout_ms=100");

# Throughput durable using batch drain in script.
nats_consumer_bind("id=ingest;stream=EVENTS;durable=ingest;
  fetch_batch=10; ring_capacity=512;
  max_ack_pending=8192");

# Quiet advisory listener; long timeout to coalesce wake-ups.
nats_consumer_bind("id=adv;stream=ADV;ephemeral=1;
  filter=$JS.EVENT.ADVISORY.MAX_DELIVERIES.>;
  fetch_timeout_ms=5000");
```

## Known limitations

- **`nats_request` is sync-only.**  The call blocks the worker for the full
  `timeout_ms`.  Callsites must be restricted to `timer_route` or
  `startup_route`.  For async request/reply from a `request_route`, use
  `event_nats` to publish the request and a plain `nats_fetch` consumer to
  receive the reply on a known subject.
- **`$nats_hdr($var(...))` dynamic names are not supported.**  The header
  name must be a literal pseudo-variable parameter.  If you need a computed
  name, pre-select the value with `nats_hdr_set` at bind time or walk a
  small switch of literal names in script.
- **`deliver_policy=by_start_time` does not round-trip through persistence.**
  The handle rehydrates without the `start_time` field; re-apply at runtime
  if needed.  (The JSON snapshot stores a ns-precision timestamp that the
  parser does not accept; a future revision can round-trip RFC3339.)
- **TLS NATS cluster integration test is not part of the unit harness.**
  TLS uses the shared `lib/nats` pool and is exercised by `event_nats`
  harnesses; no consumer-specific regression for a TLS cluster ships yet.

## Design + implementation notes

See `docs/superpowers/specs/2026-04-16-nats-consumer-design.md` on the
`feature/nats-consumer-spec` branch for the full design, plus the phased
implementation plan that landed in commits on the
`feature/nats-consumer-*` branches.

## License

GPL-2.0 (matching OpenSIPS).
