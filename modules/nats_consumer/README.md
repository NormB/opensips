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

| Parameter         | Type   | Default                                               | Description |
|-------------------|--------|-------------------------------------------------------|-------------|
| `persist_handles` | int    | `0`                                                   | Opt-in JSON snapshot of the handle registry.  Write-on-change, debounced 500 ms, rehydrated at mod_init. |
| `persist_path`    | string | `/var/lib/opensips/nats_consumer/handles.json`        | Destination path.  Parent directory must exist at init time. |

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
| `ring_capacity`       | Power-of-two ring size override (default module-wide). |

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
| `nats_request(subject, payload, timeout_ms)`| onreply / local / startup / timer / event | **Sync-only.**  Blocks the worker up to `timeout_ms`. Excluded from `request_route`/`failure_route` (would block SIP processing). |

### Return codes

- `1` — success
- `0` — no message (timeout / empty batch)
- `-1` — local error (bad id, no current message, stage overflow, …)
- `-2` — NATS transport error; detail in `nats_last_error()`

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

## MI commands

| Command                  | Parameters          | Description |
|--------------------------|---------------------|-------------|
| `nats_consumer_bind`     | `config` (kv string)| Add / replace a handle. |
| `nats_consumer_unbind`   | `id`                | Retire a handle (deferred free). |
| `nats_consumer_list`     | —                   | JSON array of all handles with counters. |
| `nats_handle_reload`     | —                   | Additive reload from `persist_path`. |

## Usage

### Dynamic bind in `startup_route`

```
loadmodule "event_nats.so"
loadmodule "nats_consumer.so"

modparam("event_nats",    "nats_url",        "nats://127.0.0.1:4222")
modparam("nats_consumer", "persist_handles", 1)

startup_route {
    nats_consumer_bind(
        "id=jobs;stream=WORK;durable=jobs_worker;"
        "filter=work.jobs;ack_wait=30s;max_deliver=5");
}
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
  parser does not accept; a future phase can round-trip RFC3339.)
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
