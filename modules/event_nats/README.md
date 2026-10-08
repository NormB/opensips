---
title: "event_nats Module"
description: "The event_nats module implements a NATS transport for the OpenSIPS Event Interface (EVI)."
---

## Admin Guide


### Overview


The *event_nats* module implements a
[NATS](https://nats.io) transport for the
OpenSIPS Event Interface (EVI).  It registers the
`nats` transport protocol with the EVI subsystem,
enabling any OpenSIPS event to be published to a NATS subject by
subscribing it with a `nats:<subject>` socket
URI.  Events are delivered as JSON payloads containing the event
name and all associated parameters.


In addition to the EVI transport, the module exports the
`nats_publish()` script function for direct
publishing from `opensips.cfg` routing blocks.
This allows arbitrary JSON (or other text) payloads to be pushed
to any NATS subject at any point in call processing, independent
of the event system.


Optional *JetStream* support is available via
the `jetstream` module parameter.  When enabled,
both EVI and script publishes use the nats.c asynchronous JetStream
publish API: the server acknowledges each message into a stream, and
failed acknowledgements are counted in the module statistics.  The
script sees only whether the message was queued.


NATS connections are managed by the shared
`lib/nats` connection pool
(`libnats_pool.so`).  Each qualifying worker
process obtains its own connection from the pool during
`child_init()`.  The pool handles startup
retries (bounded by `max_reconnect`) and runtime
reconnection (unlimited) automatically.


### Dependencies


#### OpenSIPS Modules


- *None.*  The connection comes from the shared NATS connection
pool (`libnats_pool.so`, installed with the modules); see the
[NATS family overview](../../lib/nats/README.md).
- *tls_mgm* — only for `tls://` server URLs, with a client domain
named `nats` (see [TLS configuration](#tls-configuration)).


#### External Libraries


The following external library is required:


- *libnats* (the [nats.c](https://github.com/nats-io/nats.c) client),
3.14 or later, with the same major.minor version at run time as at
build time.  For `tls://` URLs it must be built with TLS.  See the
[NATS family overview](../../lib/nats/README.md#requirements).
- *NATS Server* 2.10 or later; JetStream enabled when the
`jetstream` parameter is used.


### Exported Parameters


#### nats_url (string)


Comma-separated list of NATS server seed URLs used for the
initial connection.  Each entry must include the scheme
(`nats://` for plain TCP or
`tls://` for TLS) and may specify either an
IP address or a DNS hostname.


*Cluster topology is auto-discovered* via
the NATS INFO gossip protocol.  After the first successful
connection the nats.c library receives a
`connect_urls` list from the server and adds
all cluster peers to its internal pool automatically.  The
value of `nats_url` is therefore a
*bootstrap seed list only* — it does not
need to enumerate every cluster node.


Use DNS hostnames rather than bare IP addresses where possible.
nats.c re-invokes `getaddrinfo()` on each
reconnect attempt, allowing the hostname to resolve to a
different IP if the original server has been replaced or
renumbered.


*Default value:*
`"nats://127.0.0.1:4222"`


```opensips title="Single server"
modparam("event_nats", "nats_url", "nats://127.0.0.1:4222")
```


```opensips title="Three-node cluster seed list with DNS hostnames"
modparam("event_nats", "nats_url",
    "nats://nats-1.example.com:4222,nats://nats-2.example.com:4222,nats://nats-3.example.com:4222")
```


#### jetstream (integer)


Enable JetStream async publish for both EVI events and
`nats_publish()` script calls.


When set to `1`, all publishes use the
nats.c `js_PublishAsync()` API.  The NATS
server acknowledges each message asynchronously; ack results
are tracked in the module statistics counters
`js_ack_ok` and
`js_ack_failed`.  JetStream provides
at-least-once delivery when the target subject is covered by a
persistent stream configured in the NATS cluster.


When set to `0` (the default), core NATS
publish (`natsConnection_Publish()`) is
used.  Core publish is fire-and-forget with no server
acknowledgement.


JetStream requires the NATS server to have JetStream enabled
(`jetstream: true` in
`nats-server.conf`) and at least one
matching stream defined for the target subjects.


*Default value:* `0`
(disabled)


```opensips title="Enable JetStream publish"
modparam("event_nats", "jetstream", 1)
```


#### reconnect_wait_ms (integer)


The former name "reconnect_wait" is kept as a working
alias; new configurations should use "reconnect_wait_ms".


Time in milliseconds to wait between consecutive connection
attempts during `child_init()` startup.
This parameter governs only the bounded startup retry loop;
runtime reconnection (after a connection drop) is handled
automatically by the nats.c library using its own internal
backoff and is not limited by this value.


*Default value:* `2000`
(2 seconds)


```opensips title="Set reconnect wait to 1 second"
modparam("event_nats", "reconnect_wait_ms", 1000)
```


#### max_reconnect (integer)


Maximum number of connection attempts made during
`child_init()` startup before the worker
stops waiting for the broker.  If the NATS server is not
reachable within
`max_reconnect` * `reconnect_wait_ms`
milliseconds, `child_init()` logs a warning
and starts in a *degraded* state (it returns
`0`, not `-1`): the OpenSIPS
worker boots and routes calls normally while NATS publishes
fail cleanly and are counted in
`nats_stats->failed` until the broker
becomes reachable.  Returning `-1` here would
be fatal to the whole OpenSIPS instance, so it is deliberately
avoided.


This limit applies only to the *startup*
connection phase.  Once a worker is running, runtime
reconnection is unlimited — nats.c will continue retrying
indefinitely and will never permanently drop a server from its
candidate pool.


*Default value:* `60`


```opensips title="Allow up to 30 startup attempts"
modparam("event_nats", "max_reconnect", 30)
```


#### TLS configuration


NATS-side TLS is configured via OpenSIPS's central
*tls_mgm* module — the same way
*proto_tls*,
*event_rabbitmq*,
*rest_client*, and other TLS-using
modules do it.  *event_nats* does
not carry its own `tls_*` modparams.


To use TLS for NATS connections, define a
*tls_mgm* client domain named
`"nats"` and use a `tls://`
URL:


```opensips title="tls_mgm-driven NATS TLS"
loadmodule "tls_mgm.so"
modparam("tls_mgm", "client_domain", "nats")
modparam("tls_mgm", "certificate", "[nats]/etc/opensips/nats-cert.pem")
modparam("tls_mgm", "private_key", "[nats]/etc/opensips/nats-key.pem")
modparam("tls_mgm", "ca_list",     "[nats]/etc/opensips/nats-ca.pem")
modparam("tls_mgm", "verify_cert", "[nats]1")

loadmodule "tls_openssl.so"

loadmodule "event_nats.so"
modparam("event_nats", "nats_url", "tls://nats.example.org:4222")
```


Plaintext-only deployments (`nats://`
URLs) don't need *tls_mgm* loaded —
*event_nats* declares it
`DEP_SILENT` and only attempts the
lookup when a `tls://` URL is actually
used.  Operators who configure `tls://`
without a `tls_mgm` "nats" domain see
a clear error at connect time pointing at the missing
config.


libnats does its own TLS, with the library it was built against;
that choice is independent of the *tls_openssl* or
*tls_wolfssl* module used for SIP.  To load a specific libnats
build, set `NATS_DL_LIBNATS_PATH` in OpenSIPS's
environment.  See the
[NATS family overview](../../lib/nats/README.md#tls).


#### drain_timeout_ms (integer)


The former name "nats_drain_timeout_ms" is kept as a working
alias; new configurations should use "drain_timeout_ms".


Shutdown drain timeout, in milliseconds, for the shared
`lib/nats` connection pool.  When
OpenSIPS shuts down, every NATS connection is drained so
in-flight publish acks land on the broker before the
process exits; this parameter caps how long that drain
may block per connection.


Cross-DC deployments with high broker round-trip latency
may need a larger budget.  The setting is shared across
all NATS modules that link `libnats_pool.so`
(notably *cachedb_nats*'s
`cdb_drain_timeout_ms`); the last
writer at `mod_init()` wins because
they all map onto the same library-level global.


*Default value:*
`5000` (5 seconds)


```opensips title="Raise drain timeout for high-latency broker"
modparam("event_nats", "drain_timeout_ms", 15000)
```


#### subscribe (string, multiple)


Configures a NATS subscription that dispatches received
messages to an `event_route` handler.
A dedicated consumer process subscribes to the specified
NATS subject and dispatches messages to SIP workers via
IPC, which then call `evi_raise_event()`
to trigger the corresponding `event_route`.


Format: `subject=<pattern>;event=<name>[;queue=<group>]`


- *subject* — NATS subject pattern
(wildcards `*` and `>`
are supported).
- *event* — EVI event name to raise.
The corresponding `event_route[<name>]`
must exist in `opensips.cfg`.
- *queue* (optional) — NATS queue group
for load-balanced consumption. When set, only one
subscriber in the group receives each message.


This parameter can be set multiple times to configure
multiple subscriptions (up to 32).


Inside the `event_route`, these parameters
are available via `$param()`:


- `$param(subject)` — the NATS subject
the message arrived on.
- `$param(data)` — the message payload.


```opensips title="subscribe usage"
# opensips.cfg:
loadmodule "event_nats.so"

# Subscribe to call events and ASR results
modparam("event_nats", "subscribe",
    "subject=opensips.calls.>;event=E_NATS_CALL")
modparam("event_nats", "subscribe",
    "subject=ai.asr.>;event=E_NATS_ASR")

# Load-balanced subscription with queue group
modparam("event_nats", "subscribe",
    "subject=jobs.>;event=E_NATS_JOB;queue=workers")

# Event route handlers:
event_route[E_NATS_CALL] {
    xlog("L_INFO", "Call event: subject=$param(subject) data=$param(data)\n");
}

event_route[E_NATS_ASR] {
    xlog("L_INFO", "ASR result: $param(data)\n");
}

event_route[E_NATS_JOB] {
    xlog("L_INFO", "Job: $param(data)\n");
}
```


### Exported Functions


#### nats_publish(subject, payload)


Publish a message to a NATS subject directly from an
OpenSIPS routing script.  This function operates independently
of the EVI subsystem and can be called at any point in script
execution to push arbitrary content to NATS.


The *subject* must be a valid NATS
subject token string and must not exceed 512 bytes.
The function rejects with `-1` any
subject that:


- is empty or longer than 511 bytes;
- contains the NATS wildcards
`'*'` or
`'>'` (publish must
target a concrete subject);
- contains whitespace, control bytes, or
embedded NUL;
- has malformed dot structure (leading,
trailing, or consecutive dots).


Additionally, when the underlying NATS connection pool
is in disconnected state, the function fast-fails with
`-1` rather than blocking the worker
up to the cnats internal-buffer timeout.  Lost messages
are reflected in
`nats_stats->failed`.


The *payload* is published as-is with no
transformation.  By convention JSON is used, but any binary
or text content accepted by nats.c is valid.


When the `jetstream` module parameter is
`1`, the publish uses the nats.c
JetStream async API
(`js_PublishAsync()`); otherwise core NATS
publish (`natsConnection_Publish()`) is
used.


Both *subject* and
*payload* may contain OpenSIPS pseudo-variable
references, which are expanded at call time.


Meaning of the parameters:


- *subject* (string) — NATS subject
to publish to.  Maximum 511 bytes.
- *payload* (string) — Message
payload.  Typically a JSON object.


Return values:


- `1` — publish succeeded (message
handed to nats.c; for JetStream, ack is tracked
asynchronously).
- `-1` — publish failed (subject too
long, missing parameter, or nats.c error).


This function can be used from any route type
(*ANY_ROUTE*).


```opensips title="Publish a SIP registration event to NATS"
route[ON_REGISTER] {
    $var(payload) = "{\"event\":\"register\",\"call_id\":\"" + $ci
        + "\",\"from\":\"" + $fu + "\"}";
    nats_publish("sip.registrations", $var(payload));
}
```


```opensips title="Publish call-setup notification with JetStream"
# In opensips.cfg modparams section:
modparam("event_nats", "jetstream", 1)

# In routing script:
route[CALL_SETUP] {
    $var(evt) = "{\"event\":\"call_setup\",\"call_id\":\"" + $ci
        + "\",\"caller\":\"" + $fu
        + "\",\"callee\":\"" + $ru + "\"}";
    if (!nats_publish("sip.calls.setup", $var(evt))) {
        xlog("L_WARN", "NATS publish failed for call $ci\n");
    }
}
```


### Exported MI Functions


#### nats_status


Returns the current NATS connection state and server
information for the calling worker process.


Parameters: none.


Response fields:


- `server` — URL or hostname of the
currently connected NATS server, as reported by
`nats_pool_get_server_info()`.
- `connected` — `"yes"`
if the connection is in the CONNECTED state,
`"no"` otherwise.
- `jetstream` —
`"enabled"` or
`"disabled"` reflecting the
`jetstream` module parameter.


```bash title="Query NATS connection status via opensips-cli"
opensips-cli -x mi nats_status
{
    "server": "nats://nats-1.example.com:4222",
    "connected": "yes",
    "jetstream": "enabled"
}
```


#### nats_stats


Returns cumulative publish statistics from the shared-memory
statistics block.  Counters are incremented atomically across
all worker processes and accumulate until OpenSIPS is restarted.


Parameters: none.


Response fields:


- `published` — total messages
published successfully (EVI + script combined).
- `evi_published` — messages published
via the EVI transport (from event subscriptions).
- `script_published` — messages
published via `nats_publish()`
script calls.
- `failed` — publish attempts that
returned an error from nats.c.
- `reconnects` — number of times the
nats.c reconnect callback fired (connection was
re-established after a drop).
- `js_ack_ok` — JetStream acks received
with a success status (only meaningful when
`jetstream=1`).
- `js_ack_failed` — JetStream acks
received with an error status, or acks that timed out
(only meaningful when `jetstream=1`).


```bash title="Query publish statistics"
opensips-cli -x mi nats_stats
{
    "published": 14823,
    "evi_published": 12401,
    "script_published": 2422,
    "failed": 3,
    "reconnects": 1,
    "js_ack_ok": 14820,
    "js_ack_failed": 3
}
```


#### nats_reconnect


Reports the auto-reconnect status.  NATS runtime reconnection
is handled entirely by the nats.c library, which monitors the
connection state and reconnects automatically with no
intervention from OpenSIPS.  This MI command confirms that
auto-reconnect is active and provides a hook for operator
awareness without requiring a manual reconnect mechanism.


Parameters: none.


Response fields:


- `status` — human-readable string
confirming that NATS auto-reconnect is active.


```bash title="Check reconnect status"
opensips-cli -x mi nats_reconnect
{
    "status": "NATS auto-reconnect is active"
}
```


#### Input Validation


All JetStream management MI commands validate their
parameters before forwarding to the NATS server.
Invalid inputs are rejected with HTTP 400 / JSON-RPC
error code 400 rather than being delegated to NATS
(which would otherwise return opaque 500 errors).
This also prevents a data-loss bug where supplying
more than 32 subjects would silently truncate the
list.


- *Stream / consumer names* must
be non-empty, contain no control chars,
whitespace, `.`, `*`,
`>`, `/`, or
`\`. These rules apply to every
handler that accepts a `stream`,
`consumer`, or `name`
parameter.
- *Subjects* may contain dots
(token separators) and wildcards
(`*`, `>`),
but not whitespace or control chars. Each
comma-separated token is validated individually.
More than 32 subjects returns
`too many subjects (max 32)`.
- *filter_subject* (consumer) — same
rules as subjects; rejected above 512 bytes.
- *Numeric ranges* — `replicas`
must be 1..5; `max_msgs` and
`max_bytes` must be ≥ -1
(-1 = unlimited); `max_age` is seconds
in [0 .. 10 years] (capped to prevent int64 overflow when
converted to nanoseconds); `seq` for
`nats_msg_get` and
`nats_msg_delete` must be ≥ 1 and may be
supplied as a JSON number (up to 2^31-1) or, for stream
sequences beyond that, as a decimal string — the full
64-bit range is honoured.
- *Buffer limits* — stream/consumer
name ≤ 255 chars; subjects list ≤ 1023 chars.


#### nats_account_info


Report JetStream account-level usage: in-memory bytes,
file-storage bytes, total streams, total consumers,
API call counts, and any quota limits.  Takes no
parameters.


The read-only stream observability commands
(`nats_stream_list`,
`nats_stream_info`) are provided by the
*cachedb_nats* module, whose variants
support filtering, pagination and selectable output
formats.  This module exports only the mutating stream
admin commands below.


#### nats_stream_create(name, subjects, [replicas, max_msgs, max_bytes, max_age, retention, storage])


Create a stream.  Required: *name*,
*subjects* (comma-separated subject
list).  Optional tuning:
*replicas* (default 1),
*max_msgs* /
*max_bytes* /
*max_age* retention caps
(-1 = unlimited), *retention*
policy (`limits` /
`interest` /
`workqueue`), and
*storage* backend
(`file` / `memory`).
Three argument arities are accepted by the parser:
name+subjects, name+subjects+replicas, and the full
eight-parameter form above.


#### nats_stream_delete(stream)


Delete a stream and all its messages.  Irreversible.


#### nats_stream_purge(stream)


Drop every message currently held by
*stream*; the stream definition
survives.  Equivalent to
`nats stream purge`.


#### nats_js_consumer_list(stream)


Return a JSON array of consumer summaries (name,
num_pending, num_ack_pending) for every consumer attached
to *stream*.


#### nats_js_consumer_info(stream, consumer)


Return the per-consumer metadata: deliver / ack policy,
and run-time state (delivered count, ack floor, pending
count, redelivered count, num waiting pulls).


#### nats_js_consumer_create(stream, name, [filter_subject, deliver_policy, ack_policy])


Create a durable consumer on
*stream* with the given
*name*.  Optional tuning:
*filter_subject* (defaults to the
stream's wildcard),
*deliver_policy*
(`all` /
`last` /
`new` /
`last_per_subject`), and
*ack_policy*
(`explicit` /
`none` /
`all`).  Three argument arities
are accepted: stream+name, plus filter_subject, plus
the full five-parameter form above.


Note: this MI command creates a consumer
*on the broker*; it does not bind
that consumer to a script-callable handle in
*nats_consumer*.  Use
*nats_consumer*'s
`nats_consumer_bind`
MI command (or its script wrapper) to attach a handle.


#### nats_js_consumer_delete(stream, consumer)


Delete a durable consumer.  Pending deliveries that
were already in flight are dropped.


#### nats_msg_get(stream, seq)


Fetch a single message from
*stream* by stream sequence number.
*seq* must be ≥ 1 (a non-positive or
non-numeric value is rejected with a 400) and is parsed as a
full 64-bit value — pass it as a decimal string for sequences
beyond 2^31-1.  Returns the subject, payload (data), and
stream sequence number as JSON.


#### nats_msg_delete(stream, seq)


Delete a specific message from
*stream* by stream sequence
number.  *seq* must be ≥ 1 and is parsed as a
full 64-bit value (pass a decimal string for sequences beyond
2^31-1).  Equivalent to
`nats stream rmm`.


### EVI Transport


The *event_nats* module registers a transport
named `nats` with the OpenSIPS Event Interface.
Once registered, event subscriptions in
`opensips.cfg` can route any OpenSIPS event to
a NATS subject by using the socket syntax:


```text
nats:<subject>
```


The subject is any valid NATS token string (dot-separated
hierarchy tokens, no wildcards at publish time).  The module
publishes events as JSON objects built by the EVI payload
serialiser, containing the event name and all event parameters as
key-value pairs.


#### Subscribing Events


Use `subscribe_event()` inside a
`startup_route` block to bind OpenSIPS events
to NATS subjects.  Multiple events can be subscribed to
different subjects, and multiple subscriptions can target the
same subject.


```opensips title="Subscribing multiple events in startup_route"
startup_route {
    /* Publish user location events to NATS */
    subscribe_event("E_UL_CONTACT_INSERT", "nats:usrloc.contact.insert");
    subscribe_event("E_UL_CONTACT_DELETE", "nats:usrloc.contact.delete");

    /* Publish pike (flood detection) blocks */
    subscribe_event("E_PIKE_BLOCKED",      "nats:opensips.pike.blocked");

    /* Publish all dialog events under a common prefix */
    subscribe_event("E_DLG_STATE_CHANGED", "nats:opensips.dialog.state");
    subscribe_event("E_DLG_CREATE",        "nats:opensips.dialog.create");
    subscribe_event("E_DLG_DELETE",        "nats:opensips.dialog.delete");
}
```


Each event fires independently; the EVI subsystem calls the
`nats_evi_raise()` transport callback for
every event occurrence.  If `jetstream=1`
is configured, each EVI publish uses the JetStream async API.


#### JSON Payload Format


Events are serialised by the OpenSIPS EVI payload builder
(`evi_build_payload()`).  The resulting
JSON object includes the event name and all parameters
registered by the event source module.


Example payload for `E_UL_CONTACT_INSERT`:


```json
{
    "event": "E_UL_CONTACT_INSERT",
    "aor": "sip:alice@example.com",
    "uri": "sip:alice@192.168.1.100:5060;transport=udp",
    "received": "sip:192.168.1.100:5060",
    "path": "",
    "qvalue": -1,
    "expires": 3600,
    "flags": 0,
    "cflags": 0,
    "socket": "udp:10.0.0.1:5060",
    "callid": "abc123@192.168.1.100",
    "cseq": 1
}
```


### Cluster Configuration


The *event_nats* module is designed for use
with multi-node NATS JetStream clusters.  The
`nats_url` parameter provides a
*seed list* of one or more bootstrap servers;
the full cluster topology is discovered automatically via the
NATS INFO gossip protocol.


#### Seed List and Auto-Discovery


When nats.c connects to any seed server, the server responds
with a `connect_urls` field in its INFO
message listing all current cluster members.  The nats.c
library adds these URLs to its internal candidate pool and
will try them in rotation during reconnect.  Servers added
or removed from the cluster are reflected in subsequent INFO
gossip messages and picked up automatically without requiring
any OpenSIPS restart or configuration change.


Because topology is self-updating, the seed list only needs
to contain enough nodes to guarantee at least one is reachable
at startup.  A three-node cluster typically uses all three as
seeds for maximum bootstrap resilience.


#### DNS Hostnames for Resilience


Using DNS hostnames in `nats_url` instead of
IP addresses provides an additional layer of resilience.  On
each reconnect attempt, nats.c resolves the hostname via
`getaddrinfo()`, which allows the DNS record
to be updated to point to a replacement server if the original
has been replaced or its IP changed.  IP addresses are resolved
once at connection time and will not reflect infrastructure
changes.


```opensips title="Three-node JetStream cluster configuration"
# opensips.cfg
loadmodule "event_nats.so"

modparam("event_nats", "nats_url",
    "nats://nats-1.example.com:4222,nats://nats-2.example.com:4222,nats://nats-3.example.com:4222")
modparam("event_nats", "jetstream",       1)
modparam("event_nats", "reconnect_wait_ms",  2000)
modparam("event_nats", "max_reconnect",   60)
```


### Rank Filtering


The *event_nats* module does not initialize a
NATS connection in every OpenSIPS child process.  The
`child_init()` function applies rank-based
filtering before connecting to NATS:


- *SIP workers* (UDP and TCP,
rank >= 1) — NATS is initialized.  These are the
processes that handle SIP request routing and fire EVI
events; they must be able to publish.
- *MI / HTTPD process*
(`PROC_MODULE`) — NATS is initialized.
This process handles MI command responses, including the
`nats_status`,
`nats_stats`, and
`nats_reconnect` MI commands.
- *Timer process*
(`PROC_TIMER`) — NATS is initialized.
The timer raises a large class of subscribable events
in-process (usrloc/dialog contact/AoR expiry, tm and
dialog timeouts).  The EVI raise callback runs in
whatever process fires the event, so the timer must
hold a connection or every timer-driven publish is
dropped.
- *Attendant*
(`PROC_MAIN`) and
*TCP-main*
(`PROC_TCP_MAIN`) — NATS is
*not* initialized.  Neither handles
SIP routing, and TCP-main holds the OpenSIPS TLS module's
OpenSSL state in isolation.  Module-exported processes
(negative rank, e.g. the consumer process) self-initialize
and are not driven by `child_init()`.


```opensips title="Effect of rank filtering in a mixed UDP/TCP deployment"
# opensips.cfg
udp_workers = 8       # 8 UDP SIP workers (rank >= 1) — NATS initialized
tcp_workers = 4       # 4 TCP SIP workers (rank >= 1) — NATS initialized

# The MI process (PROC_MODULE) and the timer (PROC_TIMER) also get a
# NATS connection; only the attendant (PROC_MAIN) and TCP-main
# (PROC_TCP_MAIN) are skipped.
```
### Limitations


- **Core NATS publishes are not acknowledged.**  A message published
while no subscriber is listening is lost.
- **JetStream publishes are asynchronous.**  A return value of 1 means
the message was queued; a stream covering the subject must already
exist, and failed acknowledgements are only counted in the statistics.
- **Messages published while disconnected are dropped.**  The call
returns -1 immediately and the message is counted as failed.
- **Subjects** are at most 511 bytes and must not contain wildcards,
whitespace, control characters or empty tokens.
- **`subscribe`** allows at most 32 core-NATS subscriptions, with
at-most-once delivery: no acknowledgement, no durable state, no replay.
Inbound messages over 1 MiB are dropped, and so is any message arriving
while 4096 events are already waiting for a worker.  Use
*nats_consumer* for reliable delivery.
- **Stream MI commands** accept at most 32 subjects (1023 characters in
total), 1 to 5 replicas, names up to 255 characters and a `max_age` of
at most 10 years.
- **The attendant and TCP main processes have no connection.**
- **`drain_timeout_ms` is shared with *cachedb_nats*.**  If both
modules set it, the value set last wins.
- **Statistics** cover process numbers below 512.


<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
