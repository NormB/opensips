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
[nats_publish()](#nats_publishsubject-payload) script function for direct
publishing from `opensips.cfg` routing blocks.
This allows arbitrary JSON (or other text) payloads to be pushed
to any NATS subject at any point in call processing, independent
of the event system.


Optional *JetStream* support is available via
the [jetstream](#jetstream-integer) module parameter.  When enabled,
both EVI and script publishes use the nats.c asynchronous JetStream
publish API: the server acknowledges each message into a stream, and
failed acknowledgements are counted in the module statistics.  The
script sees only whether the message was queued.


NATS connections are managed by the shared
`lib/nats` connection pool
(`libnats_pool.so`).  Each qualifying worker
process obtains its own connection from the pool during
`child_init()`.  A broker that is unreachable at startup does not
block the boot: the process starts degraded and keeps connecting in the
background.  Runtime reconnection is unlimited.


### TLS


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
without a *tls_mgm* "nats" domain see
a clear error at connect time pointing at the missing
config.


libnats does its own TLS, with the library it was built against;
that choice is independent of the *tls_openssl* or
*tls_wolfssl* module used for SIP.  To load a specific libnats
build, set `NATS_DL_LIBNATS_PATH` in OpenSIPS's
environment.  See the
[NATS family overview](../../lib/nats/README.md#tls).


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
every event occurrence.  If [jetstream](#jetstream-integer) is set to 1,
each EVI publish uses the JetStream async API.


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
[nats_url](#nats_url-string) parameter provides a
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


Using DNS hostnames in [nats_url](#nats_url-string) instead of
IP addresses provides an additional layer of resilience.  On
each reconnect attempt, nats.c resolves the hostname via
`getaddrinfo()`, which allows the DNS record
to be updated to point to a replacement server if the original
has been replaced or its IP changed.  IP addresses are resolved
once at connection time and will not reflect infrastructure
changes.


Where the servers are published as DNS SRV records, a
`nats+srv://` URL (see [nats_url](#nats_url-string)) goes further:
the list of servers itself comes from DNS and is looked up again
when every known server has failed, so servers can be added,
removed or moved by updating the `_nats._tcp` records only.


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
[event_nats:nats_status](#event_natsnats_status),
[event_nats:nats_stats](#event_natsnats_stats), and
[event_nats:nats_reconnect](#event_natsnats_reconnect) MI commands.
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
- **[subscribe](#subscribe-string)** allows at most 32 core-NATS
subscriptions, with at-most-once delivery: no acknowledgement, no
durable state, no replay.  Inbound messages over 1 MiB are dropped, and
so is any message arriving while 4096 events are already waiting for a
worker.  Use *nats_consumer* for reliable delivery.
- **Stream MI commands** accept at most 32 subjects (1023 characters in
total), 1 to 5 replicas, names up to 255 characters and a `max_age` of
at most 10 years.
- **The attendant and TCP main processes have no connection.**
- **[drain_timeout_ms](#drain_timeout_ms-integer) is shared with
*cachedb_nats*.**  If both modules set it, the larger value wins.
- **Statistics** cover process numbers below 512.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *tls_mgm* if [nats_url](#nats_url-string) holds a `tls://` URL, with a
client domain named `nats` (see [TLS](#tls)).  No other module is
needed: the connection comes from the shared NATS connection pool
(`libnats_pool.so`, installed with the modules); see the
[NATS family overview](../../lib/nats/README.md).


#### External Libraries or Applications


The following libraries or applications must be installed before running
OpenSIPS with this module loaded:


- *libnats* (the [nats.c](https://github.com/nats-io/nats.c) client),
3.14 or later, with the same major.minor version at run time as at
build time.  For `tls://` URLs it must be built with TLS.  See the
[NATS family overview](../../lib/nats/README.md#requirements).
- *NATS Server* 2.10 or later; JetStream enabled when the
[jetstream](#jetstream-integer) parameter is used.


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
value of this parameter is therefore a
*bootstrap seed list only* — it does not
need to enumerate every cluster node.


Use DNS hostnames rather than bare IP addresses where possible.
nats.c re-invokes `getaddrinfo()` on each
reconnect attempt, allowing the hostname to resolve to a
different IP if the original server has been replaced or
renumbered.


A server can also be given as a DNS domain whose SRV records list
the servers: `nats+srv://example.com` (`tls+srv://example.com` for
TLS) looks up the SRV records of `_nats._tcp.example.com` and uses
their targets, lowest priority first (see
[no_randomize](#no_randomize-integer)).  Credentials are written as
usual (`nats+srv://user:password@example.com`) and apply to every
target; there is no port (the records provide it) and no path: a
port or a path is dropped with a warning, and an SRV URL without a
usable domain name is ignored with a warning.  The records
are looked up again each time a reconnect attempt has tried every
known server, so DNS changes apply without a restart.  For safety,
a target must be in the domain, or in its parent domain when the
domain has three labels or more: `nats-1.example.com` is used for
`example.com`, `nats-1.example.net` is ignored.


SRV URLs need a libnats with DNS SRV support (one that exports
`nats_SupportsSRV()`).  With any other libnats, OpenSIPS refuses to
start: such a libnats would connect to the domain name as a host.


*Default value is "nats://127.0.0.1:4222".*


```opensips title="Set nats_url parameter"
...
modparam("event_nats", "nats_url", "nats://127.0.0.1:4222")
...
```


```opensips title="Set nats_url parameter to a three-node seed list"
...
modparam("event_nats", "nats_url",
    "nats://nats-1.example.com:4222,nats://nats-2.example.com:4222,nats://nats-3.example.com:4222")
...
```


```opensips title="Set nats_url parameter to a DNS SRV domain"
...
modparam("event_nats", "nats_url", "nats+srv://example.com")
...
```


#### jetstream (integer)


Enable JetStream async publish for both EVI events and
[nats_publish()](#nats_publishsubject-payload) script calls.


When set to `1`, publishes use the
nats.c `js_PublishAsync()` API (a process without a JetStream context
falls back to core publish).  The NATS
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


*Default value is "0" (disabled).*


```opensips title="Set jetstream parameter"
...
modparam("event_nats", "jetstream", 1)
...
```


#### reconnect_wait_ms (integer)


The old name "reconnect_wait" is accepted as an alias.


Time in milliseconds to wait between connection attempts, both in
the `child_init()` startup loop and for runtime reconnects after a
connection drop (nats.c adds up to one more wait of random jitter).
A value of 0 or less means 2000.  The pool is shared, so the largest
value set by any NATS module wins.


*Default value is "2000" (2 seconds).*


```opensips title="Set reconnect_wait_ms parameter"
...
modparam("event_nats", "reconnect_wait_ms", 1000)
...
```


#### max_reconnect (integer)


Maximum number of connection attempts made during
`child_init()` startup for failures other than the ones below.
If the NATS server is not reachable, `child_init()` does not wait
and counts no attempts: it logs a warning and starts in a *degraded*
state, keeps connecting in the background, and the OpenSIPS worker
boots and routes calls normally while NATS publishes fail cleanly
and are counted in the `failed` statistic of
[event_nats:nats_stats](#event_natsnats_stats) until the broker
becomes reachable.  A broker that refuses the connection
(authentication, TLS handshake) looks the same, since the first
connect is asynchronous, and so does a connection that cannot be set
up with the configured servers (a `tls://` URL without *tls_mgm*, for
instance): event_nats starts degraded and logs why.  The pool is
shared, so the largest value set by any NATS module wins.


This limit applies only to the *startup*
connection phase.  Once a worker is running, runtime
reconnection is unlimited — nats.c will continue retrying
indefinitely and will never permanently drop a server from its
candidate pool.


*Default value is "60".*


```opensips title="Set max_reconnect parameter"
...
modparam("event_nats", "max_reconnect", 30)
...
```


#### drain_timeout_ms (integer)


The old name "nats_drain_timeout_ms" is accepted as an alias.


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
[drain_timeout_ms](../cachedb_nats/README.md#drain_timeout_ms-integer)):
the first value set replaces the default (even a lower one), after
that the largest value wins.  A negative value refuses startup.


*Default value is "5000" (5 seconds).*


```opensips title="Set drain_timeout_ms parameter"
...
modparam("event_nats", "drain_timeout_ms", 15000)
...
```


#### no_randomize (integer)


Server order of the connection shared by all NATS modules.  With
`0` (the default) libnats shuffles the configured servers, so the
OpenSIPS processes, each with its own connection, spread over them.
With `1`, every process tries the servers in the order they are
configured in [nats_url](#nats_url-string): the first reachable
server takes all the connections and the others are backups.


libnats then also stops shuffling the addresses of a hostname that
resolves to several IPs, and orders the targets of a DNS SRV URL by
priority, then by decreasing weight, instead of a weighted random
choice among the targets of the same priority.


The setting is shared by *event_nats*, *cachedb_nats* and
*nats_consumer*: if any of them sets it to `1`, the shared
connection keeps the configured order.  A value other than `0` or
`1` refuses startup.


*Default value is "0" (randomized).*


```opensips title="Set no_randomize parameter"
...
modparam("event_nats", "no_randomize", 1)
...
```


#### subscribe (string)


Configures a NATS subscription that dispatches received
messages to an `event_route` handler.
A dedicated consumer process subscribes to the specified
NATS subject and dispatches messages to SIP workers via
IPC, which then call `evi_raise_event()`
to trigger the corresponding `event_route`.
The parameter can be set multiple times to configure
multiple subscriptions (up to 32).


Format: `subject=<pattern>;event=<name>[;queue=<group>]`


- *subject* - NATS subject pattern
(wildcards `*` and `>`
are supported).
- *event* - EVI event name to raise.
The corresponding `event_route[<name>]`
must exist in `opensips.cfg`.
- *queue* (optional) - NATS queue group
for load-balanced consumption. When set, only one
subscriber in the group receives each message.


Inside the `event_route`, these parameters
are available via `$param()`:


- *$param(subject)* - the NATS subject
the message arrived on.
- *$param(data)* - the message payload.


*Default value is "NULL" (no subscription).*


```opensips title="Set subscribe parameter"
...
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
...
```


### Exported Functions


#### nats_publish(subject, payload)


Publish a message to a NATS subject directly from an
OpenSIPS routing script.  This function operates independently
of the EVI subsystem and can be called at any point in script
execution to push arbitrary content to NATS.


The *subject* must be a valid NATS
subject token string of at most 511 bytes.
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
are counted in the `failed` statistic of
[event_nats:nats_stats](#event_natsnats_stats).


The *payload* is published as-is with no
transformation.  By convention JSON is used, but any non-empty
text content is valid; an empty payload returns `-1`.


When the [jetstream](#jetstream-integer) module parameter is
`1`, the publish uses the nats.c
JetStream async API
(`js_PublishAsync()`); otherwise core NATS
publish (`natsConnection_Publish()`) is
used.


Both *subject* and
*payload* may contain OpenSIPS pseudo-variable
references, which are expanded at call time.


Meaning of the parameters is as follows:


- *subject* (string) - NATS subject
to publish to.  Maximum 511 bytes.
- *payload* (string) - Message
payload.  Typically a JSON object.


Return values:


- **1** - publish succeeded (message
handed to nats.c; for JetStream, ack is tracked
asynchronously).
- **-1** - publish failed (invalid subject,
missing parameter, no connection, or nats.c error).


This function can be used from any route.


```opensips title="nats_publish usage"
route[ON_REGISTER] {
    $var(payload) = "{\"event\":\"register\",\"call_id\":\"" + $ci
        + "\",\"from\":\"" + $fu + "\"}";
    nats_publish("sip.registrations", $var(payload));
}
```


```opensips title="nats_publish usage with JetStream"
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


All JetStream management MI commands validate their
parameters before forwarding to the NATS server.
Invalid inputs are rejected with HTTP 400 / JSON-RPC
error code 400 rather than being delegated to NATS
(which would otherwise return opaque 500 errors), and a
subject list is never silently truncated.  The policy enums are the
exception: an unknown *retention* or *storage* falls back to
`limits` / `file`, and an unknown *deliver_policy* or *ack_policy* is
ignored (the server default applies).


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
- *filter_subject* (consumer) - same
rules as subjects; rejected above 511 bytes.
- *Numeric ranges* - `replicas`
must be 1..5; `max_msgs` and
`max_bytes` must be ≥ -1
(-1 = unlimited); `max_age` is seconds
in [0 .. 10 years] (capped to prevent int64 overflow when
converted to nanoseconds); `seq` for
[event_nats:nats_msg_get](#event_natsnats_msg_get) and
[event_nats:nats_msg_delete](#event_natsnats_msg_delete) must be ≥ 1 and may be
supplied as a JSON number (up to 2^31-1) or, for stream
sequences beyond that, as a decimal string — the full
64-bit range is honoured.
- *Buffer limits* - stream/consumer
name ≤ 255 chars; subjects list ≤ 1023 chars.


The read-only stream observability commands
([cachedb_nats:nats_stream_list](../cachedb_nats/README.md#cachedb_natsnats_stream_list),
[cachedb_nats:nats_stream_info](../cachedb_nats/README.md#cachedb_natsnats_stream_info))
are provided by the *cachedb_nats* module, whose variants
support filtering, pagination and selectable output
formats.  This module exports only the mutating stream
admin commands below.


#### event_nats:nats_status


Returns the current NATS connection state and server
information for the calling worker process.


Parameters: *none*


Response fields:


- *server* - URL or hostname of the
currently connected NATS server, as reported by
`nats_pool_get_server_info()`.
- *connected* - `"yes"`
if the connection is in the CONNECTED state,
`"no"` otherwise.
- *jetstream* -
`"enabled"` or
`"disabled"` reflecting the
[jetstream](#jetstream-integer) module parameter.


```bash
opensips-cli -x mi event_nats:nats_status
```


```json
{
    "server": "nats://nats-1.example.com:4222",
    "connected": "yes",
    "jetstream": "enabled"
}
```


#### event_nats:nats_stats


Returns cumulative publish statistics from the shared-memory
statistics block.  All counters (except *reconnects*) are incremented
atomically across all worker processes and accumulate until OpenSIPS
is restarted.


Parameters: *none*


Response fields:


- *published* - total messages
published successfully (EVI + script combined).
- *evi_published* - messages published
via the EVI transport (from event subscriptions).
- *script_published* - messages
published via [nats_publish()](#nats_publishsubject-payload)
script calls.
- *failed* - publish attempts that
returned an error from nats.c, plus messages dropped because the
connection was down.  Subjects rejected as invalid or too long are
not counted.
- *reconnects* - number of times the connection was re-established,
as seen by the process serving the MI command (a per-process value,
not a sum across workers); the first connect after a degraded start
counts as one.
- *js_ack_ok* - JetStream acks received
with a success status (only meaningful when
[jetstream](#jetstream-integer) is 1).
- *js_ack_failed* - JetStream acks
received with an error status (only meaningful when
[jetstream](#jetstream-integer) is 1).  Publishes carry no ack
timeout, so an ack that never arrives is not counted.
- *inbound_dropped_oversize* - inbound [subscribe](#subscribe-string)
messages dropped for exceeding 1 MiB.
- *inbound_dropped_backpressure* - inbound messages dropped because
4096 events were already waiting for a worker.
- *inbound_inflight* - inbound events currently waiting for or being
raised by a worker (a gauge).


```bash
opensips-cli -x mi event_nats:nats_stats
```


```json
{
    "published": 14823,
    "evi_published": 12401,
    "script_published": 2422,
    "failed": 3,
    "reconnects": 1,
    "js_ack_ok": 14820,
    "js_ack_failed": 3,
    "inbound_dropped_oversize": 0,
    "inbound_dropped_backpressure": 0,
    "inbound_inflight": 0
}
```


#### event_nats:nats_reconnect


Reports the auto-reconnect status.  NATS runtime reconnection
is handled entirely by the nats.c library, which monitors the
connection state and reconnects automatically with no
intervention from OpenSIPS.  This MI command confirms that
auto-reconnect is active and provides a hook for operator
awareness without requiring a manual reconnect mechanism.


Parameters: *none*


Response fields:


- *status* - human-readable string
confirming that NATS auto-reconnect is active.


```bash
opensips-cli -x mi event_nats:nats_reconnect
```


```json
{
    "status": "NATS auto-reconnect is active"
}
```


#### event_nats:nats_account_info


Report JetStream account-level usage: in-memory bytes,
file-storage bytes, total streams, total consumers,
API call counts, and any quota limits.


Parameters: *none*


```bash
opensips-cli -x mi event_nats:nats_account_info
```


#### event_nats:nats_stream_create


Create a stream.  Three argument arities are accepted by the
parser: *name* + *subjects*, *name* + *subjects* + *replicas*,
and the full eight-parameter form.


Parameters:


- *name* - the stream name.
- *subjects* - comma-separated subject list.
- *replicas* (optional) - replication factor (default 1).
- *max_msgs* (optional) - maximum number of messages
(-1 = unlimited).
- *max_bytes* (optional) - maximum stream size in bytes
(-1 = unlimited).
- *max_age* (optional) - maximum message age in seconds, 0 to
10 years (0 = unlimited).
- *retention* (optional) - retention policy: `limits`,
`interest` or `workqueue`; any other value means `limits`.
- *storage* (optional) - storage backend: `file` or `memory`; any
other value means `file`.


```bash
opensips-cli -x mi event_nats:nats_stream_create JOBS 'jobs.>'
opensips-cli -x mi event_nats:nats_stream_create JOBS 'jobs.>' 3
```


#### event_nats:nats_stream_delete


Delete a stream and all its messages.  Irreversible.


Parameters:


- *stream* - the stream name.


```bash
opensips-cli -x mi event_nats:nats_stream_delete JOBS
```


#### event_nats:nats_stream_purge


Drop every message currently held by
*stream*; the stream definition
survives.  Equivalent to
`nats stream purge`.


Parameters:


- *stream* - the stream name.


```bash
opensips-cli -x mi event_nats:nats_stream_purge JOBS
```


#### event_nats:nats_js_consumer_list


Return a JSON array of consumer summaries (name,
num_pending, num_ack_pending) for every consumer attached
to *stream*.


Parameters:


- *stream* - the stream name.


```bash
opensips-cli -x mi event_nats:nats_js_consumer_list JOBS
```


#### event_nats:nats_js_consumer_info


Return the per-consumer metadata: deliver / ack policy,
and run-time state (delivered count, ack floor, pending
count, redelivered count, num waiting pulls).


Parameters:


- *stream* - the stream name.
- *consumer* - the consumer name.


```bash
opensips-cli -x mi event_nats:nats_js_consumer_info JOBS jobs_worker
```


#### event_nats:nats_js_consumer_create


Create a durable consumer on
*stream* with the given
*name*.  Three argument arities
are accepted: *stream* + *name*, plus *filter_subject*, plus
the full five-parameter form.


This command creates a consumer *on the broker*; it does not bind
that consumer to a script-callable handle in
*nats_consumer*.  Use the
[nats_consumer:nats_consumer_bind](../nats_consumer/README.md#nats_consumernats_consumer_bind)
MI command (or the
[nats_consumer_bind()](../nats_consumer/README.md#nats_consumer_bindconfig)
script function) to attach a handle.


Parameters:


- *stream* - the stream name.
- *name* - the durable consumer name.
- *filter_subject* (optional) - subject filter; left unset, the
consumer receives all of the stream's subjects.
- *deliver_policy* (optional) - `all`, `last`, `new` or
`last_per_subject`.
- *ack_policy* (optional) - `explicit`, `none` or `all`.  An unknown
*deliver_policy* or *ack_policy* is ignored (server default).


```bash
opensips-cli -x mi event_nats:nats_js_consumer_create JOBS jobs_worker 'jobs.>'
```


#### event_nats:nats_js_consumer_delete


Delete a durable consumer.  Pending deliveries that
were already in flight are dropped.


Parameters:


- *stream* - the stream name.
- *consumer* - the consumer name.


```bash
opensips-cli -x mi event_nats:nats_js_consumer_delete JOBS jobs_worker
```


#### event_nats:nats_msg_get


Fetch a single message from
*stream* by stream sequence number.
Returns the subject, payload (data), and
stream sequence number as JSON.


Parameters:


- *stream* - the stream name.
- *seq* - the stream sequence number, ≥ 1 (a non-positive or
non-numeric value is rejected with a 400).  It is parsed as a
full 64-bit value — pass it as a decimal string for sequences
beyond 2^31-1.


```bash
opensips-cli -x mi event_nats:nats_msg_get JOBS 42
```


#### event_nats:nats_msg_delete


Delete a specific message from
*stream* by stream sequence
number.  Equivalent to
`nats stream rmm`.


Parameters:


- *stream* - the stream name.
- *seq* - the stream sequence number, ≥ 1, parsed as a
full 64-bit value (pass a decimal string for sequences beyond
2^31-1).


```bash
opensips-cli -x mi event_nats:nats_msg_delete JOBS 42
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
