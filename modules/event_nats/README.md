# event_nats — OpenSIPS EVI Transport for NATS

An Event Interface (EVI) transport module for [OpenSIPS](https://opensips.org/) that
publishes SIP events to [NATS](https://nats.io/) subjects, with optional JetStream
persistence.

- **Language:** C
- **NATS client:** [nats.c](https://github.com/nats-io/nats.c) v3.13+
- **JetStream:** Optional — enable with `modparam("event_nats", "jetstream", 1)`
- **Target:** OpenSIPS 4.0+

## Dependencies

- `nats_connection.so` — must be loaded first (provides the shared connection pool)

## Parameters

The `Default` column wraps multi-line values so its rendered width
is bounded by the longest single-line value rather than the longest
full string.  Long defaults split across `<br>` breaks.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `nats_url` | string | `nats://`<br>`127.0.0.1:`<br>`4222` | Comma-separated NATS server URLs (seed list). Use DNS hostnames for cluster resilience. See nats_connection README for topology details. |
| `jetstream` | int | 0 | Enable JetStream for persistent async publish (1=on, 0=off) |
| `reconnect_wait` | int | 2000 | Milliseconds between startup connection retries |
| `max_reconnect` | int | 60 | Max startup connection attempts. Does NOT limit runtime reconnection (that is unlimited). |
| `tls_skip_verify` | int | 0 | Skip TLS server certificate verification (default 0 = verify; production default since the secure-defaults pass). |
| `tls_allow_downgrade` | int | 0 | Permit silent rewrite of `tls://` URLs to `nats://` when nats.c was built without TLS support. Default 0 fails fast; set to 1 only for development. |
| `tls_ca` | string | NULL | CA certificate file path |
| `tls_cert` | string | NULL | Client certificate file path (mutual TLS) |
| `tls_key` | string | NULL | Client private key file path |
| `tls_hostname` | string | NULL | Expected server certificate hostname |
| `skip_tls_init` | int | 1 | Skip nats.c global TLS-library init/cleanup (1=skip, required when any of OpenSIPS's `tls_openssl`, `tls_wolfssl`, or one of the `nats_tls_*` wrappers is loaded -- which is almost always the case).  Backend-neutral name covering both OpenSSL and wolfSSL libnats builds. |
| `skip_openssl_init` | int | 1 | **Deprecated** alias for `skip_tls_init` (kept for one release cycle).  Using this name emits a one-time `LM_WARN` and writes the same storage. |
| `nats_drain_timeout_ms` | int | 5000 | Shutdown drain timeout for the shared `lib/nats` connection pool. Cross-DC deployments with high RTT may need a longer budget; this setting is shared with `cachedb_nats`'s `cdb_drain_timeout_ms` (last writer wins). |
| `subscribe` | string (multi) | -- | Configure NATS→`event_route` subscriptions; format `subject=<pat>;event=<name>[;queue=<grp>]`. Each set adds one fire-and-forget core-NATS subscription that dispatches matching messages to the named `event_route[]` handler via IPC. No script ack, no durable consumer state — for explicit-ack JetStream pull semantics use the separate `nats_consumer` module. |

## Script Functions

### `nats_publish(subject, payload)`

Publish a message to a NATS subject. Uses JetStream async publish if `jetstream=1`,
otherwise plain NATS publish.

```
nats_publish("sip.events.invite", "{\"call_id\":\"$ci\",\"from\":\"$fu\"}");
```

Subject length must be under 512 bytes — longer subjects are rejected with an error.

## EVI Transport

Register event subscriptions using the `nats:` transport prefix:

```
# In opensips.cfg
subscribe_event("E_UL_CONTACT_INSERT", "nats:usrloc.contact.insert");
subscribe_event("E_DLG_STATE_CHANGED", "nats:dialog.state");
```

Events are published as JSON payloads to the specified NATS subject.

## MI Commands

### Connection & Statistics

| Command | Description |
|---------|-------------|
| `nats_status` | Connection state and server URL |
| `nats_stats` | Publish counters (total, EVI, script, failed, reconnects) |
| `nats_reconnect` | Reports auto-reconnect status (nats.c handles reconnection internally) |

### JetStream Management

| Command | Parameters | Description |
|---------|------------|-------------|
| `nats_account_info` | — | Account stats: memory, storage, streams, consumers, API stats, limits |
| `nats_stream_list` | — | List all streams with summary (name, messages, bytes, consumers, replicas) |
| `nats_stream_info` | `stream` | Detailed stream metadata: config, state, cluster info with replica lag |
| `nats_stream_create` | `name`, `subjects` [, `replicas`, `max_msgs`, `max_bytes`, `max_age`, `retention`, `storage`] | Create a stream. Subjects is comma-separated. Retention: limits/interest/workqueue. Storage: file/memory. |
| `nats_stream_delete` | `stream` | Delete a stream |
| `nats_stream_purge` | `stream` | Purge all messages from a stream |
| `nats_consumer_list` | `stream` | List consumers for a stream |
| `nats_consumer_info` | `stream`, `consumer` | Detailed consumer metadata: delivered, ack_floor, pending, config |
| `nats_consumer_create` | `stream`, `name` [, `filter_subject`, `deliver_policy`, `ack_policy`] | Create a durable consumer. deliver_policy: all/last/new/last_per_subject. ack_policy: explicit/none/all. |
| `nats_consumer_delete` | `stream`, `consumer` | Delete a consumer |
| `nats_msg_get` | `stream`, `seq` | Get a message by sequence number |
| `nats_msg_delete` | `stream`, `seq` | Delete a message by sequence number |

JetStream MI commands require `modparam("event_nats", "jetstream", 1)`.

## Cluster Configuration

```
# Use DNS names — re-resolved on every reconnect attempt
modparam("event_nats", "nats_url", "nats://nats-1:4222,nats://nats-2:4222,nats://nats-3:4222")
```

The URL list is a **seed list for bootstrap only**. After the initial connection, nats.c
discovers the full cluster topology via the INFO protocol gossip and adds/removes servers
dynamically. See the `nats_connection` README for details.

## Usage

```
loadmodule "nats_connection.so"
loadmodule "event_nats.so"

modparam("event_nats", "nats_url", "nats://nats-1:4222,nats://nats-2:4222,nats://nats-3:4222")
modparam("event_nats", "jetstream", 0)

route {
    nats_publish("sip.invite", "{\"call_id\":\"$ci\"}");
    ...
}
```

## License

GPL-2.0 (matching OpenSIPS)
