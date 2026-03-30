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

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `nats_url` | string | `nats://127.0.0.1:4222` | Comma-separated NATS server URLs (seed list). Use DNS hostnames for cluster resilience. See nats_connection README for topology details. |
| `jetstream` | int | 0 | Enable JetStream for persistent async publish (1=on, 0=off) |
| `reconnect_wait` | int | 2000 | Milliseconds between startup connection retries |
| `max_reconnect` | int | 60 | Max startup connection attempts. Does NOT limit runtime reconnection (that is unlimited). |
| `tls_skip_verify` | int | 1 | Skip TLS server certificate verification (1=skip) |
| `tls_ca` | string | NULL | CA certificate file path |
| `tls_cert` | string | NULL | Client certificate file path (mutual TLS) |
| `tls_key` | string | NULL | Client private key file path |
| `tls_hostname` | string | NULL | Expected server certificate hostname |
| `skip_openssl_init` | int | 1 | Skip nats.c OpenSSL initialization (1=skip, required when tls_openssl is loaded) |

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

| Command | Description |
|---------|-------------|
| `nats_status` | Connection state and server URL |
| `nats_stats` | Publish counters (total, EVI, script, failed, reconnects) |
| `nats_reconnect` | Reports auto-reconnect status (nats.c handles reconnection internally) |

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
