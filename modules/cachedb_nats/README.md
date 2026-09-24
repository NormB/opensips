---
title: "cachedb_nats Module"
description: "The cachedb_nats module implements the OpenSIPS CacheDB engine interface on top of NATS JetStream Key-Value stores."
---

## Admin Guide


### Overview


The *cachedb_nats* module implements the OpenSIPS CacheDB
engine interface on top of *NATS JetStream Key-Value* stores.
It provides persistent, replicated, cluster-aware key-value storage accessible
from OpenSIPS routing scripts via the standard
`cache_store`/`cache_fetch`/`cache_remove`
operations, together with several NATS-native extensions.


The module connects to a NATS JetStream-enabled server or cluster, creates a
named KV bucket on first use, and maps all CacheDB operations onto NATS KV
primitives.  Reconnection and bucket handle refresh are fully automatic:
an epoch-based staleness check at the top of every operation transparently
re-opens the KV handle after any NATS disconnect/reconnect cycle.


Beyond the standard CacheDB API the module provides:


- **Atomic CAS counters** —
`cache_add` and `cache_sub`
use compare-and-swap with a configurable retry budget (`cas_retries` default 10), giving safe concurrent
counter increments from multiple OpenSIPS worker processes.
- **JSON secondary index (optional)** —
when the [cachedb_nats_fts](../cachedb_nats_fts/README.md) module is
loaded, JSON documents stored under keys that begin with
`fts_json_prefix` are indexed in shared memory, and
`cache_query` answers equality filters on their string fields from
the index instead of scanning the bucket.  Without
*cachedb_nats_fts* (the usual choice for usrloc), `cache_query` only
serves primary-key lookups, which go straight to `kvStore_Get`.
- **Live KV watcher** —
with `kv_watch` set, a dedicated process watches the bucket, raises
the *E_NATS_KV_CHANGE* event for every put, delete and purge, and
keeps the *cachedb_nats_fts* index (if loaded) in step with writes
made by other OpenSIPS instances.
- **nats_kv_history()** —
retrieves the full version history of a KV key as a JSON array.
- **Raw query commands** —
*KV KEYS*, *KV PURGE*, and
*KV BUCKET INFO* via
`cache_raw_query`.
- **Map operations** —
composite *key:subkey* addressing for get, set,
and remove of individual fields within JSON documents.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *None.*
The connection is provided by the shared NATS connection pool
(*lib/nats/libnats_pool.so*, installed with the modules), which
every NATS module uses.  See the
[NATS family overview](../../lib/nats/README.md).
- *tls_mgm* — only for `tls://` server URLs.


#### External Libraries or Applications


The following libraries must be installed before running OpenSIPS with
this module loaded:


- *libnats* (the [nats.c](https://github.com/nats-io/nats.c) client),
3.14 or later: the module needs the per-key KV TTL API
(`kvStore_CreateWithTTL`).  The libnats loaded at run time must have
the same major.minor version as the one OpenSIPS was built against;
see the [NATS family overview](../../lib/nats/README.md#requirements).
For `tls://` URLs, libnats must be built with TLS
(`-DNATS_BUILD_WITH_TLS=ON`).
- *NATS Server with JetStream enabled:*
2.10 or later (*jetstream: {}* in the server configuration).
Native per-key expiry (`kv_ttl_below_marker`) needs more; see that
parameter.
For production deployments a three-node JetStream cluster is
recommended to survive single-node failures with
`kv_replicas` set to 3.


### Exported Parameters


#### cachedb_url (string)


The CacheDB URL that associates this module with a named cache group
in the OpenSIPS script.  The URL format follows the standard OpenSIPS
CacheDB convention:


**nats[:`<group>`]://`<host>`:`<port>`/**


The optional `<group>` label (e.g.
*nats:mycluster://*) distinguishes multiple cache
namespaces in the same script.  When `nats_url` is
also set it takes precedence over the host:port portion of this URL
for the actual NATS connection; the URL is then used solely for group
registration.


This parameter may be set more than once to register multiple cache
group names backed by the same NATS connection.


```opensips title="Set cachedb_url parameter"
...
modparam("cachedb_nats", "cachedb_url", "nats://127.0.0.1:4222/")
modparam("cachedb_nats", "cachedb_url", "nats:calls://127.0.0.1:4222/")
...
```


```opensips title="Use the nats cache group in a routing script"
...
cache_store("nats", "call.$(ci{s.md5})", "$fu");
cache_fetch("nats:calls", "call.$(ci{s.md5})", $var(caller));
...
```


#### nats_url (string)


Comma-separated list of NATS server URLs used as the bootstrap seed
list for the connection pool.  After the initial connection is
established, nats.c discovers all cluster peers via the INFO protocol
gossip mechanism and maintains the full topology automatically.
This parameter only needs to contain enough servers to bootstrap the
initial connection.


Use DNS hostnames rather than IP addresses so that
`getaddrinfo` re-resolves on each reconnect attempt,
automatically following topology changes in the cluster.


When this parameter is set it takes precedence over the host:port
embedded in `cachedb_url`.


*Default value is "nats://127.0.0.1:4222".*


```opensips title="Set nats_url parameter"
...
modparam("cachedb_nats", "nats_url",
    "nats://nats-1:4222,nats://nats-2:4222,nats://nats-3:4222")
...
```


#### kv_bucket (string)


The name of the NATS JetStream KV bucket that this module will use
for all key-value operations.  If the bucket does not yet exist it
will be created during `child_init` with the
replication, history, and TTL settings defined by the
`kv_replicas`, `kv_history`, and
`kv_ttl` parameters.


If the bucket already exists the creation parameters are ignored and
the existing bucket configuration is used as-is.  To change
replication on an existing bucket use the NATS CLI:
*nats kv update <bucket> --replicas=N*.


Bucket names must be valid NATS subject tokens (alphanumeric, hyphens,
and underscores; no spaces or dots).


*Default value is "opensips".*


```opensips title="Set kv_bucket parameter"
...
modparam("cachedb_nats", "kv_bucket", "opensips-prod")
...
```


#### kv_replicas (integer)


The JetStream replication factor for the KV bucket.  A value of 3
means every key-value entry is replicated to three NATS nodes,
tolerating single-node failure without data loss.  This parameter
only takes effect when the bucket is first created; it is ignored
if the bucket already exists.


For development or single-node deployments use a value of 1.


*Default value is "3".*


```opensips title="Set kv_replicas parameter"
...
modparam("cachedb_nats", "kv_replicas", 1)
...
```


#### kv_history (integer)


The number of value revisions to retain per key.  This parameter
only takes effect when the bucket is first created.


**Keep this at 1 for registration
buckets** unless you use
`nats_kv_history()`.  Expiry is performed by
the periodic cleanup scan (the reaper) — see
`reap_interval`.


Raise this only if your script uses
`nats_kv_history` to inspect old versions of
keys and you accept scan-only expiry.


*Default value is "1" (current version only).*


```opensips title="Set kv_history parameter"
...
modparam("cachedb_nats", "kv_history", 10)
...
```


#### kv_ttl (integer)


Bucket-level maximum age, in seconds.  It must be `0`: any other
value stops OpenSIPS at startup.  A bucket-wide maximum age would
expire every key, including permanent registrations
(*expires=0*), so expiry is left to the reaper (see
`reap_interval`).  The parameter is kept so that existing
configurations that set it to 0 still load.


The *expires* argument to `cache_store` and `cache_add` is accepted
for API compatibility but sets no per-key TTL.  Per-key expiry
applies only to usrloc rows.


*Default value is "0".*


```opensips title="Set kv_ttl parameter"
...
modparam("cachedb_nats", "kv_ttl", 0)
...
```


#### kv_ttl_below_marker (integer)


When set to 1, bucket creation requests the
*allow_msg_ttl_below_marker* stream option, so
per-key TTLs shorter than the bucket's delete-marker TTL are
honoured on buckets with `kv_history` greater
than 1.  Without it, such a server raises short per-key TTLs to
the marker TTL at ingest, and an expiring key on a
history-keeping bucket rolls back to an older revision instead of
disappearing.


Once the support probe confirms the option (and a short-TTL canary
key verifies the broker actually honours it), every usrloc row
write carries a native per-key TTL derived from the row's contact
expiry (plus the reclamation slack), so expired registrations
disappear on their own; the periodic cleanup scan (the reaper)
remains active as a backstop and stays authoritative for rows
that are not TTL-eligible (mixed-expiry multi-contact rows and
rows containing permanent contacts).


The option requires a NATS server built with the
*allow_msg_ttl_below_marker* stream config
option and a libnats that exposes `kvConfig.AllowMsgTTLBelowMarker`.
Neither is in a released nats-server or nats.c; both exist only as
patched builds.  A stock server rejects
the unknown field at bucket creation: the module probes exactly
that — the create is retried without the option, a warning is
logged, and expiry stays reaper-only, the same behaviour as with
this parameter off.  The probe outcome is reported at startup.


This parameter only takes effect when the bucket is first
created; when binding to a pre-existing bucket, the bucket's
backing-stream configuration decides (a warning is logged if it
lacks the option).  The bucket is created with a 30-second
delete-marker TTL (the option requires one), which shapes how
long delete markers stay visible to watchers.


*Default value is "0" (off).*


```opensips title="Set kv_ttl_below_marker parameter"
...
modparam("cachedb_nats", "kv_ttl_below_marker", 1)
...
```


#### require_secure_url (integer)


Strict security mode for the connection URL.  The registration
bucket is a PII / lawful-intercept-relevant store (subscriber
IP, user-agent, call-id, path) and NATS KV has no per-key ACL,
so a plaintext `nats://` URL or one without
credentials always draws a loud startup warning.  With this set
to `1` the module *refuses to
start* instead: use `tls://` with an
authenticated account and one bucket per trust domain.


Recommended *usrloc production profile*:
`require_secure_url=1` together with
`require_usrloc_safe_bucket=1`.  The default
stays `0` for lab / development brokers and
for generic (non-PII) cachedb use.


*Default value:* `0`
(warn only).


```opensips title="Set require_secure_url parameter"
...
modparam("cachedb_nats", "require_secure_url", 1)
...
```


#### require_usrloc_safe_bucket (integer)


Strict bucket-shape mode.  Binding to a pre-existing bucket
whose backing stream carries a non-zero `MaxAge`
would silently expire *all* keys, including
permanent contacts (`expires==0`); by default
this is detected once at startup and warned about loudly.  With
this set to `1` the module *refuses to
start* instead -- recreate the bucket with
`MaxAge=0` (`kv_ttl=0`) and
migrate, per the migration guide.


*Default value:* `0`
(warn only).


```opensips title="Set require_usrloc_safe_bucket parameter"
...
modparam("cachedb_nats", "require_usrloc_safe_bucket", 1)
...
```


#### fts_json_prefix (string)


Key name prefix that marks JSON documents for the search index
kept by the optional *cachedb_nats_fts* module (see
[JSON Search Index](#json-search-index)).  Documents stored under
other keys are still available through the normal KV operations but
are not indexed.  Has no effect when *cachedb_nats_fts* is not
loaded.


*Default value is "json_".*


```opensips title="Set fts_json_prefix parameter"
...
modparam("cachedb_nats", "fts_json_prefix", "usrloc.")
...
```


#### kv_watch (string)


A key pattern for the KV watcher (see [KV Watcher](#kv-watcher)).
Setting at least one pattern starts the watcher process; with no
pattern there is no watcher, no *E_NATS_KV_CHANGE* event and no
cross-instance index updates.


Patterns use NATS wildcards on dot-separated tokens: `>` matches the
rest of the key (`usrloc.>` watches every key under `usrloc.`,
and `>` alone watches the whole bucket), and `*` matches exactly one
token.  Wildcards must be whole tokens, so a prefix such as `json_`
cannot be watched as `json_>`; watch `>` or use a dotted prefix.


The parameter may be set more than once; all patterns are watched
through one subscription.


*Default value is "NULL" (watcher disabled unless
at least one kv_watch pattern is configured).*


```opensips title="Set kv_watch parameter"
...
modparam("cachedb_nats", "kv_watch", "usrloc.>")
modparam("cachedb_nats", "kv_watch", "json.>")
...
```


#### TLS configuration


NATS-side TLS for *cachedb_nats* is
configured via OpenSIPS's central *tls_mgm*
module — the same way *proto_tls*,
*event_rabbitmq*,
*rest_client*, and other TLS-using modules
do it.  *cachedb_nats* does not carry its
own `tls_*` modparams.


To use TLS, define a *tls_mgm* client
domain named `"nats"` and set `nats_url` to
`tls://` URLs.  The server list derived from
`cachedb_url` is always plaintext, so it cannot be
used for TLS.


```opensips title="tls_mgm-driven NATS TLS"
loadmodule "tls_mgm.so"
modparam("tls_mgm", "client_domain", "nats")
modparam("tls_mgm", "certificate", "[nats]/etc/opensips/nats-cert.pem")
modparam("tls_mgm", "private_key", "[nats]/etc/opensips/nats-key.pem")
modparam("tls_mgm", "ca_list",     "[nats]/etc/opensips/nats-ca.pem")
modparam("tls_mgm", "verify_cert", "[nats]1")

loadmodule "tls_openssl.so"

loadmodule "cachedb_nats.so"
modparam("cachedb_nats", "cachedb_url", "nats://nats.example.org:4222/")
modparam("cachedb_nats", "nats_url", "tls://nats.example.org:4222")
```


Plaintext-only deployments (`nats://` URLs)
don't need *tls_mgm* loaded —
*cachedb_nats* declares it
`DEP_SILENT` and only attempts the lookup
when a `tls://` URL is actually used.
Operators who configure `tls://` without a
`tls_mgm` "nats" domain see a clear error
at connect time pointing at the missing config.


*tls_mgm*'s
`ca_directory` field (a directory of PEM
files) is supported: *cachedb_nats* reads
every `.pem` in the directory in
lexicographic order, concatenates the contents in memory,
and hands the result to libnats via the PEM-string API.
This mirrors OpenSSL's
`SSL_CTX_load_verify_locations(NULL, dir)`
semantics.


#### cas_retries (integer)


The former name "nats_cas_retries" is kept as a working
alias; new configurations should use "cas_retries".


Number of compare-and-swap retries used by atomic counter
increments (`cache_add()`) and JSON field
updates (`cache_update()`).  Each retry
costs one round-trip to the NATS server.  When the retry
budget is exhausted the operation is dropped and an
*LM_WARN* is emitted naming the affected
key.


Raised from a hardcoded value of *3*
(which silently dropped increments under as few as 3
concurrent writers) to a default of *10*;
operators on hot-contested keys can raise further.


*Default value is "10".  Minimum bound is 1.*


#### index_resync_on_reconnect (integer)


Whether the KV watcher rebuilds the in-memory search
index in full after each reconnect to NATS.  The
watcher subscribes with `UpdatesOnly`,
so writes made by sibling instances while this process
was disconnected are never delivered live.  The
stale-entry self-heal in
`nats_cache_query` only evicts index
entries the KV store reports as gone; it cannot
discover a key that was never indexed locally.  The
default is therefore on, so the index always converges
after an outage.


Set to **0** only in
large-index or hot-reconnect deployments that cannot
afford the O(N) bulk rebuild on every reconnect; bound
the staleness window with
`index_resync_interval_secs` (the
periodic resync) instead, since per-query
self-heal does not recover missed inserts.


Ignored when
the *cachedb_nats_fts* module is not loaded.


*Default value is "1".*


#### index_resync_interval_secs (integer)


Periodic full rebuild of the in-memory search index.
Belt-and-braces upper bound on per-process index
staleness regardless of reconnect cadence or self-heal
pace.  Skipped silently while NATS is disconnected.
Runs in the dedicated "NATS Reaper" module
process, not the shared core timer process.


Set to a value <= the longest tolerable staleness
window in deployments where the lazy self-heal pace is
insufficient.  Each tick costs one
`kvStore_WatchAll` snapshot drain.


Ignored when
the *cachedb_nats_fts* module is not loaded.


*Default value is "0" (disabled).*


#### drain_timeout_ms (integer)


The former name "cdb_drain_timeout_ms" is kept as a working
alias; new configurations should use "drain_timeout_ms".


Shutdown drain timeout in milliseconds for the shared
*lib/nats* connection pool.
Controls how long
`nats_pool_finalize` waits for
in-flight publishes / requests to complete before
forcibly closing connections.  Cross-DC deployments
with high RTT may need to extend the budget; the
underlying setting is shared with
*event_nats* (last writer wins).


*Default value is "5000" ms.*


#### reconnect_wait_ms (integer)


The former name "reconnect_wait" is kept as a working
alias; new configurations should use "reconnect_wait_ms".


The time in milliseconds to wait between reconnection attempts when
the NATS connection is lost.  Applies to the shared connection pool
managed by *lib/nats*.


*Default value is "2000" ms.*


```opensips title="Set reconnect_wait_ms parameter"
...
modparam("cachedb_nats", "reconnect_wait_ms", 1000)
...
```


#### max_reconnect (integer)


Maximum number of reconnection attempts during
`child_init`.  Once the initial connection is
established, the nats.c library handles runtime reconnection
autonomously with no limit.  This parameter affects only the startup
retry loop, not runtime resilience.


*Default value is "60" attempts.*


```opensips title="Set max_reconnect parameter"
...
modparam("cachedb_nats", "max_reconnect", 30)
...
```


#### reap_interval (integer)


The former name "nats_reap_interval" is kept as a working
alias; new configurations should use "reap_interval".


Period, in seconds, of the reaper pass that CAS-prunes expired
bindings from the bucket.  The reaper is the module's single
expiry mechanism, so this periodic prune is what guarantees an
expired binding is physically reclaimed.  The value must be
**> 0**; a non-positive value is
refused at startup (it would leave expired bindings
unreclaimed).


The pass runs in a dedicated "NATS Reaper" module
process, so a full-bucket scan at scale never stalls the shared
core timer process that other modules' timers depend on.


*Default value is "30" (seconds).*


#### reap_grace (integer)


The former name "nats_reap_grace" is kept as a working
alias; new configurations should use "reap_grace".


Clock-skew slack, in seconds, applied to every expiry decision
(the write-side expiry hygiene, the read-side filter and the
reaper).  A binding is treated as expired only once it is more
than `reap_grace` seconds past its TTL, so
a node whose clock leads its peers never deletes or hides another
node's still-live registration.  Set this to at least the real
maximum clock skew between the nodes sharing the bucket.


*Default value is "5" (seconds).*


#### expired_linger (integer)


The former name "nats_expired_linger" is kept as a working
alias; new configurations should use "expired_linger".


How long, in seconds, an *expired* registration
record stays physically present in the bucket after it stops being
served.  This is a retention-policy knob with
**zero effect on call routing**: once
a contact's time is up (plus the `reap_grace`
clock-skew margin) it is never used again, whatever this is set to.


**0** (the default) deletes expired
records as promptly as possible — on the next cleanup-scan pass.  A value such as **30**
keeps each expired record around for ~30 more seconds, which is
useful when troubleshooting registration problems (the record stays
visible to `nats kv get` and
`nats_kv_history`) and damps delete/re-create
churn from endpoints that flap around their expiry time.


Cost of raising it: bucket size — roughly
`expired-records-per-second × linger` extra
records resident at any time.  A re-registration during the linger
window simply overwrites the lingering record; phones are never
locked out by it.  Range 0–86400; out-of-range values refuse
startup.


*Default value is "0" (reclaim as soon as
possible).*


#### max_value_size (integer)


The former name "nats_max_value_size" is kept as a working
alias; new configurations should use "max_value_size".


Maximum stored value size, in bytes, for a usrloc row.  An
oversize row is detected before the CAS write and the offending
contact's save fails cleanly — never a silent truncation or
corruption.  Set this to the deployment's real per-message cap
(and no larger than the stream's `max_msg_size`).
A value **<= 0** disables the guard.


*Default value is "1048576" (1 MiB, the
NATS `max_payload` default).*


#### kv_op_timeout_ms (integer)


Per-operation timeout, in milliseconds, for KV get/put/update
calls issued from a SIP worker (e.g. the usrloc read/write path),
so a slow-but-connected broker cannot block a worker for the full
library default (5 s).  The usrloc update path performs two
synchronous round-trips per REGISTER, so the per-REGISTER worst
case is roughly twice this value.  A value
**<= 0** removes the cap (cnats
library default applies).


*Default value is "1000" (ms; bounds the
per-REGISTER worst case at ~2 s).*


### Exported Functions


#### nats_kv_history(key, result_pvar)


Retrieves the revision history for a KV key and stores it as a JSON
array string in *result_pvar*.  Each array element
is an object with the fields *rev* (revision
number, integer), *value* (the stored string at
that revision), and *ts* (Unix timestamp of the
revision in nanoseconds).


The depth of history available depends on the
`kv_history` bucket setting.  With the default of
5, up to five past values are returned per key in reverse
chronological order (most recent first).


This function can be used from any route.


Parameters:


- **key** (string) —
KV key to retrieve history for.  May contain pseudo-variables.
- **result_pvar** (writable pvar) —
Pseudo-variable to receive the JSON history array.


Return values:


- **1** — history retrieved successfully.
- **-1** — error (NATS failure or allocation error).
- **-2** — key not found or no history available.


```opensips title="nats_kv_history usage"
...
nats_kv_history("usrloc.alice", $var(hist));
if ($retcode == 1) {
    # $var(hist) = [{"rev":3,"value":"sip:alice@192.0.2.1","ts":1700000003},
    #               {"rev":2,"value":"sip:alice@192.0.2.2","ts":1700000002},
    #               {"rev":1,"value":"sip:alice@192.0.2.3","ts":1700000001}]
    xlog("history for alice: $var(hist)\n");
}
...
```


#### nats_kv_get(bucket, key, value_pvar, [revision_pvar])


Reads a key from the JetStream KV bucket and stores its value
in *value_pvar*.  The optional
*revision_pvar* receives the current
revision number; pass it to a subsequent
`nats_kv_update` call to perform a
Compare-And-Swap update.


The bucket must already exist.  At
`child_init` time the module creates the
bucket named by the `kv_bucket` modparam; if
you call `nats_kv_get` with a different
bucket name that bucket must have been pre-created out of
band (e.g. via the `nats` CLI or another
opensips instance).


**CAS contract for
`revision_pvar`:** the wrapper
populates the script var with both string and integer views
so it can drive a subsequent
`nats_kv_update` CAS.  NATS revisions are
64-bit; the OpenSIPS script integer type is 32-bit.  In the
(unrealistic) case that a key passes
`INT_MAX` revisions the wrapper logs a
`WARN` and the truncated value will fail any
subsequent CAS.


Return values:
**1** success;
**-1** error (no NATS connection,
bucket missing, etc);
**-2** key not found.


```opensips title="nats_kv_get usage with CAS read"
$var(rev) = 0;
if (nats_kv_get("calls", "$ci", $var(state), $var(rev))) {
    xlog("call $ci is in state $var(state) at rev $var(rev)\n");
}
```


#### nats_kv_put(bucket, key, value)


Unconditionally writes *value* at
*key* in *bucket*.  Any
concurrent writer's revision is overwritten.  Use
`nats_kv_update` instead when you need to
preserve optimistic-concurrency semantics.


Return values:
**1** success;
**-1** error.


#### nats_kv_update(bucket, key, value, expected_rev)


Compare-And-Swap update: writes
*value* at *key* only
if the bucket's current revision for that key equals
*expected_rev*.  Read the rev with
`nats_kv_get`; pass it back here.


**expected_rev** accepts both a
literal integer and a script variable (e.g.
`$var(rev)`).  When passing a variable the
var must have been written by
`nats_kv_get` /
`nats_kv_revision` -- those wrappers
mark the var with the int type flag the OpenSIPS fixup engine
requires.


Return values:
**1** CAS succeeded;
**-1** error (connection,
permissions, malformed publish, etc — *not*
retryable);
**-2** CAS mismatch — the key's
current revision is not *expected_rev*; a
concurrent writer beat us, so re-read the revision and retry.
The two are now cleanly separated: -2 is returned only for a
genuine revision conflict (the broker's
*wrong last sequence* / jsErrCode 10071),
while any other failure is -1, so a CAS retry loop cannot spin
on a non-retryable error.  In script,
*retcode* is FALSE for both -1 and -2; if
you need to distinguish them inspect `$retcode`
directly.


```opensips title="Idempotent state transition with CAS"
$var(rev) = 0;
if (!nats_kv_get("calls", "$ci", $var(s), $var(rev)))
    return;

if (!nats_kv_update("calls", "$ci", "ringing", $var(rev))) {
    xlog("CAS failed: someone else updated $ci, rc=$retcode\n");
    # caller can retry, surface 503, etc.
}
```


#### nats_kv_delete(bucket, key)


Removes *key* from
*bucket*.  Subsequent
`nats_kv_get` on the same key returns -2
(not found).  Past revisions remain visible to
`nats_kv_history` until the bucket's
history window rolls them off.


Return values:
**1** success;
**-1** error.


#### nats_kv_revision(bucket, key, revision_pvar)


Convenience wrapper around `nats_kv_get`
that fetches only the current revision number, without
copying the value out.  Same int-type contract on the
returned var as
`nats_kv_get` -- safe to drive
`nats_kv_update`.


Return values:
**1** success;
**-1** error;
**-2** key not found.


### CacheDB Operations


All standard OpenSIPS CacheDB script functions are supported.  The
engine identifier in every call must match the group name used in
`cachedb_url` (default: *nats*).


#### KV Key Validation


NATS KV keys may contain only letters, digits and the characters
`.` `_` `-` `/` `\` `=`, must not be empty, and must not start or
end with a dot or contain two dots in a row.  Dots separate tokens
(`call.abc123`, `counter.calls.alice`).  An operation with an invalid
key fails with -1 and an error in the log.


SIP values rarely fit these rules: a Call-ID usually contains `@`,
and an E.164 user part starts with `+`.  Hash such values before
using them in a key, for example `"call.$(ci{s.md5})"`.


#### cache_store — KV put


Stores a string value under the given key in the NATS KV bucket.
The key must consist of valid NATS subject tokens (alphanumeric,
hyphens, underscores, and dots as separators; no spaces or colons).
If the key already exists it is overwritten.


When the key begins with `fts_json_prefix` and the
value is a valid JSON object, the document is parsed and added to the
in-process search index so that it becomes immediately queryable via
`cache_query`.


```opensips title="cache_store with nats"
...
# Plain key-value
cache_store("nats", "call.$(ci{s.md5})", "$fu|$tu");

# JSON document (auto-indexed because key starts with "json_")
cache_store("nats", "json.user.alice",
    "{\"name\":\"alice\",\"domain\":\"example.com\",\"status\":\"active\"}");
...
```


#### cache_fetch — KV get


Retrieves the current value of a key from the NATS KV bucket and
stores it in the given pseudo-variable.  Returns 1 on success, -2
if the key does not exist, and -1 on error.


```opensips title="cache_fetch with nats"
...
cache_fetch("nats", "call.$(ci{s.md5})", $var(call_info));
if ($retcode == -2) {
    xlog("no active call record for $ci\n");
}
...
```


#### cache_remove — KV delete


Removes a key from the NATS KV bucket.  The operation is a soft
delete that creates a deletion tombstone while preserving revision
history.  Use the *KV PURGE* raw query command to
permanently remove a key and its full history.


```opensips title="cache_remove with nats"
...
cache_remove("nats", "call.$(ci{s.md5})");
...
```


#### cache_add — atomic counter increment


Atomically increments an integer counter stored in the KV bucket.
The operation uses compare-and-swap (CAS) with up to `cas_retries` retry
attempts, safely handling concurrent increments from multiple OpenSIPS
worker processes.  If the key does not yet exist it is created with
an initial value equal to *increment*.


The counter is stored as a plain decimal integer string in the KV
bucket.  The *expires* argument is accepted for
API compatibility but does not set a per-key TTL (NATS KV TTL is
bucket-wide; see `kv_ttl`).


```opensips title="cache_add with nats"
...
cache_add("nats", "counter.calls.$(fU{s.md5})", 1, 0);
cache_counter_fetch("nats", "counter.calls.$(fU{s.md5})", $var(call_count));
xlog("$fU has $var(call_count) active calls\n");
...
```


#### cache_sub — atomic counter decrement


Atomically decrements an integer counter.  Equivalent to
`cache_add` with a negated increment value.
Uses the same `cas_retries` budget as `cache_add` (default 10).


```opensips title="cache_sub with nats"
...
cache_sub("nats", "counter.calls.$(fU{s.md5})", 1, 0);
...
```


#### cache_counter_fetch — read counter value


Reads the current integer value of a counter key.  Returns 1 on
success (counter value in pvar), -2 if the key does not exist, and
-1 on error.


```opensips title="cache_counter_fetch with nats"
...
cache_counter_fetch("nats", "counter.calls.$(fU{s.md5})", $var(n));
if ($var(n) > 5) {
    sl_send_reply(503, "Too Many Calls");
    exit;
}
...
```


### JSON Search Index


When the optional [cachedb_nats_fts](../cachedb_nats_fts/README.md)
module is loaded, JSON documents stored under keys that begin with
`fts_json_prefix` are indexed in shared memory: every top-level
*string* field becomes a *field:value* entry pointing at the
document key.  Numbers, booleans and nested values are not indexed.


The index answers the CacheDB `query()` and `update()` calls that
OpenSIPS modules make with non-key filters, using equality matching
only.  There is no script function for it: `cache_store`,
`cache_fetch` and `cache_raw_query` do not consult the index.
Without *cachedb_nats_fts*, those calls accept only single
primary-key equality filters (the form usrloc uses to load a
record), which go straight to `kvStore_Get`; any other filter is
rejected with an error.


**Index lifecycle:**


- *Startup:* the first SIP worker scans the bucket and indexes every
key that matches `fts_json_prefix`.  All processes share the result.
- *Live updates:* with `kv_watch` set, the watcher process applies
every put, delete and purge to the index, including writes made by
other OpenSIPS instances.  Without a watcher, the index only sees
this instance's own writes.
- *Reconnect:* after a reconnect the watcher rebuilds the index from
the bucket (`index_resync_on_reconnect`, on by default).
`index_resync_interval_secs` adds an optional periodic rebuild.


Results are capped by the *cachedb_nats_fts* `fts_max_results`
parameter.


### KV Watcher


When at least one `kv_watch` pattern is set, the module forks one
dedicated *NATS Watcher* process.  It subscribes to the matching keys
of the bucket and, for every change:


- raises the *E_NATS_KV_CHANGE* event (see
[Exported Events](#exported-events)) with the key, the operation,
the value (for puts) and the revision;
- updates the *cachedb_nats_fts* index, if that module is loaded.


The watcher only reports changes made while it is subscribed.  After
a disconnect it waits for the connection, re-subscribes and (with the
index loaded) rebuilds the index, but changes made while it was
disconnected do not raise *E_NATS_KV_CHANGE*; see
[Limitations](#limitations).


### Raw Query Commands


The module exposes NATS KV administrative operations via the standard
CacheDB `cache_raw_query` interface.  The
following commands are supported:


#### KV KEYS


Lists all keys currently present in the KV bucket.  The result is
stored in the provided pseudo-variable as a comma-separated string
of key names.


```opensips title="*KV KEYS* raw query"
...
cache_raw_query("nats", "KV KEYS", $var(keys));
xlog("all KV keys: $var(keys)\n");
...
```


#### KV PURGE <key>


Permanently removes a key and its entire revision history from the
KV bucket.  Unlike a soft delete (which leaves a deletion tombstone),
a purge is irreversible and frees the storage used by all historical
revisions.


```opensips title="*KV PURGE* raw query"
...
cache_raw_query("nats", "KV PURGE json.user.alice");
...
```


#### KV BUCKET INFO


Returns a JSON object describing the KV bucket configuration:
bucket name, replication factor, history depth, TTL, and the
backing JetStream stream name.


```opensips title="*KV BUCKET INFO* raw query"
...
cache_raw_query("nats", "KV BUCKET INFO", $var(info));
xlog("bucket info: $var(info)\n");
...
```


### Map Operations


The module supports composite *key:subkey*
addressing for reading and writing individual fields of JSON
documents stored in the KV bucket.  These operations are accessible
via the column-oriented CacheDB API functions
(`map_get`, `map_set`,
`map_remove`) which are used internally by
OpenSIPS modules such as *usrloc* when configured
with a CacheDB backend.


**map_get** — retrieves the JSON
document at *key* and returns its top-level
fields as separate columns in a *cdb_res_t*
result set.


**map_set** — reads the existing JSON
document at *key* (or starts from an empty
object), merges the provided field-value pairs, and writes the
result back using CAS for consistency.


**map_remove** — reads the existing
JSON document, removes the named field (subkey), and writes the
result back.  If no fields remain after removal the entire key is
deleted from the bucket.


### Exported MI Functions


The observability commands (`nats_reg_*`,
`nats_stream_*`, `nats_kv_keys`)
default to structured JSON output and can render their result table
as *CSV* (RFC 4180: CRLF records, header first,
quote-and-double escaping) or *plain text*
(TAB-separated lines, "# "-prefixed header) instead:
pass `format=csv` / `format=txt`
as a filter key on the list commands, or as an optional trailing
parameter on `nats_reg_summary` /
`nats_reg_show` /
`nats_stream_info` (e.g.
`nats_reg_show alice@example.com csv`; the
parameter also accepts `csv;eol=lf;header=0`).
The formatted table is returned as a single `data`
string inside the usual JSON-RPC envelope — line endings survive
JSON escaping exactly, so
`| jq -r '.result.data'` yields clean CSV/text
while counts such as `matched` stay directly
accessible as JSON.  Options: `eol=lf` (default is
CRLF), `header=0`.  An unrecognized format value
refuses the command rather than silently falling back to JSON.


The examples below show a small sample deployment (two subscribers
of `example.com`: alice with a Yealink and a
Zoiper contact, bob with a Grandstream) against the default
`opensips` bucket.  *Every example
invocation is executed verbatim against a live broker by the
sip_e2e suite* (case `096_readme_mi_examples`,
which registers exactly this population and asserts the stable
parts of these outputs) — timestamp, sequence and size fields
naturally vary.


#### nats_kv_status


Returns a JSON object with the current KV bucket configuration
and NATS connection state.  Useful for monitoring and diagnostics.


Response fields:


- **bucket** (string) —
name of the configured KV bucket.
- **replicas** (integer) —
configured replication factor.
- **history** (integer) —
configured history depth per key.
- **ttl** (integer) —
configured bucket TTL in seconds (0 = no expiry).
- **connected** (string) —
*yes* if the NATS connection pool is currently
connected, *no* otherwise.


```bash title="nats_kv_status MI call"
## opensips-cli -x mi nats_kv_status
{
    "bucket": "opensips",
    "replicas": 3,
    "history": 5,
    "ttl": 0,
    "connected": "yes"
}
```


#### nats_cdb_stats


Returns a snapshot of the cachedb_nats counter set,
summed across the per-process slots maintained in
shared memory.  Used for alerting and capacity
planning; see the usrloc playbook
([usrloc storage playbook](#operator-playbook-nats-as-backend-store-for-usrloc)) for
recommended thresholds.


Counters in the response:


- *cas_retry* — total CAS
retries across all `cache_add`
/ `cache_sub` /
`cdbf.update` calls.  Bumped
once per failed
`kvStore_Update`.
- *cas_exhausted* — total
cdbf calls that ran out of
`cas_retries` attempts and
dropped the write.  Should be 0 in steady state;
any non-zero value means writes were lost.
- *create_doc* — total times
`nats_cache_update` synthesised
a seed document and called
`kvStore_CreateString` (the
insert path).
- *index_miss_kv* — query/update
found a key in the in-memory search index but the
KV store said NOT_FOUND.  Flags index staleness,
typically from a sibling-instance delete.
Sustained non-zero values indicate cross-instance
churn worth investigating.


It also carries the `contacts_pruned` counter
(individual expired bindings removed by the reaper's survivor-writes;
`rows_reaped` counts whole rows) and the
`reap_last_*` gauges — bucket-wide registration
totals recorded by the reaper's periodic pass at zero extra broker
cost: `reap_last_run` (epoch) /
`_ms` / `_keys` /
`_aors` / `_contacts` /
`_active` / `_permanent` /
`_due`.  These refresh every
`reap_interval` seconds and are the
recommended monitoring feed for registration counts (poll this, not
`nats_reg_summary`, on large buckets).


```bash title="nats_cdb_stats MI call"
## opensips-cli -x mi nats_cdb_stats
{
    "cas_retry": 0,
    "cas_exhausted": 0,
    "create_doc": 2,
    "index_miss_kv": 0,
    "fastfail_rejected": 0,
    "op_failed": 0,
    "watcher_restarts": 0,
    "watcher_handle_leaks": 0,
    "nul_fields_rejected": 0,
    "poison_values_rejected": 0,
    "value_oversize_rejected": 0,
    "rows_reaped": 0,
    "contacts_pruned": 0,
    "reap_last_run": 1783008230,
    "reap_last_ms": 9,
    "reap_last_keys": 2,
    "reap_last_aors": 2,
    "reap_last_contacts": 3,
    "reap_last_active": 3,
    "reap_last_permanent": 0,
    "reap_last_due": 0,
    "tbm_requested": 1,
    "tbm_probe_state": 2,
    "tbm_canary_verdict": 1,
    "tbm_canary_last": 1783008228,
    "tbm_canary_failures": 0
}
```


#### nats_reg_summary


High-level registration totals, computed by scanning the KV bucket
(the source of truth — in full-sharing-cachedb mode usrloc's own
`ul_dump` is empty by design, because records are
freed from memory after every flush).  Reports AoR and contact
counts split by state: *active* (would be served:
unexpired, or within the `reap_grace` margin),
*expired* (still stored — lingering per
`expired_linger`, or awaiting cleanup) and
*permanent*, plus the soonest upcoming expiry and
scan cost.  With the optional `domains`=1 parameter
it adds a per-domain breakdown (the part after the last
"@" of each AoR, compared case-insensitively).


The scan costs one round-trip per stored AoR; on very large buckets
prefer the free `reap_last_*` gauges in
`nats_cdb_stats` for monitoring, and reserve this
command for interactive use.


```bash title="nats_reg_summary MI call"
## opensips-cli -x mi nats_reg_summary domains=1
{
    "bucket": "opensips",
    "aors": 2,
    "contacts": 3,
    "active_contacts": 3,
    "expired_contacts": 0,
    "permanent_contacts": 0,
    "soonest_expiry": 1783008325,
    "soonest_expiry_in": 118,
    "scanned_keys": 2,
    "other_docs": 0,
    "scan_ms": 14,
    "domains": [{
        "domain": "example.com",
        "aors": 2, "contacts": 3, "active_contacts": 3
    }]
}
```


```bash title="nats_reg_summary as CSV"
## opensips-cli -x mi nats_reg_summary domains=1 format=csv
{
    "bucket": "opensips", ...,
    "format": "csv",
    "data": "scope,domain,aors,contacts,active,expired,permanent\r\ntotal,,2,3,3,0,0\r\ndomain,example.com,2,3,3,,\r\n"
}
```


#### nats_reg_list


Per-AoR registration listing with filtering, sorting and pagination.
Takes one optional `filter` string of
";"-separated `key=value` pairs:


- `aor=<glob>` — shell-style
wildcard over the AoR (e.g.
`aor=*@example.com`)
- `domain=<host>` —
case-insensitive exact match on the AoR's domain
part
- `ua=<substring>` /
`contact=<substring>` — substring match
over a contact's user-agent / contact URI
- `state=active|expired|permanent|all`
— rows having at least one contact in that state; default
`active`
- `expiring_within=<secs>` —
rows whose next expiry is at most this far away
- `min_contacts=<n>` — rows
holding at least n stored contacts
- `sort=aor|expiry|contacts|last_mod`
(+ `desc=1`) — `expiry` puts
whatever dies next first; ties always break by AoR ascending, so
pagination is deterministic
- `limit=<n>` (default 50,
hard cap 200 — MI datagram size) and
`offset=<n>`


An unknown key or malformed value refuses the whole command (a
mistyped filter must never silently list the wrong subset).


```bash title="nats_reg_list MI call"
## opensips-cli -x mi nats_reg_list 'domain=example.com;sort=expiry;limit=2'
{
    "matched": 2, "returned": 2, "offset": 0,
    "scanned_aors": 2, "scan_ms": 12,
    "aors": [{
        "aor": "alice@example.com",
        "contacts": 2, "active": 2, "expired": 0, "permanent": 0,
        "expires_next": 1783008325, "expires_in": 118,
        "last_mod": 1783008207
    }, {
        "aor": "bob@example.com",
        "contacts": 1, "active": 1, "expired": 0, "permanent": 0,
        "expires_next": 1783011805, "expires_in": 3598,
        "last_mod": 1783008207
    }]
}
```


```bash title="nats_reg_list as CSV (find every Yealink)"
## opensips-cli -x mi nats_reg_list 'ua=Yealink;format=csv'
{
    "matched": 1, "returned": 1, "offset": 0, ...,
    "format": "csv",
    "data": "aor,contacts,active,expired,permanent,expires_next,expires_in,last_mod\r\nalice@example.com,2,2,0,0,1783008325,118,1783008207\r\n"
}
```


#### nats_reg_show


Full detail of one AoR: every stored contact with all its attributes
(contact URI, expires, q, callid, cseq, user-agent, socket, received,
path, flags, last_mod, ...), each annotated with its computed
`state` and `expires_in`, plus the
row's KV metadata (revision, created timestamp,
`row_exp`, `schema_version`) — the
support view for "what exactly does the cluster believe about
this subscriber?".


```bash title="nats_reg_show MI call"
## opensips-cli -x mi nats_reg_show alice@example.com
{
    "aor": "alice@example.com",
    "key": "json_alice=40example.com",
    "revision": 2, "created": 1783008207,
    "row_exp": 1783008325, "schema_version": 1,
    "contacts": [{
        "id": "c2lwOmFsaWNlQDEwLjAuMC4xOjUwNjA=",
        "contact": "sip:alice@10.0.0.1:5060",
        "expires": 1783011805, "ua": "Yealink T54W",
        "state": "active", "expires_in": 3598, ...
    }, {
        "id": "c2lwOmFsaWNlQDEwLjAuMC4yOjUwNjA=",
        "contact": "sip:alice@10.0.0.2:5060",
        "expires": 1783008325, "ua": "Zoiper 5",
        "state": "active", "expires_in": 118, ...
    }]
}
```


```bash title="nats_reg_show as CSV"
## opensips-cli -x mi nats_reg_show alice@example.com csv
{
    "aor": "alice@example.com", ..., "revision": 2,
    "format": "csv",
    "data": "aor,id,contact,state,expires,expires_in,q,cseq,callid,ua,sock,received,path,flags,cflags,last_mod\r\nalice@example.com,...,sip:alice@10.0.0.1:5060,active,...\r\n..."
}
```


#### nats_stream_list


Lists the JetStream streams on the connected server: name, message
and byte counts, subject and consumer counts, storage type.  A KV
bucket's backing stream (`KV_<bucket>`) also
reports the derived `kv_bucket` name, so operators
can think in bucket terms.  Optional `filter`
string (";"-separated `key=value`):
`name=<glob>`, `kv=1` (KV
backing streams only), `limit` (default 50, cap
200) and `offset`.  Results sort by name, so
pagination is deterministic.


```bash title="nats_stream_list MI call"
## opensips-cli -x mi nats_stream_list 'kv=1'
{
    "matched": 1, "returned": 1, "offset": 0,
    "streams": [{
        "name": "KV_opensips", "kv_bucket": "opensips",
        "messages": 2, "bytes": 1044,
        "subjects": 2, "consumers": 1, "storage": "file"
    }]
}
```


#### nats_stream_info


Full configuration and state of one stream — the direct operator
check of a registration bucket's backing-stream expiry
preconditions: `max_age_s` must be 0 (a non-zero
stream MaxAge silently expires permanent contacts), with
`max_msgs_per_subject` showing the KV history
depth.  State reports messages, bytes, first/last
sequence, subject count, deleted count and consumers.


```bash title="nats_stream_info MI call"
## opensips-cli -x mi nats_stream_info KV_opensips
{
    "name": "KV_opensips", "kv_bucket": "opensips",
    "config": {
        "subjects": ["$KV.opensips.>"],
        "storage": "file", "retention": "limits", "replicas": 1,
        "max_msgs_per_subject": 1, "max_age_s": 0,
        "allow_msg_ttl": true, "subject_delete_marker_ttl_s": 30
    },
    "state": {
        "messages": 2, "bytes": 1044,
        "first_seq": 1, "last_seq": 3,
        "subjects": 2, "deleted": 1, "consumers": 1
    }
}
```


```bash title="nats_stream_info as plain text (cut/awk-ready)"
## opensips-cli -x mi nats_stream_info KV_opensips txt
{
    "name": "KV_opensips", "kv_bucket": "opensips",
    "format": "txt",
    "data": "# field\tvalue\r\nname\tKV_opensips\r\nkv_bucket\topensips\r\nstorage\tfile\r\n...\r\nallow_msg_ttl\t1\r\nsubject_delete_marker_ttl_s\t30\r\n..."
}
```


#### nats_kv_keys


Lists the LIVE keys of a KV bucket — server-side delete markers are
never listed, so what this returns is what a reader can actually
Get.  Optional `filter` string:
`bucket=<name>` (default: the module's
`kv_bucket`), `key=<glob>`,
`detail=1` (adds revision / created / value size
for each RETURNED key — one extra round-trip per key, bounded by
the limit cap), `limit` (default 50, cap 200) and
`offset`.  Keys sort by name.


Read-only by construction: the bucket is *bound*,
never created, so a mistyped bucket name returns
"no such bucket" instead of materializing an empty
stream on the server.


```bash title="nats_kv_keys MI call"
## opensips-cli -x mi nats_kv_keys 'key=json_alice*;detail=1'
{
    "bucket": "opensips", "live_keys": 2,
    "matched": 1, "returned": 1, "offset": 0,
    "keys": [{
        "key": "json_alice=40example.com",
        "revision": 2, "created": 1783008207, "size": 731
    }]
}
```


### Exported Events


#### E_NATS_KV_CHANGE


Raised by the KV watcher thread for every mutation received from
the NATS KV bucket.  This event allows OpenSIPS routing scripts to
react to changes made by any client in the cluster — not just
changes made through OpenSIPS itself.


The event is raised with the following parameters:


- **key** (string) —
the KV key that was modified.
- **operation** (string) —
the type of mutation: *put* (value created or
updated), *delete* (soft delete tombstone), or
*purge* (hard delete with history removal).
- **value** (string) —
the new value of the key.  Only present for
*put* operations; absent for
*delete* and *purge*.
- **revision** (integer) —
the NATS JetStream sequence number (revision) of this mutation.
Revisions are monotonically increasing and globally ordered
within the KV bucket.


```opensips title="Subscribing to E_NATS_KV_CHANGE in opensips.cfg"
...
startup_route {
    subscribe_event("E_NATS_KV_CHANGE", "nats:opensips-events");
}

event_route[E_NATS_KV_CHANGE] {
    xlog("KV change: key=$param(key) op=$param(operation) rev=$param(revision)\n");
    if ($param(operation) == "put") {
        xlog("  new value: $param(value)\n");
    }
}
...
```


#### Cluster Configuration


For production deployments a three-node NATS JetStream cluster is
recommended.  The `nats_url` parameter is a seed
list used only for the initial bootstrap connection.  After the first
connection is established, nats.c discovers all cluster peers via
the INFO protocol gossip mechanism
(*connect_urls*) and maintains the full topology
automatically.  Adding or removing nodes from the cluster is
transparent to the OpenSIPS module.


Use DNS hostnames rather than IP addresses in
`nats_url`.  The nats.c library calls
`getaddrinfo` on each reconnection attempt,
so DNS-based hostnames automatically pick up topology changes such
as node replacement or IP address reassignment.


The `kv_replicas` parameter controls the JetStream
replication factor and only takes effect when the KV bucket is first
created.  A value of 3 on a three-node cluster tolerates one-node
failure without data loss or availability impact.  To change the
replication factor on an existing bucket use the NATS CLI:


```bash
nats kv update opensips --replicas=3
```


The internal reconnection loop is unlimited at runtime: nats.c will
never permanently remove a server from its routing pool.  The
`max_reconnect` parameter only limits the number of
retries during the initial connection phase in
`child_init`.


```opensips title="Three-node cluster configuration"
...
loadmodule "cachedb_nats.so"

modparam("cachedb_nats", "cachedb_url", "nats://nats-1:4222/")
modparam("cachedb_nats", "nats_url",
    "nats://nats-1:4222,nats://nats-2:4222,nats://nats-3:4222")
modparam("cachedb_nats", "kv_bucket",   "opensips")
modparam("cachedb_nats", "kv_replicas", 3)
modparam("cachedb_nats", "kv_history",  1)
modparam("cachedb_nats", "kv_ttl",      0)
modparam("cachedb_nats", "kv_watch",    "usrloc.>")
modparam("cachedb_nats", "kv_watch",    "json.>")
...
```


```opensips title="Single-node development configuration"
...
loadmodule "cachedb_nats.so"

modparam("cachedb_nats", "cachedb_url", "nats://127.0.0.1:4222/")
modparam("cachedb_nats", "kv_replicas", 1)
modparam("cachedb_nats", "kv_watch",    ">")
...
```


### Operator playbook: NATS as backend store for usrloc


This section is for operators deploying
`usrloc` in
`cluster_mode = full-sharing-cachedb` with
`cachedb_nats` as the cachedb engine.  In
this configuration JetStream KV is the authoritative store
for AoR / contact records:


- SIP REGISTER → `save("location")`
→ usrloc → CacheDB `update()` → a compare-and-swap create or
update of one JSON document per AoR, stored under the key
`<fts_json_prefix><encoded AoR>`.
- SIP lookup → usrloc → CacheDB `query()` with a primary-key filter
→ one `kvStore_Get`.  No index is involved.
- Process restart → nothing to reload: every lookup reads the bucket.


Multiple OpenSIPS instances pointing at the same bucket
converge on a consistent view of usrloc state without any
clusterer-driven binary replication; the only
synchronization between writers is JetStream's per-key CAS.


#### Topology by DC count


**Single DC, single broker**


`kv_replicas = 1`,
`kv_history = 1`,
File storage.  Use this for development and
small single-DC deployments.  Restart hydration
is fast (one round-trip per key).


**Single DC, clustered NATS (3 servers)**


`kv_replicas = 3`.  Survives a
single broker failure with no AoR loss.  Recommended
production baseline.  Inter-broker replication is
NATS-internal and adds ~1-2 ms to write latency.


**Multiple DCs, one global bucket**


Recommended only when the inter-DC RTT is
< 50 ms and concurrent same-AoR writes are
rare.  Every `kvStore_UpdateString`
CAS pays full inter-DC RTT.  The jittered
backoff bounds the worst-case at ~50 ms across
the default `nats_cas_retries = 10`
budget; raise the budget if cross-DC
contention drives `cas_exhausted`
above zero.


**Multiple DCs, bucket per DC + leafnodes**


Lower per-write latency at the cost of cross-DC
visibility being asynchronous.  Each DC reads
its local bucket; cross-DC AoR resolution
happens out of band (e.g.  GSLB or local-fail-
through-to-remote logic).  Conflict resolution
becomes operator-defined; the simplest policy is
"the first DC to see a REGISTER owns the AoR."


#### Bucket sizing


- *Storage:*
`File` (default).  Memory storage
loses AoRs on broker restart, defeating the purpose
of using NATS as the backend store.
- *Replicas:* match
broker cluster size up to 3.  Replicas > 3 add
latency without meaningful availability gains for
usrloc workloads.
- *History:*
`kv_history = 1` — required for
on-time native expiry.  A bucket that keeps old
revisions makes an expired key roll back to a
previous version instead of disappearing, so the
module disables server-side auto-expiry on it and
falls back to the periodic cleanup scan (correct,
but up to `reap_interval`
seconds late).  Use a history-keeping bucket only
when routing logic genuinely needs
`nats_kv_history`, and keep it
OFF the registration bucket if possible.
- *TTL:*
`kv_ttl = 0` (no bucket-wide
max age — it would delete permanent contacts; the
module refuses to start otherwise).  Expired
registrations are removed by the periodic cleanup
scan (`reap_interval`).  With `kv_ttl_below_marker`
on a broker that supports it, eligible registration
writes also carry a server-side TTL, and the scan
remains the safety net.  To keep expired records readable for
a while (forensics), see
`expired_linger`.
- *Max bytes / max age:*
NATS defaults are typically appropriate.  For
bounded environments, size the stream for at least
`(active_aors × avg_doc_size × kv_history)`
bytes.  An average AoR JSON document with a single
contact is roughly 400-600 bytes.


#### Snapshot and restore


JetStream KV buckets are JetStream streams named
`KV_<bucket>` under the hood, so
they snapshot and restore through the standard stream
tooling:


```bash
nats stream snapshot KV_USRLOC ./usrloc-2026-05-08.tar.gz
nats stream restore  KV_USRLOC ./usrloc-2026-05-08.tar.gz
```


Snapshot during a low-traffic window for a
point-in-time copy.  After restore, every connected
OpenSIPS instance must rebuild its in-memory index;
either bounce the instances (cleanest), set
`index_resync_on_reconnect = 1` and
cycle the broker, or set
`index_resync_interval_secs` to a
value ≤ the longest tolerable staleness window so
the periodic timer pulls the new state.  The lazy
self-heal in `nats_cache_query`
only evicts stale entries it already holds; it does
not add keys introduced by the restore, so an explicit
rebuild (or the periodic timer) is required, not merely
faster.


#### Scale tuning: PK fast path and the optional index


usrloc's read and write path is exclusively
*primary-key*: both
`cdb_load_urecord` (read) and
`cdb_flush_urecord` (write) build
`cdb_filter_t` with
`is_pk = 1`.  The in-memory JSON-FTS
search index that `cachedb_nats`
maintains is therefore *optional weight*
for any deployment that uses the module purely as a
usrloc backend.  Two operator knobs control the index
behaviour:


***cachedb_nats_fts* module (load / don't load)**


The former `enable_search_index`
modparam is gone: loading the optional
*cachedb_nats_fts* module IS the
enable switch for the JSON-FTS index.  Pure usrloc
workloads simply do not load it — PK-only operation,
no index SHM, no watcher-feed CPU.


**`index_buckets` (cachedb_nats_fts parameter, int, default 4096)**


Hash bucket count for the JSON-FTS index.
Init code rounds the value up to the next
power of two with a floor of 16
(`NATS_IDX_SHARDS`) so the
hash can use a bitmask AND.  Each doubling
halves average chain length for ~32 KB more
SHM.  Only relevant when
the *cachedb_nats_fts* module loaded;
ignored otherwise.  Recommended values:
4096 at ≤ 20k AoRs, 16384 at 100k, 65536
at 1MM.


**PK fast path (`nats_cache_query`)**


Always on; no modparam.  When the filter is a
single is_pk=1 condition with
`val.is_str = 1` and
`op = CDB_OP_EQ`, the function
encodes the value via
`_kv_encode_key`, builds the
prefixed target_key, calls
`kvStore_Get`, parses the
returned JSON, and returns one row.  No mutex
acquired, no chain walk.  Falls through to the
index path for any non-PK or multi-condition
filter.


Scaling guidance:


- *Pure usrloc workloads at any scale:*
do not load *cachedb_nats_fts*.
No index memory and no per-write index update.
- *Mixed workloads (modules issuing non-key CacheDB
queries on the same bucket):* load
*cachedb_nats_fts* and tune `index_buckets`.
The KV watcher always runs in its own dedicated
child process, so it never competes with SIP
request handling in the workers.
- *1MM endpoints:* the index off
is essentially mandatory (~250 MB SHM saved per
instance); the watcher would otherwise saturate
one core at the steady-state event rate.  If
the index is still kept on for mixed-workload
reasons, budget one core for the dedicated
watcher process.
- *10MM endpoints:* the index
off is mandatory.  Sharding remains required for
SIP-side reasons.


#### SHM allocator selection


OpenSIPS defaults the shared-memory allocator to
`Q_MALLOC`, which is single-mutex
and serialises every `shm_malloc`
/ `shm_free` across all worker
processes.  At populated index sizes (10k+ AoRs) and
sustained REGISTER churn this becomes the dominant
tail-latency contributor: the per-CAS path triggers
3-5 SHM allocations to add a doc to the in-memory
JSON-FTS index, and Q_MALLOC's lock pinches every
worker on every alloc.


Recommendation: launch `opensips`
with `-s HP_MALLOC` to select
`HP_MALLOC` ("optimized for shared
memory multiprocessing").  Bench results from the
session that introduced this playbook:


- 10k AoRs, single instance:
p99 84 ms → 54 ms (−36%);
p50 35 ms → 21 ms (−40%).
- 20k AoRs, single instance:
p99 185 ms → 142 ms (−23%);
p50 41 ms → 25 ms (−39%).


Combined with the targeted-index-remove change
(`nats_json_index_remove_fields`),
the cumulative p99 improvement at 20k AoRs is −63%
versus the start of the perf series.  Effective RPS
climbs accordingly.


Pkg memory (`-k`) is per-process
and not contended, so the default
`Q_MALLOC` there is fine.  Only
the SHM allocator (`-s`) needs the
switch.


#### MI counters and alert thresholds


`nats_cdb_stats` returns a snapshot
of four atomic per-process counters tracking the
cachedb path:


- `cas_retry` — bumped per
failed UpdateString / CreateString race.  Steady
non-zero values are normal under contention; a
sustained high rate suggests
`cas_retries` is too low
or the CAS hot key is genuinely contended.
- `cas_exhausted` — bumped when
a CAS gave up after exhausting the budget.
*Should always be 0* in a
healthy deployment; non-zero indicates lost
writes.  Page on
`delta(cas_exhausted) > 0`
over any reasonable interval.
- `create_doc` — bumped per
first-insert path (`kvStore_CreateString`
of a seed doc).  Roughly equal to the rate of
genuinely new AoRs.  A spike usually maps to a
burst of new registrations.
- `index_miss_kv` — bumped when
`nats_cache_query` hit an
index entry whose KV key was already deleted.
Self-heal evicts the entry; a non-zero rate is
expected in multi-instance deployments.  A
*large* sustained rate
suggests cross-instance churn higher than the
self-heal pace; consider enabling
`index_resync_interval_secs`.


#### Migration from full-sharing-cachedb-cluster


The legacy mode `full-sharing-cachedb-cluster`
additionally relies on clusterer to broadcast cachedb
invalidation events.  With cachedb_nats, the KV watcher
thread + stale-entry self-heal subsume that role.  To
migrate:


1. Take a snapshot of the current bucket (above).
2. On each instance, change `cluster_mode`
to `full-sharing-cachedb`;
keep the existing `location_cluster`
(clusterer is still required for shtag /
pinging coordination).
3. Roll instances one at a time.  Each rolled
instance rebuilds its index from KV on
`child_init` and is
immediately consistent with peers still on the
old mode.
4. After all instances are migrated, the
clusterer-driven cachedb broadcast capabilities
become idle and can be removed at the next
maintenance window.


#### Optional knobs introduced in this work


See [usrloc storage: scale tuning](#scale-tuning-pk-fast-path-and-the-optional-index) for
loading *cachedb_nats_fts* and
`index_buckets`, the two scale-tuning
knobs.  The remaining knobs are listed below.


**`index_resync_on_reconnect` (int, default 1)**


Whether the KV watcher rebuilds the in-memory
index in full after each reconnect.  The watcher
uses `UpdatesOnly`, so writes made
by sibling instances during an outage are never
delivered live; the query-path self-heal only evicts
stale entries it already holds and cannot recover a
missed insert, so the default is on for correctness.
Set to 0 only for large indexes that cannot afford
the O(N) rebuild per reconnect, paired with
`index_resync_interval_secs`.


**`index_resync_interval_secs` (int, default 0 = off)**


Periodic full rebuild on a timer.  Belt-and-
braces upper bound on per-process index
staleness.  Skipped silently while NATS is
disconnected.


**`cas_retries` (int, default 10)**


CAS budget per
`nats_cache_update` /
`nats_cache_counter_op`
call.  Combined with the jittered
backoff (50 us base, 5 ms cap),
the worst-case per-call latency is
~50 ms.  Raise only if
`cas_exhausted` shows
non-zero rates; lowering risks lost writes
under contention.
### Limitations


- **`kv_ttl` must be 0.**  Keys expire through the reaper, up to
`reap_interval` + `reap_grace` seconds (35 s by default) after their
expiry time.
- **Bucket settings apply only when the module creates the bucket.**
`kv_replicas`, `kv_history` and `kv_ttl` are ignored for an existing
bucket.  An existing bucket with a maximum age only produces a warning,
unless `require_usrloc_safe_bucket` is set.
- **Native per-key expiry needs patched software.**
`kv_ttl_below_marker` needs a nats-server and a libnats that support
*allow_msg_ttl_below_marker*; no release of either does.  Native TTLs
are whole seconds, and apply only to rows whose contacts share one
expiry time.
- **`kv_history` above 1 disables native expiry** on that bucket;
expiry falls back to the reaper.
- **The `expires` argument of `cache_store` and `cache_add` is
ignored.**  Only usrloc rows expire.
- **Keys** are at most 511 bytes and may contain only letters, digits
and `.` `_` `-` `/` `\` `=` (see [KV Key Validation](#kv-key-validation)).
- **Values:** usrloc rows are limited by `max_value_size` (1 MiB by
default); JSON documents over 1 MiB or nested deeper than 64 levels are
rejected.
- **Revisions are 32-bit in the script.**  `nats_kv_update` compares
against a revision truncated to 32 bits, so a compare-and-swap fails
once a key passes revision 2 147 483 647.
- **`nats_kv_*` functions on another bucket** need that bucket to exist
already.
- **Filters:** without *cachedb_nats_fts*, only single primary-key
equality filters are accepted; with it, only equality filters.
- **usrloc NAT pinging does not work with this backend.**  In
`full-sharing-cachedb` mode, nathelper asks usrloc for the contacts to
ping with an `aorhash` range query, which this module rejects, so no
contacts are returned for pinging.
- **The KV watcher misses changes made during a disconnect.**  It
re-subscribes for new changes only, so *E_NATS_KV_CHANGE* is not raised
for keys changed while it was disconnected.  (The *cachedb_nats_fts*
index is rebuilt after a reconnect and is not affected.)
- **TLS needs `nats_url`.**  The server list derived from
`cachedb_url` is always plaintext.
- **MI listings** return at most 200 rows; `nats_reg_list` scans at
most 100 000 records and `nats_reg_summary` counts at most 64 domains.
Per-process statistics cover process numbers below 512.
- **No per-key access control.**  NATS KV cannot restrict access per
key, so separate trust domains need separate buckets (and NATS
accounts).
- **Latency:** each REGISTER makes two synchronous round trips to the
broker; one bucket shared across data centres is recommended only
below about 50 ms round-trip time.


<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
