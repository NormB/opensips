# NATS for OpenSIPS — start here

OpenSIPS talks to [NATS](https://nats.io) and its JetStream persistence
layer through four modules. All four share one connection per OpenSIPS
process, provided by the connection pool in this directory
(`libnats_pool.so`).

| Module | Direction | What it gives you |
| ------ | --------- | ----------------- |
| [event_nats](../../modules/event_nats/README.md) | OpenSIPS → NATS | Event Interface transport (`nats:<subject>` sockets), `nats_publish()`, optional JetStream publishing, stream management over MI, core-NATS `subscribe` into script events |
| [cachedb_nats](../../modules/cachedb_nats/README.md) | OpenSIPS ↔ NATS KV | CacheDB backend on a JetStream KV bucket, usrloc `full-sharing-cachedb` storage, KV change events, registration MI views |
| [cachedb_nats_fts](../../modules/cachedb_nats_fts/README.md) | inside OpenSIPS | Optional secondary index for `cachedb_nats` JSON documents; loading it turns non-key queries on |
| [nats_consumer](../../modules/nats_consumer/README.md) | NATS → OpenSIPS | JetStream pull consumers delivered to SIP workers, explicit ack/nak/term, `nats_request()` request/reply (sync and async) |

Pick the modules you need. Any one of them runs on its own, and any
combination shares the same connection. Load order does not matter,
except that `cachedb_nats_fts` must be loaded after `cachedb_nats`.


## Requirements

- **nats-server** with JetStream enabled. Versions 2.10 and 2.11+ are
  tested. KV features that depend on per-message TTLs need 2.11 or
  later; see the `cachedb_nats` documentation for details.
- **libnats** (the [nats.c](https://github.com/nats-io/nats.c) client),
  **3.14 or later**. The modules need the per-key KV TTL API
  (`kvStore_CreateWithTTL`), which first shipped in 3.14. CI builds the
  commit pinned in `scripts/build/install_libnats.sh`, which can also
  build and install it for you:

  ```bash title="Build and install the pinned libnats"
  sudo LIBNATS_TLS=ON sh scripts/build/install_libnats.sh
  ```

- **The libnats you run must match the one you built against.** The
  modules do not link libnats; `lib/nats` loads it with `dlopen()` at
  startup and refuses a library whose major.minor version differs from
  the headers OpenSIPS was compiled with (JetStream option structs change
  size between minor releases). A mismatch stops OpenSIPS with an error
  naming both versions. Rebuild OpenSIPS after upgrading libnats.
- **TLS** needs a libnats built with TLS (`-DNATS_BUILD_WITH_TLS=ON`,
  `LIBNATS_TLS=ON` above) and the `tls_mgm` module; see [TLS](#tls).

If the build cannot find libnats (`pkg-config libnats`), the NATS
modules are skipped and the rest of OpenSIPS builds normally.


## Quick start

Start a broker with JetStream:

```bash title="Local broker"
nats-server -js
```

Then load what you need. This configuration publishes SIP events,
stores cache data in a KV bucket and consumes a work queue, all over one
connection. The KV bucket is created on first start; with a single
broker it must use one replica (the default is three):

```opensips title="All four modules on one broker"
loadmodule "event_nats.so"
modparam("event_nats", "nats_url", "nats://127.0.0.1:4222")

loadmodule "cachedb_nats.so"
modparam("cachedb_nats", "cachedb_url", "nats://127.0.0.1:4222/")
modparam("cachedb_nats", "kv_bucket", "opensips")
modparam("cachedb_nats", "kv_replicas", 1)

loadmodule "cachedb_nats_fts.so"

loadmodule "nats_consumer.so"
modparam("nats_consumer", "bind",
    "id=jobs;stream=JOBS;filter=jobs.>;durable=jobs_worker")

route {
    nats_publish("sip.requests", "$rm $ru");

    cache_store("nats", "call.$(ci{s.md5})", "$fu");

    if (nats_fetch("jobs")) {
        xlog("job $nats_subject: $nats_data\n");
        nats_ack();
    }
}
```

The consumer binds to the stream `JOBS`, which must exist. Create it
with the `nats` CLI or through OpenSIPS once it is running:

```bash title="Create the JOBS stream"
opensips-cli -x mi nats_stream_create JOBS 'jobs.>'
```

Until the stream exists the consumer logs a failed subscribe and keeps
retrying; it binds within a few seconds of the stream appearing.

At startup OpenSIPS logs which libnats it loaded, and each process logs
when it has connected:

```bash title="Startup log"
INFO:core:nats_dl_load: nats_dl: loaded 'libnats.so'; 126 libnats symbols resolved
INFO:core:nats_pool_register: NATS pool: registered by 'event_nats' with 1 server(s), TLS=no, reconnect_wait=2000ms, max_reconnect=60
INFO:core:nats_pool_get: NATS pool: connected to nats://127.0.0.1:4222 (1 server(s) configured)
```

If the broker is down at startup, OpenSIPS still starts. The pool logs
`NATS pool: broker unreachable at startup; continuing degraded with
background connect retries` and connects when the broker appears.


## TLS

TLS is configured in `tls_mgm`, in a client domain that must be named
`nats`. None of the NATS modules has TLS parameters of its own. A
`tls://` server URL switches the connection to TLS; `nats://` URLs ignore
the `nats` domain.

```opensips title="NATS over TLS"
loadmodule "tls_mgm.so"
loadmodule "tls_openssl.so"
modparam("tls_mgm", "client_domain", "nats")
modparam("tls_mgm", "verify_cert",   "[nats]1")
modparam("tls_mgm", "require_cert",  "[nats]1")
modparam("tls_mgm", "certificate",   "[nats]/etc/opensips/tls/client.pem")
modparam("tls_mgm", "private_key",   "[nats]/etc/opensips/tls/client.key")
modparam("tls_mgm", "ca_list",       "[nats]/etc/opensips/tls/ca.pem")
# or a directory of .pem files:
# modparam("tls_mgm", "ca_directory", "[nats]/etc/opensips/tls/ca.d/")

loadmodule "event_nats.so"
modparam("event_nats", "nats_url", "tls://nats-1:4222,tls://nats-2:4222")
```

The settings are applied when the pool connects (`apply_tls_from_mgm()`
in `nats_pool.c`), not when the modules load. There is no silent
downgrade to plaintext. The connection fails with an error naming the
missing piece in any of these cases:

- a `tls://` URL is used and `tls_mgm` is not loaded;
- `tls_mgm` is loaded but has no `nats` client domain;
- the libnats in use was built without TLS.

For a `ca_directory`, `nats_ca_dir.c` reads every `.pem` file in the
directory in name order and passes them to libnats as one PEM bundle
(`natsOptions_SetCATrustedCertificates`), matching OpenSSL's
directory-lookup behaviour.

libnats does its own TLS. Which TLS library it uses is fixed when
libnats is built, and it does not have to match the `tls_openssl` or
`tls_wolfssl` module OpenSIPS uses for SIP. One libnats is loaded per
process. To choose a specific build, set `NATS_DL_LIBNATS_PATH` in
OpenSIPS's environment (for example with `Environment=` in the systemd
unit):

```bash title="Load a specific libnats build"
NATS_DL_LIBNATS_PATH=/opt/libnats-tls/lib/libnats.so.3.15
```

To check which libraries a running instance mapped:

```bash title="Inspect a running instance"
lsof -p "$(pgrep -o opensips)" | grep -E 'libnats|libssl|libwolfssl'
```

`tls_mgm` certificate reloads take effect on the next reconnect.
Switching to a different libnats build needs a restart.

### wolfSSL-backed libnats

Upstream nats.c supports only OpenSSL. A wolfSSL port was proposed in
[nats-io/nats.c#867](https://github.com/nats-io/nats.c/pull/867) and
closed without merge. This tree carries a rebased version of that
change in [patches/](patches/), with its provenance and build recipe.
The patch targets nats.c v3.12.0 and does not apply to the 3.14+
libnats the modules now require; see [Limitations](#limitations).


## How the modules share a connection

Each module calls
`nats_pool_register(const char *url, const char *module, int
reconnect_wait, int max_reconnect)` from `mod_init`, before OpenSIPS
forks. Registrations merge:

- the pool keeps the union of all modules' server URLs (duplicates are
  dropped; past 16 URLs the extras are skipped with a warning);
- for the reconnect settings, the larger value wins, whatever the module
  load order;
- TLS settings are not registration parameters; they come from
  `tls_mgm` (`nats_pool_bind_tls()`).

All four modules self-register. `nats_consumer` has its own `nats_url`
parameter; if that is unset and no other NATS module has registered, it
falls back to `nats://localhost:4222`. It never adds that fallback to a
pool another module has already configured. `tests/test_pool_merge.c`
covers these rules.

After the fork, each process opens its own connection on first use
(`nats_pool_get()`, `nats_pool_get_js()` for JetStream). SIP workers,
module processes and timer processes connect; the attendant and the
TCP main process do not (`nats_rank.c`).

### Handle lifetime and the reconnect epoch

`nats_pool_get_kv()` returns KV handles owned by the pool. A reconnect
marks them stale, and they are destroyed and re-created, so a
`kvStore *` kept across a reconnect is a use-after-free. Code that caches
one tags it with a `nats_epoch_t` (`nats_epoch.h`) and checks it before
use: snapshot, compare with `nats_epoch_current`, re-acquire, and call
`nats_epoch_adopt` only on success. The disconnect and reconnect
callbacks bump the epoch and set the stale flag.


## Behaviour during broker outages

| Situation | What happens |
| --------- | ------------ |
| Broker down at startup | OpenSIPS starts; each process connects in the background (`NATS pool: broker unreachable at startup; ...`). Operations fail fast until then. |
| Connection lost mid-operation | The operation ends at its own timeout; the next one fails fast. A dead broker is detected in about 20 s (10 s pings, 2 outstanding). |
| Broker down when an operation starts | Operations return an error immediately instead of blocking a SIP worker (table below). |
| Broker comes back | KV handles are refreshed, consumer subscriptions are rebuilt (durables resume where they stopped), the KV watcher re-subscribes, and the async RPC inbox is re-created. No restart needed. |
| Stream, consumer or bucket deleted on the server | Ephemeral consumers are re-created automatically. A durable consumer on a deleted stream stays failed until an operator unbinds it and binds it again after re-creating the stream. |

Return values while disconnected:

| Operation | Returns |
| --------- | ------- |
| `cachedb_nats` operations (`cache_*`, `nats_kv_*`, map, raw, query) | `-1` |
| `nats_publish()` (event_nats) and Event Interface publishes | `-1`; the message is counted as failed and dropped |
| `nats_fetch()` / `nats_fetch_batch()` | `-2` |
| `nats_request()`, synchronous | `-3` |
| `nats_request()`, async | `-2` |
| `nats_ack()` and the other ack functions | `-2` |

Outage logging is rate limited: one warning per interval per process,
with per-call details at debug level. The log lines to look for:

| Log line | Meaning |
| -------- | ------- |
| `NATS pool: broker unreachable at startup; continuing degraded with background connect retries` | Started without a broker. |
| `NATS pool: disconnected` | Operations fail fast from here. |
| `NATS pool: reconnected to <url>` | Recovered; handles and subscriptions are rebuilt on next use. |
| `nats_request: NATS disconnected; failing fast instead of blocking <n> ms` | A route called synchronous `nats_request()` during an outage. |
| `watcher: disconnect detected, stopping watcher ...` | The KV watcher paused; it resumes after reconnect. |
| `nats_consumer_proc: consumer for <id> vanished (...); will recreate` | An ephemeral consumer was removed by the server (normal), or a durable was deleted (investigate). |

On a failed call, `cachedb_nats` still leaves the caller's output
arguments in a defined state (result sets initialised, reply pointers
NULL), because usrloc, b2b and the script engine free or read them after
an error. `modules/cachedb_nats/tests/test_query_res_init.c` and
`test_outparam_contracts.c` cover this.

Credentials in server URLs (`nats://user:pass@host`,
`nats://token@host`) are never logged: every log line that prints a URL
passes it through `nats_redact_url()` (`nats_redact.c`), which replaces
the whole user-info part with `[redacted]`, per URL in a seed list. The
connection itself uses the real URL.


## Limitations

These apply to the whole family. Each module's README lists its own.

- **libnats must be 3.14 or later, with the same major.minor as the
  build.** Older libraries lack required symbols; any other major.minor
  is refused at load time. There is no fallback library.
- **One libnats per process.** All connections in an OpenSIPS instance
  use the same library; switching builds needs a restart.
- **wolfSSL on the NATS side is not currently usable.** The vendored
  patch in [patches/](patches/) applies only to nats.c v3.12.0, which
  is older than the minimum libnats. Use an OpenSSL-backed libnats.
- **No packages.** The OpenSIPS packaging does not include the NATS
  modules, and OpenSIPS does not ship libnats. Build from source.
- **Builds skip the NATS modules** (with a `[skip]` build message) when
  libnats is not found. The helper
  script builds libnats only on x86_64 and aarch64 and skips
  cross-compiles.
- **Pool limits:** at most 16 server URLs; at most 16 KV buckets open per
  process, with names up to 127 characters; at most 4096 pending
  asynchronous JetStream publishes per process (a publish then waits up
  to 50 ms and fails).
- **Dead-broker detection takes about 20 seconds.** Operations issued in
  that window wait for their own timeouts.
- **The attendant and TCP main processes have no NATS connection.**
  Script code running there cannot use the NATS functions.


## Developer notes

### Files

| File | Purpose |
| ---- | ------- |
| `nats_pool.c/.h` | Connection pool, JetStream context, KV bucket cache |
| `nats_dl.c/.h` + `nats_dl_table.def` | The `dlopen()` shim. Every libnats function the tree uses is resolved into the `nats_dl` table (one `NATS_DL_FN` line per symbol in the `.def`), so the modules have no link-time libnats dependency. Also checks the libnats version at load. |
| `nats_ca_dir.c/.h` | Loads a `tls_mgm` `ca_directory` as one PEM bundle |
| `nats_epoch.h` | The reconnect-epoch idiom (snapshot / current / adopt / lost) for cached pool handles |
| `nats_rank.c` | `nats_pool_should_init()`: which process ranks connect |
| `nats_redact.c/.h` | Credential redaction for logged URLs |
| `nats_rl.h` | Once-per-interval log gate used by the outage logging policy |
| `nats_str.h` | `str` → bounded NUL-terminated buffer for the libnats C-string edge (keys, subjects); rejects embedded NUL |
| `nats_validate.c/.h` | Subject and KV-key validator used by every publish and KV path |
| `nats_js_opts.h` | Shared JetStream publish options (async queue limits) |
| `Makefile.nats` | `pkg-config` probe that gates the module builds on libnats, plus a compile probe for `kvConfig.AllowMsgTTLBelowMarker` |

The library is built once as `libnats_pool.so` in the modules directory.
The module `.so` files find it through an `$ORIGIN` rpath, so every
loaded module shares one copy of the pool's process-local state.

> [!NOTE]
> Adding or removing a `NATS_DL_FN` entry shifts every later member of
> `nats_dl_funcs_t`, so every consumer, `nats_dl.o` included, must be
> recompiled. The `-MMD` depfiles track `nats_dl_table.def`, so a plain
> `make` does this. A stale `nats_dl.o` inside `libnats_pool.so` makes
> every child process crash at startup.

### Allocator policy

- **pkg** for memory private to one process and owned by its main
  thread: the JSON hot path, MI staging, consumer configuration strings,
  async resume parameters.
- **shm** only for data shared between processes: the search index,
  intern table, rings, RPC slots, statistics, IPC payloads. It is the
  slowest allocator here, so moving private data to shm makes things
  slower.
- **Handing work from a libnats callback thread to a worker** uses
  `shm_malloc` plus `ipc_dispatch_rpc`; both are safe from foreign
  threads. `event_nats_sub.c`'s message callback is the reference.
  `pkg_malloc` and `LM_*` must not be used on those threads.
- **libc `malloc`** is kept in four places: memory owned by libnats
  (its API requires `free()`); thread-local allocations on libnats
  callback threads; large buffers sized by configuration (message-ref
  rows up to about 1.5 MB × 256 handles, worst-case MI listings), since
  pkg pools are sized at fork; and the `lib/nats` files that compile
  standalone for unit tests (`nats_ca_dir.c`, `nats_redact.c`,
  `nats_validate.c`, the `nats_str.h` helpers).

**Strings:** `str` at every OpenSIPS edge; NUL-terminated C strings at
the libnats edge (keys, subjects and bucket names through
`nats_str_to_buf`, which rejects embedded NUL); `(ptr, len)` inside the
JSON layer. Values go through the length-aware `kvStore_Put/Create/Update`,
never the `*String` variants, which stop at the first NUL.

> [!NOTE]
> Any new log statement that prints a URL or server string must pass it
> through `nats_redact_url()` first. `tests/test_redact_url.c` covers
> the redaction rules.

### Tests

| Suite | How to run |
| ----- | ---------- |
| `lib/nats/tests/` | `make -C lib/nats/tests check` (also `check-asan`, `check-tsan`) |
| `modules/<module>/tests/` | `make -C modules/<module>/tests check` for the unit tests |
| `modules/cachedb_nats/tests/sip_e2e/` | `run.sh`: two OpenSIPS instances with usrloc on a shared bucket, driven by SIPp |
| `modules/nats_consumer/tests/` | docker-compose functional and stress suites (`run_all.sh`, `stress_3way.sh`) |
| `lib/nats/tests/test_three_module_e2e.sh` | shared-connection round trip across the modules |
| `lib/nats/tests/test_tls_mgm_smoke.sh` | real TLS handshake through `tls_mgm`, plus failure cases |
| `lib/nats/tests/test_readme_format.sh` | the module READMEs follow the OpenSIPS documentation format |

The end-to-end tests start their own disposable `nats-server` (it must be
in `PATH`) and never touch a broker already running on the host.
`.github/workflows/nats-sanitizers.yml` runs every unit suite under
AddressSanitizer + UBSan and ThreadSanitizer. Tests that deliberately
race or use freed memory are left out of `check-tsan` through each
Makefile's `TESTS_TSAN_SAFE` list.
