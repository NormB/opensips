/*
 * nats_pool.h — Shared NATS Connection Pool
 *
 * Module:  lib/nats (static library linked into event_nats and cachedb_nats)
 *
 * Provides a single, shared NATS connection per OpenSIPS worker process.
 * Both event_nats and cachedb_nats register during mod_init (pre-fork);
 * after fork, each worker calls nats_pool_get() to obtain a per-process
 * natsConnection handle.  JetStream and KV store handles are similarly
 * cached per-process.
 *
 * Key constants:
 *   NATS_POOL_MAX_KV_BUCKETS — maximum cached KV bucket handles
 *
 * TLS configuration is sourced from the OpenSIPS tls_mgm "nats"
 * client domain at connect time -- see the doc block above
 * nats_pool_set_tls_api() below for the operator-facing pattern.
 *
 * Thread model:
 *   - nats_pool_register() is called from mod_init (single-threaded,
 *     pre-fork).  It is NOT safe to call after forking.
 *   - nats_pool_get(), nats_pool_get_js(), nats_pool_get_kv() are called
 *     from child_init or from OpenSIPS worker context (post-fork).  Each
 *     worker has its own connection — no cross-process sharing.
 *   - nats_pool_is_connected(), nats_pool_get_reconnect_epoch(), and
 *     nats_pool_get_server_info() are safe to call from any OpenSIPS
 *     process context (they read process-local or atomic state).
 *   - nats_pool_destroy() is called from mod_destroy (single worker).
 *   - The nats.c library spawns internal threads for reconnection.
 *     Reconnection callbacks registered with nats.c run on those threads
 *     and must NOT call OpenSIPS APIs (LM_*, pkg_malloc, etc.).
 *     They use only write(STDERR_FILENO) and atomic increments.
 *
 * Epoch-based reconnection detection:
 *   The pool maintains an atomic reconnect epoch counter, incremented by
 *   the nats.c reconnected callback (running on a library thread).
 *   Modules compare their saved epoch against nats_pool_get_reconnect_epoch()
 *   to detect that a reconnection occurred, then refresh stale handles
 *   (KV stores, JetStream contexts) without requiring explicit callbacks.
 *   This pattern avoids calling OpenSIPS APIs from nats.c threads.
 */

#ifndef NATS_POOL_H
#define NATS_POOL_H

#include <nats/nats.h>

/*
 * Pull in the libnats function-pointer table.  Every NATS source file
 * that includes nats_pool.h gets nats_dl transitively, so direct calls
 * like natsConnection_Connect(...) are written nats_dl.natsConnection_Connect(...)
 * and dispatched through the dlopen-populated table.  See nats_dl.h for
 * the architectural rationale and lifecycle.
 */
#include "nats_dl.h"

/*
 * TLS configuration source.
 *
 * NATS modules no longer carry their own TLS modparams.  When the
 * operator wants TLS for a NATS connection (URL starts with tls://),
 * lib/nats looks up the OpenSIPS tls_mgm client domain named "nats"
 * and reads cert / CA / key / verify / cipher settings from there.
 * That domain MUST be defined in opensips.cfg before any NATS module
 * connects, e.g.:
 *
 *   loadmodule "tls_mgm.so"
 *   modparam("tls_mgm", "client_domain", "nats")
 *   modparam("tls_mgm", "certificate", "[nats]/etc/opensips/nats-cert.pem")
 *   modparam("tls_mgm", "private_key", "[nats]/etc/opensips/nats-key.pem")
 *   modparam("tls_mgm", "ca_list",     "[nats]/etc/opensips/nats-ca.pem")
 *   modparam("tls_mgm", "verify_cert", "[nats]1")
 *   loadmodule "tls_openssl.so"   # or tls_wolfssl.so
 *
 *   loadmodule "cachedb_nats.so"
 *   loadmodule "event_nats.so"
 *   loadmodule "nats_consumer.so"
 *
 * Plaintext deployments (URL starts with nats://) don't need tls_mgm
 * loaded at all -- the NATS user modules declare it as DEP_SILENT.
 *
 * The user modules call nats_pool_set_tls_api(&binds) in mod_init
 * after binding tls_mgm via load_tls_mgm_api(); lib/nats's connect
 * path then uses that API to look up the "nats" domain.
 */

/* Maximum number of KV bucket handles cached per process. */
#define NATS_POOL_MAX_KV_BUCKETS 16

/*
 * Register interest in the NATS connection pool.
 *
 * Must be called from mod_init (pre-fork, single-threaded).  Multiple
 * modules may register; the pool merges configurations by taking the
 * superset of server URLs and warns on conflicting TLS settings.
 *
 * @param url             Comma-separated NATS server URLs
 *                        (e.g., "tls://h1:4222,tls://h2:4223").  TLS
 *                        material comes from tls_mgm via
 *                        nats_pool_set_tls_api(), not a parameter here.
 * @param module          Module name string, used in log messages
 *                        (e.g., "event_nats" or "cachedb_nats").
 * @param reconnect_wait  Milliseconds to wait between reconnect attempts.
 *                        Pass 0 to use the default (2000 ms).
 * @param max_reconnect   Maximum number of reconnect attempts before
 *                        giving up.  Pass 0 to use the default (60).
 * @return                0 on success, -1 on error (logged internally).
 *
 * Thread safety: NOT thread-safe.  Call only from mod_init.
 */
int nats_pool_register(const char *url, const char *module,
                       int reconnect_wait, int max_reconnect);

/*
 * Hand the OpenSIPS tls_mgm bind table to lib/nats.
 *
 * @binds  pointer to a populated `struct tls_mgm_binds` from
 *         load_tls_mgm_api(); lib/nats stores this opaquely (void *
 *         in the public header to avoid pulling tls_mgm/api.h into
 *         every source that uses nats_pool.h) and casts back inside
 *         nats_pool.c.  Pass NULL to clear (used by tests).
 *
 * Must be called BEFORE the first nats_pool_register on a TLS URL.
 * Subsequent calls overwrite the stored pointer; first-non-NULL wins
 * in practice since all NATS user modules read the same tls_mgm
 * instance.
 *
 * Idempotent: calling twice with the same pointer is a no-op.  No
 * effect on plaintext (nats://) URLs.
 */
void nats_pool_set_tls_api(void *binds);

/*
 * Get the shared NATS connection for this worker process.
 *
 * On the first call (from child_init), creates the connection using the
 * merged configuration from all nats_pool_register() calls.  Subsequent
 * calls return the cached handle.  Internally guards nats_Open()
 * to run only once per process.
 *
 * @return  natsConnection pointer on success, NULL on error.
 *
 * Thread safety: Safe to call from any OpenSIPS worker process context.
 *                Each process has its own connection (no sharing).
 */
natsConnection *nats_pool_get(void);

/*
 * Get the shared JetStream context for this worker process.
 *
 * Creates the jsCtx on first call from the shared connection.  Sets up
 * the PublishAsync AckHandler at creation time for asynchronous publish
 * acknowledgment tracking.
 *
 * @return  jsCtx pointer on success, NULL on error.
 *
 * Thread safety: Safe to call from any OpenSIPS worker process context.
 */
jsCtx *nats_pool_get_js(void);

/*
 * Get a KV store handle for a named bucket.
 *
 * Creates the bucket on the NATS server if it does not already exist.
 * Caches handles per bucket name (process-local, up to
 * NATS_POOL_MAX_KV_BUCKETS entries).  Cached handles are automatically
 * invalidated and recreated when a reconnection is detected via the
 * epoch mechanism.
 *
 * @param bucket    Bucket name (must be a valid NATS subject token:
 *                  no dots, colons, or spaces).
 * @param replicas  JetStream replication factor (only used when creating
 *                  a new bucket; existing buckets retain their config).
 * @param history   Number of historical revisions to keep per key
 *                  (only used when creating a new bucket).
 * @param ttl_secs  Bucket-wide TTL in seconds.  Pass 0 for no expiration.
 *                  Only used when creating a new bucket.
 * @return          kvStore pointer on success, NULL on error.
 *
 * Thread safety: Safe to call from any OpenSIPS worker process context.
 */
kvStore *nats_pool_get_kv(const char *bucket, int replicas,
                          int history, int64_t ttl_secs);

/*
 * Destroy the connection pool and release all resources.
 *
 * Drains the connection (flushes pending publishes), closes it, and
 * frees all cached JetStream / KV handles.  Called from mod_destroy
 * during OpenSIPS shutdown.
 *
 * Thread safety: NOT thread-safe.  Call only from mod_destroy
 *                (single process context).
 */
void nats_pool_destroy(void);

/*
 * Drop one registration reference (the counterpart to
 * nats_pool_register).  The pool is torn down only on the last unregister,
 * so the shared connection survives while any loaded NATS module still
 * uses it.  Each module should call this once from its mod_destroy if its
 * nats_pool_register() succeeded.  Prefer this over calling
 * nats_pool_destroy() directly.
 *
 * Thread safety: NOT thread-safe.  Call only from mod_destroy.
 */
void nats_pool_unregister(void);

/*
 * Check whether the pool's NATS connection is currently active.
 *
 * @return  1 if connected, 0 if disconnected or not yet initialized.
 *
 * Thread safety: Safe to call from any OpenSIPS process context.
 *                Reads volatile/atomic state.
 */
int nats_pool_is_connected(void);

/*
 * P8 [R6 / TTL-SOLUTION-SPEC.md §6 TREV-8]: process-global per-message-TTL
 * capability latch (0=UNPROBED, 1=SUPPORTED, 2=UNSUPPORTED; mirrors enum
 * ttl_cap).  Reachable by both the worker (registration write) and the timer
 * process (reaper survivor-write).  The cachedb module computes transitions via
 * _ttl_cap_next() and stores the result with nats_pool_ttl_cap_set(); the pool
 * resets it to UNPROBED on reconnect so capability is re-probed after a failover.
 */
int  nats_pool_ttl_cap(void);
void nats_pool_ttl_cap_set(int cap);

/*
 * P8 [R5 / TTL-SOLUTION-SPEC.md §3]: enable per-message TTL (AllowMsgTTL +
 * SubjectDeleteMarkerTTL) on a KV bucket's backing stream, idempotently.
 * Returns 1 = enabled/already, 0 = unavailable (latch UNSUPPORTED, reaper-only),
 * -1 = transient (leave UNPROBED, retry).  The caller drives the latch from this.
 */
int nats_pool_kv_supports_ttl(const char *bucket);

/*
 * P11b [REV-25]: read the bound bucket's backing-stream MaxAge (ns) into *out_ns.
 * Used at child_init to detect a PRE-EXISTING bucket that already carries a
 * non-zero MaxAge (which would silently expire permanent contacts).  Returns
 * 0 on success (*out_ns set), -1 if the stream info is unavailable.
 */
int nats_pool_bucket_maxage_ns(const char *bucket, int64_t *out_ns);

/*
 * Returns non-zero once any module has registered the pool
 * (nats_pool_register).  Lets a module choose to contribute a default URL
 * only when nothing else has registered, instead of injecting a spurious
 * server into another module's pool.
 */
int nats_pool_is_registered(void);

/*
 * Get a human-readable list of discovered NATS server URLs.
 *
 * Intended for MI status reporting.  Returns a comma-separated string
 * of server URLs that the nats.c library has discovered (including
 * cluster peers found via INFO gossip).
 *
 * @return  Pointer to a process-local string.  Do not free.
 *          Returns "not connected" if the connection is not active.
 *
 * Thread safety: Safe to call from any OpenSIPS process context.
 */
const char *nats_pool_get_server_info(void);

/*
 * Get the current reconnect epoch.
 *
 * The epoch is an atomic counter incremented each time the nats.c
 * library reports a successful reconnection (from its internal thread).
 * Modules save the epoch value when they obtain a handle (KV store,
 * JetStream context) and later compare against this function's return
 * to detect that a reconnect occurred and the handle may be stale.
 *
 * See also: nats_con_refresh_kv() in cachedb_nats.h, which uses this
 * epoch to transparently refresh KV handles.
 *
 * @return  Current epoch counter value (starts at 0, never wraps in
 *          practice).
 *
 * Thread safety: Safe to call from any thread (atomic read).
 */
int nats_pool_get_reconnect_epoch(void);

/*
 * Return 1 if the calling OpenSIPS process should initialize NATS,
 * 0 otherwise.
 *
 * NATS is initialized in:
 *   - SIP workers (UDP and TCP workers, rank >= 1)
 *   - HTTPD/MI process (rank == PROC_MODULE, -2)
 *
 * NATS is NOT initialized in:
 *   - Attendant (rank == PROC_MAIN, 0)
 *   - Timer (rank == PROC_TIMER, -1)
 *   - TCP-main (rank == PROC_TCP_MAIN, -4) — holds TLS/OpenSSL state
 *     in a single process post-refactor, and does not handle SIP routing
 *   - Module-exported processes (negative rank, self-initialize)
 *
 * Post TCP/TLS refactor, TCP workers no longer hold OpenSSL state
 * (TLS runs only in TCP-main), so they are safe to co-host nats.c.
 *
 * This helper is the single source of truth for the admission rule;
 * both event_nats and cachedb_nats must call it rather than open-coding
 * the check.
 *
 * Callable from any OpenSIPS process context.  Pure function — no
 * locking, no globals.
 */
int nats_pool_should_init(int rank);

/*
 * Drain timeout for the shutdown drain in nats_pool_destroy(), in
 * milliseconds.
 *
 * Each module loaded against lib/nats may override this from its own
 * mod_init (e.g. via a modparam) to tune how long shutdown waits for
 * outstanding NATS publishes — including JetStream async-pub acks —
 * to flush before destroying the connection.  The default of 5000 ms
 * is appropriate for low-latency local brokers; deployments hitting
 * a remote broker over higher-latency links may want to raise this
 * to avoid silent drops on shutdown.
 *
 * Read from any thread; write only from mod_init (pre-fork, single-
 * threaded), so no synchronization is required.
 */
extern int nats_pool_drain_timeout_ms;

/* Shared modparam setter for the drain timeout: both event_nats and
 * cachedb_nats register it (INT_PARAM|USE_FUNC_PARAM) so the value is merged
 * by MAX across modules instead of last-writer-wins.  `type` is modparam_t
 * (== unsigned int); spelled out here so this header stays free of the heavy
 * sr_module.h include that the standalone lib unit-tests cannot satisfy. */
int nats_pool_drain_timeout_setter(unsigned int type, void *val);

/*
 * Module-tunable per-operation timeout (ms) for JetStream / KV requests,
 * plumbed into jsOptions.Wait.  0 keeps cnats's 5 s default; set a smaller
 * value (e.g. cachedb_nats "kv_op_timeout_ms") on hot paths.
 */
extern int nats_pool_kv_op_timeout_ms;

/*
 * Redact userinfo (user[:pass]@) from NATS URL strings before logging.
 *
 * Replaces every "user[:pass]@" segment that appears in the authority
 * section after a "scheme://" prefix with four ASCII asterisks
 * followed by '@'.  Handles comma-separated lists of URLs.  URLs
 * without userinfo are copied unchanged.  Always NUL-terminates @out
 * unless out_sz == 0.
 *
 * (Inline asterisk strings are avoided in this doc-comment because
 *  a literal slash-star sequence inside a slash-star block trips
 *  gcc's -Wcomment "nested comment" warning under -Werror.)
 *
 * @param url      Source URL string.  May be NULL.
 * @param out      Destination buffer.  Must be non-NULL if out_sz > 0.
 * @param out_sz   Size of @out in bytes.  If 0, no write is performed.
 *
 * Examples (REDACTED == four asterisks):
 *   nats://user:pass@h:4222         becomes  nats://REDACTED@h:4222
 *   nats://h:4222                   unchanged
 *   nats://h1,nats://u:p@h2         becomes  nats://h1,nats://REDACTED@h2
 *
 * Thread safety: Pure function on caller-provided memory; safe anywhere.
 */
void nats_redact_url(const char *url, char *out, size_t out_sz);

/*
 * Validate a NATS subject for use as an outbound publish target.
 *
 * Rejects empty/NULL, embedded NUL, control/whitespace chars, NATS
 * wildcards ('*' and '>'), and ill-formed dot structure (leading,
 * trailing, or consecutive dots).  Length bound is the caller's job
 * (this function is content-only).
 *
 * @param s   Subject bytes (NOT required to be NUL-terminated).
 * @param len Length of @s in bytes.
 *
 * @return 0 if valid for publish, -1 otherwise.
 *
 * Thread safety: Pure function on caller-provided memory.
 */
int nats_validate_publish_subject(const char *s, int len);

/*
 * Unified validator for the NATS subject/key/name strings used across the
 * modules.  All modes reject an empty/NULL string, an embedded NUL, control
 * chars (< 0x20, 0x7f) and whitespace.  Mode-specific rules:
 *
 *   NATS_VALIDATE_PUBLISH_SUBJECT  concrete publish target: no wildcards;
 *                                  no leading/trailing/consecutive dots.
 *   NATS_VALIDATE_FILTER_SUBJECT   subscribe filter: dots AND wildcards
 *                                  ('*','>') allowed.
 *   NATS_VALIDATE_STREAM_NAME      single token: no '.', '*', '>', '/', '\'.
 *   NATS_VALIDATE_KV_KEY           dots allowed; ':' rejected (reserved as
 *                                  the legacy map separator); no wildcards.
 *
 * Pure function, content-only (re-scans every call -- see the security note
 * on nats_validate_publish_subject).  Returns 0 if valid, -1 otherwise.
 */
typedef enum {
	NATS_VALIDATE_PUBLISH_SUBJECT = 0,
	NATS_VALIDATE_FILTER_SUBJECT,
	NATS_VALIDATE_STREAM_NAME,
	NATS_VALIDATE_KV_KEY,
} nats_validate_mode_t;

int nats_validate(const char *s, int len, nats_validate_mode_t mode);

/*
 * Register a callback for JetStream publish-ack outcomes.
 *
 * The cnats library invokes the AckHandler from a library-internal
 * I/O thread.  Modules that want to observe per-ack success/failure
 * (e.g. to bump nats_stats counters) register a callback here.
 * The callback runs on the cnats thread and MUST NOT call any
 * OpenSIPS APIs (LM_*, pkg_malloc, etc.); it may only do atomic
 * memory operations and async-signal-safe I/O.
 *
 * @param cb  Function called as cb(success) where success != 0 if
 *            the JS broker acked the publish, 0 on error.  Pass
 *            NULL to clear any previously-registered callback.
 *
 * Thread safety: Set once during mod_init, before fork.  The
 * callback pointer is read on the cnats thread without locking.
 */
void nats_pool_set_pub_ack_cb(void (*cb)(int success));

#endif /* NATS_POOL_H */
