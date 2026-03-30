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
 * Key types:
 *   nats_tls_opts  — TLS configuration (CA, client cert/key, hostname)
 *
 * Key constants:
 *   NATS_POOL_MAX_KV_BUCKETS — maximum cached KV bucket handles
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
 * TLS configuration for NATS connections.
 *
 * Passed to nats_pool_register() to configure TLS on the shared connection.
 * All string fields are borrowed pointers (must remain valid for the
 * lifetime of the process).  Pass NULL to nats_pool_register() for
 * plaintext connections.
 */
typedef struct nats_tls_opts {
    char *ca;               /* Path to CA certificate file (PEM).
                             * Used to verify the NATS server certificate. */
    char *cert;             /* Path to client certificate file (PEM).
                             * Required for mutual TLS authentication. */
    char *key;              /* Path to client private key file (PEM).
                             * Must correspond to the client certificate. */
    char *hostname;         /* Expected server hostname for TLS verification.
                             * Required when connecting by IP address, since
                             * nats.c enables host verification by default. */
    int skip_verify;        /* If non-zero, skip server certificate verification.
                             * Use only for development/testing. */
    int skip_openssl_init;  /* If non-zero, tell nats.c to skip OpenSSL_init().
                             * Required when running inside OpenSIPS, which
                             * manages OpenSSL lifecycle via tls_openssl. */
} nats_tls_opts;

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
 *                        (e.g., "tls://h1:4222,tls://h2:4223").
 * @param tls             TLS options, or NULL for plaintext connections.
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
int nats_pool_register(const char *url, nats_tls_opts *tls,
                       const char *module, int reconnect_wait,
                       int max_reconnect);

/*
 * Get the shared NATS connection for this worker process.
 *
 * On the first call (from child_init), creates the connection using the
 * merged configuration from all nats_pool_register() calls.  Subsequent
 * calls return the cached handle.  Internally guards nats_OpenWithConfig()
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
 * Check whether the pool's NATS connection is currently active.
 *
 * @return  1 if connected, 0 if disconnected or not yet initialized.
 *
 * Thread safety: Safe to call from any OpenSIPS process context.
 *                Reads volatile/atomic state.
 */
int nats_pool_is_connected(void);

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

#endif /* NATS_POOL_H */
