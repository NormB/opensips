#ifndef NATS_CONNECTION_H
#define NATS_CONNECTION_H

#include <nats/nats.h>

/* TLS configuration for NATS connections */
typedef struct nats_tls_opts {
    char *ca;               /* CA cert path */
    char *cert;             /* Client cert path */
    char *key;              /* Client key path */
    char *hostname;         /* Expected server hostname */
    int skip_verify;        /* Skip cert verification */
    int skip_openssl_init;  /* Skip OpenSSL init (for OpenSIPS) */
} nats_tls_opts;

/* Reconnection/disconnection callback types */
typedef void (*nats_reconnected_cb)(void *closure);
typedef void (*nats_disconnected_cb)(void *closure);

/* Maximum registered callbacks */
#define NATS_POOL_MAX_CALLBACKS 8
#define NATS_POOL_MAX_KV_BUCKETS 16

/*
 * Register interest in a NATS connection pool.
 * Called from mod_init (pre-fork). Multiple modules can register.
 * The pool merges configs: uses superset of servers, warns on TLS conflict.
 *
 * @param url             Comma-separated server URLs
 *                        (e.g., "tls://h1:4222,tls://h2:4223")
 * @param tls             TLS options (can be NULL for no TLS)
 * @param module          Module name for logging
 * @param reconnect_wait  Reconnect wait in ms (0 = use default 2000)
 * @param max_reconnect   Max reconnect attempts (0 = use default 60)
 * @return 0 on success, -1 on error
 */
int nats_pool_register(const char *url, nats_tls_opts *tls,
                       const char *module, int reconnect_wait,
                       int max_reconnect);

/*
 * Get the shared NATS connection for this worker process.
 * Called from child_init (post-fork). Creates the connection on first call,
 * returns cached handle on subsequent calls.
 * Internally guards nats_OpenWithConfig() to run only once per process.
 *
 * @return natsConnection* on success, NULL on error
 */
natsConnection *nats_pool_get(void);

/*
 * Get the shared JetStream context for this worker process.
 * Creates the jsCtx on first call from the shared connection.
 * Sets up the PublishAsync.AckHandler at creation time.
 *
 * @return jsCtx* on success, NULL on error
 */
jsCtx *nats_pool_get_js(void);

/*
 * Get a KV store handle for a bucket. Creates the bucket if it
 * doesn't exist. Caches handles per bucket name (process-local).
 * Handles are invalidated and recreated on reconnection.
 *
 * @param bucket    Bucket name
 * @param replicas  Replication factor (used only if creating new bucket)
 * @param history   History depth (used only if creating new bucket)
 * @param ttl_secs  Bucket TTL in seconds (0 = no TTL, used only if creating)
 * @return kvStore* on success, NULL on error
 */
kvStore *nats_pool_get_kv(const char *bucket, int replicas,
                          int history, int64_t ttl_secs);

/*
 * Register a reconnected callback. Both modules can register callbacks;
 * all are called when the connection reconnects.
 * Callbacks are used to rebuild search indexes, re-establish watchers, etc.
 *
 * @return 0 on success, -1 if max callbacks reached
 */
int nats_pool_on_reconnect(nats_reconnected_cb cb, void *closure);

/*
 * Register a disconnected callback.
 *
 * @return 0 on success, -1 if max callbacks reached
 */
int nats_pool_on_disconnect(nats_disconnected_cb cb, void *closure);

/*
 * Destroy the connection pool. Called from mod_destroy.
 * Drains and closes the connection, frees all resources.
 */
void nats_pool_destroy(void);

/*
 * Check if pool is currently connected.
 *
 * @return 1 if connected, 0 if disconnected
 */
int nats_pool_is_connected(void);

/*
 * Get the list of discovered server URLs (for MI status reporting).
 * Returns comma-separated string of connected server URLs.
 * The returned string is process-local and must not be freed.
 *
 * @return server URL string, or "not connected"
 */
const char *nats_pool_get_server_info(void);

#endif /* NATS_CONNECTION_H */
