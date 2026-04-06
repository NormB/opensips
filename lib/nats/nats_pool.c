/*
 * Copyright (C) 2025 Summit-2026 / nats_connection contributors
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

/**
 * @file nats_pool.c
 * @brief Shared NATS connection pool for OpenSIPS modules.
 *
 * This library provides a single shared NATS connection per OpenSIPS worker
 * process, used by both event_nats.so and cachedb_nats.so.  It is compiled
 * as libnats_pool.a and statically linked into each module via misclibs=.
 *
 * ## Thread model
 *
 * OpenSIPS is a multi-process server.  All public API functions in this file
 * (nats_pool_register, nats_pool_get, nats_pool_get_js, nats_pool_get_kv,
 * nats_pool_destroy, etc.) are called from OpenSIPS process context — either
 * the main attendant (pre-fork, during mod_init) or a worker/timer process
 * (post-fork, during child_init or normal request processing).
 *
 * However, the nats.c library internally creates its own I/O threads for
 * connection management.  The disconnect/reconnect callbacks
 * (_pool_disconnected_cb, _pool_reconnected_cb) and the JetStream async
 * publish ack handler (_js_pub_ack_handler) run on these nats.c-internal
 * threads, NOT on an OpenSIPS process.  This is critical because OpenSIPS
 * APIs (LM_*, pkg_malloc, shm_malloc) depend on per-process state
 * (process_no, pkg memory pool) that does not exist in nats.c threads.
 * Calling them causes SIGABRT.  Only atomic ops, write(), and nats.c APIs
 * are safe in callbacks.
 *
 * ## Design
 *
 * - **Configuration** (pool_cfg) lives in SHM, set pre-fork by
 *   nats_pool_register().  Multiple modules can register; configs are merged.
 * - **Connection state** (_nc, _js, _kv_cache) is process-local, created
 *   post-fork on first access via nats_pool_get().
 * - **KV lazy invalidation**: On reconnect, the _kv_stale atomic flag is set
 *   by the reconnect callback.  The next call to nats_pool_get_kv() detects
 *   this and clears the KV cache, forcing fresh handle creation.  This avoids
 *   calling any OpenSIPS APIs from the callback thread.
 * - **Connection lifetime**: _nc is never destroyed or replaced after
 *   creation (except in nats_pool_destroy at shutdown).  nats.c handles
 *   reconnection internally; all derived objects (_js, kvStore, kvWatcher)
 *   remain valid across reconnects.
 */

#include <string.h>
#include <stdatomic.h>
#include <unistd.h>

#include <nats/nats.h>

#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../ut.h"
#include "nats_pool.h"

/* This is a shared library (lib/nats), not a loadable module.
 * Compiled as libnats_pool.a and linked into event_nats.so
 * and cachedb_nats.so via misclibs= in their Makefiles. */

/* ----------------------------------------------------------------
 * Shared pool configuration (shm, set pre-fork in mod_init)
 * ---------------------------------------------------------------- */

#define NATS_POOL_MAX_SERVERS 16
#define NATS_POOL_DEFAULT_RECONNECT_WAIT 2000
#define NATS_POOL_DEFAULT_MAX_RECONNECT  60

/**
 * Pool configuration structure, allocated in shared memory.
 * Set during mod_init (pre-fork) and read-only after fork.
 * The only exception is the TLS probe in nats_pool_get() which may
 * rewrite tls:// URLs to nats:// — guarded by a static flag.
 */
typedef struct nats_pool_cfg {
	char *servers[NATS_POOL_MAX_SERVERS]; /* shm-allocated URL strings */
	int   server_cnt;
	int   use_tls;                        /* 1 if any URL starts with tls:// */

	nats_tls_opts tls;                    /* deep-copied into shm */

	int   reconnect_wait;                 /* ms */
	int   max_reconnect;
} nats_pool_cfg;

/* Single shared config — allocated on first register */
static nats_pool_cfg *pool_cfg = NULL;

/* ----------------------------------------------------------------
 * Process-local connection state (set post-fork)
 * ---------------------------------------------------------------- */

static int              _lib_initialized = 0;   /* nats_Open called? */
static natsConnection  *_nc = NULL;              /* NATS connection handle */
static jsCtx           *_js = NULL;              /* JetStream context */
static atomic_int       _connected = 0;          /* 1 if connected */
static atomic_int       _reconnect_epoch = 0;    /* bumped on each reconnect */

/* KV handle cache — maps bucket names to kvStore pointers.
 * Process-local; invalidated on reconnection via _kv_stale. */
typedef struct {
	char     bucket[128];
	kvStore *kv;
} kv_cache_entry;

static kv_cache_entry _kv_cache[NATS_POOL_MAX_KV_BUCKETS];
static int            _kv_cache_cnt = 0;

/* ----------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------- */

/* shm_strdup provided by ../../ut.h — no local copy needed */

/**
 * Parse comma-separated URL string into pool_cfg->servers[].
 *
 * Each token is trimmed of surrounding whitespace and commas, then
 * shm-allocated.  Sets pool_cfg->use_tls if any URL starts with "tls://".
 *
 * @param url  Comma-separated URL string (e.g. "nats://h1:4222,nats://h2:4222").
 * @return     0 on success, -1 on error (empty string, too many servers, OOM).
 *
 * Thread safety: Called only during mod_init (single-threaded, pre-fork).
 */
static int parse_urls(const char *url)
{
	const char *p, *tok;
	int len;

	if (!url || !*url) {
		LM_ERR("empty URL string\n");
		return -1;
	}

	p = url;
	while (*p) {
		/* skip leading whitespace and commas */
		while (*p == ',' || *p == ' ' || *p == '\t')
			p++;
		if (!*p)
			break;

		tok = p;
		while (*p && *p != ',')
			p++;

		len = (int)(p - tok);
		/* trim trailing whitespace */
		while (len > 0 && (tok[len - 1] == ' ' || tok[len - 1] == '\t'))
			len--;

		if (len <= 0)
			continue;

		if (pool_cfg->server_cnt >= NATS_POOL_MAX_SERVERS) {
			LM_ERR("too many NATS servers (max %d)\n",
				NATS_POOL_MAX_SERVERS);
			return -1;
		}

		pool_cfg->servers[pool_cfg->server_cnt] = shm_malloc(len + 1);
		if (!pool_cfg->servers[pool_cfg->server_cnt]) {
			LM_ERR("shm_malloc for server URL failed\n");
			return -1;
		}
		memcpy(pool_cfg->servers[pool_cfg->server_cnt], tok, len);
		pool_cfg->servers[pool_cfg->server_cnt][len] = '\0';

		/* detect TLS */
		if (len >= 6 &&
		    strncmp(pool_cfg->servers[pool_cfg->server_cnt], "tls://", 6) == 0)
			pool_cfg->use_tls = 1;

		pool_cfg->server_cnt++;
	}

	if (pool_cfg->server_cnt == 0) {
		LM_ERR("no valid NATS server URLs found in '%s'\n", url);
		return -1;
	}

	return 0;
}

/* ----------------------------------------------------------------
 * nats.c callbacks (run on nats.c internal I/O thread)
 *
 * CRITICAL: These callbacks run on a thread created by nats.c, NOT
 * an OpenSIPS process.  OpenSIPS APIs (LM_*, pkg_malloc, shm_malloc)
 * must NOT be called here — they rely on per-process state (process_no,
 * pkg memory pool) that doesn't exist in nats.c's threads.  Calling
 * them causes SIGABRT (free(): invalid pointer).
 *
 * Safe operations in these callbacks:
 *   - C11 atomic ops (atomic_store, atomic_exchange, atomic_fetch_add)
 *   - POSIX write() for logging to stderr
 *   - nats.c API calls (natsConnection_GetConnectedUrl, etc.)
 *
 * Unsafe operations (will crash):
 *   - LM_ERR, LM_INFO, LM_DBG, etc.
 *   - pkg_malloc, pkg_free
 *   - shm_malloc, shm_free
 *   - Any OpenSIPS API that accesses process_no or pkg memory
 *
 * The pattern used here is "lazy invalidation": callbacks set atomic
 * flags, and the main process thread checks them on the next API call
 * to perform the actual work (cache clearing, logging, etc.) in a
 * safe context.
 * ---------------------------------------------------------------- */

/**
 * KV stale flag — lazy invalidation for the KV handle cache.
 *
 * This flag implements a producer-consumer pattern across thread boundaries:
 *
 * - Producer (nats.c I/O thread): The disconnect and reconnect callbacks
 *   set this flag to 1 via atomic_store() when the connection state changes.
 *   KV handles may reference stale server-side state (streams, consumers)
 *   after a reconnection, so they must be recreated.
 *
 * - Consumer (OpenSIPS process thread): nats_pool_get_kv() checks this flag
 *   using atomic_exchange(&_kv_stale, 0), which atomically reads the value
 *   and clears it in one operation.  This prevents the TOCTOU race that
 *   existed with the prior volatile read-then-write pattern, where a
 *   reconnect callback could set the flag between the read and the clear.
 *
 * Using atomic_int (C11) instead of volatile int because volatile only
 * prevents compiler reordering — it does not guarantee atomicity of
 * read-modify-write sequences or provide memory ordering between threads.
 */
static atomic_int _kv_stale = 0;

/**
 * Disconnect callback — called by nats.c I/O thread when the connection drops.
 *
 * Sets _connected to 0 and marks KV handles as stale.  Only uses atomic ops
 * and write() — no OpenSIPS APIs are safe here (see callback header comment).
 *
 * @param nc       The NATS connection (provided by nats.c, unused).
 * @param closure  User closure (NULL, unused).
 */
static void _pool_disconnected_cb(natsConnection *nc, void *closure)
{
	/* safe: atomic op + raw write() — no OpenSIPS APIs */
	atomic_store(&_connected, 0);
	atomic_store(&_kv_stale, 1);  /* mark KV handles stale immediately on disconnect */
	(void)write(STDERR_FILENO,
		"NATS pool: disconnected\n", 24);
}

/**
 * Reconnect callback — called by nats.c I/O thread after a successful reconnect.
 *
 * Restores _connected, bumps the reconnect epoch (so modules can detect
 * reconnection), and marks KV handles as stale.  Logs the new server URL
 * via write() to stderr.
 *
 * Only atomic ops, nats.c APIs, and write() are used here — no OpenSIPS APIs.
 * See the callback section header comment for the full rationale.
 *
 * @param nc       The NATS connection (used to query the new server URL).
 * @param closure  User closure (NULL, unused).
 */
static void _pool_reconnected_cb(natsConnection *nc, void *closure)
{
	char buf[300];
	char url[256];
	int len;

	natsConnection_GetConnectedUrl(nc, url, sizeof(url));
	atomic_store(&_connected, 1);
	atomic_fetch_add(&_reconnect_epoch, 1);
	atomic_store(&_kv_stale, 1);

	len = snprintf(buf, sizeof(buf),
		"NATS pool: reconnected to %s\n", url);
	if (len > 0)
		(void)write(STDERR_FILENO, buf, len);
}

/**
 * JetStream async publish ack handler — runs on nats.c internal thread.
 *
 * Called by nats.c when an async JetStream publish completes (success or
 * failure).  Signature must match jsPubAckHandler typedef:
 *   void (*)(jsCtx*, natsMsg*, jsPubAck*, jsPubAckErr*, void*)
 *
 * Memory ownership rules (set by nats.c js.c:_handleAsyncReply):
 * - pa and pae are STACK-ALLOCATED by nats.c — do NOT call jsPubAck_Destroy().
 *   nats.c calls _freePubAck() after this callback returns.
 * - msg (the original published message) IS our responsibility to destroy.
 *   nats.c sets pmsg=NULL after calling us (js.c:719).
 *
 * @param js       JetStream context (unused).
 * @param msg      Original published message — MUST be destroyed by us.
 * @param pa       Publish ack (stack-allocated by nats.c — do NOT destroy).
 * @param pae      Publish ack error, or NULL on success (stack-allocated).
 * @param closure  User closure (NULL, unused).
 */
static void _js_pub_ack_handler(jsCtx *js, natsMsg *msg, jsPubAck *pa,
                                 jsPubAckErr *pae, void *closure)
{
	if (pae && pae->ErrText) {
		char buf[256];
		int len = snprintf(buf, sizeof(buf),
			"NATS JetStream async publish error: %s\n",
			pae->ErrText);
		if (len > 0)
			(void)write(STDERR_FILENO, buf, len);
	}
	if (msg)
		natsMsg_Destroy(msg);
}

/* ----------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------- */

/**
 * Register interest in the shared NATS connection pool.
 *
 * Called from mod_init (pre-fork, single-threaded).  Multiple modules
 * (event_nats, cachedb_nats) may call this; configurations are merged:
 * - Server URLs are de-duplicated and added to the pool.
 * - TLS config uses the first registration's values; conflicts are warned.
 * - Reconnect parameters use the largest values across registrations.
 *
 * The first call allocates pool_cfg in shared memory.  Subsequent calls
 * merge additional servers into the existing config.
 *
 * @param url             Comma-separated server URLs
 *                        (e.g., "tls://h1:4222,tls://h2:4223").
 * @param tls             TLS options (NULL for no TLS).
 * @param module          Module name string for log messages.
 * @param reconnect_wait  Reconnect wait in ms (0 = use default 2000ms).
 * @param max_reconnect   Max reconnect attempts (0 = use default 60).
 * @return                0 on success, -1 on error.
 *
 * Thread safety: Must only be called from mod_init (single-threaded).
 */
int nats_pool_register(const char *url, nats_tls_opts *tls,
                       const char *module, int reconnect_wait,
                       int max_reconnect)
{
	if (!url || !*url) {
		LM_ERR("[%s] empty NATS URL\n", module ? module : "?");
		return -1;
	}

	/* First registration — allocate the shared config */
	if (!pool_cfg) {
		pool_cfg = shm_malloc(sizeof(nats_pool_cfg));
		if (!pool_cfg) {
			LM_ERR("shm_malloc for pool_cfg failed\n");
			return -1;
		}
		memset(pool_cfg, 0, sizeof(nats_pool_cfg));

		/* parse initial URL set */
		if (parse_urls(url) < 0) {
			shm_free(pool_cfg);
			pool_cfg = NULL;
			return -1;
		}

		/* deep-copy TLS config into shared memory */
		if (tls) {
			pool_cfg->tls.ca = tls->ca ? shm_strdup(tls->ca) : NULL;
			pool_cfg->tls.cert = tls->cert ? shm_strdup(tls->cert) : NULL;
			pool_cfg->tls.key = tls->key ? shm_strdup(tls->key) : NULL;
			pool_cfg->tls.hostname = tls->hostname ?
				shm_strdup(tls->hostname) : NULL;

			/* Verify required TLS fields were allocated */
			if ((tls->ca && !pool_cfg->tls.ca) ||
			    (tls->cert && !pool_cfg->tls.cert) ||
			    (tls->key && !pool_cfg->tls.key) ||
			    (tls->hostname && !pool_cfg->tls.hostname)) {
				LM_ERR("shm_strdup failed for TLS config\n");
				if (pool_cfg->tls.ca) shm_free(pool_cfg->tls.ca);
				if (pool_cfg->tls.cert) shm_free(pool_cfg->tls.cert);
				if (pool_cfg->tls.key) shm_free(pool_cfg->tls.key);
				if (pool_cfg->tls.hostname)
					shm_free(pool_cfg->tls.hostname);
				shm_free(pool_cfg);
				pool_cfg = NULL;
				return -1;
			}

			pool_cfg->tls.skip_verify = tls->skip_verify;
			pool_cfg->tls.skip_openssl_init = tls->skip_openssl_init;
		}

		pool_cfg->reconnect_wait = reconnect_wait > 0 ?
			reconnect_wait : NATS_POOL_DEFAULT_RECONNECT_WAIT;
		pool_cfg->max_reconnect = max_reconnect > 0 ?
			max_reconnect : NATS_POOL_DEFAULT_MAX_RECONNECT;

		LM_INFO("NATS pool: registered by '%s' with %d server(s), "
			"TLS=%s, reconnect_wait=%dms, max_reconnect=%d\n",
			module ? module : "?",
			pool_cfg->server_cnt,
			pool_cfg->use_tls ? "yes" : "no",
			pool_cfg->reconnect_wait,
			pool_cfg->max_reconnect);
	} else {
		/* Subsequent registration — merge servers (add any new ones) */
		const char *p, *tok;
		int len, i, found;

		LM_INFO("NATS pool: additional registration by '%s'\n",
			module ? module : "?");

		p = url;
		while (*p) {
			while (*p == ',' || *p == ' ' || *p == '\t')
				p++;
			if (!*p)
				break;

			tok = p;
			while (*p && *p != ',')
				p++;

			len = (int)(p - tok);
			while (len > 0 && (tok[len - 1] == ' ' || tok[len - 1] == '\t'))
				len--;

			if (len <= 0)
				continue;

			/* check if this server is already known */
			found = 0;
			for (i = 0; i < pool_cfg->server_cnt; i++) {
				if ((int)strlen(pool_cfg->servers[i]) == len &&
				    strncmp(pool_cfg->servers[i], tok, len) == 0) {
					found = 1;
					break;
				}
			}

			if (!found) {
				if (pool_cfg->server_cnt >= NATS_POOL_MAX_SERVERS) {
					LM_WARN("NATS pool: max servers reached, "
						"ignoring additional URL\n");
					continue;
				}
				pool_cfg->servers[pool_cfg->server_cnt] = shm_malloc(len + 1);
				if (!pool_cfg->servers[pool_cfg->server_cnt]) {
					LM_ERR("shm_malloc for server URL failed\n");
					return -1;
				}
				memcpy(pool_cfg->servers[pool_cfg->server_cnt], tok, len);
				pool_cfg->servers[pool_cfg->server_cnt][len] = '\0';

				if (len >= 6 && strncmp(
				    pool_cfg->servers[pool_cfg->server_cnt],
				    "tls://", 6) == 0)
					pool_cfg->use_tls = 1;

				pool_cfg->server_cnt++;
				LM_INFO("NATS pool: added server from '%s'\n",
					module ? module : "?");
			}
		}

		/* warn on TLS config conflict if both provide TLS */
		if (tls && pool_cfg->tls.skip_verify != tls->skip_verify) {
			LM_WARN("NATS pool: TLS skip_verify conflict between "
				"modules (using first registration's value)\n");
		}

		/* use the larger reconnect values */
		if (reconnect_wait > 0 &&
		    reconnect_wait > pool_cfg->reconnect_wait)
			pool_cfg->reconnect_wait = reconnect_wait;
		if (max_reconnect > 0 &&
		    max_reconnect > pool_cfg->max_reconnect)
			pool_cfg->max_reconnect = max_reconnect;
	}

	return 0;
}

/**
 * Get the shared NATS connection for this worker process.
 *
 * On first call (post-fork), initializes the nats.c library, probes TLS
 * availability, creates connection options, and connects in a retry loop.
 * Subsequent calls return the cached connection handle.
 *
 * The connection is NEVER destroyed or replaced after creation (except
 * at shutdown in nats_pool_destroy).  Multiple components (watcher threads,
 * producers, nats.c I/O threads) cache pointers to _nc and objects derived
 * from it (_js, kvStore, kvWatcher).  Destroying _nc would invalidate all
 * of them.  nats.c's built-in reconnection handles failover transparently.
 *
 * @return  natsConnection pointer on success, NULL on error (no config,
 *          library init failure, or options creation failure).
 *
 * Thread safety: Called from OpenSIPS process context only.  The first-call
 * initialization is not thread-safe, but OpenSIPS processes are forked
 * (not threaded), so each process has its own _nc.
 */
natsConnection *nats_pool_get(void)
{
	natsOptions *opts = NULL;
	natsStatus s;

	/* Return existing connection — let nats.c handle reconnection.
	 *
	 * IMPORTANT: Never destroy or replace _nc after creation.
	 * Multiple threads (watcher, producer, nats.c I/O) cache pointers
	 * to _nc and objects derived from it (_js, kvStore, kvWatcher).
	 * Destroying _nc invalidates all of them → use-after-free.
	 *
	 * nats.c's built-in reconnection handles failover transparently.
	 * Operations during the disconnected window return NATS errors,
	 * which callers handle gracefully. The reconnect callback bumps
	 * _reconnect_epoch so modules know to refresh KV handles. */
	if (_nc)
		return _nc;

	if (!pool_cfg) {
		LM_ERR("NATS pool: not registered (call nats_pool_register first)\n");
		return NULL;
	}

	/* Initialize nats.c library — once per process.
	 * -1 lets nats.c pick default lock spin count. */
	if (!_lib_initialized) {
		s = nats_Open(-1);
		if (s != NATS_OK) {
			LM_ERR("NATS pool: nats_Open failed: %s\n",
				natsStatus_GetText(s));
			return NULL;
		}
		_lib_initialized = 1;
	}

	/* TLS probe: If tls:// URLs were configured, check whether nats.c
	 * was built with TLS support.  nats.c parses the URL scheme —
	 * tls:// triggers TLS internally.  If nats.c lacks TLS,
	 * SetServers with tls:// URLs returns NATS_ILLEGAL_STATE.
	 *
	 * The URL rewrite modifies pool_cfg (SHM), so it must run exactly
	 * once.  The static _tls_probed flag ensures the first child process
	 * to reach here does the probe; others see use_tls already cleared.
	 * This is safe because child processes are forked sequentially. */
	if (pool_cfg->use_tls) {
		static int _tls_probed = 0;
		if (!_tls_probed) {
			natsOptions *probe = NULL;
			int tls_ok = 0;

			_tls_probed = 1;

			if (natsOptions_Create(&probe) == NATS_OK) {
				if (natsOptions_SetServers(probe,
				    (const char **)pool_cfg->servers,
				    pool_cfg->server_cnt) == NATS_OK)
					tls_ok = 1;
				natsOptions_Destroy(probe);
			}

			if (!tls_ok) {
				int i;
				LM_WARN("NATS pool: TLS requested (tls:// URLs) "
					"but not available in nats.c library. "
					"Downgrading to plain nats:// "
					"connections.\n");
				pool_cfg->use_tls = 0;

				/* Rewrite tls:// URLs to nats:// in-place */
				for (i = 0; i < pool_cfg->server_cnt; i++) {
					if (strncmp(pool_cfg->servers[i],
					    "tls://", 6) == 0) {
						char *old =
							pool_cfg->servers[i];
						int hlen = strlen(old + 6);
						char *p = shm_malloc(
							7 + hlen + 1);
						if (p) {
							snprintf(p,
								7 + hlen + 1,
								"nats://%s",
								old + 6);
							shm_free(old);
							pool_cfg->servers[i]
								= p;
						} else {
							LM_ERR("shm_malloc failed"
								" for TLS URL"
								" rewrite\n");
						}
					}
				}
			}
		}
	}

	/* Create connection options */
	s = natsOptions_Create(&opts);
	if (s != NATS_OK) {
		LM_ERR("NATS pool: natsOptions_Create failed: %s\n",
			natsStatus_GetText(s));
		return NULL;
	}

	/* Set server list (URLs now guaranteed compatible with nats.c) */
	s = natsOptions_SetServers(opts,
		(const char **)pool_cfg->servers, pool_cfg->server_cnt);
	if (s != NATS_OK) {
		LM_ERR("NATS pool: natsOptions_SetServers failed: %s\n",
			natsStatus_GetText(s));
		goto error;
	}

	/* Configure reconnection behavior and register callbacks */
	/*
	 * Set nats.c internal reconnect to UNLIMITED (-1). nats.c permanently
	 * removes a server from its pool after max_reconnect failures
	 * (natsSrvPool_GetNextServer calls _freeSrv). With a finite limit,
	 * a long partition empties the pool and kills the connection forever.
	 *
	 * pool_cfg->max_reconnect only gates the startup loop below.
	 * Once connected, nats.c reconnect is unlimited so cluster gossip
	 * (INFO connect_urls) keeps working through any partition length.
	 */
	natsOptions_SetMaxReconnect(opts, -1);
	natsOptions_SetReconnectWait(opts, pool_cfg->reconnect_wait);
	natsOptions_SetDisconnectedCB(opts, _pool_disconnected_cb, NULL);
	natsOptions_SetReconnectedCB(opts, _pool_reconnected_cb, NULL);

	/* TLS configuration — only if URLs weren't downgraded to nats:// */
	if (pool_cfg->use_tls) {
		natsOptions_SetSecure(opts, true);

		if (pool_cfg->tls.ca && *pool_cfg->tls.ca)
			natsOptions_LoadCATrustedCertificates(opts,
				pool_cfg->tls.ca);

		if (pool_cfg->tls.cert && *pool_cfg->tls.cert)
			natsOptions_LoadCertificatesChain(opts,
				pool_cfg->tls.cert,
				(pool_cfg->tls.key && *pool_cfg->tls.key) ?
					pool_cfg->tls.key : NULL);

		if (pool_cfg->tls.hostname && *pool_cfg->tls.hostname)
			natsOptions_SetExpectedHostname(opts,
				pool_cfg->tls.hostname);

		if (pool_cfg->tls.skip_verify)
			natsOptions_SkipServerVerification(opts, true);
	}

	/* Retry connection with bounded attempts. pool_cfg->max_reconnect
	 * gates startup only; runtime reconnection is unlimited (set above). */
	{
		int attempts = 0;
		for (;;) {
			s = natsConnection_Connect(&_nc, opts);
			if (s == NATS_OK)
				break;

			attempts++;
			{
				char stack_buf[1024];
				nats_GetLastErrorStack(stack_buf, sizeof(stack_buf));
				LM_ERR("NATS pool: connection attempt %d/%d failed: "
					"%s [%s]\n",
					attempts, pool_cfg->max_reconnect,
					natsStatus_GetText(s),
					stack_buf[0] ? stack_buf : "no detail");
			}

			if (attempts >= pool_cfg->max_reconnect) {
				LM_ERR("NATS pool: giving up after %d attempts\n",
					attempts);
				goto error;
			}

			nats_Sleep(pool_cfg->reconnect_wait);
		}
	}

	natsOptions_Destroy(opts);
	atomic_store(&_connected, 1);

	/* Log connected URL */
	{
		char url[256];
		natsConnection_GetConnectedUrl(_nc, url, sizeof(url));
		LM_INFO("NATS pool: connected to %s (%d server(s) configured)\n",
			url, pool_cfg->server_cnt);
	}

	return _nc;

error:
	if (opts)
		natsOptions_Destroy(opts);
	return NULL;
}

/**
 * Get the shared JetStream context for this worker process.
 *
 * Creates the jsCtx on first call using the shared connection.
 * The async publish ack handler (_js_pub_ack_handler) is registered
 * at creation time to handle JetStream publish acknowledgments.
 *
 * @return  jsCtx pointer on success, NULL on error (no connection,
 *          or JetStream context creation failure).
 *
 * Thread safety: Called from OpenSIPS process context only.
 * The jsCtx is process-local and never shared across processes.
 */
jsCtx *nats_pool_get_js(void)
{
	natsStatus s;
	jsOptions jsOpts;

	/* Return cached JetStream context */
	if (_js)
		return _js;

	/* Ensure we have a connection first */
	if (!_nc && !nats_pool_get())
		return NULL;

	/* Initialize JetStream options with async publish ack handler */
	jsOptions_Init(&jsOpts);
	jsOpts.PublishAsync.AckHandler = _js_pub_ack_handler;

	s = natsConnection_JetStream(&_js, _nc, &jsOpts);
	if (s != NATS_OK) {
		LM_ERR("NATS pool: JetStream context creation failed: %s\n",
			natsStatus_GetText(s));
		return NULL;
	}

	LM_INFO("NATS pool: JetStream context created\n");
	return _js;
}

/**
 * Get a KV store handle for a named bucket.
 *
 * Checks a process-local cache first.  If the bucket handle is not cached,
 * attempts to bind to an existing bucket on the server; if that fails,
 * creates a new bucket with the specified parameters.
 *
 * The cache is invalidated on reconnection via the _kv_stale atomic flag.
 * When a reconnect occurs, stale kvStore handles may reference outdated
 * server-side state (streams, consumers), so the cache is cleared and
 * fresh handles are obtained.
 *
 * @param bucket    KV bucket name (must be a valid NATS subject token).
 * @param replicas  Replication factor (used only when creating a new bucket).
 * @param history   History depth (used only when creating a new bucket).
 * @param ttl_secs  Bucket TTL in seconds (0 = no TTL; creation only).
 * @return          kvStore pointer on success, NULL on error.
 *
 * Thread safety: Called from OpenSIPS process context only.
 * The KV cache is process-local.  The _kv_stale flag is set by the
 * reconnect callback (nats.c thread) and consumed here via atomic_exchange.
 */
kvStore *nats_pool_get_kv(const char *bucket, int replicas,
                          int history, int64_t ttl_secs)
{
	int i;
	natsStatus s;
	kvStore *kv = NULL;
	kvConfig kvCfg;

	if (!bucket || !*bucket) {
		LM_ERR("NATS pool: empty KV bucket name\n");
		return NULL;
	}

	/* Ensure we have a JetStream context */
	if (!_js && !nats_pool_get_js())
		return NULL;

	/* Check if reconnection invalidated KV handles.
	 *
	 * atomic_exchange atomically reads the current value of _kv_stale
	 * and sets it to 0 in a single operation.  This eliminates the
	 * TOCTOU race that would exist with separate read-then-write:
	 * a reconnect callback could set _kv_stale=1 between our read
	 * and our clear, causing us to lose the invalidation signal.
	 *
	 * We do NOT destroy old kvStore handles here.  They are derived
	 * from _nc and _js which remain valid across reconnects (nats.c
	 * reconnects the underlying socket transparently).  We simply
	 * discard our cached pointers and let nats.c's refcounting
	 * clean them up.  Creating fresh handles ensures we pick up
	 * any server-side state changes (new stream leaders, etc.). */
	if (atomic_exchange(&_kv_stale, 0)) {
		for (i = 0; i < _kv_cache_cnt; i++)
			_kv_cache[i].kv = NULL;
		_kv_cache_cnt = 0;
		LM_NOTICE("NATS pool: KV cache cleared after reconnect\n");
	}

	/* Check cache for an existing handle for this bucket */
	for (i = 0; i < _kv_cache_cnt; i++) {
		if (_kv_cache[i].kv &&
		    strcmp(_kv_cache[i].bucket, bucket) == 0)
			return _kv_cache[i].kv;
	}

	/* Try to bind to existing bucket on the server first */
	s = js_KeyValue(&kv, _js, bucket);
	if (s != NATS_OK) {
		/* Bucket does not exist on server — create it */
		LM_DBG("NATS pool: KV bucket '%s' not found, creating\n",
			bucket);

		memset(&kvCfg, 0, sizeof(kvCfg));
		kvCfg.Bucket = bucket;
		kvCfg.Replicas = replicas > 0 ? replicas : 1;
		kvCfg.History = history > 0 ? history : 1;
		if (ttl_secs > 0)
			kvCfg.TTL = ttl_secs * 1000000000LL; /* seconds to nanos */

		s = js_CreateKeyValue(&kv, _js, &kvCfg);
		if (s != NATS_OK) {
			LM_ERR("NATS pool: KV bucket '%s' create failed: %s\n",
				bucket, natsStatus_GetText(s));
			return NULL;
		}
		LM_INFO("NATS pool: KV bucket '%s' created "
			"(replicas=%d, history=%d, ttl=%llds)\n",
			bucket, kvCfg.Replicas, kvCfg.History,
			(long long)ttl_secs);
	} else {
		LM_DBG("NATS pool: bound to existing KV bucket '%s'\n", bucket);
	}

	/* Cache the handle for future lookups */
	if (_kv_cache_cnt < NATS_POOL_MAX_KV_BUCKETS) {
		snprintf(_kv_cache[_kv_cache_cnt].bucket,
			sizeof(_kv_cache[_kv_cache_cnt].bucket), "%s", bucket);
		_kv_cache[_kv_cache_cnt].kv = kv;
		_kv_cache_cnt++;
	} else {
		LM_WARN("NATS pool: KV cache full (%d buckets), "
			"handle for '%s' will not be cached\n",
			NATS_POOL_MAX_KV_BUCKETS, bucket);
	}

	return kv;
}

/**
 * Destroy the connection pool and free all resources.
 *
 * Called from mod_destroy during OpenSIPS shutdown.
 *
 * ## Shutdown ordering
 *
 * The destruction sequence is critical because nats.c's internal I/O
 * threads may still be running when we enter this function:
 *
 * 1. KV handles destroyed first — they depend on _js.
 * 2. JetStream context destroyed — it depends on _nc.
 * 3. Connection drained THEN destroyed — natsConnection_Drain() flushes
 *    pending messages and waits for in-flight operations to complete
 *    before closing.  This ensures the I/O threads finish their work
 *    before we destroy the connection.  Without draining first,
 *    natsConnection_Destroy() would tear down the socket while I/O
 *    threads may still be reading/writing, causing races.
 * 4. Shared config freed last — it's SHM, no thread dependency.
 *
 * Note: Even with this ordering, there is a small window where
 * callbacks could fire between the drain completing and the destroy
 * call.  In practice this is harmless because the callbacks only
 * set atomic flags and call write(), which are idempotent.
 *
 * Thread safety: Must only be called from OpenSIPS process context
 * during shutdown (mod_destroy).
 */
void nats_pool_destroy(void)
{
	int i;

	LM_INFO("NATS pool: destroying\n");

	/* Step 1: Destroy KV handles (depend on _js) */
	for (i = 0; i < _kv_cache_cnt; i++) {
		if (_kv_cache[i].kv) {
			kvStore_Destroy(_kv_cache[i].kv);
			_kv_cache[i].kv = NULL;
		}
	}
	_kv_cache_cnt = 0;

	/* Step 2: Destroy JetStream context (depends on _nc) */
	if (_js) {
		jsCtx_Destroy(_js);
		_js = NULL;
	}

	/* Step 3: Drain then destroy connection.
	 * Drain flushes pending publishes, waits for acks, then closes.
	 * This ensures nats.c I/O threads complete before we destroy. */
	if (_nc) {
		natsConnection_Drain(_nc);
		natsConnection_Destroy(_nc);
		_nc = NULL;
	}

	atomic_store(&_connected, 0);

	/* Step 4: Free shared config (SHM) */
	if (pool_cfg) {
		for (i = 0; i < pool_cfg->server_cnt; i++) {
			if (pool_cfg->servers[i])
				shm_free(pool_cfg->servers[i]);
		}
		if (pool_cfg->tls.ca)
			shm_free(pool_cfg->tls.ca);
		if (pool_cfg->tls.cert)
			shm_free(pool_cfg->tls.cert);
		if (pool_cfg->tls.key)
			shm_free(pool_cfg->tls.key);
		if (pool_cfg->tls.hostname)
			shm_free(pool_cfg->tls.hostname);
		shm_free(pool_cfg);
		pool_cfg = NULL;
	}
}

/**
 * Check if the pool is currently connected.
 *
 * @return  1 if connected, 0 if disconnected.
 *
 * Thread safety: Safe to call from any context.  Uses atomic_load
 * on _connected which is set by callbacks on the nats.c I/O thread.
 */
int nats_pool_is_connected(void)
{
	return atomic_load(&_connected) ? 1 : 0;
}

/**
 * Get the currently connected server URL for status reporting.
 *
 * Queries natsConnection_GetConnectedUrl() directly on each call to
 * avoid returning a stale pointer.  The result is written into a
 * process-local static buffer and is valid until the next call.
 *
 * @return  Server URL string (process-local, do not free), or
 *          "not connected" if no active connection.
 *
 * Thread safety: Called from OpenSIPS process context only.
 * The static buffer is process-local (each forked process has its own).
 * We call natsConnection_GetConnectedUrl() which is thread-safe in
 * nats.c (it locks internally), so this is safe even if the reconnect
 * callback fires concurrently — we always get a consistent snapshot.
 */
const char *nats_pool_get_server_info(void)
{
	static char _server_info_buf[512];

	if (!_nc)
		return "not connected";

	if (natsConnection_GetConnectedUrl(_nc, _server_info_buf,
	    sizeof(_server_info_buf)) != NATS_OK)
		return "not connected";

	return _server_info_buf;
}

/**
 * Get the current reconnect epoch counter.
 *
 * Incremented atomically each time nats.c reports a successful
 * reconnection.  Modules can save the value and compare later to
 * detect that a reconnection occurred (e.g., to re-establish
 * watchers or rebuild indexes).
 *
 * @return  Current epoch counter value.
 *
 * Thread safety: Safe to call from any context.  Uses atomic_load.
 */
int nats_pool_get_reconnect_epoch(void)
{
	return atomic_load(&_reconnect_epoch);
}
