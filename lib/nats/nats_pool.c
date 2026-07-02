/*
 * Copyright (C) 2026 OpenSIPS Solutions
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
 * process, used by event_nats.so, cachedb_nats.so, and nats_consumer.so.  It
 * is compiled as the shared library libnats_pool.so and linked into each
 * module via -lnats_pool (resolved at load time through an $ORIGIN rpath).
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

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "../../dprint.h"
#include "../../sr_module.h"   /* find_export() */
#include "../../mem/shm_mem.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "nats_pool.h"
#include "nats_ca_dir.h"
#include "../../modules/tls_mgm/api.h"   /* tls_mgm_binds, tls_domain */

/* This is a shared library (lib/nats), not a loadable module.
 * Compiled as libnats_pool.so and linked into event_nats.so,
 * cachedb_nats.so, and nats_consumer.so via -lnats_pool ($ORIGIN rpath). */

/* ----------------------------------------------------------------
 * Shared pool configuration (shm, set pre-fork in mod_init)
 * ---------------------------------------------------------------- */

#define NATS_POOL_MAX_SERVERS 16
#define NATS_POOL_DEFAULT_RECONNECT_WAIT 2000
#define NATS_POOL_DEFAULT_MAX_RECONNECT  60

/* Max in-flight JetStream async publishes per process before
 * js_PublishAsync errors (bounds per-worker memory under a slow-acking
 * broker), and how long a full queue may stall the worker before it does. */
#define NATS_JS_PUBLISH_ASYNC_MAX_PENDING    4096
#define NATS_JS_PUBLISH_ASYNC_STALL_WAIT_MS  50

/* Connection liveness probing so a black-holed broker is declared dead in
 * ~20 s (vs cnats's ~4-minute default) -- shrinks the window where inline
 * publishes block/buffer in SIP workers before the fast-fail trips. */
#define NATS_POOL_PING_INTERVAL_MS  10000
#define NATS_POOL_MAX_PINGS_OUT     2

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

/* Registration refcount.  Each module that calls nats_pool_register()
 * increments this; nats_pool_unregister() decrements it and tears the pool
 * down only on the last unregister, so the connection survives while any
 * module still uses it and is always destroyed once the last one is gone.
 * Single-threaded (mod_init / mod_destroy run before fork / at shutdown). */
static int              _register_count = 0;
static atomic_int       _connected = 0;          /* 1 if connected */
static atomic_int       _reconnect_epoch = 0;    /* bumped on each reconnect */

/* tls_mgm bind table set by user-module mod_init via
 * nats_pool_set_tls_api().  NULL means "tls_mgm not loaded" -- the
 * connect path uses this to error out cleanly when a tls:// URL is
 * configured but no TLS-domain source is available. */
static struct tls_mgm_binds *_tls_api = NULL;

void nats_pool_set_tls_api(void *binds)
{
	_tls_api = (struct tls_mgm_binds *)binds;
}

/* KV handle cache — maps bucket names to kvStore pointers.
 * Process-local; invalidated on reconnection via _kv_stale. */
typedef struct {
	char     bucket[128];
	kvStore *kv;
} kv_cache_entry;

static kv_cache_entry _kv_cache[NATS_POOL_MAX_KV_BUCKETS];
static int            _kv_cache_cnt = 0;

/* See nats_pool.h — module-tunable shutdown drain timeout, ms. */
int nats_pool_drain_timeout_ms = 5000;

/* Drain-timeout modparam setter shared by event_nats (nats_drain_timeout_ms)
 * and cachedb_nats (cdb_drain_timeout_ms), which both target this one global.
 * Take the MAX across registrants so the longest-configured shutdown grace
 * wins regardless of module load order (mirrors the reconnect-param merge in
 * nats_pool_register), instead of last-writer-wins. */
int nats_pool_drain_timeout_setter(modparam_t type, void *val)
{
	int v;
	if ((type & PARAM_TYPE_MASK(INT_PARAM)) == 0) {
		LM_ERR("nats drain_timeout: must be an integer\n");
		return -1;
	}
	v = (int)(long)val;
	if (v > nats_pool_drain_timeout_ms)
		nats_pool_drain_timeout_ms = v;
	return 0;
}

/* See nats_pool.h — module-tunable JetStream/KV op timeout, ms.  0 keeps
 * cnats's default (5 s).  Set a smaller value (500-1000 ms) on hot paths
 * like usrloc so a slow-but-connected broker can't block a SIP worker for
 * the full default. */
int nats_pool_kv_op_timeout_ms = 0;

/* ----------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------- */

/* shm_strdup provided by ../../ut.h — no local copy needed */

/**
 * Tokenize a comma-separated URL string and append each unique server (one
 * not already in pool_cfg->servers[]) to the config, trimming surrounding
 * whitespace/commas and detecting "tls://".  Shared by the initial parse and
 * the subsequent-registration merge so the tokenizer lives in one place.
 *
 * @param url            Comma-separated URL string.
 * @param hard_overflow  If non-zero, exceeding NATS_POOL_MAX_SERVERS is a
 *                       hard error (-1); otherwise the extra URL is
 *                       warn-skipped (merge semantics).
 * @return  number of servers added, or -1 on OOM / hard overflow.  On -1 the
 *          caller owns any partial additions.
 *
 * Thread safety: Called only during mod_init (single-threaded, pre-fork).
 */
static int _append_server_urls(const char *url, int hard_overflow)
{
	const char *p = url, *tok;
	int len, i, added = 0;

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

		/* skip a URL already in the list (a duplicate within this string
		 * or one a previous registration already added) */
		for (i = 0; i < pool_cfg->server_cnt; i++)
			if ((int)strlen(pool_cfg->servers[i]) == len &&
			    strncmp(pool_cfg->servers[i], tok, len) == 0)
				break;
		if (i < pool_cfg->server_cnt)
			continue;

		if (pool_cfg->server_cnt >= NATS_POOL_MAX_SERVERS) {
			if (hard_overflow) {
				LM_ERR("too many NATS servers (max %d)\n",
					NATS_POOL_MAX_SERVERS);
				return -1;
			}
			LM_WARN("NATS pool: max servers reached, ignoring "
				"additional URL\n");
			continue;
		}

		pool_cfg->servers[pool_cfg->server_cnt] = shm_malloc(len + 1);
		if (!pool_cfg->servers[pool_cfg->server_cnt]) {
			LM_ERR("shm_malloc for server URL failed\n");
			return -1;
		}
		memcpy(pool_cfg->servers[pool_cfg->server_cnt], tok, len);
		pool_cfg->servers[pool_cfg->server_cnt][len] = '\0';

		if (len >= 6 &&
		    strncmp(pool_cfg->servers[pool_cfg->server_cnt], "tls://", 6) == 0)
			pool_cfg->use_tls = 1;

		pool_cfg->server_cnt++;
		added++;
	}
	return added;
}

/*
 * Parse comma-separated URL string into pool_cfg->servers[] (initial
 * registration).  Sets pool_cfg->use_tls if any URL starts with "tls://".
 *
 * @param url  Comma-separated URL string (e.g. "nats://h1:4222,nats://h2:4222").
 * @return     0 on success, -1 on error (empty string, too many servers, OOM).
 *
 * Thread safety: Called only during mod_init (single-threaded, pre-fork).
 */
static int parse_urls(const char *url)
{
	if (!url || !*url) {
		LM_ERR("empty URL string\n");
		return -1;
	}

	if (_append_server_urls(url, 1 /* hard overflow */) < 0)
		goto err_free_partial;

	if (pool_cfg->server_cnt == 0) {
		char redacted[256];
		nats_redact_url(url, redacted, sizeof(redacted));
		LM_ERR("no valid NATS server URLs found in '%s'\n", redacted);
		return -1;
	}

	return 0;

err_free_partial:
	{
		int i;
		for (i = 0; i < pool_cfg->server_cnt; i++) {
			shm_free(pool_cfg->servers[i]);
			pool_cfg->servers[i] = NULL;
		}
		pool_cfg->server_cnt = 0;
	}
	return -1;
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
 *   and clears it in one operation.  This prevents the Time-Of-Check to
 *   Time-Of-Use (TOCTOU) race that existed with the prior volatile
 *   read-then-write pattern, where a reconnect callback could set the
 *   flag between the read and the clear.
 *
 * Using atomic_int (C11) instead of volatile int because volatile only
 * prevents compiler reordering — it does not guarantee atomicity of
 * read-modify-write sequences or provide memory ordering between threads.
 */
static atomic_int _kv_stale = 0;

/* P8 [R6 / TTL-SOLUTION-SPEC.md §6 TREV-8]: per-message-TTL capability latch,
 * process-global (each process owns its NATS connection, so each probes
 * independently; the reaper runs in the timer process and must reach the same
 * latch the worker does -- hence pool-global, not on a worker's ncon).
 * 0=UNPROBED, 1=SUPPORTED, 2=UNSUPPORTED (mirrors enum ttl_cap).  The cachedb
 * module drives transitions via the tested _ttl_cap_next(); the pool only
 * stores the latch and resets it to UNPROBED on a reconnect (re-probe: a
 * failover may land on a different server version/config). */
static atomic_int _ttl_cap = 0;

/*
 * Callback-thread-safe stderr emit.
 *
 * The nats.c callbacks below run on library-internal threads where OpenSIPS
 * APIs (LM_*, pkg_malloc, …) are not safe to call, so we emit diagnostics
 * with a raw write(2).  glibc decorates write() with warn_unused_result, and
 * GCC's -Wunused-result is not silenced by a (void) cast, so we capture the
 * return into a local and explicitly discard it.  Centralizing the discard
 * here keeps any future callback site from re-introducing -Werror breakage.
 */
static void nats_pool_unsafe_log(const char *buf, size_t len)
{
	ssize_t n = write(STDERR_FILENO, buf, len);
	(void)n;
}

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
	nats_pool_unsafe_log("NATS pool: disconnected\n", 24);
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
	char redacted[256];
	int len;

	/* Init defensively: on a non-OK status GetConnectedUrl may leave
	 * the buffer unterminated, and nats_redact_url() would then read
	 * uninitialised stack. */
	url[0] = '\0';
	nats_dl.natsConnection_GetConnectedUrl(nc, url, sizeof(url));
	nats_redact_url(url, redacted, sizeof(redacted));
	atomic_store(&_connected, 1);
	atomic_fetch_add(&_reconnect_epoch, 1);
	atomic_store(&_kv_stale, 1);

	len = snprintf(buf, sizeof(buf),
		"NATS pool: reconnected to %s\n", redacted);
	/* Clamp the snprintf return to the buffer before logging (see the
	 * matching note in _js_pub_ack_handler): a long redacted URL would
	 * otherwise make write() over-read the stack buffer. */
	if (len >= (int)sizeof(buf))
		len = (int)sizeof(buf) - 1;
	if (len > 0)
		nats_pool_unsafe_log(buf, (size_t)len);
}

/**
 * JetStream async publish ack handler — runs on nats.c internal thread.
 *
 * Called by nats.c when an async JetStream publish completes (success or
 * failure).  Signature must match jsPubAckHandler typedef:
 *   void (*)(jsCtx*, natsMsg*, jsPubAck*, jsPubAckErr*, void*)
 *
 * Memory ownership rules (set by nats.c js.c:_handleAsyncReply):
 * - pa and pae are STACK-ALLOCATED by nats.c — do NOT call nats_dl.jsPubAck_Destroy().
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
/* Optional caller-registered hook to report JS ack outcomes.
 * Read on the cnats thread, set once pre-fork via
 * nats_pool_set_pub_ack_cb().  Always called with success=1 (acked)
 * or success=0 (error). */
static void (*_pub_ack_cb)(int success) = NULL;

void nats_pool_set_pub_ack_cb(void (*cb)(int success))
{
	_pub_ack_cb = cb;
}

static void _js_pub_ack_handler(jsCtx *js, natsMsg *msg, jsPubAck *pa,
                                 jsPubAckErr *pae, void *closure)
{
	int success = (pae == NULL || pae->ErrText == NULL);
	if (!success) {
		char buf[256];
		int len = snprintf(buf, sizeof(buf),
			"NATS JetStream async publish error: %s\n",
			pae->ErrText);
		/* snprintf returns the length it WOULD have written; a
		 * broker-controlled ErrText longer than buf makes len exceed
		 * sizeof(buf), so the write() below would read past the stack
		 * buffer and leak adjacent stack.  Clamp to the buffer. */
		if (len >= (int)sizeof(buf))
			len = (int)sizeof(buf) - 1;
		if (len > 0)
			nats_pool_unsafe_log(buf, (size_t)len);
	}
	if (_pub_ack_cb)
		_pub_ack_cb(success);
	if (msg)
		nats_dl.natsMsg_Destroy(msg);
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
int nats_pool_register(const char *url, const char *module,
                       int reconnect_wait, int max_reconnect)
{
	if (!url || !*url) {
		LM_ERR("[%s] empty NATS URL\n", module ? module : "?");
		return -1;
	}

	/* Lazy-load libnats via dlopen on first registration.  All
	 * subsequent libnats calls in this file (and in the user
	 * modules that link this library) dispatch through nats_dl.X
	 * — see lib/nats/nats_dl.h for the architectural rationale.
	 * Idempotent: repeated calls are no-ops once libnats is in.
	 *
	 * Operator picks the libnats variant via standard ld.so
	 * mechanisms (LD_LIBRARY_PATH, ldconfig priorities) or via
	 * the $NATS_DL_LIBNATS_PATH env-var override; lib/nats does
	 * not bake in version numbers or install-prefix conventions. */
	if (nats_dl_load(NULL) < 0) {
		LM_ERR("[%s] nats_dl_load failed; libnats not available\n",
		       module ? module : "?");
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

		/* TLS configuration (cert/CA/key/verify) is sourced from the
		 * tls_mgm "nats" client domain at connect time -- see
		 * apply_tls_from_mgm() below.  Caller MUST have called
		 * nats_pool_set_tls_api(&binds) first if any URL is tls://. */

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
		/* Subsequent registration — merge in any new servers (soft
		 * overflow: extra URLs past the cap are warn-skipped). */
		int added;

		LM_INFO("NATS pool: additional registration by '%s'\n",
			module ? module : "?");

		added = _append_server_urls(url, 0 /* soft overflow */);
		if (added < 0)
			return -1;
		if (added > 0)
			LM_INFO("NATS pool: merged %d new server(s) from '%s'\n",
				added, module ? module : "?");

		/* TLS config conflicts no longer possible: every NATS
		 * module reads from the same tls_mgm "nats" domain, so
		 * there's nothing to conflict over. */

		/* use the larger reconnect values */
		if (reconnect_wait > 0 &&
		    reconnect_wait > pool_cfg->reconnect_wait)
			pool_cfg->reconnect_wait = reconnect_wait;
		if (max_reconnect > 0 &&
		    max_reconnect > pool_cfg->max_reconnect)
			pool_cfg->max_reconnect = max_reconnect;
	}

	_register_count++;
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
/*
 * nats_load_ca_directory -- read every regular file in @dir whose
 * name ends in ".pem", concatenate the contents in lexicographic
 * order, and hand it to libnats via the in-memory PEM API.  The
 * actual implementation is in lib/nats/nats_ca_dir.c (libc-only,
 * unit-testable independently).  This file just calls it.
 */

/*
 * apply_tls_from_mgm -- look up the tls_mgm "nats" client domain
 * and pass its cert / CA / key / verify / cipher settings to libnats
 * via nats_dl.natsOptions_*.  Caller must already have called
 * nats_dl.natsOptions_SetSecure(opts, true).
 *
 * Returns 0 on success (opts populated or no TLS settings to apply),
 * -1 if tls_mgm isn't bound or the "nats" domain isn't defined.
 * Either condition means the operator asked for TLS (tls:// URL) but
 * didn't configure tls_mgm to back it -- a hard error.
 */
static int apply_tls_from_mgm(natsOptions *opts)
{
	str dom_name = str_init("nats");
	struct tls_domain *dom;

	if (!_tls_api) {
		LM_ERR("NATS pool: tls:// URL configured but tls_mgm is not "
		       "loaded.  Add `loadmodule \"tls_mgm.so\"` plus a "
		       "client_domain named \"nats\" before any NATS module "
		       "loads, or use a plain nats:// URL.\n");
		return -1;
	}

	dom = _tls_api->find_client_domain_name(&dom_name);
	if (!dom) {
		LM_ERR("NATS pool: tls:// URL configured but tls_mgm has no "
		       "client_domain named \"nats\".  Define one in "
		       "opensips.cfg, e.g.:\n"
		       "  modparam(\"tls_mgm\", \"client_domain\", \"nats\")\n"
		       "  modparam(\"tls_mgm\", \"certificate\", "
		       "\"[nats]/etc/opensips/nats-cert.pem\")\n"
		       "  modparam(\"tls_mgm\", \"private_key\", "
		       "\"[nats]/etc/opensips/nats-key.pem\")\n"
		       "  modparam(\"tls_mgm\", \"ca_list\", "
		       "\"[nats]/etc/opensips/nats-ca.pem\")\n"
		       "  modparam(\"tls_mgm\", \"verify_cert\", \"[nats]1\")\n");
		return -1;
	}

	/* CA: ca_list (single file) preferred; fall back to ca_directory
	 * (concatenate all .pem in the directory).  libnats has no
	 * directory-load API, so nats_ca_dir.c does it OpenSIPS-side. */
	/* Every natsOptions TLS call below is checked: if libnats rejects a
	 * cert/CA/cipher (bad path, malformed PEM, ...) we must fail closed,
	 * not connect with TLS silently downgraded (no CA pinning / no client
	 * cert). */
	natsStatus ts;
	if (dom->ca.len > 0 && dom->ca.s) {
		ts = nats_dl.natsOptions_LoadCATrustedCertificates(opts, dom->ca.s);
		if (ts != NATS_OK) {
			LM_ERR("nats TLS: LoadCATrustedCertificates failed: %s\n",
			       nats_dl.natsStatus_GetText(ts));
			_tls_api->release_domain(dom);
			return -1;
		}
	} else if (dom->ca_directory) {
		char *err = NULL;
		char *concat = nats_load_ca_directory(dom->ca_directory, &err);
		if (!concat) {
			LM_ERR("nats CA-dir load failed for tls_mgm 'nats': %s\n",
			       err ? err : "unknown");
			free(err);
			_tls_api->release_domain(dom);
			return -1;
		}
		free(err);
		ts = nats_dl.natsOptions_SetCATrustedCertificates(opts, concat);
		free(concat);  /* libnats copies internally */
		if (ts != NATS_OK) {
			LM_ERR("nats TLS: SetCATrustedCertificates failed: %s\n",
			       nats_dl.natsStatus_GetText(ts));
			_tls_api->release_domain(dom);
			return -1;
		}
	}

	/* Client cert + key (mutual TLS).  libnats wants both or neither. */
	if (dom->cert.len > 0 && dom->cert.s &&
	    dom->pkey.len > 0 && dom->pkey.s) {
		ts = nats_dl.natsOptions_LoadCertificatesChain(opts,
		                                          dom->cert.s,
		                                          dom->pkey.s);
		if (ts != NATS_OK) {
			LM_ERR("nats TLS: LoadCertificatesChain failed (mTLS): %s\n",
			       nats_dl.natsStatus_GetText(ts));
			_tls_api->release_domain(dom);
			return -1;
		}
	}

	if (dom->ciphers_list) {
		ts = nats_dl.natsOptions_SetCiphers(opts, dom->ciphers_list);
		if (ts != NATS_OK) {
			LM_ERR("nats TLS: SetCiphers failed: %s\n",
			       nats_dl.natsStatus_GetText(ts));
			_tls_api->release_domain(dom);
			return -1;
		}
	}

	/* tls_mgm verify_cert: 1 = verify (default), 0 = skip.
	 * libnats SkipServerVerification is the inverse polarity.  A failure
	 * here leaves verification ON (the secure default), so it is not a
	 * downgrade -- log but do not fail the connection. */
	if (!dom->verify_cert) {
		ts = nats_dl.natsOptions_SkipServerVerification(opts, true);
		if (ts != NATS_OK)
			LM_WARN("nats TLS: SkipServerVerification failed: %s "
			        "(verification stays enabled)\n",
			        nats_dl.natsStatus_GetText(ts));
	}

	_tls_api->release_domain(dom);
	return 0;
}

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
		s = nats_dl.nats_Open(-1);
		if (s != NATS_OK) {
			LM_ERR("NATS pool: nats_Open failed: %s\n",
				nats_dl.natsStatus_GetText(s));
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

			if (nats_dl.natsOptions_Create(&probe) == NATS_OK) {
				if (nats_dl.natsOptions_SetServers(probe,
				    (const char **)pool_cfg->servers,
				    pool_cfg->server_cnt) == NATS_OK)
					tls_ok = 1;
				nats_dl.natsOptions_Destroy(probe);
			}

			if (!tls_ok) {
				LM_ERR("NATS pool: TLS requested "
					"(tls:// URLs) but the linked "
					"libnats was built without TLS "
					"support.  Install a TLS-built "
					"libnats (or set $NATS_DL_LIBNATS_PATH "
					"to one) and reload.  No silent "
					"plaintext downgrade.\n");
				return NULL;
			}
		}
	}

	/* Create connection options */
	s = nats_dl.natsOptions_Create(&opts);
	if (s != NATS_OK) {
		LM_ERR("NATS pool: natsOptions_Create failed: %s\n",
			nats_dl.natsStatus_GetText(s));
		return NULL;
	}

	/* Set server list (URLs now guaranteed compatible with nats.c) */
	s = nats_dl.natsOptions_SetServers(opts,
		(const char **)pool_cfg->servers, pool_cfg->server_cnt);
	if (s != NATS_OK) {
		LM_ERR("NATS pool: natsOptions_SetServers failed: %s\n",
			nats_dl.natsStatus_GetText(s));
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
	nats_dl.natsOptions_SetMaxReconnect(opts, -1);
	nats_dl.natsOptions_SetReconnectWait(opts, pool_cfg->reconnect_wait);
	/* Spread runtime reconnects: without jitter, all N worker processes
	 * reconnect in lockstep after a broker restart (a thundering herd that
	 * hammers the broker every reconnect_wait).  Jitter up to one full
	 * reconnect_wait window (TLS uses the same). */
	nats_dl.natsOptions_SetReconnectJitter(opts,
		(int64_t)pool_cfg->reconnect_wait, (int64_t)pool_cfg->reconnect_wait);
	/* Liveness probing.  Publishes run inline in SIP workers; a black-holed
	 * broker (network drop with no RST) leaves the socket writable until
	 * cnats's ping mechanism declares the connection DISCONNECTED.  The
	 * default 2-minute ping interval x 2 missed pings means ~4 minutes of
	 * workers blocking/buffering before fast-fail trips.  Shorten it: a
	 * 10 s ping with 2 missed pings detects the dead link in ~20 s. */
	nats_dl.natsOptions_SetPingInterval(opts, (int64_t)NATS_POOL_PING_INTERVAL_MS);
	nats_dl.natsOptions_SetMaxPingsOut(opts, NATS_POOL_MAX_PINGS_OUT);
	nats_dl.natsOptions_SetDisconnectedCB(opts, _pool_disconnected_cb, NULL);
	nats_dl.natsOptions_SetReconnectedCB(opts, _pool_reconnected_cb, NULL);

	/* Async first connect: with the broker unreachable at BOOT,
	 * natsConnection_Connect() returns NATS_NOT_YET_CONNECTED
	 * immediately and cnats keeps dialing in the background using the
	 * reconnect settings above, firing the connected callback on first
	 * success.  Without this every OpenSIPS process blocked inside the
	 * synchronous retry loop below for the full max_reconnect budget
	 * (~2 min) during child_init -- core timers stalled and SIP was
	 * unresponsive (caught by test_boot_degraded_e2e.sh).  Reuse
	 * _pool_reconnected_cb as the first-connect callback: it sets
	 * _connected, bumps the reconnect epoch and marks KV handles
	 * stale -- exactly the post-connect bookkeeping needed here. */
	nats_dl.natsOptions_SetRetryOnFailedConnect(opts, true,
		_pool_reconnected_cb, NULL);

	/* TLS configuration -- sourced from the tls_mgm "nats" client
	 * domain (apply_tls_from_mgm).  Set up only when at least one
	 * configured URL is tls://. */
	if (pool_cfg->use_tls) {
		nats_dl.natsOptions_SetSecure(opts, true);
		if (apply_tls_from_mgm(opts) < 0)
			goto error;
	}

	/* Retry connection with bounded attempts. pool_cfg->max_reconnect
	 * gates startup only; runtime reconnection is unlimited (set above). */
	{
		int attempts = 0;
		for (;;) {
			s = nats_dl.natsConnection_Connect(&_nc, opts);
			if (s == NATS_OK)
				break;

			/* Broker unreachable: the connection object is live and
			 * dialing in the background (SetRetryOnFailedConnect).
			 * Continue DEGRADED instead of blocking this process --
			 * _connected stays 0 (fast-fails everywhere) until the
			 * first-connect callback fires. */
			if (s == NATS_NOT_YET_CONNECTED) {
				LM_WARN("NATS pool: broker unreachable at startup; "
					"continuing degraded with background "
					"connect retries\n");
				break;
			}

			attempts++;
			{
				char stack_buf[1024];
				nats_dl.nats_GetLastErrorStack(stack_buf, sizeof(stack_buf));
				LM_ERR("NATS pool: connection attempt %d/%d failed: "
					"%s [%s]\n",
					attempts, pool_cfg->max_reconnect,
					nats_dl.natsStatus_GetText(s),
					stack_buf[0] ? stack_buf : "no detail");
			}

			if (attempts >= pool_cfg->max_reconnect) {
				LM_ERR("NATS pool: giving up after %d attempts\n",
					attempts);
				goto error;
			}

			/* Per-process jitter on the retry sleep so N workers that all
			 * start (or recover) against a down broker don't retry in
			 * lockstep.  Derived from the PID so it is stable but spread;
			 * up to half the base wait on top of it. */
			{
				int base = pool_cfg->reconnect_wait;
				int span = base / 2 + 1;
				int jit  = (int)((unsigned)getpid() % (unsigned)span);
				nats_dl.nats_Sleep(base + jit);
			}
		}
	}

	nats_dl.natsOptions_Destroy(opts);

	/* Degraded start: skip the connected bookkeeping -- the
	 * first-connect callback handles it when the broker appears. */
	if (s != NATS_OK)
		return _nc;

	atomic_store(&_connected, 1);

	/* Log connected URL — natsConnection_GetConnectedUrl is documented
	 * to strip credentials, but redact defensively in case any nats.c
	 * version preserves them. */
	{
		char url[256];
		char redacted[256];
		url[0] = '\0';   /* defensive: see _pool_reconnected_cb */
		nats_dl.natsConnection_GetConnectedUrl(_nc, url, sizeof(url));
		nats_redact_url(url, redacted, sizeof(redacted));
		LM_INFO("NATS pool: connected to %s (%d server(s) configured)\n",
			redacted, pool_cfg->server_cnt);
	}

	return _nc;

error:
	if (opts)
		nats_dl.natsOptions_Destroy(opts);
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
	nats_dl.jsOptions_Init(&jsOpts);
	jsOpts.PublishAsync.AckHandler = _js_pub_ack_handler;
	/* Cap in-flight async publishes.  Left at 0 (cnats default = unlimited)
	 * a degraded-but-connected JetStream would let every event queue inside
	 * cnats in each SIP worker until OOM, with no fast-fail (the connection
	 * is still up).  With a cap, js_PublishAsync returns an error once the
	 * queue is full — counted as a drop by the producer's `failed` stat —
	 * instead of growing memory.  A small StallWait bounds how long a full
	 * queue blocks the worker before erroring. */
	jsOpts.PublishAsync.MaxPending = NATS_JS_PUBLISH_ASYNC_MAX_PENDING;
	jsOpts.PublishAsync.StallWait  = NATS_JS_PUBLISH_ASYNC_STALL_WAIT_MS;
	/* Per-op request timeout for JetStream/KV operations.  Left at 0 cnats
	 * uses its 5 s default, which is far above any per-REGISTER budget on
	 * the usrloc hot path; let the operator tune it down. */
	if (nats_pool_kv_op_timeout_ms > 0)
		jsOpts.Wait = nats_pool_kv_op_timeout_ms;

	s = nats_dl.natsConnection_JetStream(&_js, _nc, &jsOpts);
	if (s != NATS_OK) {
		LM_ERR("NATS pool: JetStream context creation failed: %s\n",
			nats_dl.natsStatus_GetText(s));
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
/* P8 [R6]: read / set the process-global per-message-TTL capability latch.
 * The cachedb module computes the next state via _ttl_cap_next() and stores it;
 * the pool resets it to UNPROBED (0) on reconnect (see the cache-clear above). */
int nats_pool_ttl_cap(void)
{
	return atomic_load(&_ttl_cap);
}
void nats_pool_ttl_cap_set(int cap)
{
	atomic_store(&_ttl_cap, cap);
}

/* P8 [R5 / TTL-SOLUTION-SPEC.md §3]: enable per-message TTL on a KV bucket's
 * backing stream (KV_<bucket>) via js_UpdateStream.  Idempotent (no-op if
 * already enabled).  Pure broker plumbing -- the caller (cachedb module) drives
 * the capability latch from the return code so the tested _ttl_cap_next() state
 * machine stays in the module, not in lib/nats.
 *
 *   return  1: AllowMsgTTL is now (or was already) enabled -> SUPPORTED
 *           0: not available (server <2.11 / AllowMsgTTL rejected / MaxAge!=0)
 *              -> UNSUPPORTED, fall back to reaper-only expiry
 *          -1: transient (no JS / GetStreamInfo failed) -> leave UNPROBED, retry
 *
 * marker_ttl_ns = SubjectDeleteMarkerTTL (ns): emit a delete marker on
 * server-side expiry so the watcher learns of it (§4); 0 would mean silent
 * vanish -> index drift, so callers pass a small non-zero value. */
/* P11b [REV-25]: read the bound bucket's backing-stream MaxAge (ns). */
int nats_pool_bucket_maxage_ns(const char *bucket, int64_t *out_ns)
{
	char stream[160];
	jsStreamInfo *si = NULL;
	jsErrCode jerr = 0;
	natsStatus s;

	if (!_js || !bucket || !out_ns)
		return -1;
	snprintf(stream, sizeof(stream), "KV_%s", bucket);

	s = nats_dl.js_GetStreamInfo(&si, _js, stream, NULL, &jerr);
	if (s != NATS_OK || !si || !si->Config) {
		LM_WARN("NATS pool: GetStreamInfo(%s) failed (%s, jerr=%d); cannot "
			"read bucket MaxAge\n", stream, nats_dl.natsStatus_GetText(s), jerr);
		if (si)
			nats_dl.jsStreamInfo_Destroy(si);
		return -1;
	}
	*out_ns = (int64_t)si->Config->MaxAge;
	nats_dl.jsStreamInfo_Destroy(si);
	return 0;
}

/* P8 Phase A [TTL-SOLUTION §2.4 / TREV-4]: SubjectDeleteMarkerTTL applied at
 * bucket creation via kvConfig.LimitMarkerTTL (nats.c PR #1000).  The default
 * 30s bounds the server-placed delete marker's lifetime so the watcher can
 * drop the index entry (§4) without the marker lingering.  [D6/HREV-6] the
 * value is now operator-tunable: the module's kv_marker_ttl modparam is
 * pushed here via nats_pool_set_marker_ttl_ns() at mod_init, BEFORE any
 * bucket creation. */
#define NATS_KV_MARKER_TTL_NS  (30LL * 1000000000LL)

static int64_t _marker_ttl_ns = NATS_KV_MARKER_TTL_NS;

void nats_pool_set_marker_ttl_ns(int64_t ns)
{
	if (ns > 0)
		_marker_ttl_ns = ns;
}

/* P8 Phase A: read-only per-message-TTL capability probe.  The bucket is created
 * with AllowMsgTTL natively via kvConfig.LimitMarkerTTL (see nats_pool_get_kv),
 * so this no longer writes the stream -- no js_UpdateStream read-modify-write,
 * and hence no _marshalPlacement(strlen(NULL)) crash to work around.  Just reads
 * the bound stream's config and reports capability.
 *
 * [HREV-1] the probe additionally REPORTS the stream's MaxMsgsPerSubject via
 * @out_mmps (nullable): per-message TTL misbehaves on history-keeping streams
 * (late removal + revision rollback, verified on 2.11.10), but the single
 * tested history rule (_kv_ttl_history_ok + the nats_ttl_allow_history
 * override) lives in the MODULE -- this probe stays mechanical so there is
 * exactly one implementation of the policy.
 *
 *   return  1: AllowMsgTTL enabled and MaxAge==0 -> stream-level SUPPORTED
 *              (the caller still applies the history rule to *out_mmps)
 *           0: not available (pre-existing bucket created without it, or
 *              MaxAge!=0) -> UNSUPPORTED, fall back to reaper-only expiry
 *          -1: transient (no JS / GetStreamInfo failed) -> leave UNPROBED, retry */
int nats_pool_kv_supports_ttl(const char *bucket, int64_t *out_mmps)
{
	char stream[160];
	jsStreamInfo *si = NULL;
	jsErrCode jerr = 0;
	natsStatus s;

	if (!_js)
		return -1;
	snprintf(stream, sizeof(stream), "KV_%s", bucket);

	s = nats_dl.js_GetStreamInfo(&si, _js, stream, NULL, &jerr);
	if (s != NATS_OK || !si || !si->Config) {
		LM_WARN("NATS pool: GetStreamInfo(%s) failed (%s, jerr=%d); cannot "
			"probe AllowMsgTTL\n", stream, nats_dl.natsStatus_GetText(s), jerr);
		if (si)
			nats_dl.jsStreamInfo_Destroy(si);
		return -1;
	}

	if (out_mmps)
		*out_mmps = (int64_t)si->Config->MaxMsgsPerSubject;

	/* [R7 pair, §3] bucket MaxAge MUST be 0: a non-zero MaxAge overrides
	 * per-message TTL and expires permanent contacts.  Refuse TTL here too. */
	if (si->Config->MaxAge != 0) {
		LM_ERR("NATS pool: stream %s has MaxAge=%lldns != 0; per-message TTL "
			"would be overridden -- set kv_ttl=0. Falling back to reaper.\n",
			stream, (long long)si->Config->MaxAge);
		nats_dl.jsStreamInfo_Destroy(si);
		return 0;
	}

	if (si->Config->AllowMsgTTL) {
		LM_DBG("NATS pool: stream %s has AllowMsgTTL\n", stream);
		nats_dl.jsStreamInfo_Destroy(si);
		return 1;
	}

	/* A pre-existing bucket created before LimitMarkerTTL was used: no native
	 * retrofit (Phase A dropped the js_UpdateStream path) -- recreate the bucket
	 * to get per-key TTL; until then the reaper remains authoritative. */
	LM_INFO("NATS pool: stream %s has no AllowMsgTTL (pre-existing bucket); "
		"per-message TTL off, reaper remains authoritative\n", stream);
	nats_dl.jsStreamInfo_Destroy(si);
	return 0;
}

/* [HREV-1/D1.4] read the bound bucket's backing-stream MaxMsgsPerSubject
 * (the KV history depth) for the module's startup surfacing.  Mirrors
 * nats_pool_bucket_maxage_ns.  0 = ok (*out_mmps filled), -1 = unavailable. */
int nats_pool_bucket_mmps(const char *bucket, int64_t *out_mmps)
{
	char stream[160];
	jsStreamInfo *si = NULL;
	jsErrCode jerr = 0;
	natsStatus s;

	if (!_js || !bucket || !out_mmps)
		return -1;
	snprintf(stream, sizeof(stream), "KV_%s", bucket);

	s = nats_dl.js_GetStreamInfo(&si, _js, stream, NULL, &jerr);
	if (s != NATS_OK || !si || !si->Config) {
		LM_WARN("NATS pool: GetStreamInfo(%s) failed (%s, jerr=%d); cannot "
			"read bucket MaxMsgsPerSubject\n", stream,
			nats_dl.natsStatus_GetText(s), jerr);
		if (si)
			nats_dl.jsStreamInfo_Destroy(si);
		return -1;
	}
	*out_mmps = (int64_t)si->Config->MaxMsgsPerSubject;
	nats_dl.jsStreamInfo_Destroy(si);
	return 0;
}

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
	/* Reject a name that would not fit the cache key buffer rather than
	 * snprintf-truncating it below: two distinct buckets sharing a long
	 * prefix would otherwise collide on the truncated key and the cache
	 * would hand back the wrong kvStore handle. */
	if (strlen(bucket) >= sizeof(_kv_cache[0].bucket)) {
		LM_ERR("NATS pool: KV bucket name too long (max %zu): '%s'\n",
			sizeof(_kv_cache[0].bucket) - 1, bucket);
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
	 * libnats requires the caller to destroy kvStore handles when
	 * done; see nats/nats.h kvStore_Destroy().  Earlier revisions
	 * relied on refcounting to clean these up on reconnect, but the
	 * public contract puts destruction on us, and skipping it leaks
	 * one handle per bucket per reconnect event. */
	if (atomic_exchange(&_kv_stale, 0)) {
		for (i = 0; i < _kv_cache_cnt; i++) {
			if (_kv_cache[i].kv) {
				nats_dl.kvStore_Destroy(_kv_cache[i].kv);
				_kv_cache[i].kv = NULL;
			}
		}
		_kv_cache_cnt = 0;
		atomic_store(&_ttl_cap, 0);   /* [R6] re-probe TTL capability after reconnect */
		LM_NOTICE("NATS pool: KV cache cleared after reconnect\n");
	}

	/* Check cache for an existing handle for this bucket */
	for (i = 0; i < _kv_cache_cnt; i++) {
		if (_kv_cache[i].kv &&
		    strcmp(_kv_cache[i].bucket, bucket) == 0)
			return _kv_cache[i].kv;
	}

	/* Try to bind to existing bucket on the server first */
	s = nats_dl.js_KeyValue(&kv, _js, bucket);
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
		else
			/* P8 Phase A: per-key TTL mode (no bucket MaxAge).  Enable
			 * AllowMsgTTL + auto-expiring delete markers natively at creation
			 * via kvConfig.LimitMarkerTTL (nats.c PR #1000), replacing the
			 * post-create js_UpdateStream retrofit.  Inert until a write sets a
			 * per-message TTL, so it is safe for all of this module's buckets.
			 * [D6] lifetime = kv_marker_ttl (nats_pool_set_marker_ttl_ns). */
			kvCfg.LimitMarkerTTL = _marker_ttl_ns;

		s = nats_dl.js_CreateKeyValue(&kv, _js, &kvCfg);
		if (s != NATS_OK) {
			LM_ERR("NATS pool: KV bucket '%s' create failed: %s\n",
				bucket, nats_dl.natsStatus_GetText(s));
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
		/* Cache full: do NOT hand back an uncached handle.  Callers
		 * treat the result as pool-owned and never kvStore_Destroy()
		 * it, so every subsequent call for this bucket would create
		 * and leak another handle.  Destroy this one and fail loudly
		 * instead -- raise NATS_POOL_MAX_KV_BUCKETS if more buckets
		 * are genuinely needed. */
		LM_ERR("NATS pool: KV bucket cache full (%d buckets); refusing "
			"bucket '%s' to avoid leaking handles.  Raise "
			"NATS_POOL_MAX_KV_BUCKETS if you need more.\n",
			NATS_POOL_MAX_KV_BUCKETS, bucket);
		nats_dl.kvStore_Destroy(kv);
		return NULL;
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
 * 3. Connection drained THEN destroyed — nats_dl.natsConnection_Drain() flushes
 *    pending messages and waits for in-flight operations to complete
 *    before closing.  This ensures the I/O threads finish their work
 *    before we destroy the connection.  Without draining first,
 *    nats_dl.natsConnection_Destroy() would tear down the socket while I/O
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
/*
 * Drop one registration reference.  The pool is actually torn down only on
 * the LAST unregister, so the shared connection survives while any loaded
 * NATS module still uses it, and is always destroyed when the last module
 * is unloaded (even when event_nats -- the historical sole caller of
 * nats_pool_destroy -- is not loaded).  Call once per module from
 * mod_destroy, matching the module's successful nats_pool_register().
 */
void nats_pool_unregister(void)
{
	if (_register_count > 0)
		_register_count--;
	if (_register_count > 0) {
		LM_DBG("NATS pool: unregister (%d registration(s) remain)\n",
			_register_count);
		return;
	}
	nats_pool_destroy();
}

void nats_pool_destroy(void)
{
	int i;

	/* Idempotent: tolerate a direct call or a repeated last-unregister. */
	if (!pool_cfg && !_nc && !_js) {
		_register_count = 0;
		return;
	}

	LM_INFO("NATS pool: destroying\n");

	/* Step 1: Destroy KV handles (depend on _js) */
	for (i = 0; i < _kv_cache_cnt; i++) {
		if (_kv_cache[i].kv) {
			nats_dl.kvStore_Destroy(_kv_cache[i].kv);
			_kv_cache[i].kv = NULL;
		}
	}
	_kv_cache_cnt = 0;

	/* Step 2: Destroy JetStream context (depends on _nc).  First wait
	 * (bounded) for outstanding async publishes to be acked, so events
	 * published just before shutdown are not silently abandoned when the
	 * JS context is torn down. */
	if (_js) {
		jsPubOptions po;
		int budget_ms = nats_pool_drain_timeout_ms > 0
			? nats_pool_drain_timeout_ms : 5000;
		nats_dl.jsPubOptions_Init(&po);
		po.MaxWait = budget_ms;
		(void)nats_dl.js_PublishAsyncComplete(_js, &po);
		nats_dl.jsCtx_Destroy(_js);
		_js = NULL;
	}

	/* Step 3: Drain then destroy connection.
	 * Drain flushes pending publishes, waits for acks, then closes.
	 * Use DrainTimeout with an explicit bound (nats_pool_drain_timeout_ms,
	 * default 5 s, modparam-tunable per loaded module) so we don't
	 * hang mod_destroy if the broker is unreachable.  Log non-OK
	 * with the configured budget so an operator investigating
	 * ack-loss has both a fingerprint and a hint at which knob to
	 * raise, then proceed to Destroy regardless -- shutdown must
	 * complete. */
	if (_nc) {
		int budget_ms = nats_pool_drain_timeout_ms > 0
			? nats_pool_drain_timeout_ms : 5000;
		natsStatus ds = nats_dl.natsConnection_DrainTimeout(_nc, budget_ms);
		if (ds != NATS_OK) {
			LM_WARN("NATS pool: connection drain returned %s "
				"after %d ms; in-flight JetStream publishes "
				"may not have acked before destroy.  Raise "
				"nats_drain_timeout_ms (event_nats) or "
				"cdb_drain_timeout_ms (cachedb_nats) if you "
				"are seeing ack loss on shutdown.\n",
				nats_dl.natsStatus_GetText(ds), budget_ms);
		}
		nats_dl.natsConnection_Destroy(_nc);
		_nc = NULL;
	}

	atomic_store(&_connected, 0);

	/* Step 4: Free shared config (SHM) */
	if (pool_cfg) {
		for (i = 0; i < pool_cfg->server_cnt; i++) {
			if (pool_cfg->servers[i])
				shm_free(pool_cfg->servers[i]);
		}
		shm_free(pool_cfg);
		pool_cfg = NULL;
	}

	_register_count = 0;
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
 * Queries nats_dl.natsConnection_GetConnectedUrl() directly on each call to
 * avoid returning a stale pointer.  The result is written into a
 * process-local static buffer and is valid until the next call.
 *
 * @return  Server URL string (process-local, do not free), or
 *          "not connected" if no active connection.
 *
 * Thread safety: Called from OpenSIPS process context only.
 * The static buffer is process-local (each forked process has its own).
 * We call nats_dl.natsConnection_GetConnectedUrl() which is thread-safe in
 * nats.c (it locks internally), so this is safe even if the reconnect
 * callback fires concurrently — we always get a consistent snapshot.
 */
const char *nats_pool_get_server_info(void)
{
	static char _server_info_buf[512];
	char raw[512];

	if (!_nc)
		return "not connected";

	/* Init defensively: on a non-OK status GetConnectedUrl may leave the
	 * buffer unterminated, and nats_redact_url() would then read
	 * uninitialised stack. */
	raw[0] = '\0';
	if (nats_dl.natsConnection_GetConnectedUrl(_nc, raw,
	    sizeof(raw)) != NATS_OK)
		return "not connected";

	/* Redact any user:pass@ credentials before returning — this value is
	 * surfaced to MI clients (mi_nats_status) and must not leak the
	 * broker password. */
	nats_redact_url(raw, _server_info_buf, sizeof(_server_info_buf));
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

/* True once any module has called nats_pool_register().  Lets a module
 * decide whether to contribute a default URL (standalone) or inherit a
 * pool another NATS module already registered. */
int nats_pool_is_registered(void)
{
	return pool_cfg != NULL;
}
