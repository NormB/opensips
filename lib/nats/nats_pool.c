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

#include <string.h>
#include <stdatomic.h>

#include <nats/nats.h>

#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../sr_module.h"
#include "nats_connection.h"

/*
 * Minimal OpenSIPS module exports — nats_connection is a shared library
 * module with no script functions, no params, no MI commands. It exists
 * solely to be dlopen'd with RTLD_GLOBAL so event_nats and cachedb_nats
 * can link against its symbols at runtime.
 */
struct module_exports exports = {
	"nats_connection",       /* module name */
	MOD_TYPE_DEFAULT,        /* class */
	MODULE_VERSION,          /* version */
	RTLD_NOW | RTLD_GLOBAL,  /* dlopen flags — MUST be GLOBAL for symbol sharing */
	0,                       /* load function */
	NULL,                    /* module deps */
	0,                       /* exported functions */
	0,                       /* async functions */
	0,                       /* module parameters */
	0,                       /* statistics */
	0,                       /* MI commands */
	0,                       /* pseudo-variables */
	0,                       /* transformations */
	0,                       /* extra processes */
	0,                       /* pre_init */
	0,                       /* mod_init */
	0,                       /* response handler */
	0,                       /* destroy */
	0,                       /* child_init */
	0                        /* reload confirm */
};

/* ----------------------------------------------------------------
 * Shared pool configuration (shm, set pre-fork in mod_init)
 * ---------------------------------------------------------------- */

#define NATS_POOL_MAX_SERVERS 16
#define NATS_POOL_DEFAULT_RECONNECT_WAIT 2000
#define NATS_POOL_DEFAULT_MAX_RECONNECT  60

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
 * Callback registry (process-local, registered pre-fork but
 * invoked post-fork on the nats.c internal thread)
 * ---------------------------------------------------------------- */

typedef struct {
	nats_reconnected_cb  cb;
	void                *closure;
} reconnect_entry;

typedef struct {
	nats_disconnected_cb cb;
	void                *closure;
} disconnect_entry;

static reconnect_entry  _reconnect_cbs[NATS_POOL_MAX_CALLBACKS];
static int              _reconnect_cb_cnt = 0;

static disconnect_entry _disconnect_cbs[NATS_POOL_MAX_CALLBACKS];
static int              _disconnect_cb_cnt = 0;

/* ----------------------------------------------------------------
 * Process-local connection state (set post-fork)
 * ---------------------------------------------------------------- */

static int              _lib_initialized = 0;
static natsConnection  *_nc = NULL;
static jsCtx           *_js = NULL;
static atomic_int       _connected = 0;

/* KV handle cache */
typedef struct {
	char     bucket[128];
	kvStore *kv;
} kv_cache_entry;

static kv_cache_entry _kv_cache[NATS_POOL_MAX_KV_BUCKETS];
static int            _kv_cache_cnt = 0;

/* Server info string (process-local) */
static char _server_info[512];

/* ----------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------- */

/* Deep-copy a C string into shared memory. Returns NULL on failure. */
static char *shm_strdup(const char *s)
{
	size_t len;
	char *p;

	if (!s)
		return NULL;
	len = strlen(s) + 1;
	p = shm_malloc(len);
	if (!p) {
		LM_ERR("shm_malloc(%zu) failed\n", len);
		return NULL;
	}
	memcpy(p, s, len);
	return p;
}

/* Parse comma-separated URL string into pool_cfg->servers[].
 * Each token is shm-allocated. Sets pool_cfg->use_tls if any URL
 * starts with "tls://". */
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
 * nats.c callbacks (run on nats.c internal thread)
 * ---------------------------------------------------------------- */

static void _pool_disconnected_cb(natsConnection *nc, void *closure)
{
	int i;

	LM_WARN("NATS pool: connection disconnected\n");
	atomic_store(&_connected, 0);

	for (i = 0; i < _disconnect_cb_cnt; i++) {
		if (_disconnect_cbs[i].cb)
			_disconnect_cbs[i].cb(_disconnect_cbs[i].closure);
	}
}

static void _pool_reconnected_cb(natsConnection *nc, void *closure)
{
	char url[256];
	int i;

	natsConnection_GetConnectedUrl(nc, url, sizeof(url));
	LM_NOTICE("NATS pool: reconnected to %s\n", url);
	atomic_store(&_connected, 1);

	/*
	 * Invalidate cached KV handles. Do NOT call kvStore_Destroy() here —
	 * SIP worker threads may hold pointers to these handles and be
	 * mid-operation (kvStore_Get, kvStore_PutString, etc.). Destroying
	 * from this callback thread would be a use-after-free.
	 *
	 * Instead, NULL out the cache entries. The old handles are
	 * intentionally leaked; nats.c cleans them up at nats_Close() time.
	 * Fresh handles are created on the next nats_pool_get_kv() call.
	 */
	for (i = 0; i < _kv_cache_cnt; i++)
		_kv_cache[i].kv = NULL;
	_kv_cache_cnt = 0;

	/* notify registered modules */
	for (i = 0; i < _reconnect_cb_cnt; i++) {
		if (_reconnect_cbs[i].cb)
			_reconnect_cbs[i].cb(_reconnect_cbs[i].closure);
	}
}

/* JetStream async publish ack handler — runs on nats.c internal thread.
 * Signature must match jsPubAckHandler typedef:
 *   void (*)(jsCtx*, natsMsg*, jsPubAck*, jsPubAckErr*, void*)
 */
static void _js_pub_ack_handler(jsCtx *js, natsMsg *msg, jsPubAck *pa,
                                 jsPubAckErr *pae, void *closure)
{
	if (pae) {
		LM_ERR("NATS JetStream async publish error: %s\n",
			pae->ErrText ? pae->ErrText : "unknown");
	}
	if (pa)
		jsPubAck_Destroy(pa);
	if (msg)
		natsMsg_Destroy(msg);
}

/* ----------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------- */

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

		/* copy TLS config */
		if (tls) {
			pool_cfg->tls.ca = shm_strdup(tls->ca);
			pool_cfg->tls.cert = shm_strdup(tls->cert);
			pool_cfg->tls.key = shm_strdup(tls->key);
			pool_cfg->tls.hostname = shm_strdup(tls->hostname);
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

natsConnection *nats_pool_get(void)
{
	natsOptions *opts = NULL;
	natsStatus s;

	/* return cached connection */
	if (_nc)
		return _nc;

	if (!pool_cfg) {
		LM_ERR("NATS pool: not registered (call nats_pool_register first)\n");
		return NULL;
	}

	/* initialize nats.c library — once per process */
	if (!_lib_initialized) {
		s = nats_Open(-1);
		if (s != NATS_OK) {
			LM_ERR("NATS pool: nats_Open failed: %s\n",
				natsStatus_GetText(s));
			return NULL;
		}
		_lib_initialized = 1;
	}

	/* create options */
	s = natsOptions_Create(&opts);
	if (s != NATS_OK) {
		LM_ERR("NATS pool: natsOptions_Create failed: %s\n",
			natsStatus_GetText(s));
		return NULL;
	}

	/* set server list */
	s = natsOptions_SetServers(opts,
		(const char **)pool_cfg->servers, pool_cfg->server_cnt);
	if (s != NATS_OK) {
		LM_ERR("NATS pool: natsOptions_SetServers failed: %s\n",
			natsStatus_GetText(s));
		goto error;
	}

	/*
	 * Set nats.c internal reconnect to UNLIMITED (-1). This is critical
	 * for cluster resilience: nats.c permanently removes a server from
	 * its pool after max_reconnect failures (natsSrvPool_GetNextServer
	 * calls _freeSrv). With a finite limit, a long network partition
	 * can empty the pool and kill the connection forever.
	 *
	 * The bounded retry in our startup loop (pool_cfg->max_reconnect)
	 * is separate — it only gates the initial connection in child_init.
	 * Once connected, nats.c's reconnect thread takes over and should
	 * never give up. Cluster gossip (INFO connect_urls) dynamically
	 * adds new servers; unlimited reconnect ensures they stay in the
	 * pool even if temporarily unreachable.
	 */
	natsOptions_SetMaxReconnect(opts, -1);
	natsOptions_SetReconnectWait(opts, pool_cfg->reconnect_wait);
	natsOptions_SetDisconnectedCB(opts, _pool_disconnected_cb, NULL);
	natsOptions_SetReconnectedCB(opts, _pool_reconnected_cb, NULL);

	/* TLS configuration — only applied when URLs use tls:// */
	if (pool_cfg->use_tls) {
		natsOptions_SetSecure(opts, true);

		/* CA certificate for server verification */
		if (pool_cfg->tls.ca && *pool_cfg->tls.ca) {
			s = natsOptions_LoadCATrustedCertificates(opts,
				pool_cfg->tls.ca);
			if (s != NATS_OK)
				LM_WARN("NATS pool: failed to load CA cert '%s': %s\n",
					pool_cfg->tls.ca, natsStatus_GetText(s));
		}

		/* client certificate + key for mutual TLS */
		if (pool_cfg->tls.cert && *pool_cfg->tls.cert) {
			s = natsOptions_LoadCertificatesChain(opts,
				pool_cfg->tls.cert,
				(pool_cfg->tls.key && *pool_cfg->tls.key) ?
					pool_cfg->tls.key : NULL);
			if (s != NATS_OK)
				LM_WARN("NATS pool: failed to load client cert '%s': %s\n",
					pool_cfg->tls.cert, natsStatus_GetText(s));
		}

		/* expected hostname for cert verification */
		if (pool_cfg->tls.hostname && *pool_cfg->tls.hostname) {
			s = natsOptions_SetExpectedHostname(opts,
				pool_cfg->tls.hostname);
			if (s != NATS_OK)
				LM_WARN("NATS pool: failed to set expected hostname "
					"'%s': %s\n",
					pool_cfg->tls.hostname, natsStatus_GetText(s));
		}

		/* skip server certificate verification if configured */
		if (pool_cfg->tls.skip_verify)
			natsOptions_SkipServerVerification(opts, true);
	}

	/* retry connection with bounded attempts */
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

jsCtx *nats_pool_get_js(void)
{
	natsStatus s;
	jsOptions jsOpts;

	/* return cached context */
	if (_js)
		return _js;

	/* ensure we have a connection */
	if (!_nc && !nats_pool_get())
		return NULL;

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

	/* ensure we have a JetStream context */
	if (!_js && !nats_pool_get_js())
		return NULL;

	/* check cache first */
	for (i = 0; i < _kv_cache_cnt; i++) {
		if (_kv_cache[i].kv &&
		    strcmp(_kv_cache[i].bucket, bucket) == 0)
			return _kv_cache[i].kv;
	}

	/* try to bind to existing bucket first */
	s = js_KeyValue(&kv, _js, bucket);
	if (s != NATS_OK) {
		/* bucket does not exist — create it */
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

	/* cache the handle */
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

int nats_pool_on_reconnect(nats_reconnected_cb cb, void *closure)
{
	if (_reconnect_cb_cnt >= NATS_POOL_MAX_CALLBACKS) {
		LM_ERR("NATS pool: max reconnect callbacks reached (%d)\n",
			NATS_POOL_MAX_CALLBACKS);
		return -1;
	}

	_reconnect_cbs[_reconnect_cb_cnt].cb = cb;
	_reconnect_cbs[_reconnect_cb_cnt].closure = closure;
	_reconnect_cb_cnt++;
	return 0;
}

int nats_pool_on_disconnect(nats_disconnected_cb cb, void *closure)
{
	if (_disconnect_cb_cnt >= NATS_POOL_MAX_CALLBACKS) {
		LM_ERR("NATS pool: max disconnect callbacks reached (%d)\n",
			NATS_POOL_MAX_CALLBACKS);
		return -1;
	}

	_disconnect_cbs[_disconnect_cb_cnt].cb = cb;
	_disconnect_cbs[_disconnect_cb_cnt].closure = closure;
	_disconnect_cb_cnt++;
	return 0;
}

void nats_pool_destroy(void)
{
	static int _pool_destroyed = 0;
	int i;

	if (_pool_destroyed) {
		LM_DBG("NATS pool: already destroyed, skipping\n");
		return;
	}
	_pool_destroyed = 1;

	LM_INFO("NATS pool: destroying\n");

	/* destroy KV handles */
	for (i = 0; i < _kv_cache_cnt; i++) {
		if (_kv_cache[i].kv) {
			kvStore_Destroy(_kv_cache[i].kv);
			_kv_cache[i].kv = NULL;
		}
	}
	_kv_cache_cnt = 0;

	/* destroy JetStream context */
	if (_js) {
		jsCtx_Destroy(_js);
		_js = NULL;
	}

	/* drain and destroy connection */
	if (_nc) {
		natsConnection_Drain(_nc);
		natsConnection_Destroy(_nc);
		_nc = NULL;
	}

	atomic_store(&_connected, 0);

	/* shut down nats.c library (thread pool, timers, etc.) */
	if (_lib_initialized) {
		nats_Close();
		_lib_initialized = 0;
	}

	/* free shared config */
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

	_reconnect_cb_cnt = 0;
	_disconnect_cb_cnt = 0;
}

int nats_pool_is_connected(void)
{
	return atomic_load(&_connected) ? 1 : 0;
}

const char *nats_pool_get_server_info(void)
{
	if (!_nc)
		return "not connected";

	if (natsConnection_GetConnectedUrl(_nc, _server_info,
	    sizeof(_server_info)) != NATS_OK)
		return "not connected";

	return _server_info;
}
