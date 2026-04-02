/*
 * Copyright (C) 2025 Summit-2026 / cachedb_nats contributors
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

/*
 * cachedb_nats.c -- OpenSIPS cachedb engine backed by NATS JetStream KV
 *
 * Module architecture:
 *
 * This module implements the OpenSIPS cachedb API on top of NATS JetStream
 * Key-Value stores.  It provides:
 *
 *   - Standard cachedb operations (get/set/remove/add/sub/get_counter)
 *     mapped to KV put/get/delete/create/purge operations.
 *   - JSON full-text search via raw_query ("search:term") and the
 *     cachedb query/update/map_get/map_set/map_remove extensions.
 *   - Native script functions: nats_request() for synchronous NATS
 *     request/reply, and nats_kv_history() for key version history.
 *   - A self-healing KV watcher thread (cachedb_nats_watch.c) that
 *     keeps the JSON search index in sync with live KV mutations and
 *     raises E_NATS_KV_CHANGE EVI events.
 *
 * Connection management:
 *   mod_init() registers with the shared NATS connection pool (lib/nats/).
 *   child_init() obtains per-process connections, creates the KV bucket
 *   if needed, builds the initial search index, and starts the watcher
 *   thread on the first SIP worker.
 *
 * Rank filtering:
 *   Only SIP UDP workers (rank 1..udp_workers_no) and the HTTPD/MI
 *   process (PROC_MODULE) initialize NATS.  TCP/WSS receivers are
 *   excluded to avoid heap corruption from nats.c I/O threads
 *   conflicting with OpenSSL in WSS receiver processes.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../sr_module.h"
#include "../../globals.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../pt.h"
#include "../../cachedb/cachedb.h"
#include "../../mod_fix.h"
#include "../../mi/mi.h"

#include "cachedb_nats.h"
#include "cachedb_nats_dbase.h"
#include "cachedb_nats_json.h"
#include "cachedb_nats_watch.h"
#include "cachedb_nats_native.h"
#include "../../lib/nats/nats_pool.h"

#ifdef HAVE_EVI
#include "../../evi/evi.h"
#endif

/* module lifecycle */
static int mod_init(void);
static int child_init(int rank);
static void destroy(void);

/* script function wrappers (implementations in cachedb_nats_native.c) */
static int w_nats_request_wrap(struct sip_msg *msg, str *subject, str *payload,
                               int *timeout, pv_spec_t *result);
static int w_nats_kv_history_wrap(struct sip_msg *msg, str *key,
                                  pv_spec_t *result);
static int w_nats_kv_get_wrap(struct sip_msg *msg, str *bucket, str *key,
                              pv_spec_t *value_var, pv_spec_t *rev_var);
static int w_nats_kv_put_wrap(struct sip_msg *msg, str *bucket, str *key,
                              str *value);
static int w_nats_kv_update_wrap(struct sip_msg *msg, str *bucket, str *key,
                                 str *value, int *expected_rev);
static int w_nats_kv_delete_wrap(struct sip_msg *msg, str *bucket, str *key);
static int w_nats_kv_revision_wrap(struct sip_msg *msg, str *bucket, str *key,
                                   pv_spec_t *rev_var);

/* MI command handler */
static mi_response_t *mi_nats_kv_status(const mi_params_t *params,
                                         struct mi_handler *async_hdl);

/* cachedb engine name -- must match the URL scheme prefix */
static str cache_mod_name = str_init("nats");
static struct cachedb_url *nats_cdb_urls = NULL;

/* module parameters -- non-static, accessed from cachedb_nats_dbase.c */
char *kv_bucket = "opensips";
int kv_replicas = 3;
int kv_history = 5;
int kv_ttl = 0;

/* TLS parameters (mirrored from event_nats for independent pool) */
static char *nats_url = NULL;      /* NATS server URL(s) -- overrides cachedb_url host */
static char *tls_ca = NULL;
static char *tls_cert = NULL;
static char *tls_key = NULL;
static char *tls_hostname = NULL;
static int   tls_skip_verify = 0;

/* JSON full-text search parameters */
char *fts_json_prefix = "json:";
int   fts_max_results = 100;

/* KV watcher patterns -- built via repeated modparam("kv_watch", "pattern")
 * calls.  When empty (no kv_watch configured), the watcher watches all keys.
 * When one or more patterns are set, kvStore_WatchMulti() is used. */
struct kv_watch_entry {
	char *pattern;
	struct kv_watch_entry *next;
};
static struct kv_watch_entry *kv_watch_list = NULL;
static int kv_watch_count = 0;

static int set_connection(unsigned int type, void *val)
{
	return cachedb_store_url(&nats_cdb_urls, (char *)val);
}

static int set_watch_pattern(unsigned int type, void *val)
{
	struct kv_watch_entry *e;
	char *pattern = (char *)val;

	if (!pattern || !*pattern) {
		LM_ERR("empty kv_watch pattern\n");
		return -1;
	}

	e = pkg_malloc(sizeof(*e));
	if (!e) {
		LM_ERR("no more pkg memory for kv_watch entry\n");
		return -1;
	}
	e->pattern = pattern;
	e->next = kv_watch_list;
	kv_watch_list = e;
	kv_watch_count++;
	return 0;
}

static const param_export_t params[] = {
	{"cachedb_url",    STR_PARAM|USE_FUNC_PARAM, (void *)&set_connection},
	{"nats_url",       STR_PARAM,                 &nats_url},
	{"kv_bucket",      STR_PARAM,                 &kv_bucket},
	{"kv_replicas",    INT_PARAM,                 &kv_replicas},
	{"kv_history",     INT_PARAM,                 &kv_history},
	{"kv_ttl",         INT_PARAM,                 &kv_ttl},
	{"tls_ca",         STR_PARAM,                 &tls_ca},
	{"tls_cert",       STR_PARAM,                 &tls_cert},
	{"tls_key",        STR_PARAM,                 &tls_key},
	{"tls_hostname",   STR_PARAM,                 &tls_hostname},
	{"tls_skip_verify", INT_PARAM,                &tls_skip_verify},
	{"fts_json_prefix", STR_PARAM,               &fts_json_prefix},
	{"fts_max_results", INT_PARAM,               &fts_max_results},
	{"kv_watch",        STR_PARAM|USE_FUNC_PARAM, (void *)&set_watch_pattern},
	{0, 0, 0}
};

static const cmd_export_t cmds[] = {
	{"nats_request", (cmd_function)w_nats_request_wrap, {
		{CMD_PARAM_STR, 0, 0},   /* subject */
		{CMD_PARAM_STR, 0, 0},   /* payload */
		{CMD_PARAM_INT, 0, 0},   /* timeout */
		{CMD_PARAM_VAR, 0, 0},   /* result pvar */
		{0, 0, 0}},
	ALL_ROUTES},
	{"nats_kv_history", (cmd_function)w_nats_kv_history_wrap, {
		{CMD_PARAM_STR, 0, 0},   /* key */
		{CMD_PARAM_VAR, 0, 0},   /* result pvar */
		{0, 0, 0}},
	ALL_ROUTES},
	{"nats_kv_get", (cmd_function)w_nats_kv_get_wrap, {
		{CMD_PARAM_STR, 0, 0},   /* bucket */
		{CMD_PARAM_STR, 0, 0},   /* key */
		{CMD_PARAM_VAR, 0, 0},   /* value pvar (output) */
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},  /* revision pvar (output, optional) */
		{0, 0, 0}},
	ALL_ROUTES},
	{"nats_kv_put", (cmd_function)w_nats_kv_put_wrap, {
		{CMD_PARAM_STR, 0, 0},   /* bucket */
		{CMD_PARAM_STR, 0, 0},   /* key */
		{CMD_PARAM_STR, 0, 0},   /* value */
		{0, 0, 0}},
	ALL_ROUTES},
	{"nats_kv_update", (cmd_function)w_nats_kv_update_wrap, {
		{CMD_PARAM_STR, 0, 0},   /* bucket */
		{CMD_PARAM_STR, 0, 0},   /* key */
		{CMD_PARAM_STR, 0, 0},   /* value */
		{CMD_PARAM_INT, 0, 0},   /* expected revision */
		{0, 0, 0}},
	ALL_ROUTES},
	{"nats_kv_delete", (cmd_function)w_nats_kv_delete_wrap, {
		{CMD_PARAM_STR, 0, 0},   /* bucket */
		{CMD_PARAM_STR, 0, 0},   /* key */
		{0, 0, 0}},
	ALL_ROUTES},
	{"nats_kv_revision", (cmd_function)w_nats_kv_revision_wrap, {
		{CMD_PARAM_STR, 0, 0},   /* bucket */
		{CMD_PARAM_STR, 0, 0},   /* key */
		{CMD_PARAM_VAR, 0, 0},   /* revision pvar (output) */
		{0, 0, 0}},
	ALL_ROUTES},
	{0, 0, {{0, 0, 0}}, 0}
};

static const mi_export_t mi_cmds[] = {
	{"nats_kv_status", 0, 0, 0, {
		{mi_nats_kv_status, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static const dep_export_t deps = {
	{
		{MOD_TYPE_NULL, NULL, 0},
	},
	{
		{NULL, NULL},
	},
};

/** module exports */
struct module_exports exports = {
	"cachedb_nats",             /* module name */
	MOD_TYPE_CACHEDB,           /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	0,                          /* load function */
	&deps,                      /* OpenSIPS module dependencies */
	cmds,                       /* exported functions */
	0,                          /* exported async functions */
	params,                     /* exported parameters */
	0,                          /* exported statistics */
	mi_cmds,                    /* exported MI functions */
	0,                          /* exported pseudo-variables */
	0,                          /* exported transformations */
	0,                          /* extra processes */
	0,                          /* module pre-initialization function */
	mod_init,                   /* module initialization function */
	(response_function) 0,      /* response handling function */
	(destroy_function) destroy, /* destroy function */
	child_init,                 /* per-child init function */
	0                           /* reload confirm function */
};

/**
 * mod_init() -- Module initialization (pre-fork).
 *
 * Registers this module with the shared NATS connection pool and the
 * OpenSIPS cachedb engine subsystem.  The NATS URL is resolved from
 * either the explicit nats_url parameter, the cachedb_url host portion,
 * or a localhost default.  TLS options are applied if tls_ca is set.
 *
 * Also populates the cachedb_engine function table with all supported
 * operations (get, set, remove, add, sub, get_counter, raw_query,
 * query, update, map_get, map_set, map_remove).
 *
 * @return  0 on success, -1 on error (aborts module loading).
 */
static int mod_init(void)
{
	cachedb_engine cde;

	LM_NOTICE("initializing module cachedb_nats ...\n");

	/*
	 * Register with the NATS connection pool.
	 *
	 * Since lib/nats is statically linked, each module has its own pool.
	 * cachedb_nats needs its own nats_url and TLS params to connect.
	 *
	 * If nats_url is set, use it directly. Otherwise, extract server
	 * addresses from the cachedb_url (format: nats:group://host:port,.../)
	 * and build a plain nats:// URL from the host:port portion.
	 */
	{
		nats_tls_opts tls_opts, *tls_ptr = NULL;
		const char *url_to_use = NULL;
		static char url_buf[1024];

		if (nats_url && *nats_url) {
			/* explicit nats_url param takes precedence */
			url_to_use = nats_url;
		} else if (nats_cdb_urls && nats_cdb_urls->url.s &&
				nats_cdb_urls->url.len) {
			/* extract host:port from cachedb_url
			 * format: nats:group1://host1:4222,host2:4223/
			 * we need: nats://host1:4222,nats://host2:4223 */
			char *p = nats_cdb_urls->url.s;
			char *hosts_start;
			/* skip past "://" */
			hosts_start = strstr(p, "://");
			if (hosts_start) {
				hosts_start += 3;
				/* strip trailing slash */
				int hlen = nats_cdb_urls->url.len -
					(hosts_start - nats_cdb_urls->url.s);
				while (hlen > 0 && hosts_start[hlen-1] == '/')
					hlen--;
				if (hlen > 0 && hlen < (int)sizeof(url_buf) - 8) {
					snprintf(url_buf, sizeof(url_buf),
						"nats://%.*s", hlen, hosts_start);
					url_to_use = url_buf;
				}
			}
			if (!url_to_use) {
				LM_WARN("could not parse cachedb_url; "
					"using nats://localhost:4222\n");
				url_to_use = "nats://localhost:4222";
			}
		} else {
			LM_WARN("no nats_url or cachedb_url -- "
				"using nats://localhost:4222\n");
			url_to_use = "nats://localhost:4222";
		}

		/* build TLS opts if tls_ca is configured */
		if (tls_ca && *tls_ca) {
			memset(&tls_opts, 0, sizeof(tls_opts));
			tls_opts.ca = tls_ca;
			tls_opts.cert = tls_cert;
			tls_opts.key = tls_key;
			tls_opts.hostname = tls_hostname;
			tls_opts.skip_verify = tls_skip_verify;
			tls_opts.skip_openssl_init = 1;
			tls_ptr = &tls_opts;

			/* if URL doesn't start with tls://, rewrite it */
			if (strncmp(url_to_use, "nats://", 7) == 0) {
				snprintf(url_buf, sizeof(url_buf),
					"tls://%s", url_to_use + 7);
				url_to_use = url_buf;
			}
		}

		if (nats_pool_register(url_to_use, tls_ptr,
				"cachedb_nats", 2000, 60) < 0) {
			LM_ERR("NATS pool registration failed\n");
			return -1;
		}
	}

	/* populate cachedb engine */
	memset(&cde, 0, sizeof(cachedb_engine));

	cde.name = cache_mod_name;

	cde.cdb_func.init = nats_cachedb_init;
	cde.cdb_func.destroy = nats_cachedb_destroy;
	cde.cdb_func.get = nats_cache_get;
	cde.cdb_func.set = nats_cache_set;
	cde.cdb_func.remove = nats_cache_remove;
	cde.cdb_func.add = nats_cache_add;
	cde.cdb_func.sub = nats_cache_sub;
	cde.cdb_func.get_counter = nats_cache_get_counter;
	cde.cdb_func.raw_query = nats_cache_raw_query_impl;
	cde.cdb_func.query = nats_cache_query;
	cde.cdb_func.update = nats_cache_update;
	cde.cdb_func.map_get = nats_cache_map_get;
	cde.cdb_func.map_set = nats_cache_map_set;
	cde.cdb_func.map_remove = nats_cache_map_remove;

	cde.cdb_func.capability = 0;

	if (register_cachedb(&cde) < 0) {
		LM_ERR("failed to register cachedb_nats engine\n");
		return -1;
	}

	/* Register E_NATS_KV_CHANGE event in mod_init (pre-fork, runs once).
	 * This avoids the "previously published" warning that occurs when
	 * both startup_route's subscribe_event() and child_init's
	 * nats_watch_start() each try to register the same event. */
#ifdef HAVE_EVI
	{
		extern event_id_t evi_kv_change_id;
		str evi_name = str_init("E_NATS_KV_CHANGE");
		evi_kv_change_id = evi_publish_event(evi_name);
		if (evi_kv_change_id == EVI_ERROR)
			LM_WARN("cannot register E_NATS_KV_CHANGE event\n");
	}
#endif

	LM_INFO("cachedb_nats: bucket=%s replicas=%d history=%d ttl=%d\n",
		kv_bucket, kv_replicas, kv_history, kv_ttl);

	return 0;
}

/**
 * child_init() -- Per-child process initialization (post-fork).
 *
 * Ensures the KV bucket exists, initializes and builds the JSON search
 * index from existing KV data, starts the self-healing watcher thread
 * (on rank 1 only), and opens cachedb connections for each configured URL.
 *
 * Rank filtering: only SIP UDP workers (rank 1..udp_workers_no) and the
 * HTTPD/MI process (PROC_MODULE) initialize NATS.  TCP/WSS receivers are
 * excluded because nats.c's internal I/O threads cause heap corruption
 * in processes that also handle OpenSSL for WSS.
 *
 * Watcher startup decision: only rank 1 (first SIP worker) starts the
 * watcher thread to minimize JetStream ordered consumer count.  Each
 * watcher creates an ordered consumer; fewer consumers reduce the race
 * window during cluster topology changes.  Other workers rely on the
 * initial index build; live updates from rank 1's watcher are best-effort.
 *
 * @param rank  OpenSIPS process rank (1-based for SIP workers).
 * @return      0 on success, -1 on error (kills the child process).
 */
static int child_init(int rank)
{
	struct cachedb_url *it;
	cachedb_con *con;
	kvStore *kv;

	/* Rank filtering: skip TCP/WSS receivers and other non-SIP processes.
	 * Only UDP workers and the MI/HTTPD process need NATS access. */
	if (rank != PROC_MODULE &&
	    (rank < 1 || rank > udp_workers_no))
		return 0;

	/* ensure KV bucket exists via the shared pool */
	kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history,
		(int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get/create KV bucket '%s'\n", kv_bucket);
		return -1;
	}

	/* initialize the JSON search index */
	if (nats_json_index_init() < 0) {
		LM_ERR("failed to initialize JSON search index\n");
		return -1;
	}

	/* build the search index from existing KV data */
	if (nats_json_index_build(kv, fts_json_prefix) < 0) {
		LM_WARN("failed to build initial search index; "
			"queries may return empty results until index is rebuilt\n");
	}

	/* Start the self-healing KV watcher thread on rank 1 only.
	 * Only the first SIP worker runs the watcher to minimize JetStream
	 * ordered consumer count.  Each watcher creates an ordered consumer
	 * in nats.c; during cluster topology changes (node failure), nats.c's
	 * I/O thread rebalances consumers and can race with kvWatcher_Next()
	 * causing a free(): invalid pointer.  Fewer consumers = smaller race
	 * window.
	 *
	 * The HTTPD/MI process (PROC_MODULE) doesn't need a watcher -- it
	 * only handles MI commands, not SIP routing with index lookups.
	 * Other SIP workers rely on the initial index build above; live
	 * updates from the watcher on rank 1 are a best-effort bonus. */
	if (rank == 1 && kv_watch_count > 0) {
		const char **patterns;
		struct kv_watch_entry *e;
		int i = 0;

		/* convert linked list to array for kvStore_WatchMulti() */
		patterns = pkg_malloc((kv_watch_count + 1) * sizeof(char *));
		if (!patterns) {
			LM_ERR("no more pkg memory for watch patterns\n");
			return -1;
		}
		for (e = kv_watch_list; e; e = e->next)
			patterns[i++] = e->pattern;
		patterns[i] = NULL;

		if (nats_watch_start(kv, patterns, kv_watch_count) < 0)
			LM_WARN("KV watcher not started; index will not "
				"track live changes\n");

		pkg_free(patterns);
	}

	/* open cachedb connections for each configured URL */
	for (it = nats_cdb_urls; it; it = it->next) {
		LM_DBG("opening cachedb_nats connection for [%.*s]\n",
			it->url.len, it->url.s);
		con = nats_cachedb_init(&it->url);
		if (con == NULL) {
			LM_ERR("failed to open cachedb_nats connection\n");
			return -1;
		}
		if (cachedb_put_connection(&cache_mod_name, con) < 0) {
			LM_ERR("failed to insert cachedb_nats connection\n");
			return -1;
		}
	}

	cachedb_free_url(nats_cdb_urls);
	return 0;
}

/**
 * destroy() -- Module cleanup on OpenSIPS shutdown.
 *
 * Stops the KV watcher thread, destroys the JSON search index, and
 * closes all cachedb connections.  Called once from the main process.
 */
static void destroy(void)
{
	LM_NOTICE("destroying module cachedb_nats ...\n");
	nats_watch_stop();
	nats_json_index_destroy();
	cachedb_end_connections(&cache_mod_name);
}

/**
 * w_nats_request_wrap() -- Script wrapper for nats_request().
 *
 * Thin wrapper that delegates to w_nats_request() in cachedb_nats_native.c.
 * Performs a synchronous NATS request/reply: sends a message to the given
 * subject, waits up to timeout milliseconds for a reply, and stores the
 * reply payload in the specified pseudo-variable.
 *
 * @param msg      Current SIP message context.
 * @param subject  NATS subject for the request.
 * @param payload  Request payload (typically JSON).
 * @param timeout  Reply timeout in milliseconds.
 * @param result   Pseudo-variable to store the reply payload.
 * @return         1 on success, -1 on error (OpenSIPS script convention).
 */
static int w_nats_request_wrap(struct sip_msg *msg, str *subject,
                               str *payload, int *timeout, pv_spec_t *result)
{
	return w_nats_request(msg, subject, payload, timeout, result);
}

/**
 * w_nats_kv_history_wrap() -- Script wrapper for nats_kv_history().
 *
 * Thin wrapper that delegates to w_nats_kv_history() in cachedb_nats_native.c.
 * Retrieves the version history for a KV key and stores the result as a
 * JSON array in the specified pseudo-variable.
 *
 * @param msg     Current SIP message context.
 * @param key     KV key to retrieve history for.
 * @param result  Pseudo-variable to store the JSON history array.
 * @return        1 on success, -1 on error (OpenSIPS script convention).
 */
static int w_nats_kv_history_wrap(struct sip_msg *msg, str *key,
                                  pv_spec_t *result)
{
	return w_nats_kv_history(msg, key, result);
}

static int w_nats_kv_get_wrap(struct sip_msg *msg, str *bucket, str *key,
                              pv_spec_t *value_var, pv_spec_t *rev_var)
{
	return w_nats_kv_get(msg, bucket, key, value_var, rev_var);
}

static int w_nats_kv_put_wrap(struct sip_msg *msg, str *bucket, str *key,
                              str *value)
{
	return w_nats_kv_put(msg, bucket, key, value);
}

static int w_nats_kv_update_wrap(struct sip_msg *msg, str *bucket, str *key,
                                 str *value, int *expected_rev)
{
	return w_nats_kv_update(msg, bucket, key, value, expected_rev);
}

static int w_nats_kv_delete_wrap(struct sip_msg *msg, str *bucket, str *key)
{
	return w_nats_kv_delete(msg, bucket, key);
}

static int w_nats_kv_revision_wrap(struct sip_msg *msg, str *bucket, str *key,
                                   pv_spec_t *rev_var)
{
	return w_nats_kv_revision(msg, bucket, key, rev_var);
}

/**
 * mi_nats_kv_status() -- MI handler for "nats_kv_status".
 *
 * Returns a JSON object with the KV bucket configuration (name, replicas,
 * history depth, TTL) and the current NATS connection state.
 *
 * @param params    MI parameters (unused).
 * @param async_hdl MI async handler (unused).
 * @return          MI response object, or NULL on error.
 */
static mi_response_t *mi_nats_kv_status(const mi_params_t *params,
                                         struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;

	if (add_mi_string(resp_obj, MI_SSTR("bucket"),
			kv_bucket, strlen(kv_bucket)) < 0)
		goto error;

	if (add_mi_number(resp_obj, MI_SSTR("replicas"), kv_replicas) < 0)
		goto error;

	if (add_mi_number(resp_obj, MI_SSTR("history"), kv_history) < 0)
		goto error;

	if (add_mi_number(resp_obj, MI_SSTR("ttl"), kv_ttl) < 0)
		goto error;

	if (add_mi_string_fmt(resp_obj, MI_SSTR("connected"), "%s",
			nats_pool_is_connected() ? "yes" : "no") < 0)
		goto error;

	return resp;

error:
	free_mi_response(resp);
	return NULL;
}
