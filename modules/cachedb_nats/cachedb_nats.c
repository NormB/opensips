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
 *   NATS initializes in SIP workers (UDP and TCP, rank >= 1) and the
 *   HTTPD/MI process (PROC_MODULE).  Attendant, timer, and TCP-main
 *   processes skip initialization.  The KV watcher thread spawns only
 *   on rank 1 (first SIP worker) to minimize JetStream consumer count;
 *   other workers receive live updates via the shared SHM index.
 *
 *   The admission rule is centralized in lib/nats/nats_pool_should_init().
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
#include "../tls_mgm/api.h"
#include "cachedb_nats_json.h"
#include "cachedb_nats_intern.h"
#include "cachedb_nats_watch.h"
#include "cachedb_nats_native.h"
#include "cachedb_nats_stats.h"
#include "../../lib/nats/nats_pool.h"
#include "../../timer.h"

#ifdef HAVE_EVI
#include "../../evi/evi.h"
#endif

/* module lifecycle */
static int mod_init(void);
static int child_init(int rank);
static void destroy(void);
static void _nats_cdb_periodic_resync(unsigned int ticks, void *param);

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
/* Multi-instance index coordination knobs.
 *
 * index_resync_on_reconnect (default 0):
 *   On a NATS reconnect (epoch change), should the watcher rebuild
 *   the in-memory JSON index in full?  The rebuild costs O(N)
 *   round-trips against the bucket and on a 50k-AoR deployment
 *   stalls the watcher for ~5-10 s.  The stale-entry self-heal in
 *   nats_cache_query covers correctness without the bulk rebuild,
 *   so the default is OFF: stale entries are evicted lazily on the
 *   first query that hits them.  Operators with high cross-instance
 *   churn or deep historical drift after prolonged outages may set
 *   this to 1 to force the bulk reconciliation.
 *
 * index_resync_interval_secs (default 0 = off):
 *   Optional periodic full rebuild on a timer.  Belt-and-braces
 *   for deployments that want a hard upper bound on how stale any
 *   process-local index entry can ever be, beyond what reconnects
 *   and lazy self-heal already guarantee.
 */
int index_resync_on_reconnect = 0;
int index_resync_interval_secs = 0;

/* NATS server URL(s) -- overrides cachedb_url host when set.  TLS
 * configuration is sourced from the tls_mgm "nats" client domain at
 * connect time (apply_tls_from_mgm in lib/nats); no per-module TLS
 * modparams. */
static char *nats_url = NULL;
static struct tls_mgm_binds tls_api;

/* JSON full-text search parameters */
/* Default uses '_' rather than ':' because NATS-KV rejects ':' in
 * subject tokens (validate_kv_key in cachedb_nats_dbase.c), and any
 * key whose underlying form starts with the prefix would therefore be
 * unstorable. '_' is unambiguously safe across all allowed key
 * characters; operators may override via modparam if their bucket
 * convention requires a different separator. */
char *fts_json_prefix = "json_";
int   fts_max_results = 100;

/* Maximum bytes accepted in a NATS request/reply response.  Caps
 * the per-call pkg_malloc in w_nats_request so a malicious or
 * misbehaving responder can't exhaust per-worker pkg memory by
 * sending an oversized reply.  Default 65536 (64 KB). */
int   nats_request_max_reply = 65536;

/* Default timeout for nats_request when the script call passes 0 or
 * a negative timeout argument.  Tightened from "no default" to
 * 500 ms so a misconfigured caller can no longer block a SIP worker
 * for the upper-clamp duration of 30 seconds. */
int   nats_request_default_timeout_ms = 500;

/* Compare-and-swap retry count for atomic counter increments
 * (nats_cache_add) and JSON field updates (nats_cache_update).
 * Each retry costs one round-trip to the NATS server.  Default 10
 * is a balance between giving up too early under modest contention
 * (the previous hard-coded 3 dropped silent counter increments
 * with as few as 3 concurrent writers) and burning latency on
 * pathological hotspots.  Operator can raise for very contended
 * counters; minimum bound is 1. */
int   nats_cas_retries = 10;

/* Whether to maintain the in-memory JSON-FTS search index.
 *
 * Default 1 (enabled) preserves legacy behaviour: the index is
 * built at startup, kept live by the watcher, and consulted by
 * non-PK query/update filters.  Set to 0 for usrloc-style PK-only
 * workloads where every read/write is a is_pk=1 lookup -- the
 * index is then dead weight (extra SHM, watcher CPU, lock
 * contention on every set/update/delete) and we route the entire
 * query/update path through the PK fast path that already exists
 * in nats_cache_query / nats_cache_update.
 *
 * When 0:
 *   - nats_json_index_init / index_build / watcher start are
 *     skipped at module init.
 *   - nats_json_index_add / remove / remove_fields become no-ops
 *     on the hot path.
 *   - nats_cache_query rejects any non-PK filter with -1 (the
 *     PK fast path already handles is_pk=1 without touching
 *     the index).
 *   - nats_cache_update likewise rejects non-PK filters.
 *
 * For the canonical usrloc-as-store deployment this is the
 * recommended setting; doc/SCALING.md covers the rationale at
 * 1MM / 10MM endpoint scales. */
int   nats_enable_search_index = 1;

/* dedicated_watcher_proc: move the KV watcher out of the rank-1 SIP worker.
 *
 * Default 0 preserves legacy behaviour: the watcher runs as a
 * pthread inside the rank-1 SIP worker and shares its CPU with
 * SIP request handling.  Set to 1 to fork a dedicated OpenSIPS
 * child process (declared via proc_export_t) that owns the
 * watcher loop and writes to the SHM-backed JSON-FTS index.
 *
 * Only meaningful when enable_search_index=1.  When the index is
 * disabled there is no watcher to relocate, so the dedicated
 * process is neither declared nor forked.
 *
 * The benefit is isolation: at >=100k AoRs the steady-state
 * watcher event rate (~1 700 events/s, ~17 % of one core) no
 * longer competes with SIP routing on rank 1.  At lower scales
 * the rank-1 pthread is fine and the dedicated process is just
 * extra address-space and a duplicate NATS connection.  Doc
 * SCALING.md "Watcher CPU at scale" has the threshold table. */
int   nats_dedicated_watcher_proc = 0;

/* lib/nats connection-pool tuning.  These three modparams previously
 * appeared in the admin XML but were never actually exported -- the
 * values were hardcoded at the nats_pool_register() call site.  They
 * now match the documented behaviour.
 *
 * First-registrant-wins: when event_nats (or any other NATS module)
 * is loaded before cachedb_nats and has already called
 * nats_pool_register(), the pool's connection parameters are already
 * set and these values are ignored.  See lib/nats/README.md
 * "Registration contract" for the rule.  In practice that means:
 * load the NATS module whose connection settings should take effect
 * FIRST (typically event_nats), or load only cachedb_nats and these
 * settings own the pool.
 *
 * Defaults match the previously-hardcoded values so a deployment
 * that doesn't touch the modparams sees exactly the same behaviour
 * as before this commit. */
int   nats_cdb_reconnect_wait_ms = 2000;
int   nats_cdb_max_reconnect     = 60;

/* KV watcher patterns -- built via repeated modparam("kv_watch", "pattern")
 * calls.  When empty (no kv_watch configured), the watcher watches all keys.
 * When one or more patterns are set, nats_dl.kvStore_WatchMulti() is used.
 * Definition lives in cachedb_nats_watch.h so the dedicated-process
 * watcher (when running as a dedicated process) can read it from cachedb_nats_watch.c. */
struct kv_watch_entry *kv_watch_list = NULL;
int kv_watch_count = 0;

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
	{"index_resync_on_reconnect",   INT_PARAM,    &index_resync_on_reconnect},
	{"index_resync_interval_secs",  INT_PARAM,    &index_resync_interval_secs},
	/* Shared lib/nats shutdown drain timeout, ms.  See
	 * lib/nats/nats_pool.h for the contract; last-writer wins
	 * across modules. */
	{"cdb_drain_timeout_ms",        INT_PARAM,    &nats_pool_drain_timeout_ms},
	{"fts_json_prefix", STR_PARAM,               &fts_json_prefix},
	{"fts_max_results", INT_PARAM,               &fts_max_results},
	{"nats_request_max_reply", INT_PARAM,        &nats_request_max_reply},
	{"nats_request_default_timeout_ms", INT_PARAM, &nats_request_default_timeout_ms},
	{"nats_cas_retries",        INT_PARAM,         &nats_cas_retries},
	{"index_buckets",   INT_PARAM,                 &nats_idx_buckets},
	{"enable_search_index", INT_PARAM,             &nats_enable_search_index},
	{"dedicated_watcher_proc", INT_PARAM,          &nats_dedicated_watcher_proc},
	{"kv_watch",        STR_PARAM|USE_FUNC_PARAM, (void *)&set_watch_pattern},
	{"reconnect_wait",      INT_PARAM,             &nats_cdb_reconnect_wait_ms},
	{"max_reconnect",       INT_PARAM,             &nats_cdb_max_reconnect},
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
		{EMPTY_MI_RECIPE}},
		{0}        /* aliases — required by mi_export_t struct */
	},
	{"nats_cdb_stats", 0, 0, 0, {
		{mi_nats_cdb_stats, {0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{EMPTY_MI_EXPORT}
};

/* tls_mgm is required only when the operator wants TLS (URL begins
 * with tls://).  DEP_SILENT lets plaintext-only deployments load
 * cachedb_nats without tls_mgm; the tls:// path checks at connect
 * time and errors with operator-friendly guidance if tls_mgm is
 * missing or the "nats" domain isn't defined. */
static const dep_export_t deps = {
	{
		{MOD_TYPE_DEFAULT, "tls_mgm", DEP_SILENT},
		{MOD_TYPE_NULL, NULL, 0},
	},
	{
		{NULL, NULL},
	},
};

/* dedicated KV watcher process.
 *
 * Declared unconditionally so the symbol resolves at link time, but
 * only attached to module_exports.procs at runtime in mod_init when
 * BOTH enable_search_index=1 AND dedicated_watcher_proc=1.  The
 * core's start_module_procs() walks exports.procs after init_modules
 * returns, so the late binding is safe.
 *
 * Single instance ("no" = 1) -- one watcher is enough; multiplying
 * watchers does not parallelise the per-event cost (see SCALING.md
 * "Re-examining option 2 (watcher)") and would just multiply broker
 * delivery cost. */
static const proc_export_t nats_watcher_procs[] = {
	{ "NATS Watcher", 0, 0, nats_watcher_proc_main, 1, 0 },
	{ 0, 0, 0, 0, 0, 0 }
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

	/* Bind tls_mgm if loaded; hand the bind table to lib/nats so the
	 * pool's connect path can look up the "nats" client domain.  No
	 * effect on plaintext (nats://) URLs; tls:// URLs error at
	 * connect time if tls_mgm isn't bound or the "nats" domain
	 * isn't defined. */
	if (find_export("load_tls_mgm", 0)) {
		if (load_tls_mgm_api(&tls_api) == 0) {
			nats_pool_set_tls_api(&tls_api);
			LM_INFO("cachedb_nats: tls_mgm bound; "
			        "tls:// URLs will use the \"nats\" client domain\n");
		} else {
			LM_WARN("cachedb_nats: tls_mgm exports load_tls_mgm but "
			        "the bind failed; tls:// URLs will not work\n");
		}
	} else {
		LM_INFO("cachedb_nats: tls_mgm not loaded; only nats:// URLs "
		        "will work (tls:// will error at connect)\n");
	}

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

		/* TLS comes from the tls_mgm "nats" client domain at connect
		 * time (apply_tls_from_mgm in lib/nats).  Operator switches to
		 * TLS by writing tls:// in cachedb_url and defining the
		 * tls_mgm domain. */

		if (nats_pool_register(url_to_use,
				"cachedb_nats",
				nats_cdb_reconnect_wait_ms,
				nats_cdb_max_reconnect) < 0) {
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

	if (nats_cdb_stats_init() < 0) {
		LM_ERR("failed to initialize cdb stats\n");
		return -1;
	}

	/* Allocate the SHM-backed search index BEFORE forking so every
	 * worker maps the same instance.  Each worker then reads/writes
	 * via the shared shard locks; rank 1 is responsible for the
	 * initial KV-driven population (see child_init) and for the
	 * watcher thread that keeps it live.
	 *
	 * Gated on enable_search_index so PK-only workloads (usrloc,
	 * counters) can opt out and skip the SHM cost + watcher CPU. */
	if (nats_enable_search_index) {
		/* The intern table is required by the index's
		 * _entry_add_key path; allocate it BEFORE the index
		 * itself.  Skipped when the index is disabled
		 * (nothing calls intern_acquire then). */
		if (nats_intern_init() < 0) {
			LM_ERR("failed to initialise doc-key intern table\n");
			return -1;
		}

		if (nats_json_index_init() < 0) {
			LM_ERR("failed to initialize JSON search index\n");
			return -1;
		}

		/* Periodic index resync: optional belt-and-braces rebuild
		 * for deployments that want a hard upper bound on
		 * per-process index staleness regardless of reconnect
		 * cadence or self-heal pace.  Default 0 means no timer is
		 * registered. */
		if (index_resync_interval_secs > 0) {
			if (register_timer("nats_cdb_resync",
					_nats_cdb_periodic_resync, NULL,
					index_resync_interval_secs, 0) < 0) {
				LM_ERR("failed to register periodic "
					"resync timer\n");
				return -1;
			}
			LM_INFO("cachedb_nats: periodic index resync "
				"every %d s\n",
				index_resync_interval_secs);
		}
	} else {
		LM_INFO("cachedb_nats: search index DISABLED "
			"(enable_search_index=0); query/update accept "
			"PK-only filters\n");
		if (nats_dedicated_watcher_proc) {
			LM_INFO("cachedb_nats: dedicated_watcher_proc=1 "
				"is meaningless when enable_search_index=0; "
				"the dedicated process will NOT be forked\n");
		}
	}

	/* attach the dedicated watcher process to the module
	 * exports only when both knobs are on AND at least one
	 * kv_watch pattern was configured.  start_module_procs()
	 * (in main_loop) reads exports.procs AFTER init_modules
	 * returns, so this late assignment is safe and is the cleanest
	 * way to keep the proc declaration runtime-conditional without
	 * forking when it isn't wanted.
	 *
	 * Mirrors the rank-1 child_init gate (kv_watch_count > 0): if
	 * the operator hasn't configured any kv_watch patterns there is
	 * nothing for the watcher to do, so we don't fork the dedicated
	 * process either. */
	if (nats_enable_search_index && nats_dedicated_watcher_proc) {
		if (kv_watch_count > 0) {
			exports.procs = nats_watcher_procs;
			LM_INFO("cachedb_nats: dedicated KV watcher process "
				"ENABLED (rank-1 SIP worker will skip the "
				"watcher pthread)\n");
		} else {
			LM_INFO("cachedb_nats: dedicated_watcher_proc=1 but "
				"no kv_watch pattern configured; dedicated "
				"process NOT forked\n");
		}
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
 * Rank filtering is delegated to lib/nats/nats_pool_should_init();
 * see that function's documentation for the admission set.
 *
 * Watcher startup decision: only rank 1 (first SIP worker) starts the
 * KV watcher thread.  All other workers rely on the SHM-shared index
 * for the initial build; live updates from rank 1's watcher are
 * best-effort.
 *
 * @param rank  OpenSIPS process rank (1-based for SIP workers).
 * @return      0 on success, -1 on error (kills the child process).
 */
static int child_init(int rank)
{
	struct cachedb_url *it;
	cachedb_con *con;
	kvStore *kv;

	if (!nats_pool_should_init(rank))
		return 0;

	/* ensure KV bucket exists via the shared pool */
	kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history,
		(int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get/create KV bucket '%s'\n", kv_bucket);
		return -1;
	}

	/* The JSON search index is now SHM-backed and was allocated in
	 * mod_init pre-fork; every worker dereferences the same g_idx.
	 * Only rank 1 populates it from KV: the watcher (also rank-1)
	 * keeps it live thereafter, and every other worker sees those
	 * updates immediately through the shared SHM mapping.
	 *
	 * Skip both the initial build and the watcher if the index is
	 * disabled -- there's no SHM index to populate and nothing for
	 * the watcher to update. */
	if (nats_enable_search_index && rank == 1 &&
			nats_json_index_build(kv, fts_json_prefix) < 0) {
		LM_WARN("failed to build initial search index; "
			"queries may return empty results until index is rebuilt\n");
	}

	/* Start the self-healing KV watcher thread on rank 1 only.
	 * Only the first SIP worker runs the watcher to minimize the
	 * JetStream ordered-consumer count -- each watcher creates one
	 * ordered consumer in nats.c, and keeping that count low is a
	 * cluster-side resource optimization.
	 *
	 * The HTTPD/MI process (PROC_MODULE) doesn't need a watcher -- it
	 * only handles MI commands, not SIP routing with index lookups.
	 * Other SIP workers rely on the initial index build above; live
	 * updates from the watcher on rank 1 are a best-effort bonus.
	 *
	 * When dedicated_watcher_proc=1 the watcher runs in its
	 * own forked child (declared via exports.procs), so rank 1 must
	 * NOT also spawn the pthread -- otherwise we'd have two watchers
	 * racing each other on the same SHM index. */
	if (nats_enable_search_index && !nats_dedicated_watcher_proc &&
			rank == 1 && kv_watch_count > 0) {
		const char **patterns;
		struct kv_watch_entry *e;
		int i = 0;

		/* convert linked list to array for nats_dl.kvStore_WatchMulti() */
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
	/* nats_watch_stop() flips the pthread-running flag and
	 * pthread_join()s the watcher thread.  In the dedicated-process
	 * mode the watcher pthread lives in another process entirely,
	 * so calling it from main would block on a tid that this
	 * process never spawned.  The OpenSIPS core delivers SIGTERM to
	 * every child including the dedicated watcher proc, which
	 * terminates it cleanly via the kernel; we have nothing to do
	 * here. */
	if (!nats_dedicated_watcher_proc)
		nats_watch_stop();
	nats_json_index_destroy();
	/* Tear down the doc-key intern table after the index, since
	 * _free_entry calls nats_intern_release on every key. */
	nats_intern_destroy();
	cachedb_end_connections(&cache_mod_name);
	nats_cdb_stats_destroy();
}

/*
 * Periodic full-index resync handler, registered when
 * index_resync_interval_secs > 0. Acquires a fresh KV handle from the
 * pool and rebuilds the JSON-FTS search index in place. Skips silently
 * when NATS is disconnected; the next reconnect (or the next tick)
 * will retry.
 */
static void _nats_cdb_periodic_resync(unsigned int ticks, void *param)
{
	kvStore *kv;

	(void)ticks; (void)param;

	if (!nats_pool_is_connected()) {
		LM_DBG("periodic resync: NATS disconnected; skipping tick\n");
		return;
	}

	kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history,
		(int64_t)kv_ttl);
	if (!kv) {
		LM_WARN("periodic resync: failed to get KV handle; "
			"skipping tick\n");
		return;
	}

	if (nats_json_index_rebuild(kv, fts_json_prefix) < 0)
		LM_WARN("periodic resync: index rebuild failed\n");
	else
		LM_DBG("periodic resync: index rebuilt\n");
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
