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
 *   - Native script functions: nats_kv_* KV primitives and
 *     nats_kv_history() for key version history.  (Synchronous NATS
 *     request/reply from script is owned by the nats_consumer module.)
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
#include "cachedb_nats_expiry.h"
#include "cachedb_nats_reg.h"      /* [OBS] registration MI + reap-pass gauges */
#include "cachedb_nats_kvobs.h"    /* [KVOBS] generic stream/KV introspection MI */
#include "../../lib/nats/nats_pool.h"
#include "../../timer.h"

#include "../../evi/evi.h"

/* module lifecycle */
static int mod_init(void);
static int child_init(int rank);
static void destroy(void);
static void _nats_cdb_periodic_resync(unsigned int ticks, void *param);
static void _nats_cdb_reaper_tick(unsigned int ticks, void *param);   /* P9 reaper host */

/* script function wrappers (implementations in cachedb_nats_native.c) */
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
/* [HREV-1] history default 1: per-message TTL (native expiry) is only safe
 * on a bucket that keeps NO old revisions -- on a history-keeping bucket an
 * expired key ROLLS BACK to an older revision instead of disappearing
 * (verified on nats-server 2.11.10).  Raise only for nats_kv_history()
 * consumers, accepting reaper-only (scan-based) expiry. */
int kv_history = 1;
int kv_ttl = 0;
/* Multi-instance index coordination knobs.
 *
 * index_resync_on_reconnect (default 1):
 *   On a NATS reconnect (epoch change), should the watcher rebuild
 *   the in-memory JSON index in full?  The watcher subscribes with
 *   UpdatesOnly, so writes made by sibling instances WHILE this
 *   process was disconnected are never delivered live -- without a
 *   rebuild the index silently diverges after any outage during which
 *   writes occurred.  The default is therefore ON so the index always
 *   converges on reconnect.  The rebuild costs O(N) round-trips against
 *   the bucket (a 50k-AoR deployment stalls the watcher for ~5-10 s),
 *   so operators with large indexes or hot-reconnect topologies may set
 *   this to 0 and rely instead on index_resync_interval_secs (the
 *   periodic timer) plus the query-time stale-entry self-heal in
 *   nats_cache_query, accepting a brief window of staleness.
 *
 * index_resync_interval_secs (default 0 = off):
 *   Optional periodic full rebuild on a timer.  Belt-and-braces
 *   for deployments that want a hard upper bound on how stale any
 *   process-local index entry can ever be, beyond what reconnects
 *   and lazy self-heal already guarantee.
 */
int index_resync_on_reconnect = 1;

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

/* Compare-and-swap retry count for atomic counter increments
 * (nats_cache_add) and JSON field updates (nats_cache_update).
 * Each retry costs one round-trip to the NATS server.  Default 10
 * is a balance between giving up too early under modest contention
 * (the previous hard-coded 3 dropped silent counter increments
 * with as few as 3 concurrent writers) and burning latency on
 * pathological hotspots.  Operator can raise for very contended
 * counters; minimum bound is 1. */
int   nats_cas_retries = 10;

/* [REV-1/REV-21] Max tolerated inter-node clock skew S, in seconds.  Used as
 * the grace margin everywhere absolute `expires`/`row_exp` is compared with
 * node-local now: the write-side expiry hygiene (P2.7), the read filter (P4),
 * and the reaper (P9) all require `+S` slack so a node whose clock leads by S
 * never deletes/omits another node's still-live binding.  MUST be >= the
 * deployment's real maximum node skew. */
int   nats_reap_grace = 5;

/* [REV-1/16] (SPEC §4.3A) Reaper scan period, seconds.  The reaper is the
 * SINGLE expiry mechanism (the native per-message-TTL fast path was
 * deleted in P1.5 -- it was lost on update, #1994/#6959, and misbehaves
 * on history-keeping buckets): a periodic CAS-prune is what guarantees an
 * expired binding is physically reclaimed.  Must be > 0; a non-positive
 * value HARD-FAILS mod_init rather than silently leaving expiries
 * unreclaimed.  Default 30s. */
int   nats_reap_interval = 30;

/* [HREV-3/D6] Physical retention of a row past its logical expiry
 * (expires + nats_reap_grace), in seconds.  0 = reclaim ASAP; e.g. 30 keeps an expired registration
 * readable in the bucket for ~30 s (forensics / churn damping).  Added to
 * every physical-reclamation cutoff (TTL computation, reaper due-gate +
 * projection, write hygiene) and NEVER to the read filter -- an expired
 * contact is not served, lingering or not.  Range 0..86400. */
int   nats_expired_linger = 0;

/* [REV-5] Max serialized KV value (one AoR row holds all its contacts), in
 * bytes.  All contacts of an AoR share one message; NATS caps message size
 * (max_payload, default 1 MiB; a stream's max_msg_size may be lower).  An
 * oversize row is detected before the CAS write and the offending contact's
 * save fails cleanly — never a silent truncation / corruption.  Default 1 MiB
 * (the NATS max_payload default); set to the deployment's real per-message cap
 * (and <= the stream's max_msg_size).  <= 0 disables the guard. */
int   nats_max_value_size = 1048576;

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
 * recommended setting; the design-repo SCALING.md covers the rationale at
 * 1MM / 10MM endpoint scales. */
int   nats_enable_search_index = 1;

/* The KV watcher always runs as a dedicated OpenSIPS child process
 * (proc_export_t, forked when enable_search_index=1 and at least one
 * kv_watch pattern is configured).  The former in-worker pthread mode
 * (dedicated_watcher_proc=0) was removed: a pthread inside the rank-1
 * SIP worker called nats_pool_get_kv() concurrently with the worker's
 * main thread, but the pool's cached KV/JS handles are managed
 * process-single-threaded — after a reconnect one thread could destroy
 * a cached handle while the other was still using it (use-after-free
 * under broker flap, in what used to be the default mode).  The
 * dedicated process runs exactly one thread against the pool and has
 * none of these races. */

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
	/* Shared lib/nats shutdown drain timeout, ms.  Merged by MAX across
	 * modules (see nats_pool_drain_timeout_setter), not last-writer-wins. */
	{"cdb_drain_timeout_ms",        INT_PARAM|USE_FUNC_PARAM,
	      (void *)nats_pool_drain_timeout_setter},
	{"kv_op_timeout_ms",            INT_PARAM,    &nats_pool_kv_op_timeout_ms},
	{"fts_json_prefix", STR_PARAM,               &fts_json_prefix},
	{"fts_max_results", INT_PARAM,               &fts_max_results},
	{"nats_cas_retries",        INT_PARAM,         &nats_cas_retries},
	{"nats_reap_grace",         INT_PARAM,         &nats_reap_grace},
	{"nats_reap_interval",      INT_PARAM,         &nats_reap_interval},
	{"nats_expired_linger",     INT_PARAM,         &nats_expired_linger},
	{"nats_max_value_size",     INT_PARAM,         &nats_max_value_size},
	{"index_buckets",   INT_PARAM,                 &nats_idx_buckets},
	{"enable_search_index", INT_PARAM,             &nats_enable_search_index},
	{"kv_watch",        STR_PARAM|USE_FUNC_PARAM, (void *)&set_watch_pattern},
	{"reconnect_wait",      INT_PARAM,             &nats_cdb_reconnect_wait_ms},
	{"max_reconnect",       INT_PARAM,             &nats_cdb_max_reconnect},
	{0, 0, 0}
};

static const cmd_export_t cmds[] = {
	/* Synchronous NATS request/reply from script is provided ONLY by
	 * the nats_consumer module (headers + async support); this module's
	 * duplicate request/reply export was removed (P0.3). */
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
	/* [OBS] registration observability — usrloc's own MI is empty by
	 * design in full-sharing-cachedb mode; the KV bucket is the truth. */
	{"nats_reg_summary", 0, 0, 0, {
		{mi_nats_reg_summary, {0}},
		{mi_nats_reg_summary, {"domains", 0}},
		{mi_nats_reg_summary, {"domains", "format", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{"nats_reg_list", 0, 0, 0, {
		{mi_nats_reg_list, {0}},
		{mi_nats_reg_list, {"filter", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{"nats_reg_show", 0, 0, 0, {
		{mi_nats_reg_show, {"aor", 0}},
		{mi_nats_reg_show, {"aor", "format", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	/* [KVOBS] generic stream/KV introspection (read-only; buckets are
	 * bound, never created). */
	{"nats_stream_list", 0, 0, 0, {
		{mi_nats_stream_list, {0}},
		{mi_nats_stream_list, {"filter", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{"nats_stream_info", 0, 0, 0, {
		{mi_nats_stream_info, {"stream", 0}},
		{mi_nats_stream_info, {"stream", "format", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{"nats_kv_keys", 0, 0, 0, {
		{mi_nats_kv_keys, {0}},
		{mi_nats_kv_keys, {"filter", 0}},
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

/* dedicated KV watcher process — the ONLY watcher mode.
 *
 * Declared unconditionally so the symbol resolves at link time, but
 * only attached to module_exports.procs at runtime in mod_init when
 * enable_search_index=1 and at least one kv_watch pattern is set.  The
 * core's start_module_procs() walks exports.procs after init_modules
 * returns, so the late binding is safe.
 *
 * Single instance ("no" = 1) -- one watcher is enough; multiplying
 * watchers does not parallelise the per-event cost (see the design-repo SCALING.md
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
/* [REV-24 / §11] Is the effective connection URL insecure for a PII store?
 * Returns 1 when the WARN must fire: not tls://, OR no "user[:pass]@" in the
 * authority (between "://" and the first '/').  Credentials in a path/query do
 * not count.  Pure; mirrored by tests/test_insecure_url_warn.c. */
static int _nats_url_insecure(const char *url)
{
	const char *sep, *authority, *slash, *at;
	int is_tls, has_creds;

	if (!url)
		return 1;
	sep = strstr(url, "://");
	if (!sep)
		return 1;
	is_tls = (sep - url == 3) && (strncmp(url, "tls", 3) == 0);
	authority = sep + 3;
	slash = strchr(authority, '/');
	at = strchr(authority, '@');
	has_creds = (at != NULL) && (slash == NULL || at < slash);
	return (!is_tls || !has_creds) ? 1 : 0;
}

static int mod_init(void)
{
	cachedb_engine cde;

	LM_NOTICE("initializing module cachedb_nats ...\n");

	/* P8 [REV-7 / TTL-SOLUTION-SPEC.md §5.3]: kv_ttl becomes the KV bucket's
	 * MaxAge (nats_pool.c: kvCfg.TTL).  Stream MaxAge takes precedence over
	 * per-message TTL and would SILENTLY EXPIRE PERMANENT CONTACTS
	 * (expires==0) -- data loss in a registration store.  Refuse to start
	 * (fail closed) before any bucket is created/bound. */
	if (_kv_ttl_guard(kv_ttl) != 0) {
		LM_ERR("cachedb_nats: kv_ttl=%d invalid -- a non-zero kv_ttl sets the "
		       "KV bucket MaxAge, which overrides per-message TTL and would "
		       "EXPIRE PERMANENT CONTACTS (expires==0). Set kv_ttl=0 [REV-7].\n",
		       kv_ttl);
		return -1;
	}

	/* [D6/HREV-6] validate the new operator params -- fail loudly at boot,
	 * never misbehave silently at runtime. */
	if (_linger_guard(nats_expired_linger) != 0) {
		LM_ERR("cachedb_nats: nats_expired_linger=%d out of range (0..86400); "
		       "large retention wants a different tool than this module\n",
		       nats_expired_linger);
		return -1;
	}
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
	 * lib/nats is a shared .so, so all NATS modules share ONE pool; each
	 * module registers its config (URLs / reconnect) and the pool merges
	 * them.  cachedb_nats still needs its own nats_url and TLS params so a
	 * cachedb-only deployment can connect without another NATS module.
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
			char *hosts_start;
			/* skip past "://" — counted search [P0.9]: core
			 * cachedb_store_url() does NOT NUL-terminate url.s,
			 * so a libc strstr() here could read past the pkg
			 * allocation when the URL lacks the separator */
			hosts_start = str_strstr(&nats_cdb_urls->url,
					_str("://"));
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

		/* [REV-24 / §11] The registration bucket is a PII / LI-relevant
		 * store (subscriber IP, UA, call-id, path) and NATS KV has no
		 * per-key ACL.  Transport + auth are mandatory: warn loudly when
		 * the connection URL is plaintext and/or carries no credentials. */
		if (_nats_url_insecure(url_to_use)) {
			/* the URL may carry nats://user:pass@host credentials —
			 * never log it raw */
			char _redacted_url[512];
			nats_redact_url(url_to_use, _redacted_url,
				sizeof(_redacted_url));
			LM_WARN("cachedb_nats: connection URL '%s' is INSECURE for a "
				"PII/lawful-intercept store (subscriber IP, user-agent, "
				"call-id, path) — use tls:// with an authenticated account "
				"and one bucket per trust domain (SPEC \xc2\xa7""11 [REV-24])\n",
				_redacted_url);
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
	/* [P11 / SPEC §1.2 REV-10] non-NULL "unsupported" stub: usrloc
	 * full-sharing never calls _remove; register it so a wrong-mode caller
	 * fails loudly (-1 + LM_ERR) instead of a NULL function-pointer crash. */
	cde.cdb_func._remove = nats_cache_remove_unsupported;
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
		if (nats_intern_init(nats_idx_buckets) < 0) {
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
	}

	/* attach the dedicated watcher process to the module exports when
	 * the index is enabled AND at least one kv_watch pattern was
	 * configured.  This is the ONLY watcher mode: the process runs a
	 * single thread against the connection pool, so it has none of the
	 * pool races the removed in-worker pthread mode had.
	 * start_module_procs() (in main_loop) reads exports.procs AFTER
	 * init_modules returns, so this late assignment is safe and is the
	 * cleanest way to keep the proc declaration runtime-conditional
	 * without forking when it isn't wanted. */
	if (nats_enable_search_index && kv_watch_count > 0) {
		exports.procs = nats_watcher_procs;
		LM_INFO("cachedb_nats: dedicated KV watcher process "
			"ENABLED (%d kv_watch pattern(s))\n", kv_watch_count);
	} else if (nats_enable_search_index) {
		LM_INFO("cachedb_nats: no kv_watch pattern configured; "
			"KV watcher process NOT forked (the index will only "
			"track changes via the periodic resync, if enabled)\n");
	}

	/* P9 reaper host [REV-1/16/2] (SPEC §4.3A): register the periodic
	 * CAS-prune timer.  Index-independent (enumerates via kvStore_Keys), so
	 * it runs regardless of enable_search_index.  The reaper is the SINGLE
	 * expiry mechanism (P1.5), so a non-positive interval is refused. */
	if (_reap_interval_guard(nats_reap_interval) < 0) {
		LM_ERR("nats_reap_interval=%d disables the reaper, the only "
			"expiry mechanism -- expired bindings would never be "
			"reclaimed; set nats_reap_interval > 0\n",
			nats_reap_interval);
		return -1;
	}
	if (register_timer("nats_cdb_reaper", _nats_cdb_reaper_tick, NULL,
			nats_reap_interval, 0) < 0) {
		LM_ERR("failed to register reaper timer\n");
		return -1;
	}
	LM_INFO("cachedb_nats: reaper ENABLED, scan every %d s "
		"(grace %d s)\n", nats_reap_interval, nats_reap_grace);

	/* Register E_NATS_KV_CHANGE event in mod_init (pre-fork, runs once)
	 * so it exists before startup_route's subscribe_event() and before
	 * the dedicated watcher process forks. */
	{
		extern event_id_t evi_kv_change_id;
		str evi_name = str_init("E_NATS_KV_CHANGE");
		evi_kv_change_id = evi_publish_event(evi_name);
		if (evi_kv_change_id == EVI_ERROR)
			LM_WARN("cannot register E_NATS_KV_CHANGE event\n");
	}

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

	/* P11b [REV-25]: a PRE-EXISTING bucket may already carry a non-zero
	 * backing-stream MaxAge (older deployment / another tool).  The kv_ttl
	 * modparam guard (mod_init) only stops US from creating one; binding to an
	 * existing MaxAge!=0 bucket would SILENTLY expire permanent contacts
	 * (expires==0).  Detect it once (rank 1) and WARN loudly with the
	 * remediation -- the documented migration policy, never a silent expiry.
	 * WARN (not refuse) so a generic cachedb_nats TTL-cache user is not broken;
	 * a usrloc deployment must recreate the bucket with MaxAge=0. */
	if (rank == 1) {
		int64_t maxage_ns = 0, mmps = 0;
		if (nats_pool_bucket_maxage_ns(kv_bucket, &maxage_ns) == 0 &&
				_kv_legacy_bucket_maxage_warn(maxage_ns)) {
			LM_WARN("cachedb_nats: bound bucket '%s' has a non-zero backing-stream "
				"MaxAge (%lld ns) -- it will SILENTLY EXPIRE ALL keys including "
				"PERMANENT contacts (expires==0). If this bucket backs usrloc, "
				"recreate it with MaxAge=0 (kv_ttl=0) and migrate [REV-25].\n",
				kv_bucket, (long long)maxage_ns);
		}
		/* Reaper-only expiry (P1.5): a history-keeping bucket is fine
		 * for nats_kv_history() consumers; no per-message TTL exists to
		 * misbehave on it, so nothing to surface beyond the MaxAge
		 * check above. */
		(void)mmps;
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

	/* Live index updates come from the dedicated watcher process
	 * (exports.procs, attached in mod_init when enable_search_index=1
	 * and kv_watch patterns exist).  The former rank-1 in-worker
	 * watcher pthread was removed: it shared the SIP worker's
	 * per-process connection pool from a second thread, racing the
	 * pool's single-threaded KV-handle cache (use-after-free under
	 * broker flap). */

	/* open cachedb connections for each configured URL */
	for (it = nats_cdb_urls; it; it = it->next) {
		char _redacted[512];
		char _tmp[512];
		int _n = it->url.len < (int)sizeof(_tmp) - 1
			? it->url.len : (int)sizeof(_tmp) - 1;
		memcpy(_tmp, it->url.s, _n);
		_tmp[_n] = '\0';
		nats_redact_url(_tmp, _redacted, sizeof(_redacted));
		LM_DBG("opening cachedb_nats connection for [%s]\n", _redacted);
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
	/* The KV watcher lives in its own forked child process; the
	 * OpenSIPS core delivers SIGTERM to every child including it,
	 * which terminates it cleanly — nothing to stop from here. */
	nats_json_index_destroy();
	/* Tear down the doc-key intern table after the index, since
	 * _free_entry calls nats_intern_release on every key. */
	nats_intern_destroy();
	cachedb_end_connections(&cache_mod_name);
	/* Drop our pool reference (pool tears down on the last module's
	 * unregister) -- after the watcher/index that used it are gone. */
	nats_pool_unregister();
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

	/* Do NOT gate on the pool's process-local "connected" flag: this
	 * handler runs in the OpenSIPS timer process, which never calls
	 * nats_pool_get() on its own, so that flag is permanently 0 and every
	 * tick used to be skipped (the periodic rebuild never ran).
	 * nats_pool_get_kv() lazily establishes the connection on first use;
	 * if the broker is genuinely down it returns NULL and we skip just
	 * this tick, retrying on the next. */
	kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history,
		(int64_t)kv_ttl);
	if (!kv) {
		LM_DBG("periodic resync: no KV handle (broker down?); "
			"skipping tick\n");
		return;
	}

	if (nats_json_index_rebuild(kv, fts_json_prefix) < 0)
		LM_WARN("periodic resync: index rebuild failed\n");
	else
		LM_DBG("periodic resync: index rebuilt\n");
}

/* ------------------------------------------------------------------ */
/*   P9 reaper host (SPEC §4.3A [REV-1/16])                           */
/* ------------------------------------------------------------------ */

/* CAS-guarded publish-delete of a KV key [REV-16].  Publishes a KV-Operation:DEL
 * marker for "$KV.<bucket>.<key>" with ExpectLastSubjectSeq=@rev, so a
 * concurrent re-REGISTER that bumped the head between our read and this delete
 * makes the delete FAIL (jerr 10071) instead of destroying the renew.  A blind
 * kvStore_Delete() would lose that race -- never use it here.
 * Returns 0 deleted, 1 CAS-lost (a renew won -- leave the key), -1 on error. */
static int _reap_cas_delete(jsCtx *js, const char *bucket, const char *key,
	uint64_t rev)
{
	char subj[512];
	natsMsg *m = NULL;
	jsPubAck *pa = NULL;
	jsErrCode je = 0;
	jsPubOptions o;
	natsStatus s;

	if (nats_kv_key_to_subject(bucket, key, subj, sizeof subj) < 0)
		return -1;
	if (nats_dl.natsMsg_Create(&m, subj, NULL, NULL, 0) != NATS_OK)
		return -1;
	if (nats_dl.natsMsgHeader_Set(m, "KV-Operation", NATS_KV_OP_DEL) != NATS_OK) {
		nats_dl.natsMsg_Destroy(m);
		return -1;
	}
	nats_dl.jsPubOptions_Init(&o);
	o.ExpectLastSubjectSeq = rev;             /* CAS predicate */
	s = nats_dl.js_PublishMsg(&pa, js, m, &o, &je);
	nats_dl.jsPubAck_Destroy(pa);
	nats_dl.natsMsg_Destroy(m);
	if (s == NATS_OK)
		return 0;
	if (je == 10071)                          /* JSStreamWrongLastSequenceErr */
		return 1;                         /* a concurrent renew won the race */
	LM_DBG("reaper: CAS-delete '%s' failed: %s (jerr=%d)\n",
		key, nats_dl.natsStatus_GetText(s), je);
	return -1;
}

/* The reaper tick: scan the bucket once, and for each DUE usrloc row either
 * CAS-rewrite it to its survivors or CAS-delete it when nothing survives.  Runs
 * in the OpenSIPS timer process (like the resync handler) -- so it does NOT gate
 * on nats_pool_is_connected() (that flag is process-local and always 0 here);
 * a NULL KV/JS handle means the broker is down and we skip just this tick.
 *
 * Independent of the search index [REV-17]: enumeration is a direct
 * kvStore_Keys() over the bucket, so the reaper works with enable_search_index=0.
 * Malformed/poison rows are LEFT in place (the read path alarms them); permanent
 * and not-yet-due rows are skipped by the cheap row_exp due-gate. */
static void _nats_cdb_reaper_tick(unsigned int ticks, void *param)
{
	kvStore *kv;
	jsCtx *js;
	kvKeysList keys;
	natsStatus s;
	time_t now;
	int i, prefix_len, reaped = 0;
	/* [HREV-3] physical-reclamation slack: the skew margin plus the
	 * operator's retention window -- without the linger term the reaper
	 * would reclaim rows the TTL path was told to keep. */
	const int slack = nats_reap_grace + nats_expired_linger;
	/* [OBS/D-OBS-2] pass gauges: the scan below Gets every prefixed key
	 * anyway, so bucket-wide registration totals are free here.  "active"
	 * uses grace only (visibility semantics), independent of the slack. */
	long g_keys = 0, g_aors = 0, g_contacts = 0, g_active = 0,
	     g_perm = 0, g_due = 0;
	struct timespec g_t0, g_t1;

	(void)ticks; (void)param;
	clock_gettime(CLOCK_MONOTONIC, &g_t0);

	kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history, (int64_t)kv_ttl);
	if (!kv) {
		LM_DBG("reaper: no KV handle (broker down?); skipping tick\n");
		return;
	}
	js = nats_pool_get_js();
	if (!js) {
		LM_DBG("reaper: no JetStream ctx; skipping tick\n");
		return;
	}

	now = time(NULL);
	prefix_len = (fts_json_prefix && *fts_json_prefix)
		? (int)strlen(fts_json_prefix) : 0;

	memset(&keys, 0, sizeof(keys));
	s = nats_dl.kvStore_Keys(&keys, kv, NULL);
	if (s == NATS_NOT_FOUND)
		return;                           /* empty bucket */
	if (s != NATS_OK) {
		LM_DBG("reaper: kvStore_Keys failed: %s\n",
			nats_dl.natsStatus_GetText(s));
		return;
	}

	for (i = 0; i < keys.Count; i++) {
		const char *key = keys.Keys[i];
		kvEntry *e = NULL;
		const char *val;
		int vlen, n_surv = 0, plen = 0, p_all_same = 0, n_before = 0;
		int64_t p_row_exp = 0;            /* P8: survivors' TTL eligibility */
		uint64_t rev;
		char *proj;

		if (!key)
			continue;
		/* only our usrloc rows; never touch another consumer's keys. */
		if (prefix_len && strncmp(key, fts_json_prefix, prefix_len) != 0)
			continue;
		g_keys++;
		if (nats_dl.kvStore_Get(&e, kv, key) != NATS_OK)
			continue;                     /* mid-delete / vanished -> skip */
		val = nats_dl.kvEntry_ValueString(e);
		vlen = nats_dl.kvEntry_ValueLen(e);
		rev = nats_dl.kvEntry_Revision(e);

		/* [OBS] pass gauges (visibility semantics: grace only); n_before
		 * feeds the contacts_pruned tally in the survivors branch. */
		n_before = 0;
		{
			struct reg_row_info g_ri;
			if (val && vlen > 0 &&
			    _reg_row_scan(val, vlen, now, nats_reap_grace,
					NULL, 0, NULL, 0, &g_ri) == 0) {
				g_aors++;
				g_contacts += g_ri.n_contacts;
				g_active   += g_ri.n_active;
				g_perm     += g_ri.n_perm;
				n_before = g_ri.n_contacts;
			}
		}

		/* cheap due-gate: skip permanent / not-yet-due rows without a
		 * full reprojection (row_exp == min contact expiry). */
		if (_reap_row_due_json(val, vlen, now, slack) == 0) {
			nats_dl.kvEntry_Destroy(e);
			continue;
		}
		g_due++;
		proj = _reap_project_survivors(val, vlen, now, slack,
			&n_surv, &plen, &p_row_exp, &p_all_same);
		nats_dl.kvEntry_Destroy(e);           /* proj is independent of val */
		if (!proj)
			continue;                     /* malformed/poison: read path alarms it */
		if (n_surv < 0) {                     /* not a usrloc row */
			free(proj);
			continue;
		}
		if (n_surv == 0) {
			if (_reap_cas_delete(js, kv_bucket, key, rev) == 0) {
				NATS_CDB_STATS_INC(rows_reaped);
				reaped++;
			}
		} else {
			/* P8 [§2.0]: WRITE-SURVIVORS through the one row-write helper so
			 * the pruned row goes through the one row-write helper (CAS
			 * publish, conflict-classified).  The reaper defers index
			 * convergence to the watcher (no index code). */
			uint64_t newrev = 0;
			if (nats_kv_write_row_cas(kv, kv_bucket, key, proj, plen, rev,
					&newrev) == 0) {
				NATS_CDB_STATS_INC(rows_reaped);
				/* [OBS] bindings physically removed by this survivor-write */
				if (n_before > n_surv)
					NATS_CDB_STATS_ADD(contacts_pruned,
						n_before - n_surv);
				reaped++;
			}
			/* CAS conflict / error: a concurrent writer won; retry next tick */
		}
		free(proj);
	}
	nats_dl.kvKeysList_Destroy(&keys);

	/* [OBS/D-OBS-2] publish the pass gauges (single writer: this process) */
	clock_gettime(CLOCK_MONOTONIC, &g_t1);
	NATS_CDB_STATS_SET(reap_last_run, (unsigned long)time(NULL));
	NATS_CDB_STATS_SET(reap_last_ms,
		(g_t1.tv_sec - g_t0.tv_sec) * 1000
		+ (g_t1.tv_nsec - g_t0.tv_nsec) / 1000000);
	NATS_CDB_STATS_SET(reap_last_keys, g_keys);
	NATS_CDB_STATS_SET(reap_last_aors, g_aors);
	NATS_CDB_STATS_SET(reap_last_contacts, g_contacts);
	NATS_CDB_STATS_SET(reap_last_active, g_active);
	NATS_CDB_STATS_SET(reap_last_permanent, g_perm);
	NATS_CDB_STATS_SET(reap_last_due, g_due);

	if (reaped)
		LM_INFO("cachedb_nats reaper: reclaimed %d row(s) this pass\n", reaped);
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
