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
 */

/*
 * nats_consumer.c -- module lifecycle + registrations.
 *
 * Script-surface exports:
 *   - sync  cmd:   nats_fetch(id, timeout_ms),
 *                  nats_fetch_batch(id, opts), nats_batch_select(i),
 *                  nats_ack(), nats_ack_next(), nats_ack_progress(),
 *                  nats_nak(), nats_nak_delay(delay_ms),
 *                  nats_term(), nats_in_progress(),
 *                  nats_hdr_set(name, value),
 *                  nats_reply(payload),
 *                  nats_request(subject, payload, timeout_ms)
 *   - async acmd:  nats_fetch(id, timeout_ms),
 *                  nats_fetch_batch(id, opts)
 *   - pvars:       $nats_subject, $nats_data, $nats_reply_to,
 *                  $nats_seq, $nats_consumer_seq, $nats_delivered,
 *                  $nats_pending, $nats_token, $nats_hdr(Name)
 *
 * IMPORTANT: nats_request() is SYNC-ONLY -- it blocks the calling
 * worker for up to timeout_ms.  Restrict callsites to timer_route /
 * startup_route until an async variant is added.  See nats_rpc.c /
 * nats_rpc.h for the full rationale.
 */

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../lib/nats/nats_pool.h"
#include "nats_consumer.h"
#include "nats_handle_parse.h"
#include "nats_handle_registry.h"
#include "nats_mi.h"
#include "nats_ack_ipc.h"
#include "nats_consumer_proc.h"
#include "nats_fetch.h"
#include "nats_ack.h"
#include "nats_rpc.h"
#include "nats_persist.h"

static int  mod_init(void);
static int  child_init(int rank);
static void mod_destroy(void);

/* w_nats_consumer_bind() -- script wrapper for the bind API.
 *
 * Same parse + register sequence as the MI command's mi_consumer_bind
 * (nats_mi.c:81), expressed as a cmd_export so operators can write the
 * canonical OpenSIPS pattern:
 *
 *     startup_route {
 *         nats_consumer_bind("id=jobs;stream=jobs;subject=jobs.>");
 *         nats_consumer_bind("id=audit;stream=audit;subject=audit.>");
 *     }
 *
 * Restricted to STARTUP_ROUTE: bindings define the consumer-process's
 * fetch handles, which the consumer process reads at child_init.
 * Calling from request_route would mean "modify the registry mid-flight"
 * which is doable via the MI path but isn't what the script API is
 * documented to express.
 *
 * Returns 1 on success, -1 on parse/registry/duplicate-id error.  The
 * specific error reason is logged at LM_ERR; script callers can branch
 * on $retcode.  Mirrors the MI handler's error mapping (parse -> 400,
 * dup -> 409, OOM -> 500) but collapses to a single -1 since cmd_export
 * doesn't carry status codes.
 */
static int w_nats_consumer_bind(struct sip_msg *msg, str *config_str)
{
	const char    *err = NULL;
	nats_handle_t *h;
	int            rc;

	(void)msg;

	if (!config_str || config_str->len <= 0 || !config_str->s) {
		LM_ERR("nats_consumer_bind: empty/null config string\n");
		return -1;
	}

	h = nats_handle_parse(config_str, &err);
	if (!h) {
		if (!err) err = "parse error";
		LM_ERR("nats_consumer_bind: parse failed: %s\n", err);
		return -1;
	}

	rc = nats_registry_bind(h);
	if (rc == -1) {
		LM_ERR("nats_consumer_bind: duplicate id '%.*s'\n",
			h->id.len, h->id.s);
		nats_handle_free(h);
		return -1;
	}
	if (rc == -2) {
		LM_ERR("nats_consumer_bind: registry full or OOM\n");
		nats_handle_free(h);
		return -1;
	}

	LM_INFO("nats_consumer: bound handle id=%.*s stream=%.*s "
		"(via script)\n",
		h->id.len, h->id.s, h->stream.len, h->stream.s);
	return 1;
}

/* ── script-callable commands ────────────────────────────────── */

static const cmd_export_t cmds[] = {
	{ "nats_fetch", (cmd_function)w_nats_fetch, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0},
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_fetch_batch", (cmd_function)w_nats_fetch_batch, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_batch_select", (cmd_function)w_nats_batch_select, {
		{CMD_PARAM_INT, 0, 0},
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_ack", (cmd_function)w_nats_ack, {
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_ack_next", (cmd_function)w_nats_ack_next, {
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_ack_progress", (cmd_function)w_nats_ack_progress, {
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_nak", (cmd_function)w_nats_nak, {
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_nak_delay", (cmd_function)w_nats_nak_delay, {
		{CMD_PARAM_INT, 0, 0},
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_term", (cmd_function)w_nats_term, {
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_in_progress", (cmd_function)w_nats_in_progress, {
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_hdr_set", (cmd_function)w_nats_hdr_set, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_reply", (cmd_function)w_nats_reply, {
		{CMD_PARAM_STR, 0, 0},
		{0, 0, 0}},
		ALL_ROUTES },
	/* nats_request is SYNC-ONLY: natsConnection_RequestMsg blocks the
	 * calling process for up to timeout_ms.  Restrict the route mask
	 * so the engine refuses to call it from contexts where blocking
	 * a SIP UDP/TCP worker would stall request processing
	 * (REQUEST_ROUTE, FAILURE_ROUTE, BRANCH_ROUTE, ERROR_ROUTE).
	 * Allow it from STARTUP/TIMER/LOCAL/EVENT/ONREPLY routes, which
	 * either don't own a SIP worker (startup, timer, event) or
	 * already accept synchronous semantics (local, onreply). */
	{ "nats_request", (cmd_function)w_nats_request, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT, 0, 0},
		{0, 0, 0}},
		ONREPLY_ROUTE | LOCAL_ROUTE | STARTUP_ROUTE |
		TIMER_ROUTE | EVENT_ROUTE },
	/* Script wrapper for the registry bind API.  STARTUP_ROUTE only:
	 * binds define the consumer-process's pull handles, which are
	 * read at child_init.  Mid-flight binds belong on the MI path. */
	{ "nats_consumer_bind", (cmd_function)w_nats_consumer_bind, {
		{CMD_PARAM_STR, 0, 0},
		{0, 0, 0}},
		STARTUP_ROUTE },
	{ 0, 0, {{0, 0, 0}}, 0 }
};

static const acmd_export_t acmds[] = {
	{ "nats_fetch", (acmd_function)w_nats_fetch_async, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0},
		{0, 0, 0}} },
	{ "nats_fetch_batch", (acmd_function)w_nats_fetch_batch_async, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{0, 0, 0}} },
	/* `nats_request` is also registered above as a sync cmd with a
	 * restrictive route mask.  The dispatch between sync and async is
	 * driven by call-site syntax: `nats_request(...)` resolves to the
	 * sync entry, `async(nats_request(...), rt)` resolves here.  Phase
	 * 1 of the async entry runs the same sync body and reports
	 * ASYNC_SYNC; phase 2 will yield on a libnats reply inbox. */
	{ "nats_request", (acmd_function)w_nats_request_async, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT, 0, 0},
		{0, 0, 0}} },
	{ 0, 0, {{0, 0, 0}} }
};

/* ── modparams ───────────────────────────────────────────────── */

/* Opt-in persistence.  Defaults: off.  If enabled, the registry is
 * JSON-serialized to `persist_path` on every bind/unbind (debounced
 * 500 ms) and rehydrated on mod_init.  If the parent directory of
 * `persist_path` does not exist at init time, we log a warning and run
 * with persistence disabled for this instance. */
static int persist_handles = 0;
static char *persist_path  = "/var/lib/opensips/nats_consumer/handles.json";

/* Module-global Fetch tuning.  Per-handle bind keys (`fetch_batch=`,
 * `fetch_timeout_ms=`) override these for a single handle; the
 * consumer process resolves the effective values at every Fetch call.
 * Defaults stay conservative (10 msgs / 1 s) so the module behaves
 * the same after upgrade for operators who do not set anything. */
int nats_consumer_fetch_batch      = 10;
int nats_consumer_fetch_timeout_ms = 1000;

static const param_export_t params[] = {
	{ "persist_handles",   INT_PARAM, &persist_handles },
	{ "persist_path",      STR_PARAM, &persist_path    },
	{ "fetch_batch",       INT_PARAM, &nats_consumer_fetch_batch       },
	{ "fetch_timeout_ms",  INT_PARAM, &nats_consumer_fetch_timeout_ms  },
	{ 0, 0, 0 }
};

/* ── pseudo-variables ────────────────────────────────────────── */

static const pv_export_t mod_pvars[] = {
	{ str_const_init("nats_subject"),      1000, pv_get_nats_subject,
		0, 0, 0, 0, 0 },
	{ str_const_init("nats_data"),         1000, pv_get_nats_data,
		0, 0, 0, 0, 0 },
	{ str_const_init("nats_reply_to"),     1000, pv_get_nats_reply_to,
		0, 0, 0, 0, 0 },
	{ str_const_init("nats_seq"),          1000, pv_get_nats_seq,
		0, 0, 0, 0, 0 },
	{ str_const_init("nats_consumer_seq"), 1000, pv_get_nats_consumer_seq,
		0, 0, 0, 0, 0 },
	{ str_const_init("nats_delivered"),    1000, pv_get_nats_delivered,
		0, 0, 0, 0, 0 },
	{ str_const_init("nats_pending"),      1000, pv_get_nats_pending,
		0, 0, 0, 0, 0 },
	{ str_const_init("nats_token"),        1000, pv_get_nats_token,
		0, 0, 0, 0, 0 },
	{ str_const_init("nats_hdr"),          1000, pv_get_nats_hdr,
		0, pv_parse_nats_hdr_name, 0, 0, 0 },
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

/* Dedicated JetStream pull consumer process.
 * One instance -- there is a single process for the module. */
static const proc_export_t procs[] = {
	{ "NATS consumer", 0, 0, nats_consumer_proc_main, 1, 0 },
	{ 0, 0, 0, 0, 0, 0 }
};

struct module_exports exports = {
	"nats_consumer",            /* module name */
	MOD_TYPE_DEFAULT,           /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	0,                          /* load function */
	NULL,                       /* OpenSIPS module dependencies */
	cmds,                       /* exported functions */
	acmds,                      /* exported async functions */
	params,                     /* exported parameters */
	0,                          /* exported statistics */
	nats_consumer_mi_cmds,      /* exported MI functions */
	mod_pvars,                  /* exported pseudo-variables */
	0,                          /* exported transformations */
	procs,                      /* extra processes -- NATS consumer */
	0,                          /* module pre-initialization function */
	mod_init,                   /* module initialization function */
	0,                          /* response handling function */
	mod_destroy,                /* destroy function */
	child_init,                 /* per-child init function */
	0                           /* reload confirm function */
};

static int mod_init(void)
{
	LM_INFO("nats_consumer %s initializing\n", NATS_CONSUMER_VERSION);

	if (nats_registry_init(NATS_CONSUMER_REGISTRY_BUCKETS) < 0) {
		LM_ERR("nats_consumer: registry init failed\n");
		return -1;
	}
	LM_DBG("nats_consumer: registry ready (%d buckets)\n",
		NATS_CONSUMER_REGISTRY_BUCKETS);

	if (nats_ack_ipc_init() < 0) {
		LM_ERR("nats_consumer: ack IPC init failed\n");
		nats_registry_destroy();
		return -1;
	}
	LM_DBG("nats_consumer: ack IPC queue ready (fd=%d)\n",
		nats_ack_ipc_fd());

	if (nats_consumer_hb_init() < 0) {
		LM_ERR("nats_consumer: heartbeat SHM alloc failed\n");
		nats_ack_ipc_destroy();
		nats_registry_destroy();
		return -1;
	}

	/* Opt-in persistence.  If enabled, start the writer thread and
	 * rehydrate any snapshot left by a previous run.  Failures here
	 * are non-fatal -- we log, disable persistence, and continue
	 * with an empty registry so the module still loads. */
	if (persist_handles) {
		if (!persist_path || !*persist_path) {
			LM_WARN("nats_consumer: persist_handles=1 but persist_path "
					"is empty; persistence disabled\n");
		} else if (nats_persist_init(persist_path) < 0) {
			LM_WARN("nats_consumer: persistence init failed for %s; "
					"continuing with empty registry\n", persist_path);
		} else {
			int n = nats_persist_rehydrate();
			if (n < 0)
				LM_WARN("nats_consumer: rehydrate failed; starting "
						"with empty registry\n");
			else
				LM_INFO("nats_consumer: rehydrated %d handles from %s\n",
						n, persist_path);
		}
	}

	return 0;
}

static int child_init(int rank)
{
	if (!nats_pool_should_init(rank)) {
		LM_DBG("nats_consumer: skipping rank=%d\n", rank);
		return 0;
	}
	LM_DBG("nats_consumer: child_init rank=%d\n", rank);
	return 0;
}

static void mod_destroy(void)
{
	LM_INFO("nats_consumer: shutting down\n");
	/* Order matters: persistence flush first (so the outgoing snapshot
	 * reflects the final live state), then ack IPC (so any future
	 * drain path can flush before the registry disappears
	 * underneath it), then registry.  nats_persist_destroy() joins the
	 * writer thread after flushing any outstanding dirty state -- no
	 * pending writer can race with the registry teardown below. */
	nats_persist_destroy();
	nats_ack_ipc_destroy();
	nats_consumer_hb_destroy();
	nats_registry_destroy();
}
