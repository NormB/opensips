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
 * Phase 4 exports:
 *   - sync  cmd:   nats_fetch(id, timeout_ms),
 *                  nats_ack(), nats_nak(), nats_nak_delay(delay_ms),
 *                  nats_term(), nats_in_progress()
 *   - async acmd:  nats_fetch(id, timeout_ms)  (wrapped via async())
 *   - pvars:       $nats_subject, $nats_data, $nats_reply_to,
 *                  $nats_seq, $nats_consumer_seq, $nats_delivered,
 *                  $nats_pending, $nats_token
 */

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../lib/nats/nats_pool.h"
#include "nats_consumer.h"
#include "nats_handle_registry.h"
#include "nats_mi.h"
#include "nats_ack_ipc.h"
#include "nats_consumer_proc.h"
#include "nats_fetch.h"
#include "nats_ack.h"

static int  mod_init(void);
static int  child_init(int rank);
static void mod_destroy(void);

/* ── script-callable commands ────────────────────────────────── */

static const cmd_export_t cmds[] = {
	{ "nats_fetch", (cmd_function)w_nats_fetch, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0},
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_ack", (cmd_function)w_nats_ack, {
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
	{ 0, 0, {{0, 0, 0}}, 0 }
};

static const acmd_export_t acmds[] = {
	{ "nats_fetch", (acmd_function)w_nats_fetch_async, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0},
		{0, 0, 0}} },
	{ 0, 0, {{0, 0, 0}} }
};

static const param_export_t params[] = {
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
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

/* Phase 3: dedicated JetStream pull consumer process.
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
	/* Order matters: ack IPC first (so any future Phase 4 drain path
	 * can flush before the registry disappears underneath it), then
	 * registry. */
	nats_ack_ipc_destroy();
	nats_registry_destroy();
}
