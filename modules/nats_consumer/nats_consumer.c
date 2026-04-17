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
 * Phase 0 skeleton: loads, logs a version line at mod_init, uses the
 * lib/nats rank helper to admit the right process ranks.  Real script
 * functions, MI commands, and the consumer process arrive in later phases.
 */

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../lib/nats/nats_pool.h"
#include "nats_consumer.h"
#include "nats_handle_registry.h"
#include "nats_mi.h"

static int  mod_init(void);
static int  child_init(int rank);
static void mod_destroy(void);

static const cmd_export_t cmds[] = {
	{ 0, 0, {{0, 0, 0}}, 0 }
};

static const param_export_t params[] = {
	{ 0, 0, 0 }
};

struct module_exports exports = {
	"nats_consumer",            /* module name */
	MOD_TYPE_DEFAULT,           /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	0,                          /* load function */
	NULL,                       /* OpenSIPS module dependencies */
	cmds,                       /* exported functions */
	0,                          /* exported async functions */
	params,                     /* exported parameters */
	0,                          /* exported statistics */
	nats_consumer_mi_cmds,      /* exported MI functions */
	0,                          /* exported pseudo-variables */
	0,                          /* exported transformations */
	0,                          /* extra processes */
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
	nats_registry_destroy();
}
