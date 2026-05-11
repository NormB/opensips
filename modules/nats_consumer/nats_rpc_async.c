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
 * nats_rpc_async.c -- async entry point for nats_request.
 *
 * Phase 1 (this file): the acmd binding exists and is wired through
 * the OpenSIPS async() construct, but its body still runs the
 * synchronous request path under the hood and reports completion via
 * async_status = ASYNC_SYNC.  The plumbing is real -- script-level
 * `async(nats_request(...), resume_route)` invokes this function,
 * then resumes into the named route on return -- but the worker
 * still blocks for the duration of natsConnection_RequestMsg.  This
 * is intentional: phase 1 validates the script surface, the cmds /
 * acmds dual registration, and the build / link path without
 * introducing any libnats-callback-thread interactions.
 *
 * Phase 2 will replace the body with:
 *   1. A persistent per-worker reply-inbox subscription, registered
 *      in child_init on the wildcard subject `_INBOX.opensips.<pid>.>`.
 *   2. A per-call eventfd + correlation entry inserted into a
 *      process-local hash table keyed on the inbox suffix.
 *   3. natsConnection_PublishRequest with reply-to set to the
 *      per-call inbox.
 *   4. A resume function that drains the eventfd, retrieves the
 *      reply from the correlation entry, populates the current-message
 *      state, and reports ASYNC_DONE.
 * Until then this file owns only the dispatch skeleton.
 */

#include "../../dprint.h"
#include "../../async.h"

#include "nats_rpc.h"

int w_nats_request_async(struct sip_msg *msg, async_ctx *ctx,
                         str *subject, str *payload, int *timeout_ms)
{
	int rc;

	(void)ctx;

	/* Phase 1 sync fall-through.  The acmd contract permits a
	 * synchronous completion via async_status = ASYNC_SYNC: the
	 * reactor will not register any FD and will continue script
	 * execution into the resume route immediately.  Behaviour is
	 * identical to the bare-call sync path; only the call-site
	 * syntax changes. */
	rc = w_nats_request(msg, subject, payload, timeout_ms);

	async_status = ASYNC_SYNC;
	return rc;
}
