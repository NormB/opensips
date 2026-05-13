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
 * @file nats_rank.c
 * @brief OpenSIPS process-rank admission rule for NATS init.
 *
 * Placed in its own translation unit (rather than inlined in nats_pool.c)
 * so that unit tests can link it without dragging in the rest of the pool
 * and its OpenSIPS core dependencies (shm, logging, nats.c).  The function
 * is the single source of truth for the admission rule; both event_nats
 * and cachedb_nats call it from their mod_child_init.
 */

#include "../../sr_module.h"
#include "nats_pool.h"

int nats_pool_should_init(int rank)
{
	/*
	 * SIP workers (UDP + TCP, rank >= 1) and the HTTPD/MI process
	 * (PROC_MODULE) are the only ranks that should initialize NATS.
	 * Everything else (attendant, timer, TCP-main, module-exported
	 * processes) either does not run SIP routing or has its own
	 * explicit initialization path.
	 */
	return (rank == PROC_MODULE || rank >= 1);
}
