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
 * nats_consumer_proc.h -- dedicated JetStream pull consumer process.
 *
 * The process is forked by the OpenSIPS core via a proc_export_t entry
 * registered in `module_exports.procs`.  It is the sole producer into
 * each handle's SHM ring: SIP workers only pop.  On fork it joins the
 * nats_pool, then loops forever reconciling subscriptions with the
 * registry and pulling batches.
 *
 * Phase 3 limitations (documented in the .c):
 *   - auto-acks every successfully pushed message (no ack-token
 *     plumbing yet; Phase 4 replaces this with explicit worker-driven
 *     ack via the IPC queue).
 *   - no reconnect-aware subscription refresh (Phase 7).
 *   - no persistence / durable-name reconciliation beyond what the
 *     server already does for us (Phase 8).
 */

#ifndef NATS_CONSUMER_PROC_H
#define NATS_CONSUMER_PROC_H

/* Process entry point.  Matches the `mod_proc` signature expected by
 * OpenSIPS' proc_export_t: it is called once per fork with the rank
 * assigned by the core.  Returns only on fatal error; the core treats
 * return-from-main as an exiting child and reaps the process. */
void nats_consumer_proc_main(int rank);

#endif /* NATS_CONSUMER_PROC_H */
