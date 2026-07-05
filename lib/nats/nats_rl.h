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
 * nats_rl.h -- one-per-interval log gate [P3.7].
 *
 * The outage logging policy across the NATS modules: a state that
 * repeats per call (broker down, payload dropped, buffer truncated)
 * logs a rate-limited WARN plus a per-call DBG, instead of either a
 * WARN flood (nats_consumer's old per-request disconnect WARN) or
 * production invisibility (cachedb_nats's 13 DBG-only fast-fail
 * sites).  Usage:
 *
 *     static time_t rl;   // one slot per site (or shared per policy)
 *     if (nats_rl_pass(&rl, time(NULL), 30))
 *         LM_WARN("... (repeats suppressed for 30s)\n");
 *     LM_DBG("...\n");
 *
 * Slots are process-local; per-process emission is the intent (each
 * worker names itself in the log prefix).  Not thread-safe by design:
 * the only cost of a racing pass is one extra WARN line.  Contract is
 * unit-locked in lib/nats/tests/test_rl.c.
 */

#ifndef NATS_RL_H
#define NATS_RL_H

#include <time.h>

/*
 * Returns 1 when the caller may emit (and stamps *last = now),
 * 0 when the site is inside its quiet interval.  interval_s <= 0
 * disables limiting.  A clock that jumps backwards re-arms the gate
 * (re-stamping to the new now) instead of silencing the site until
 * wall time catches back up to the stale stamp.
 */
static inline int nats_rl_pass(time_t *last, time_t now, int interval_s)
{
	if (interval_s <= 0)
		return 1;
	if (*last != 0 && now >= *last && now - *last < (time_t)interval_s)
		return 0;
	*last = now;
	return 1;
}

#endif /* NATS_RL_H */
