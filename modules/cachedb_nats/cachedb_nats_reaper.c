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
 */

/*
 * cachedb_nats_reaper.c — reaper decision logic (SPEC.md §4.3A).  Broker-less
 * and side-effect-free; the loop / timer-host integration builds on top.
 */

#include "cachedb_nats_reaper.h"

/* (§4.3A [REV-1]) row-due selection. */
int _reap_row_due(int64_t row_exp, time_t now, int grace)
{
	return row_exp != 0 && (row_exp + (int64_t)grace) <= (int64_t)now;
}

/* (§4.3A [REV-16/31]) per-row action after pruning expired contacts. */
enum reap_action _reap_row_action(int n_live_survivors)
{
	return (n_live_survivors > 0) ? REAP_WRITE_SURVIVORS : REAP_DELETE_EMPTY;
}

/* (F2 [PREV-26/REV-2], extended [D6/HREV-6]) reaper-off guard.  With the
 * reaper off (interval<=0), nats_unsafe_ttl_only=1 only suffices while the
 * native-TTL path (nats_native_ttl) is still on; both mechanisms off leaves
 * nothing to expire records and is refused unconditionally. */
int _reap_interval_guard(int interval, int unsafe_ttl_only, int native_ttl)
{
	if (interval > 0)
		return 0;
	if (!native_ttl)
		return -1;
	return unsafe_ttl_only ? 0 : -1;
}
