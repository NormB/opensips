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

#include "nats_rpc_subject.h"

#include <stdio.h>

int nats_rpc_subject_build(char *out, size_t out_sz,
                           const char *prefix, uint32_t slot, uint32_t gen)
{
	int n;

	if (!out || out_sz == 0 || !prefix)
		return -1;

	n = snprintf(out, out_sz, "%s.%u.%u", prefix,
		(unsigned)slot, (unsigned)gen);
	if (n <= 0 || (size_t)n >= out_sz)
		return -1;   /* truncated */
	return n;
}

int nats_rpc_subject_parse(const char *subject, int len,
                           uint32_t *slot, uint32_t *gen)
{
	int         i, gdot = -1, sdot = -1;
	long        sv, gv;
	const char *p;

	if (!subject || len <= 0 || !slot || !gen)
		return -1;

	/* last '.' separates the <gen> tail */
	for (i = len - 1; i >= 0; i--)
		if (subject[i] == '.') { gdot = i; break; }
	if (gdot < 0 || gdot >= len - 1)
		return -1;   /* no dot, or nothing after it */

	/* preceding '.' separates the <slot> segment */
	for (i = gdot - 1; i >= 0; i--)
		if (subject[i] == '.') { sdot = i; break; }
	if (sdot < 0 || sdot >= gdot - 1)
		return -1;   /* no second dot, or empty <slot> segment */

	/* <slot> digits live in (sdot, gdot) -- clamp to INT32_MAX to
	 * match the slot-index domain. */
	sv = 0;
	for (p = subject + sdot + 1; p < subject + gdot; p++) {
		if (*p < '0' || *p > '9')
			return -1;
		sv = sv * 10 + (*p - '0');
		if (sv > 0x7fffffffL)
			return -1;
	}

	/* <gen> digits live in (gdot, len) -- full uint32 domain. */
	gv = 0;
	for (p = subject + gdot + 1; p < subject + len; p++) {
		if (*p < '0' || *p > '9')
			return -1;
		gv = gv * 10 + (*p - '0');
		if (gv > 0xffffffffL)
			return -1;
	}

	*slot = (uint32_t)sv;
	*gen  = (uint32_t)gv;
	return 0;
}
