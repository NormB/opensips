/*
 * Decision logic for handling a 423 (Interval Too Brief) reply.
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include "min_expires.h"

/* The truth table and the full rationale for each outcome live with the enum in
 * min_expires.h; the branches below carry only a one-line tag each. Keep this a
 * pure function (no logging, no globals) so test/test.c can exercise it as a
 * standalone translation unit. */
enum min_expires_action min_expires_decide(unsigned int min_expires,
		unsigned int wanted_expires, int strict)
{
	if (min_expires == 0)                       /* no header, or Expires:0 footgun */
		return ME_ERR_NO_VALUE;
	if (min_expires > UAC_REG_MAX_SANE_EXPIRES) /* broken registrar; never ratchet */
		return ME_ERR_INSANE;
	if (min_expires > wanted_expires)           /* conformant: strict '>', not '>=' */
		return ME_RETRY_CONFORMANT;
	/* 0 < min_expires <= wanted_expires: non-conformant 423 */
	return strict ? ME_ERR_NONCONFORMANT : ME_RETRY_TOLERATED;
}
