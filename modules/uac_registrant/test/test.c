/*
 * Unit tests (TAP) for the uac_registrant 423 / Min-Expires decision logic.
 *
 * Run with:  make test module=uac_registrant
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

#include <tap.h>

#include "../min_expires.h"

/*
 * min_expires_decide(min_expires, wanted_expires, strict)
 *
 * Truth table being pinned (M = Min-Expires from the 423, 0 when the header was
 * missing/unparsable; W = wanted/requested expires):
 *
 *   reply                         strict=1              strict=0
 *   ---------------------------   --------------------  --------------------
 *   M >  W (conformant)           ME_RETRY_CONFORMANT   ME_RETRY_CONFORMANT
 *   M == W (boundary)             ME_ERR_NONCONFORMANT  ME_RETRY_TOLERATED
 *   M <  W                        ME_ERR_NONCONFORMANT  ME_RETRY_TOLERATED
 *   M == 0 (or no/unparsable hdr) ME_ERR_NO_VALUE       ME_ERR_NO_VALUE
 *   M >  MAX_SANE                 ME_ERR_INSANE         ME_ERR_INSANE
 *
 * Two values are special, errors even in tolerant mode: 0 (retrying with it
 * would put Expires: 0 on the wire - a de-registration) and anything above
 * UAC_REG_MAX_SANE_EXPIRES (a broken registrar we refuse rather than adopt).
 * A missing/unparsable header is expressed as M == 0 (the caller passes 0 for
 * it): the two are indistinguishable here by design and share ME_ERR_NO_VALUE.
 */
static void test_min_expires_decide(void)
{
	/* conformant: Min-Expires strictly greater than requested -> always retry */
	ok(min_expires_decide(120, 60, 1) == ME_RETRY_CONFORMANT,
		"conformant (120>60), strict: conformant retry");
	ok(min_expires_decide(120, 60, 0) == ME_RETRY_CONFORMANT,
		"conformant (120>60), tolerant: conformant retry");
	ok(min_expires_decide(61, 60, 1) == ME_RETRY_CONFORMANT,
		"just above (61>60), strict: conformant retry");
	ok(min_expires_decide(7200, 3600, 1) == ME_RETRY_CONFORMANT,
		"conformant at larger scale, strict: conformant retry");

	/* boundary: Min-Expires == requested. The comparison must be a strict
	 * '>', not '>=' - this is the off-by-one that the patch hinges on. */
	ok(min_expires_decide(60, 60, 1) == ME_ERR_NONCONFORMANT,
		"equal (60==60), strict: registrar error (not '>=')");
	ok(min_expires_decide(60, 60, 0) == ME_RETRY_TOLERATED,
		"equal (60==60), tolerant: tolerated retry");
	ok(min_expires_decide(3600, 3600, 1) == ME_ERR_NONCONFORMANT,
		"equal at larger scale, strict: registrar error");

	/* non-conformant: Min-Expires below requested */
	ok(min_expires_decide(30, 60, 1) == ME_ERR_NONCONFORMANT,
		"below (30<60), strict: registrar error");
	ok(min_expires_decide(30, 60, 0) == ME_RETRY_TOLERATED,
		"below (30<60), tolerant: tolerated retry");
	ok(min_expires_decide(59, 60, 1) == ME_ERR_NONCONFORMANT,
		"just below (59<60), strict: registrar error");

	/* absurd minimum: above UAC_REG_MAX_SANE_EXPIRES is a broken registrar -
	 * refuse it in both modes rather than adopt a pathological interval. The
	 * boundary value itself (== MAX) is still a normal conformant retry. */
	ok(min_expires_decide(UAC_REG_MAX_SANE_EXPIRES + 1, 3600, 1)
			== ME_ERR_INSANE,
		"above sane maximum, strict: registrar error");
	ok(min_expires_decide(UAC_REG_MAX_SANE_EXPIRES + 1, 3600, 0)
			== ME_ERR_INSANE,
		"above sane maximum, tolerant: registrar error (no unbounded ratchet)");
	ok(min_expires_decide(UAC_REG_MAX_SANE_EXPIRES, 3600, 1)
			== ME_RETRY_CONFORMANT,
		"exactly at sane maximum, strict: still a conformant retry");

	/* Min-Expires: 0 - or, equivalently, a missing/unparsable header (the
	 * caller passes 0 for both). Retrying with it would send Expires: 0 (a
	 * de-registration) while the record still believes it is REGISTERED, so it
	 * is an error in BOTH modes - tolerant must not flip it. */
	ok(min_expires_decide(0, 60, 1) == ME_ERR_NO_VALUE,
		"zero/missing Min-Expires, strict: registrar error");
	ok(min_expires_decide(0, 60, 0) == ME_ERR_NO_VALUE,
		"zero/missing Min-Expires, tolerant: registrar error (never self-de-register)");

	/* strict only changes the outcome of the non-conformant, non-zero rows
	 * (the zero row stays an error in both modes - tested above) */
	ok(min_expires_decide(50, 60, 1) != min_expires_decide(50, 60, 0),
		"strict flips the non-conformant case");
	ok(min_expires_decide(90, 60, 1) == min_expires_decide(90, 60, 0),
		"strict does not affect the conformant case");
}

void mod_tests(void)
{
	test_min_expires_decide();
}
