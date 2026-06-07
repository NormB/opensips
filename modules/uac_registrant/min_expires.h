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

#ifndef _UAC_REGISTRANT_MIN_EXPIRES_H_
#define _UAC_REGISTRANT_MIN_EXPIRES_H_

/*
 * Defensive upper bound on a registrar-advertised Min-Expires we are willing
 * to adopt. A 423 demanding a *minimum* registration interval longer than this
 * is treated as a registrar error (ME_ERR_INSANE) rather than retried: no sane
 * registrar requires it, and adopting it would ratchet our requested expiry up
 * to a pathological value with no way back down. Clamping below the demanded
 * minimum is not an option either - it would just earn another 423 and loop.
 * One day is already far above any realistic minimum expiry.
 */
#define UAC_REG_MAX_SANE_EXPIRES 86400

/*
 * How the registrant should react to a 423 (Interval Too Brief) reply, and why.
 * This enum is the single source of truth for the decision: min_expires_decide()
 * picks one value, and the caller maps it straight to a log message and a state
 * transition without re-deriving any of these conditions.
 *
 * Rationale (RFC 3261 10.3 / 10.2.8 and the min_expires_strict modparam):
 * a registrar may reply 423 only when the requested expiration is *smaller*
 * than its configured minimum, so a conformant Min-Expires is always strictly
 * greater than what we requested, and 10.2.8 lets us retry with a value "equal
 * to or greater than" it (we use exactly it). On any accepted 423 the value is
 * stored in rec->wanted_expires (what send_register() actually puts on the
 * wire), so the retry carries it AND every later re-REGISTER reuses it - the
 * interval is renegotiated once, not on each refresh.
 *
 * Truth table (M = Min-Expires from the 423, 0 if no parsable header;
 *              W = the expiry we requested; strict = min_expires_strict):
 *
 *   condition                       strict=1               strict=0
 *   ------------------------------  ---------------------  -------------------
 *   M == 0 (or no header)           ME_ERR_NO_VALUE        ME_ERR_NO_VALUE
 *   M >  UAC_REG_MAX_SANE_EXPIRES    ME_ERR_INSANE          ME_ERR_INSANE
 *   M >  W   (conformant)           ME_RETRY_CONFORMANT    ME_RETRY_CONFORMANT
 *   0 < M <= W (non-conformant)     ME_ERR_NONCONFORMANT   ME_RETRY_TOLERATED
 */
enum min_expires_action {
	ME_RETRY_CONFORMANT,  /* Min-Expires > requested: retry (both modes)      */
	ME_RETRY_TOLERATED,   /* Min-Expires <= requested, strict=0: retry anyway */
	/* No usable value to retry with (no parsable header, or M == 0). Error in
	 * both modes: retrying with 0 would put Expires: 0 on the wire - a
	 * de-registration - while the record still believes it is REGISTERED, so
	 * tolerant mode must never flip it. */
	ME_ERR_NO_VALUE,
	ME_ERR_INSANE,        /* Min-Expires > UAC_REG_MAX_SANE_EXPIRES (see macro) */
	ME_ERR_NONCONFORMANT, /* Min-Expires <= requested, rejected by strict=1   */
};

/*
 * Decide how to handle a 423 reply; see the rationale above for the policy.
 *
 *   min_expires    - the Min-Expires value; pass 0 when the 423 carried no
 *                    parsable Min-Expires header (a missing header and an
 *                    explicit 0 are indistinguishable here, by design: both
 *                    mean "no usable value" -> ME_ERR_NO_VALUE)
 *   wanted_expires - the expiration the registrant requested
 *   strict         - value of the min_expires_strict modparam (0 or 1)
 *
 * Pure function (no side effects, no globals) so it can be unit tested
 * directly - see test/test.c.
 */
enum min_expires_action min_expires_decide(unsigned int min_expires,
		unsigned int wanted_expires, int strict);

#endif /* _UAC_REGISTRANT_MIN_EXPIRES_H_ */
