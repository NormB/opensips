/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Security regression test: the consumer-routed async nats_request reply
 * inbox subject was "<prefix>.<slot_idx>.<generation>".  That subject
 * lives under a shared "<prefix>.>" wildcard the consumer subscribes to,
 * which ANY broker peer can publish to.  slot_idx (0..N) and generation
 * (small monotonic) are both guessable, so a malicious peer could forge a
 * reply for an in-flight call and have on_inbox_reply deliver an
 * attacker-controlled body/headers into the SIP script.  The per-call
 * UUIDv7 corr_id existed but was only sent as an X-Request-Id header, not
 * checked against the reply.
 *
 * Fix: the corr_id is embedded as a 4th subject segment
 * ("<prefix>.<slot>.<gen>.<corr_id>") and on_inbox_reply requires it to
 * match the slot's stored corr_id.  A forger who guesses slot+gen but not
 * the 74-bit UUID is rejected.
 *
 * This test drives the real subject grammar (../nats_rpc_subject.c) and
 * slot table (../nats_rpc_slot.c) and models the on_inbox_reply accept
 * decision in accept_reply():
 *
 *   -DSIMULATE_PREFIX_BUG -> generation-only check (pre-fix): the forged
 *                            reply is ACCEPTED -> the spoof assertion FAILS.
 *   (default)             -> generation + corr_id check: forged reply
 *                            REJECTED, genuine reply accepted -> ALL PASS.
 *
 * Build: TEST_SHIM + ../nats_rpc_subject.c + ../nats_rpc_slot.c.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdatomic.h>

#include "../nats_rpc_subject.h"
#include "../nats_rpc_slot.h"

static int g_fails;
#define CHECK(cond, label) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", (label)); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", (label)); } \
} while (0)

/* Models the accept/drop decision in on_inbox_reply for a parsed reply
 * (pgen, pcorr) landing on slot s. */
static int accept_reply(const nats_rpc_slot_t *s, uint32_t pgen,
		const char *pcorr)
{
	/* generation guard (present in both pre-fix and fixed code) */
	if (atomic_load_explicit(&s->generation, memory_order_relaxed) != pgen)
		return 0;
#ifndef SIMULATE_PREFIX_BUG
	/* corr_id authentication (the fix) */
	{
		size_t cl = strlen(pcorr);
		if (s->corr_id_len == 0 ||
		    cl != (size_t)s->corr_id_len ||
		    memcmp(pcorr, s->corr_id, cl) != 0)
			return 0;
	}
#else
	(void)pcorr;
#endif
	return 1;
}

int main(void)
{
	const char *prefix = "_INBOX.opensips.12345";
	const char *uuid   = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
	nats_rpc_slot_t *s;
	char             subj[128], pcorr[40];
	uint32_t         idx, gen, pslot, pgen;

	CHECK(nats_rpc_slot_init() == 0, "slot pool initialised");

	/* Worker claims a slot and stamps its per-call corr_id (as
	 * w_nats_request_async does). */
	s = nats_rpc_slot_claim();
	CHECK(s != NULL, "slot claimed");
	CHECK(nats_rpc_slot_publish(s) == 0, "slot published (INFLIGHT)");
	idx = s->slot_idx;
	gen = atomic_load_explicit(&s->generation, memory_order_relaxed);
	memcpy(s->corr_id, uuid, strlen(uuid) + 1);
	s->corr_id_len = (uint32_t)strlen(uuid);

	/* The consumer advertises this reply-to subject. */
	CHECK(nats_rpc_subject_build(subj, sizeof(subj), prefix, idx, gen,
		uuid, (int)strlen(uuid)) > 0, "reply-to subject built with corr_id");

	/* (1) Genuine reply: responder echoes the advertised subject. */
	CHECK(nats_rpc_subject_parse(subj, (int)strlen(subj), &pslot, &pgen,
		pcorr, sizeof(pcorr)) == 0, "genuine reply subject parses");
	CHECK(accept_reply(s, pgen, pcorr) == 1,
		"genuine reply (correct corr_id) is accepted");

	/* (2) Forged reply: attacker guesses slot+gen but NOT the corr_id.
	 * They publish to <prefix>.<idx>.<gen>.<their-guess>. */
	{
		char forged[128], fcorr[40];
		uint32_t fslot, fgen;
		const char *guess = "deadbeef-0000-7000-8000-000000000000";

		CHECK(nats_rpc_subject_build(forged, sizeof(forged), prefix,
			idx, gen, guess, (int)strlen(guess)) > 0,
			"attacker crafts a slot/gen-correct subject");
		CHECK(nats_rpc_subject_parse(forged, (int)strlen(forged),
			&fslot, &fgen, fcorr, sizeof(fcorr)) == 0,
			"forged subject parses (slot+gen match the in-flight call)");
		CHECK(fslot == idx && fgen == gen,
			"forged reply targets the right slot and generation");

		/* THE security contract: the forgery is rejected because its
		 * corr_id does not match the slot's.  Under the pre-fix
		 * generation-only check this is ACCEPTED (the spoof). */
		CHECK(accept_reply(s, fgen, fcorr) == 0,
			"forged reply (wrong corr_id) is REJECTED");
	}

	/* (3) A reply with the right corr_id but a stale generation is still
	 * rejected by the generation guard (defence in depth). */
	CHECK(accept_reply(s, gen + 1, uuid) == 0,
		"right corr_id but wrong generation is rejected");

	nats_rpc_slot_free(s,
		atomic_load_explicit(&(s)->generation, memory_order_relaxed));
	nats_rpc_slot_destroy();

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
