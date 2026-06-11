/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test for TODO #33 (survivability, part A): with the default
 * max_deliver=0 a JetStream consumer redelivers a message that always
 * fails processing forever, broker-paced, with no dead-letter -- one
 * poison message can wedge a handle indefinitely.
 *
 * Fix: a configurable consumer-side poison cap (poison_max_deliver
 * modparam, 0 = off).  When a delivered message's NumDelivered exceeds the
 * cap, the consumer Terms it (telling the broker to stop redelivering) and
 * bumps a per-handle `poisoned` counter instead of pushing it to the ring.
 *
 * This test carries the cap-decision model and asserts the production
 * wiring (modparam, per-handle counter, proc Term site, MI surfacing).
 *
 * Build (self-contained):
 *   gcc -g -O0 -Wall -o test_poison_term test_poison_term.c
 */

#include <stdio.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	char line[4096];
	int hit = 0;
	if (!f) { fprintf(stderr, "  (cannot open %s)\n", path); return 0; }
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

/* ---- carried model: is this delivery poisoned? --------------------- */

/* cap <= 0 disables the check entirely (current behaviour: unlimited
 * broker-paced redelivery).  Otherwise a message is poison once it has
 * been delivered MORE than `cap` times. */
static int is_poison(unsigned long delivered, int cap)
{
	return cap > 0 && delivered > (unsigned long)cap;
}

int main(void)
{
	/* ---- model -------------------------------------------------- */
	{
		ASSERT(is_poison(6, 5) == 1, "delivered past the cap is poison");
		ASSERT(is_poison(5, 5) == 0, "delivered AT the cap is not yet poison");
		ASSERT(is_poison(1, 5) == 0, "first delivery is never poison");
		ASSERT(is_poison(1000, 0) == 0, "cap=0 disables the check (unlimited)");
		ASSERT(is_poison(1000, -1) == 0, "negative cap disables the check");
	}

	/* ---- modparam declared + registered ------------------------- */
	{
		const char *c = "../nats_consumer.c";
		ASSERT(file_contains(c, "nats_consumer_poison_max_deliver"),
			"poison cap global defined");
		ASSERT(file_contains(c, "\"poison_max_deliver\""),
			"poison_max_deliver modparam registered");
	}

	/* ---- per-handle counter declared ---------------------------- */
	{
		ASSERT(file_contains("../nats_handle_registry.h", "poisoned"),
			"registry handle declares the poisoned counter");
	}

	/* ---- proc loop Terms past the cap + counts it --------------- */
	{
		const char *p = "../nats_consumer_proc.c";
		ASSERT(file_contains(p, "nats_consumer_poison_max_deliver"),
			"proc loop consults the poison cap");
		ASSERT(file_contains(p, "&ss->h_ref->poisoned"),
			"proc loop bumps the poisoned counter");
		ASSERT(file_contains(p, "natsMsg_Term"),
			"proc loop Terms the poison message");
	}

	/* ---- MI surfaces the counter -------------------------------- */
	{
		const char *m = "../nats_mi.c";
		ASSERT(file_contains(m, "poisoned"),
			"MI surfaces the poisoned counter");
	}

	if (g_fails == 0) fprintf(stderr, "\n=== ALL PASS (fails=0) ===\n");
	else              fprintf(stderr, "\n=== FAILS=%d ===\n", g_fails);
	return g_fails ? 1 : 0;
}
