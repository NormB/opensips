/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * test_registry_ring_ref_safety.c -- guards the removal of the two
 * unused, ref-unsafe registry ring helpers.
 *
 * Bug class: nats_registry_ring_get() handed out the raw `cur->ring`
 * pointer with NO pending_ops reference taken, and
 * nats_registry_set_ring_capacity() was a never-called stub.  The
 * production fetch path (nats_fetch.c) instead dereferences h->ring only
 * AFTER taking a pending_ops ref, which is what keeps the ring alive
 * against a concurrent unbind/reap.  Reintroducing ring_get and routing
 * a popper through it would reopen the unbind/reap use-after-free.
 *
 * Both functions had zero callers (production OR tests), so they were
 * deleted.  This test pins that decision: it fails if either the
 * ref-unsafe accessor or the dead stub reappears in the registry source
 * or header.
 *
 * Self-contained; run from the tests/ directory (reads
 * ../nats_handle_registry.{c,h}).
 * Build: cc -g -O0 -Wall -o test_registry_ring_ref_safety \
 *           test_registry_ring_ref_safety.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	if (!f) return -1;   /* missing file -> distinguishable */
	char line[2048];
	int hit = 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

int main(void)
{
	const char *src = "../nats_handle_registry.c";
	const char *hdr = "../nats_handle_registry.h";

	/* sanity: the files are reachable from the tests/ cwd */
	ASSERT(file_contains(src, "nats_registry_bind") == 1,
		"can read ../nats_handle_registry.c");
	ASSERT(file_contains(hdr, "nats_registry_bind") == 1,
		"can read ../nats_handle_registry.h");

	/* the ref-unsafe raw-ring accessor must be gone, source + header */
	ASSERT(file_contains(src, "nats_registry_ring_get") == 0,
		"ref-unsafe nats_registry_ring_get removed from the source");
	ASSERT(file_contains(hdr, "nats_registry_ring_get") == 0,
		"ref-unsafe nats_registry_ring_get removed from the header");

	/* the dead never-called capacity stub must be gone, source + header */
	ASSERT(file_contains(src, "nats_registry_set_ring_capacity") == 0,
		"unused nats_registry_set_ring_capacity removed from the source");
	ASSERT(file_contains(hdr, "nats_registry_set_ring_capacity") == 0,
		"unused nats_registry_set_ring_capacity removed from the header");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
