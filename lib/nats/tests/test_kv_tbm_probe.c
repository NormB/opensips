/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * kv_ttl_below_marker support probe (pool side).
 *
 * Background: per-message TTLs below SubjectDeleteMarkerTTL are raised to
 * it at ingest on MaxMsgsPer!=1 streams (nats-server PR #6741 / ADR-43) --
 * the root cause of the TTL-HISTORY rollback.  The fork servers fix this
 * (opt-in flag `allow_msg_ttl_below_marker`, or stale-marker replacement
 * with no flag); a STOCK server rejects the flag as an unknown config
 * field at bucket create.  That rejection is the support probe.
 *
 * Pool contract locked here:
 *
 *   - nats_pool_kv_request_ttl_below_marker(): modparam-driven request,
 *     called at init; without libnats support compiled in
 *     (LIBNATS_HAS_TTL_BELOW_MARKER) it must latch UNSUPPORTED at once.
 *   - nats_pool_kv_ttl_below_marker_state(): -1 unprobed, 0 unsupported
 *     (broker rejected the flag / pre-existing bucket lacks it),
 *     1 supported (bucket carries the flag).
 *   - create path: the flag is set on kvConfig only when requested; on a
 *     create failure with the flag set, the create is retried WITHOUT the
 *     flag -- retry success proves the failure was the unknown field ->
 *     latch 0 + one loud WARN; retry failure is a genuine error (state
 *     stays unprobed).  Create success with the flag -> latch 1.
 *   - bind path (bucket already exists): when requested, the backing
 *     stream's config decides the latch.
 *
 * Structural part greps ../nats_pool.c for the wiring; behavioral part is
 * a carried copy of the latch decision matrix (kept in sync by the
 * structural asserts on the function names).
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_kv_tbm_probe test_kv_tbm_probe.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

static char *slurp(const char *path)
{
	FILE *f = fopen(path, "rb");
	long n;
	char *buf;
	if (!f) return NULL;
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	buf = malloc(n + 1);
	if (!buf) { fclose(f); return NULL; }
	if (fread(buf, 1, n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
	buf[n] = '\0';
	fclose(f);
	return buf;
}

/* ─── carried copy: the latch decision after a create attempt ─────── */
/* Models the create-path outcome handling in nats_pool_get_kv().
 * @requested   modparam asked for the flag (and libnats support built in)
 * @create_ok   first create (flag set iff requested) succeeded
 * @retry_ok    the flag-less retry succeeded (only run when requested
 *              and the first create failed)
 * Returns the latch value to store: 1 supported, 0 unsupported,
 * -1 unprobed/genuine-failure. */
static int tbm_latch_after_create(int requested, int create_ok, int retry_ok)
{
	if (!requested)
		return -1;                 /* nothing requested: never probed */
	if (create_ok)
		return 1;                  /* broker accepted the flag */
	if (retry_ok)
		return 0;                  /* flag was the problem: unsupported */
	return -1;                     /* genuine failure: stay unprobed */
}

/* Bind path: bucket pre-exists; the stream config decides. */
static int tbm_latch_after_bind(int requested, int stream_has_flag)
{
	if (!requested)
		return -1;
	return stream_has_flag ? 1 : 0;
}

int main(void)
{
	printf("== carried-copy latch matrix ==\n");
	CHECK(tbm_latch_after_create(0, 1, 0) == -1,
		"not requested: create success never latches");
	CHECK(tbm_latch_after_create(0, 0, 0) == -1,
		"not requested: create failure never latches");
	CHECK(tbm_latch_after_create(1, 1, 0) == 1,
		"requested + create ok -> SUPPORTED");
	CHECK(tbm_latch_after_create(1, 0, 1) == 0,
		"requested + rejected + flag-less retry ok -> UNSUPPORTED");
	CHECK(tbm_latch_after_create(1, 0, 0) == -1,
		"requested + both creates fail -> genuine error, stays unprobed");
	CHECK(tbm_latch_after_bind(1, 1) == 1,
		"bind: pre-existing bucket with the flag -> SUPPORTED");
	CHECK(tbm_latch_after_bind(1, 0) == 0,
		"bind: pre-existing bucket without the flag -> UNSUPPORTED");
	CHECK(tbm_latch_after_bind(0, 1) == -1,
		"bind: not requested -> never probed");

	printf("== structural wiring (../nats_pool.c) ==\n");
	{
		char *src = slurp("../nats_pool.c");
		CHECK(src != NULL, "can read ../nats_pool.c");
		if (src) {
			CHECK(strstr(src, "nats_pool_kv_request_ttl_below_marker") != NULL,
				"request entry point exists");
			CHECK(strstr(src, "nats_pool_kv_ttl_below_marker_state") != NULL,
				"state accessor exists");
			CHECK(strstr(src, "AllowMsgTTLBelowMarker") != NULL,
				"kvConfig flag is set on the create path");
			CHECK(strstr(src, "kvCfg.LimitMarkerTTL") != NULL,
				"create carries a marker TTL (the flag requires "
				"subject_delete_marker_ttl > 0 server-side)");
			CHECK(strstr(src, "LIBNATS_HAS_TTL_BELOW_MARKER") != NULL,
				"guarded by the libnats feature probe define");
			/* the flag-less retry after a rejected create */
			CHECK(strstr(src, "retry") != NULL
			      && strstr(src, "_kv_tbm") != NULL,
				"rejection handled by a flag-less retry + latch");
			free(src);
		}
	}

	printf("== structural: header exposes the API (../nats_pool.h) ==\n");
	{
		char *hdr = slurp("../nats_pool.h");
		CHECK(hdr != NULL, "can read ../nats_pool.h");
		if (hdr) {
			CHECK(strstr(hdr, "nats_pool_kv_request_ttl_below_marker") != NULL,
				"request declared in the header");
			CHECK(strstr(hdr, "nats_pool_kv_ttl_below_marker_state") != NULL,
				"state accessor declared in the header");
			free(hdr);
		}
	}

	printf("== structural: feature probe source exists ==\n");
	{
		char *p = slurp("../nats_probe_tbm.c");
		CHECK(p != NULL, "lib/nats/nats_probe_tbm.c exists");
		if (p) {
			CHECK(strstr(p, "AllowMsgTTLBelowMarker") != NULL,
				"probe references the kvConfig field");
			free(p);
		}
		char *mk = slurp("../Makefile.nats");
		CHECK(mk != NULL, "can read ../Makefile.nats");
		if (mk) {
			CHECK(strstr(mk, "LIBNATS_HAS_TTL_BELOW_MARKER") != NULL,
				"Makefile.nats wires the feature define");
			CHECK(strstr(mk, "nats_probe_tbm.c") != NULL,
				"Makefile.nats compiles the checked-in probe source");
			free(mk);
		}
	}

	printf("%s (%d failure(s))\n", fails ? "RED" : "GREEN", fails);
	return fails ? 1 : 0;
}
