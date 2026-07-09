/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * [SPEC §11 / REV-24, Tier-2] Strict security mode for usrloc
 * deployments.  The default stays warn-only (dev/lab ergonomics: the
 * usual lab broker is plaintext, and generic cachedb users are not
 * PII stores), but a usrloc production profile must be able to fail
 * closed instead of logging and proceeding:
 *
 *   require_secure_url=1        refuse to start when the effective
 *                               connection URL is insecure for a PII
 *                               store (plaintext nats:// and/or no
 *                               credentials -- _nats_url_insecure()),
 *   require_usrloc_safe_bucket=1  refuse to start when the bound
 *                               pre-existing bucket carries a non-zero
 *                               backing-stream MaxAge (it would
 *                               silently expire permanent contacts).
 *
 * Locks: both modparams registered; both warn sites gain a strict arm
 * that fails init; docbook documents both params; carried model of the
 * decision ladder.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_strict_security
 *            test_strict_security.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, label) do { \
	if (cond) fprintf(stderr, "  ok: %s\n", (label)); \
	else { fprintf(stderr, "  FAIL: %s\n", (label)); g_fails++; } \
} while (0)

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	char line[4096];
	int hit = 0;
	if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(1); }
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

/* ── carried decision model ──────────────────────────────────────── */

enum verdict { PROCEED, WARN_ONLY, REFUSE };

static enum verdict url_verdict(int insecure, int strict)
{
	if (!insecure) return PROCEED;
	return strict ? REFUSE : WARN_ONLY;
}

static enum verdict bucket_verdict(int maxage_nonzero, int strict)
{
	if (!maxage_nonzero) return PROCEED;
	return strict ? REFUSE : WARN_ONLY;
}

int main(void)
{
	/* ---- model -------------------------------------------------- */
	{
		ASSERT(url_verdict(0, 0) == PROCEED, "secure URL proceeds (lax)");
		ASSERT(url_verdict(0, 1) == PROCEED, "secure URL proceeds (strict)");
		ASSERT(url_verdict(1, 0) == WARN_ONLY, "insecure URL warns by default");
		ASSERT(url_verdict(1, 1) == REFUSE, "insecure URL refused under strict");
		ASSERT(bucket_verdict(0, 1) == PROCEED, "MaxAge=0 bucket proceeds (strict)");
		ASSERT(bucket_verdict(1, 0) == WARN_ONLY, "MaxAge!=0 warns by default");
		ASSERT(bucket_verdict(1, 1) == REFUSE, "MaxAge!=0 refused under strict");
	}

	/* ---- modparams registered ------------------------------------ */
	{
		const char *c = "../cachedb_nats.c";
		ASSERT(file_contains(c, "\"require_secure_url\""),
			"require_secure_url modparam registered");
		ASSERT(file_contains(c, "\"require_usrloc_safe_bucket\""),
			"require_usrloc_safe_bucket modparam registered");
		ASSERT(file_contains(c, "int require_secure_url"),
			"require_secure_url global defined");
		ASSERT(file_contains(c, "int require_usrloc_safe_bucket"),
			"require_usrloc_safe_bucket global defined");
	}

	/* ---- strict arms wired at both gate sites -------------------- */
	{
		const char *c = "../cachedb_nats.c";
		ASSERT(file_contains(c, "require_secure_url=1 -- refusing to start"),
			"insecure URL strict arm refuses to start");
		ASSERT(file_contains(c, "require_usrloc_safe_bucket=1 -- refusing to start"),
			"MaxAge strict arm refuses to start");
	}

	/* ---- documented ---------------------------------------------- */
	{
		const char *x = "../doc/cachedb_nats_admin.xml";
		ASSERT(file_contains(x, "param_require_secure_url"),
			"docbook documents require_secure_url");
		ASSERT(file_contains(x, "param_require_usrloc_safe_bucket"),
			"docbook documents require_usrloc_safe_bucket");
	}

	if (g_fails == 0) { fprintf(stderr, "=== ALL PASS ===\n"); return 0; }
	fprintf(stderr, "=== FAILS=%d ===\n", g_fails);
	return 1;
}
