/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * P11c / SPEC.md §11 [REV-24]: the registration bucket is a PII / LI-relevant
 * store (subscriber IP, UA, call-id, path).  Transport + auth are MANDATORY:
 * cachedb_nats MUST emit a startup LM_WARN when cachedb_url is plaintext
 * nats:// and/or carries no credentials, naming the data classification.
 *
 * _nats_url_insecure(url) drives the WARN: 1 if the URL must be warned about
 * (not tls://, OR no "user[:pass]@" in the authority), else 0.  Credentials are
 * only recognized in the AUTHORITY (between "://" and the first "/"), so an "@"
 * in a path/query is not mistaken for credentials.
 *
 *   gcc -DSEC_CURRENT ... -> no classification (never warns) => RED.
 *   gcc ...             -> the FIXED classifier => GREEN.
 *
 * Rule 6: the AUTHORITATIVE proof is the Tier-2 e2e against a TLS+accounts broker
 * fixture (insecure URL => WARN fires; tenant A cred cannot read tenant B).
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_insecure_url_warn test_insecure_url_warn.c
 */
#include <stdio.h>
#include <string.h>

/* ─── carried copy of the production helper (cachedb_nats.c) ─────── */
static int _nats_url_insecure(const char *url)
{
#ifdef SEC_CURRENT
	(void)url; return 0;   /* today: no security classification */
#else
	const char *sep, *authority, *slash, *at;
	int is_tls, has_creds;

	if (!url) return 1;
	sep = strstr(url, "://");
	if (!sep) return 1;                       /* malformed => warn */
	is_tls = (sep - url == 3) && (strncmp(url, "tls", 3) == 0);
	authority = sep + 3;
	slash = strchr(authority, '/');           /* authority ends at first '/' */
	at = strchr(authority, '@');
	has_creds = (at != NULL) && (slash == NULL || at < slash);
	return (!is_tls || !has_creds) ? 1 : 0;
#endif
}

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
#ifdef SEC_CURRENT
	printf("== carried copy: SEC_CURRENT (no security warn) ==\n");
#else
	printf("== carried copy: FIXED url classifier ==\n");
#endif

	printf("[REV-24] insecure URLs MUST warn:\n");
	CHECK(_nats_url_insecure("nats://host:4222") == 1, "plaintext + no creds => WARN");
	CHECK(_nats_url_insecure("nats://user:pass@host:4222") == 1, "plaintext WITH creds => still WARN (no TLS)");
	CHECK(_nats_url_insecure("tls://host:4222") == 1, "TLS but NO creds => WARN");
	CHECK(_nats_url_insecure("10.0.0.31:4222") == 1, "no scheme => WARN (malformed)");
	CHECK(_nats_url_insecure(NULL) == 1, "NULL url => WARN");

	printf("[REV-24] only TLS + credentials is clean (no warn):\n");
	CHECK(_nats_url_insecure("tls://user:pass@host:4222") == 0, "tls + user:pass => no WARN");
	CHECK(_nats_url_insecure("tls://user@host:4222") == 0, "tls + user@ (creds present) => no WARN");
	CHECK(_nats_url_insecure("tls://u:p@host:4222/path") == 0, "tls + creds + path => no WARN");

	printf("[REV-24] adversarial: '@' in the path is NOT a credential:\n");
	CHECK(_nats_url_insecure("tls://host:4222/a@b") == 1, "'@' only in path => no creds => WARN");
	CHECK(_nats_url_insecure("nats://host/u:p@x") == 1, "plaintext, '@' in path => WARN");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
