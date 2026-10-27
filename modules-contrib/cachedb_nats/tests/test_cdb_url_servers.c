/*
 * Copyright (C) 2025 Summit-2026 / cachedb_nats contributors
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

/*
 * test_cdb_url_servers.c -- the NATS server list cachedb_nats derives from
 * cachedb_url when no nats_url is set.
 *
 * Every host needs its own scheme ("nats://h1,nats://h2", not
 * "nats://h1,h2"), credentials apply to every host, and TLS is asked for
 * the way cachedb_redis does it: "?tls_domain=<dom>" (the NATS pool's TLS
 * comes from the tls_mgm "nats" client domain, so that is the only name
 * accepted).  The URL is not NUL-terminated (core cachedb_store_url()), so
 * nothing past url_len may be read -- the buffers below are exact-size
 * heap copies, ASan checks the rest.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../cachedb_nats_url.h"
#include "../cachedb_nats_url.c"

static int fails;

static void expect(const char *url, const char *want, int want_rc)
{
	int n = (int)strlen(url), rc;
	char *u = malloc(n ? n : 1);   /* exact size, no NUL */
	char out[512];

	memcpy(u, url, n);
	rc = cdbn_url_to_servers(u, n, out, sizeof out);
	if (want) {
		if (rc != (int)strlen(want) || strcmp(out, want)) {
			printf("  FAIL: %s\n        want %s, got rc=%d '%s'\n",
				url, want, rc, rc >= 0 ? out : "");
			fails++;
		} else
			printf("  ok:   %s -> %s\n", url, out);
	} else if (rc != want_rc) {
		printf("  FAIL: %s: want rc %d, got %d\n", url, want_rc, rc);
		fails++;
	} else
		printf("  ok:   %s -> rc %d\n", url, rc);
	free(u);
}

int main(void)
{
	char small[16];

	printf("hosts:\n");
	expect("nats:loc://127.0.0.1:4222/", "nats://127.0.0.1:4222", 0);
	expect("nats:loc://127.0.0.1:4222", "nats://127.0.0.1:4222", 0);
	expect("nats:loc://h1:4222,h2:4223/", "nats://h1:4222,nats://h2:4223", 0);
	expect("nats:loc://h1:4222,h2:4223,h3:4224/kvdb",
		"nats://h1:4222,nats://h2:4223,nats://h3:4224", 0);
	expect("nats:loc://[::1]:4222,[fe80::1]:4223/",
		"nats://[::1]:4222,nats://[fe80::1]:4223", 0);
	expect("nats://h:4222/", "nats://h:4222", 0);   /* no group */

	printf("credentials go on every host:\n");
	expect("nats:loc://user:pw@h1:4222,h2:4222/",
		"nats://user:pw@h1:4222,nats://user:pw@h2:4222", 0);
	expect("nats:loc://u:p@ss,w0rd@h1:4222/",
		"nats://u:p@ss,w0rd@h1:4222", 0);   /* '@' and ',' in the password */
	expect("nats:loc://tok@h1:4222/", "nats://tok@h1:4222", 0);

	printf("TLS the cachedb_redis way:\n");
	expect("nats:loc://h1:4222,h2:4223/?tls_domain=nats",
		"tls://h1:4222,tls://h2:4223", 0);
	expect("nats:loc://user:pw@h1:4222/kv?tls_domain=nats",
		"tls://user:pw@h1:4222", 0);
	expect("nats:loc://h1:4222/?foo=bar&tls_domain=nats", "tls://h1:4222", 0);
	expect("nats:loc://h1:4222/?tls_domain=nats&foo=bar", "tls://h1:4222", 0);
	expect("nats:loc://h1:4222/?tls_domain=redis", NULL, CDBN_URL_TLS_DOMAIN);
	expect("nats:loc://h1:4222/?tls_domain=", NULL, CDBN_URL_TLS_DOMAIN);
	expect("nats:loc://h1:4222/?tls_domain=natsx", NULL, CDBN_URL_TLS_DOMAIN);
	expect("nats:loc://h1:4222/?foo=bar", "nats://h1:4222", 0);

	printf("unusable URLs:\n");
	expect("", NULL, CDBN_URL_BAD);
	expect("nats:loc:/h:4222/", NULL, CDBN_URL_BAD);
	expect("nats:loc://", NULL, CDBN_URL_BAD);
	expect("nats:loc:///", NULL, CDBN_URL_BAD);
	expect("nats:loc://h1:4222,,h2:4223/", NULL, CDBN_URL_BAD);
	expect("nats:loc://h1:4222,/", NULL, CDBN_URL_BAD);
	expect("nats:loc://user:pw@/", NULL, CDBN_URL_BAD);
	expect("nats:loc://tls://h:4222/", NULL, CDBN_URL_BAD);  /* not a host */

	printf("bounds:\n");
	{
		/* the URL ends at url_len even if the buffer goes on */
		const char *buf = "nats:loc://h1:4222/?tls_domain=nats";
		char out[64];
		int rc = cdbn_url_to_servers(buf, 18, out, sizeof out);
		if (rc < 0 || strcmp(out, "nats://h1:4222")) {
			printf("  FAIL: url_len honoured (got rc=%d)\n", rc); fails++;
		} else
			printf("  ok:   url_len honoured: options past it ignored\n");
	}
	if (cdbn_url_to_servers("nats:loc://hostname:4222/", 25, small,
			sizeof small) != CDBN_URL_BAD) {
		printf("  FAIL: an output that does not fit is refused\n"); fails++;
	} else
		printf("  ok:   an output that does not fit is refused\n");
	{
		char out[64];
		int rc = cdbn_url_to_servers("nats:loc://h\0x:4222/", 20, out, sizeof out);
		if (rc != CDBN_URL_BAD) {
			printf("  FAIL: embedded NUL refused (rc=%d)\n", rc); fails++;
		} else
			printf("  ok:   embedded NUL refused\n");
	}

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails,
		fails == 1 ? "" : "s");
	return fails ? 1 : 0;
}
