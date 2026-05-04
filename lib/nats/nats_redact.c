/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * nats_redact.c — credential scrubbing for NATS URL strings.
 *
 * Self-contained: depends only on libc (no OpenSIPS or nats.c symbols)
 * so it can be unit-tested standalone and reused by lib/nats and any
 * module that wants to log a URL.
 */

#include <stddef.h>
#include <string.h>
#include "nats_pool.h"

/*
 * Scan a single NATS URL ("nats://..." or "tls://...") starting at @url
 * and write its redacted form to @dst (advancing @dst).  Returns the
 * input cursor advanced past the URL (pointing at ',' or '\0').
 *
 * Never writes more than @dst_remaining bytes; the caller updates the
 * remaining count.
 */
static const char *redact_one(const char *url, char **dst, size_t *rem)
{
	const char *scheme_end;
	const char *authority;
	const char *at;
	const char *next_slash;
	const char *url_end;

	url_end = strchr(url, ',');
	if (!url_end) url_end = url + strlen(url);

	scheme_end = strstr(url, "://");
	if (!scheme_end || scheme_end >= url_end) {
		/* No scheme found within this URL — copy verbatim */
		size_t n = (size_t)(url_end - url);
		if (n > *rem) n = *rem;
		memcpy(*dst, url, n);
		*dst += n;
		*rem -= n;
		return url_end;
	}

	authority = scheme_end + 3;
	next_slash = strchr(authority, '/');
	if (!next_slash || next_slash > url_end) next_slash = url_end;

	/* '@' must be in authority section, before any path '/'.
	 * For URLs without a path, that's "before url_end". */
	at = memchr(authority, '@', (size_t)(next_slash - authority));

	if (!at) {
		/* No userinfo — copy verbatim */
		size_t n = (size_t)(url_end - url);
		if (n > *rem) n = *rem;
		memcpy(*dst, url, n);
		*dst += n;
		*rem -= n;
		return url_end;
	}

	/* Copy: scheme://****@<host..url_end> */
	{
		size_t prefix_n = (size_t)(authority - url);   /* through "://" */
		size_t mask_n   = 4;                             /* "****" */
		size_t at_n     = 1;                             /* "@" */
		size_t host_n   = (size_t)(url_end - (at + 1));
		size_t total    = prefix_n + mask_n + at_n + host_n;
		size_t budget   = *rem;

		if (total > budget) {
			/* truncate — write what fits, drop the rest */
			size_t want = prefix_n;
			if (want > budget) want = budget;
			memcpy(*dst, url, want);
			*dst += want; *rem -= want;
			if (*rem >= mask_n) {
				memcpy(*dst, "****", mask_n);
				*dst += mask_n; *rem -= mask_n;
			} else {
				memcpy(*dst, "****", *rem);
				*dst += *rem; *rem = 0;
				return url_end;
			}
			if (*rem >= 1) {
				**dst = '@'; (*dst)++; (*rem)--;
			} else return url_end;
			if (host_n > *rem) host_n = *rem;
			memcpy(*dst, at + 1, host_n);
			*dst += host_n; *rem -= host_n;
			return url_end;
		}

		memcpy(*dst, url, prefix_n);
		*dst += prefix_n; *rem -= prefix_n;
		memcpy(*dst, "****", mask_n);
		*dst += mask_n; *rem -= mask_n;
		**dst = '@'; (*dst)++; (*rem)--;
		memcpy(*dst, at + 1, host_n);
		*dst += host_n; *rem -= host_n;
		return url_end;
	}
}

void nats_redact_url(const char *url, char *out, size_t out_sz)
{
	if (out_sz == 0) return;
	out[0] = '\0';
	if (!url) return;

	char  *dst = out;
	/* reserve one byte for terminating NUL */
	size_t rem = out_sz - 1;
	const char *cursor = url;

	while (*cursor && rem > 0) {
		cursor = redact_one(cursor, &dst, &rem);
		if (*cursor == ',' && rem > 0) {
			*dst++ = ',';
			rem--;
			cursor++;
		} else if (*cursor == ',') {
			break;
		}
	}
	*dst = '\0';
}
