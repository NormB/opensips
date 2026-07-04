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
#include "nats_redact.h"

/* Mask written in place of any "scheme://userinfo@" credentials. */
#define NATS_REDACT_MASK "[redacted]"

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
	const char *url_end;
	const char *scan;

	url_end = strchr(url, ',');
	if (!url_end) url_end = url + strlen(url);

	/* The authority begins after "scheme://" when present, otherwise at
	 * the start of the token: a NATS URL string is always a URL, so a
	 * scheme-less "user:pass@host" still carries credentials to scrub. */
	scheme_end = strstr(url, "://");
	if (scheme_end && scheme_end < url_end)
		authority = scheme_end + 3;
	else
		authority = url;

	/* Locate the userinfo '@' separator. Two subtleties:
	 *  1. The userinfo (a base64 NATS token or user:pass) may itself
	 *     contain '/' and '=', e.g. nats://AbC/dEf=@host. So the '@'
	 *     search must NOT stop at the FIRST '/': that '/' can be INSIDE
	 *     the credential, before the real '@' — stopping there misses the
	 *     '@' entirely and the token is logged verbatim (credential leak).
	 *  2. A path after the host may itself contain '@' (e.g. .../t@home).
	 *     The host/port never contain '/' or '@', so the real path begins
	 *     at the first '/' that occurs AFTER the first '@'.
	 * So: path_start = first '/' after the first '@' (else end); the
	 * userinfo '@' is the LAST '@' within [authority, path_start)
	 * (passwords may contain '@'). */
	at = NULL;
	{
		const char *first_at = memchr(authority, '@',
			(size_t)(url_end - authority));
		const char *path_start = url_end;
		if (first_at) {
			const char *slash = memchr(first_at, '/',
				(size_t)(url_end - first_at));
			if (slash) path_start = slash;
		}
		for (scan = authority; scan < path_start; scan++)
			if (*scan == '@') at = scan;
	}

	if (!at) {
		/* No userinfo — copy verbatim */
		size_t n = (size_t)(url_end - url);
		if (n > *rem) n = *rem;
		memcpy(*dst, url, n);
		*dst += n;
		*rem -= n;
		return url_end;
	}

	/* Copy the prefix (scheme + authority slashes), the redaction
	 * mask (NATS_REDACT_MASK, "[redacted]"), '@', and the rest of the
	 * host portion through url_end. */
	{
		size_t prefix_n = (size_t)(authority - url);   /* through scheme + "//" */
		size_t mask_n   = sizeof(NATS_REDACT_MASK) - 1;  /* redaction mask */
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
				memcpy(*dst, NATS_REDACT_MASK, mask_n);
				*dst += mask_n; *rem -= mask_n;
			} else {
				memcpy(*dst, NATS_REDACT_MASK, *rem);
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
		memcpy(*dst, NATS_REDACT_MASK, mask_n);
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
