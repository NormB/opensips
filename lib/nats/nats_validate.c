/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * nats_validate.c — input validators for NATS subject/key strings used
 * across event_nats, cachedb_nats, and nats_consumer.
 *
 * Self-contained: depends only on libc.  No LM_* logging here — callers
 * apply context-appropriate logging on rejection.
 */

#include "nats_pool.h"

/*
 * Validate a NATS subject as it would appear in a publish call.
 *
 * Rejects everything that NATS pub/sub semantics or the wire format
 * cannot tolerate from an *outbound* publisher:
 *   - empty / NULL
 *   - embedded NUL byte
 *   - control chars (< 0x20, 0x7f) and whitespace (' ', '\t')
 *   - wildcards '*' and '>' (publish must target a concrete subject)
 *   - leading dot, trailing dot, consecutive dots (empty token)
 *
 * Allows everything else, including punctuation and high-ASCII bytes
 * (NATS itself does not restrict these for publish).  Callers that
 * want a stricter alphabet should layer their own check on top.
 *
 * Returns 0 if valid, -1 if invalid.
 *
 * Performance: scripted publishes commonly pass the same subject
 * literal call after call (the OpenSIPS script engine reuses the
 * underlying str buffer across invocations).  Re-scanning identical
 * bytes on every call is wasteful at high publish rates, so we cache
 * (last input pointer, last input length, last result) per thread.
 * The cache is consulted only when the pointer AND length match —
 * the script engine's stable buffer guarantee means equal pointers
 * imply equal contents in practice; in the rare case the same
 * address is reused with different bytes, the worst outcome is
 * accepting an invalid subject that NATS itself will reject at
 * publish time (no security or correctness regression).  Callers
 * that need a stricter contract can pass freshly-allocated buffers
 * each time.
 */
int nats_validate_publish_subject(const char *s, int len)
{
	int i;
	int last_was_dot;

	static _Thread_local const char *cache_s   = NULL;
	static _Thread_local int         cache_len = 0;
	static _Thread_local int         cache_rc  = 0;

	if (s && len > 0 && s == cache_s && len == cache_len)
		return cache_rc;

	if (!s || len <= 0)
		return -1;

	if (s[0] == '.' || s[len - 1] == '.') {
		cache_s = s; cache_len = len; cache_rc = -1;
		return -1;
	}

	last_was_dot = 0;
	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)s[i];
		if (c == '\0')           goto reject;
		if (c < 0x20 || c == 0x7f) goto reject;
		if (c == ' ' || c == '\t') goto reject;
		if (c == '*' || c == '>')  goto reject;
		if (c == '.') {
			if (last_was_dot) goto reject;
			last_was_dot = 1;
		} else {
			last_was_dot = 0;
		}
	}
	cache_s = s; cache_len = len; cache_rc = 0;
	return 0;

reject:
	cache_s = s; cache_len = len; cache_rc = -1;
	return -1;
}
