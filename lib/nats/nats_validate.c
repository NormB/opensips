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
 */
int nats_validate_publish_subject(const char *s, int len)
{
	int i;
	int last_was_dot;

	if (!s || len <= 0)
		return -1;

	if (s[0] == '.' || s[len - 1] == '.')
		return -1;

	last_was_dot = 0;
	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)s[i];
		if (c == '\0')           return -1;
		if (c < 0x20 || c == 0x7f) return -1;
		if (c == ' ' || c == '\t') return -1;
		if (c == '*' || c == '>')  return -1;
		if (c == '.') {
			if (last_was_dot) return -1;
			last_was_dot = 1;
		} else {
			last_was_dot = 0;
		}
	}
	return 0;
}
