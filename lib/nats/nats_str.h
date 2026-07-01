/*
 * Copyright (C) 2026 OpenSIPS Solutions
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
 * nats_str.h -- small OpenSIPS-str helpers shared by the NATS modules.
 *
 * Header-only inline helpers (no new symbol in libnats_pool.so).  These
 * previously lived as per-module copies (cachedb_nats's str_to_buf /
 * native_str_to_buf, nats_consumer's str_to_cstr); consolidated here so the
 * negative-length guard and the bounds check live in one place (P3-63).
 *
 * Only the NATS modules include this (they all pull in dprint.h / str.h);
 * lib/nats's own translation units and standalone unit tests do not.
 */

#ifndef NATS_STR_H
#define NATS_STR_H

#include <string.h>
#include <stdlib.h>

#include "../../str.h"
#include "../../dprint.h"

/*
 * Copy an OpenSIPS str into a caller-provided fixed buffer, NUL-terminating.
 *
 * Guards a negative s->len: it is an int, and the (size_t) cast in the bounds
 * check below would turn a negative value into a huge positive one, silently
 * passing the check and causing a massive memcpy.  A NULL/empty str yields an
 * empty C string.  Returns 0 on success, -1 if the string does not fit or the
 * descriptor is corrupt.
 */
static inline int nats_str_to_buf(const str *s, char *buf, size_t buf_size)
{
	if (s && s->len < 0) {
		LM_ERR("negative string length (%d)\n", s->len);
		return -1;
	}
	if (!s || !s->s || s->len <= 0) {
		buf[0] = '\0';
		return 0;
	}
	if ((size_t)s->len >= buf_size) {
		LM_ERR("string too long (%d >= %zu)\n", s->len, buf_size);
		return -1;
	}
	/* Reject an embedded NUL: the caller hands the resulting C string to the
	 * NATS *String KV API (kvStore_PutString / CreateString / UpdateString),
	 * which stops at the first NUL and would SILENTLY TRUNCATE a NUL-bearing
	 * value on write while the length-aware read path preserves it -- a lossy
	 * set/get round-trip.  Fail closed instead (keys never legitimately carry
	 * a NUL; the usrloc row payload uses length-aware natsMsg_Create, not this
	 * helper). */
	if (memchr(s->s, '\0', s->len)) {
		LM_ERR("string contains an embedded NUL (%d bytes) -- refusing "
			"(the NATS C-string KV API would silently truncate it)\n",
			s->len);
		return -1;
	}
	memcpy(buf, s->s, s->len);
	buf[s->len] = '\0';
	return 0;
}

/*
 * Allocate (libc malloc) a NUL-terminated copy of an OpenSIPS str.  Returns
 * NULL on a NULL/empty input or OOM.  The caller frees the result with free().
 * libc malloc (not pkg/shm) so the copy is valid in non-OpenSIPS thread
 * contexts such as the nats_consumer process's borrowed-to-nats.c strings.
 */
static inline char *nats_str_to_cstr(const str *s)
{
	char *out;
	if (!s || s->len <= 0 || !s->s)
		return NULL;
	out = (char *)malloc((size_t)s->len + 1);
	if (!out)
		return NULL;
	memcpy(out, s->s, s->len);
	out[s->len] = '\0';
	return out;
}

#endif /* NATS_STR_H */
