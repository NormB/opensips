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
 * nats_handle_parse.c -- table-driven parser for the bind-parameter
 * config string.  Builds a freshly-allocated nats_handle_t in SHM.
 *
 * Grammar: pairs := pair ( ';' pair )*
 *          pair  := key '=' value
 *
 * Leading whitespace is trimmed from both key and value.  Trailing
 * whitespace is preserved on values (an explicit quoting scheme can be
 * added later if needed).
 *
 * Unknown keys are stashed into handle->extra_json as JSON
 * ("k":"v",...) for forward-compat.  All other syntactic / semantic
 * errors are fatal.
 */

#ifdef TEST_SHIM
#include "tests/test_shim.h"
#else
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#endif

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>

#include "nats_handle_parse.h"

/* error strings (borrowed static) */
#define ERR_MISSING_ID      "missing id"
#define ERR_MISSING_STREAM  "missing stream"
#define ERR_MUT_EXCL        "durable and ephemeral are mutually exclusive"
#define ERR_NEED_DUR_EPH    "consumer requires either durable= or ephemeral=1"
#define ERR_BAD_DELIVER     "invalid deliver_policy"
#define ERR_BAD_ACK         "invalid ack_policy"
#define ERR_BAD_REPLAY      "invalid replay_policy"
#define ERR_NEED_SSEQ       "start_seq required with deliver_policy=by_start_seq"
#define ERR_NEED_STIME      "start_time required with deliver_policy=by_start_time"
#define ERR_BAD_DURATION    "invalid duration"
#define ERR_BAD_INT         "invalid integer"
#define ERR_BAD_UINT        "invalid unsigned integer"
#define ERR_BAD_BOOL        "invalid boolean"
#define ERR_BAD_TIME        "invalid RFC3339 timestamp"
#define ERR_DUP_KEY         "duplicate key"
#define ERR_BAD_PAIR        "malformed pair (missing =)"
#define ERR_OOM             "out of memory"
#define ERR_SAMPLE_RANGE    "sample_freq out of range 0..100"

/* ── helpers: trim / case-insensitive compare ─────────────────── */

static inline const char *ltrim(const char *p, const char *end)
{
	while (p < end && (*p == ' ' || *p == '\t'))
		p++;
	return p;
}

static int ieq(const char *a, int alen, const char *b)
{
	int blen = (int)strlen(b);
	int i;
	if (alen != blen) return 0;
	for (i = 0; i < alen; i++)
		if (a[i] != b[i])
			return 0;
	return 1;
}

static int str_dup_shm(str *dst, const char *src, int len)
{
	dst->s = (char *)shm_malloc(len > 0 ? len : 1);
	if (!dst->s) return -1;
	if (len > 0) memcpy(dst->s, src, len);
	dst->len = len;
	return 0;
}

/* ── scalar value parsers ─────────────────────────────────────── */

static int parse_bool(const char *s, int len, int *out)
{
	if (len == 1) {
		if (s[0] == '0') { *out = 0; return 0; }
		if (s[0] == '1') { *out = 1; return 0; }
	}
	if (ieq(s, len, "true") || ieq(s, len, "yes") || ieq(s, len, "on")) {
		*out = 1; return 0;
	}
	if (ieq(s, len, "false") || ieq(s, len, "no") || ieq(s, len, "off")) {
		*out = 0; return 0;
	}
	return -1;
}

static int parse_int(const char *s, int len, int *out)
{
	char buf[32];
	char *end;
	long v;
	if (len <= 0 || len >= (int)sizeof(buf)) return -1;
	memcpy(buf, s, len);
	buf[len] = '\0';
	errno = 0;
	v = strtol(buf, &end, 10);
	if (errno != 0 || *end != '\0') return -1;
	if (v < INT_MIN || v > INT_MAX) return -1;
	*out = (int)v;
	return 0;
}

static int parse_uint64(const char *s, int len, uint64_t *out)
{
	char buf[32];
	char *end;
	unsigned long long v;
	if (len <= 0 || len >= (int)sizeof(buf)) return -1;
	memcpy(buf, s, len);
	buf[len] = '\0';
	errno = 0;
	v = strtoull(buf, &end, 10);
	if (errno != 0 || *end != '\0') return -1;
	*out = (uint64_t)v;
	return 0;
}

/* Duration syntax: <int>(ms|s|m|h|d).
 * Returns milliseconds in *out. */
static int parse_duration_ms(const char *s, int len, int *out)
{
	int i = 0, digits = 0;
	long long v = 0;
	long long mult;

	while (i < len && isdigit((unsigned char)s[i])) {
		v = v * 10 + (s[i] - '0');
		if (v > (long long)INT_MAX) return -1;
		digits++;
		i++;
	}
	if (!digits) return -1;

	if (i == len) {
		/* no suffix -> treat as ms for consistency with spec */
		mult = 1;
	} else if (i + 2 == len && s[i] == 'm' && s[i+1] == 's') {
		mult = 1;
	} else if (i + 1 == len && s[i] == 's') {
		mult = 1000LL;
	} else if (i + 1 == len && s[i] == 'm') {
		mult = 60LL * 1000LL;
	} else if (i + 1 == len && s[i] == 'h') {
		mult = 60LL * 60LL * 1000LL;
	} else if (i + 1 == len && s[i] == 'd') {
		mult = 24LL * 60LL * 60LL * 1000LL;
	} else {
		return -1;
	}

	v *= mult;
	if (v > (long long)INT_MAX || v < 0) return -1;
	*out = (int)v;
	return 0;
}

/* Minimal RFC3339 -> unix_ns parser. Accepts "YYYY-MM-DDThh:mm:ssZ"
 * or "YYYY-MM-DDThh:mm:ss.fffZ" or ...+hh:mm. */
static int parse_rfc3339_ns(const char *s, int len, int64_t *out)
{
	char buf[64];
	struct tm tm;
	time_t tt;
	int frac_ns = 0;
	int tz_off_sec = 0;
	const char *p;
	int pos;

	if (len <= 0 || len >= (int)sizeof(buf)) return -1;
	memcpy(buf, s, len);
	buf[len] = '\0';

	memset(&tm, 0, sizeof(tm));
	/* require at least "YYYY-MM-DDThh:mm:ss" (19 chars) */
	if (len < 19) return -1;
	if (sscanf(buf, "%4d-%2d-%2dT%2d:%2d:%2d",
			&tm.tm_year, &tm.tm_mon, &tm.tm_mday,
			&tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6)
		return -1;
	tm.tm_year -= 1900;
	tm.tm_mon  -= 1;

	pos = 19;
	p = buf + pos;
	if (*p == '.') {
		/* fractional seconds */
		int f = 0, scale = 100000000; /* nanos per 0.1 */
		p++; pos++;
		while (pos < len && isdigit((unsigned char)*p) && scale > 0) {
			f += (*p - '0') * scale;
			scale /= 10;
			p++; pos++;
		}
		/* skip any remaining digits (truncate) */
		while (pos < len && isdigit((unsigned char)*p)) { p++; pos++; }
		frac_ns = f;
	}
	if (pos == len) return -1;       /* must have Z or offset */
	if (*p == 'Z' || *p == 'z') {
		if (pos + 1 != len) return -1;
		tz_off_sec = 0;
	} else if (*p == '+' || *p == '-') {
		int sign = (*p == '+') ? 1 : -1;
		int hh, mm;
		if (pos + 6 != len) return -1;
		if (sscanf(p+1, "%2d:%2d", &hh, &mm) != 2) return -1;
		tz_off_sec = sign * (hh * 3600 + mm * 60);
	} else {
		return -1;
	}

	/* timegm treats tm as UTC -> seconds since epoch */
	tt = timegm(&tm);
	if (tt == (time_t)-1) return -1;
	tt -= tz_off_sec;

	*out = ((int64_t)tt) * 1000000000LL + (int64_t)frac_ns;
	return 0;
}

/* ── enums ────────────────────────────────────────────────────── */

static int parse_deliver_policy(const char *s, int len,
		nats_deliver_policy_e *out)
{
	if (ieq(s, len, "all"))               { *out = NATS_DELIVER_ALL; return 0; }
	if (ieq(s, len, "last"))              { *out = NATS_DELIVER_LAST; return 0; }
	if (ieq(s, len, "new"))               { *out = NATS_DELIVER_NEW; return 0; }
	if (ieq(s, len, "last_per_subject"))  { *out = NATS_DELIVER_LAST_PER_SUBJECT; return 0; }
	if (ieq(s, len, "by_start_seq"))      { *out = NATS_DELIVER_BY_START_SEQ; return 0; }
	if (ieq(s, len, "by_start_time"))     { *out = NATS_DELIVER_BY_START_TIME; return 0; }
	return -1;
}

static int parse_ack_policy(const char *s, int len, nats_ack_policy_e *out)
{
	if (ieq(s, len, "explicit")) { *out = NATS_ACK_EXPLICIT; return 0; }
	if (ieq(s, len, "none"))     { *out = NATS_ACK_NONE; return 0; }
	if (ieq(s, len, "all"))      { *out = NATS_ACK_ALL; return 0; }
	return -1;
}

static int parse_replay_policy(const char *s, int len,
		nats_replay_policy_e *out)
{
	if (ieq(s, len, "instant"))  { *out = NATS_REPLAY_INSTANT; return 0; }
	if (ieq(s, len, "original")) { *out = NATS_REPLAY_ORIGINAL; return 0; }
	return -1;
}

/* ── field flag bits (for duplicate + cross-field detection) ──── */

enum {
	F_ID             = 1<<0,
	F_STREAM         = 1<<1,
	F_DURABLE        = 1<<2,
	F_EPHEMERAL      = 1<<3,
	F_FILTER         = 1<<4,
	F_FILTERS        = 1<<5,
	F_DELIVER        = 1<<6,
	F_START_SEQ      = 1<<7,
	F_START_TIME     = 1<<8,
	F_REPLAY         = 1<<9,
	F_ACK_POLICY     = 1<<10,
	F_ACK_WAIT       = 1<<11,
	F_MAX_DELIVER    = 1<<12,
	F_BACKOFF        = 1<<13,
	F_MAX_ACK_PEND   = 1<<14,
	F_HEADERS_ONLY   = 1<<15,
	F_SAMPLE_FREQ    = 1<<16,
	F_RATE_LIMIT     = 1<<17,
	F_INACTIVE_THR   = 1<<18,
	F_JS_DOMAIN      = 1<<19,
	F_API_PREFIX     = 1<<20,
};

/* ── extra_json builder ───────────────────────────────────────── */

/* Append "key":"value" to an extra_json str, allocating/growing as needed.
 * Leaves the buffer without closing '}'; caller appends the terminator. */
static int extra_json_append(str *buf, const char *k, int klen,
		const char *v, int vlen)
{
	/* rough upper bound: key_escaped + value_escaped + 5 ("":"", ) */
	int needed = klen * 2 + vlen * 2 + 16;
	int newlen;
	char *newbuf;

	if (buf->len == 0) {
		newbuf = (char *)shm_malloc(1 + needed + 1);
		if (!newbuf) return -1;
		newbuf[0] = '{';
		buf->s = newbuf;
		buf->len = 1;
	} else {
		newlen = buf->len + 1 + needed;
		newbuf = (char *)shm_realloc(buf->s, newlen + 1);
		if (!newbuf) return -1;
		buf->s = newbuf;
		buf->s[buf->len++] = ',';
	}

	{
		char *p = buf->s + buf->len;
		int i;
		*p++ = '"';
		for (i = 0; i < klen; i++) {
			if (k[i] == '"' || k[i] == '\\') *p++ = '\\';
			*p++ = k[i];
		}
		*p++ = '"';
		*p++ = ':';
		*p++ = '"';
		for (i = 0; i < vlen; i++) {
			if (v[i] == '"' || v[i] == '\\') *p++ = '\\';
			*p++ = v[i];
		}
		*p++ = '"';
		buf->len = p - buf->s;
	}
	return 0;
}

static int extra_json_finalize(str *buf)
{
	char *newbuf;
	if (buf->len == 0) return 0;
	newbuf = (char *)shm_realloc(buf->s, buf->len + 2);
	if (!newbuf) return -1;
	buf->s = newbuf;
	buf->s[buf->len++] = '}';
	return 0;
}

/* ── main parser ──────────────────────────────────────────────── */

#define FAIL(_err) do { *err = (_err); goto fail; } while (0)

nats_handle_t *nats_handle_parse(const str *config_str, const char **err)
{
	nats_handle_t *h;
	const char *p, *end, *pair_end, *eq;
	const char *key, *val;
	int keylen, vallen;
	uint32_t seen = 0;
	int have_durable = 0, have_ephemeral = 0, ephemeral_val = 0;
	static const char *dummy_err = NULL;

	if (!err) err = &dummy_err;
	*err = NULL;

	if (!config_str || !config_str->s || config_str->len <= 0) {
		*err = ERR_MISSING_ID;
		return NULL;
	}

	h = (nats_handle_t *)shm_malloc(sizeof(*h));
	if (!h) { *err = ERR_OOM; return NULL; }
	memset(h, 0, sizeof(*h));

	/* defaults */
	h->type           = NATS_CONSUMER_EPHEMERAL; /* overridden below */
	h->deliver_policy = NATS_DELIVER_ALL;
	h->replay_policy  = NATS_REPLAY_INSTANT;
	h->ack_policy     = NATS_ACK_EXPLICIT;

	p = config_str->s;
	end = p + config_str->len;

	while (p < end) {
		/* skip leading ws + semicolons */
		while (p < end && (*p == ' ' || *p == '\t' || *p == ';'))
			p++;
		if (p >= end) break;

		pair_end = memchr(p, ';', end - p);
		if (!pair_end) pair_end = end;

		key = ltrim(p, pair_end);
		eq = memchr(key, '=', pair_end - key);
		if (!eq) FAIL(ERR_BAD_PAIR);

		/* trim trailing ws from key */
		keylen = (int)(eq - key);
		while (keylen > 0 && (key[keylen-1] == ' ' || key[keylen-1] == '\t'))
			keylen--;
		if (keylen == 0) FAIL(ERR_BAD_PAIR);

		val = eq + 1;
		val = ltrim(val, pair_end);
		vallen = (int)(pair_end - val);
		/* trim trailing ws from value too */
		while (vallen > 0 && (val[vallen-1] == ' ' || val[vallen-1] == '\t'))
			vallen--;

		p = pair_end;

		/* dispatch */
		#define SETFLAG(b) do { \
			if (seen & (b)) FAIL(ERR_DUP_KEY); \
			seen |= (b); \
		} while (0)

		if (ieq(key, keylen, "id")) {
			SETFLAG(F_ID);
			if (vallen == 0) FAIL(ERR_MISSING_ID);
			if (str_dup_shm(&h->id, val, vallen) < 0) FAIL(ERR_OOM);
		} else if (ieq(key, keylen, "stream")) {
			SETFLAG(F_STREAM);
			if (vallen == 0) FAIL(ERR_MISSING_STREAM);
			if (str_dup_shm(&h->stream, val, vallen) < 0) FAIL(ERR_OOM);
		} else if (ieq(key, keylen, "durable")) {
			SETFLAG(F_DURABLE);
			if (vallen == 0) FAIL(ERR_NEED_DUR_EPH);
			if (str_dup_shm(&h->durable, val, vallen) < 0) FAIL(ERR_OOM);
			have_durable = 1;
		} else if (ieq(key, keylen, "ephemeral")) {
			SETFLAG(F_EPHEMERAL);
			if (parse_bool(val, vallen, &ephemeral_val) < 0)
				FAIL(ERR_BAD_BOOL);
			have_ephemeral = ephemeral_val;
		} else if (ieq(key, keylen, "filter")) {
			SETFLAG(F_FILTER);
			if (str_dup_shm(&h->filter, val, vallen) < 0) FAIL(ERR_OOM);
		} else if (ieq(key, keylen, "filters")) {
			SETFLAG(F_FILTERS);
			if (str_dup_shm(&h->filters_csv, val, vallen) < 0) FAIL(ERR_OOM);
		} else if (ieq(key, keylen, "deliver_policy")) {
			SETFLAG(F_DELIVER);
			if (parse_deliver_policy(val, vallen, &h->deliver_policy) < 0)
				FAIL(ERR_BAD_DELIVER);
		} else if (ieq(key, keylen, "start_seq")) {
			SETFLAG(F_START_SEQ);
			if (parse_uint64(val, vallen, &h->start_seq) < 0)
				FAIL(ERR_BAD_UINT);
		} else if (ieq(key, keylen, "start_time")) {
			SETFLAG(F_START_TIME);
			if (parse_rfc3339_ns(val, vallen, &h->start_time_unix_ns) < 0)
				FAIL(ERR_BAD_TIME);
		} else if (ieq(key, keylen, "replay_policy")) {
			SETFLAG(F_REPLAY);
			if (parse_replay_policy(val, vallen, &h->replay_policy) < 0)
				FAIL(ERR_BAD_REPLAY);
		} else if (ieq(key, keylen, "ack_policy")) {
			SETFLAG(F_ACK_POLICY);
			if (parse_ack_policy(val, vallen, &h->ack_policy) < 0)
				FAIL(ERR_BAD_ACK);
		} else if (ieq(key, keylen, "ack_wait")) {
			SETFLAG(F_ACK_WAIT);
			if (parse_duration_ms(val, vallen, &h->ack_wait_ms) < 0)
				FAIL(ERR_BAD_DURATION);
		} else if (ieq(key, keylen, "max_deliver")) {
			SETFLAG(F_MAX_DELIVER);
			if (parse_int(val, vallen, &h->max_deliver) < 0)
				FAIL(ERR_BAD_INT);
		} else if (ieq(key, keylen, "backoff")) {
			SETFLAG(F_BACKOFF);
			if (str_dup_shm(&h->backoff_csv, val, vallen) < 0) FAIL(ERR_OOM);
		} else if (ieq(key, keylen, "max_ack_pending")) {
			SETFLAG(F_MAX_ACK_PEND);
			if (parse_int(val, vallen, &h->max_ack_pending) < 0)
				FAIL(ERR_BAD_INT);
		} else if (ieq(key, keylen, "headers_only")) {
			SETFLAG(F_HEADERS_ONLY);
			if (parse_bool(val, vallen, &h->headers_only) < 0)
				FAIL(ERR_BAD_BOOL);
		} else if (ieq(key, keylen, "sample_freq")) {
			SETFLAG(F_SAMPLE_FREQ);
			if (parse_int(val, vallen, &h->sample_freq) < 0)
				FAIL(ERR_BAD_INT);
			if (h->sample_freq < 0 || h->sample_freq > 100)
				FAIL(ERR_SAMPLE_RANGE);
		} else if (ieq(key, keylen, "rate_limit")) {
			SETFLAG(F_RATE_LIMIT);
			if (parse_int(val, vallen, &h->rate_limit_bps) < 0)
				FAIL(ERR_BAD_INT);
		} else if (ieq(key, keylen, "inactive_threshold")) {
			SETFLAG(F_INACTIVE_THR);
			if (parse_duration_ms(val, vallen, &h->inactive_threshold_ms) < 0)
				FAIL(ERR_BAD_DURATION);
		} else if (ieq(key, keylen, "js_domain")) {
			SETFLAG(F_JS_DOMAIN);
			if (str_dup_shm(&h->js_domain, val, vallen) < 0) FAIL(ERR_OOM);
		} else if (ieq(key, keylen, "api_prefix")) {
			SETFLAG(F_API_PREFIX);
			if (str_dup_shm(&h->api_prefix, val, vallen) < 0) FAIL(ERR_OOM);
		} else {
			/* unknown: forward-compat via extra_json */
			if (extra_json_append(&h->extra_json, key, keylen,
					val, vallen) < 0) FAIL(ERR_OOM);
		}
		#undef SETFLAG
	}

	/* close extra_json if populated */
	if (extra_json_finalize(&h->extra_json) < 0) FAIL(ERR_OOM);

	/* cross-field validation */
	if (!(seen & F_ID)) FAIL(ERR_MISSING_ID);
	if (h->id.len == 0) FAIL(ERR_MISSING_ID);
	if (!(seen & F_STREAM)) FAIL(ERR_MISSING_STREAM);
	if (h->stream.len == 0) FAIL(ERR_MISSING_STREAM);

	if (have_durable && have_ephemeral) FAIL(ERR_MUT_EXCL);
	if (!have_durable && !have_ephemeral) FAIL(ERR_NEED_DUR_EPH);
	h->type = have_durable ? NATS_CONSUMER_DURABLE : NATS_CONSUMER_EPHEMERAL;

	if (h->deliver_policy == NATS_DELIVER_BY_START_SEQ &&
			!(seen & F_START_SEQ))
		FAIL(ERR_NEED_SSEQ);
	if (h->deliver_policy == NATS_DELIVER_BY_START_TIME &&
			!(seen & F_START_TIME))
		FAIL(ERR_NEED_STIME);

	return h;

fail:
	nats_handle_free(h);
	return NULL;
}
