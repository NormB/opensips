/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: cachedb_nats_native.c::w_nats_request copied the
 * caller's payload into a buffer with
 *     memcpy(pay_buf, payload->s, payload->len);
 * (and the heap branch likewise) WITHOUT checking payload->s != NULL or
 * payload->len >= 0.  A pvar that resolves to an unset/empty value can
 * yield payload->s == NULL, and a corrupted str descriptor can carry a
 * negative len.  Either feeds garbage into memcpy: NULL deref, or a
 * negative len that the `(size_t)payload->len < sizeof(pay_buf)` test
 * turns into a HUGE size_t -> heap overflow in the would-be heap branch.
 *
 * The fix:
 *   - reject payload->len < 0 with -1
 *   - treat NULL/empty payload as the empty string ""
 *   - only then choose stack vs heap copy
 *
 * This test carries the FIXED payload-prep logic verbatim and exercises
 * it under AddressSanitizer with NULL, empty, negative-length, small,
 * boundary, and large payloads, asserting:
 *   - NULL / empty -> "" (no crash)
 *   - negative len -> rejected (-1)
 *   - valid -> exact bytes copied, NUL-terminated, no overrun
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_request_payload_guard \
 *       test_request_payload_guard.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* minimal str (matches OpenSIPS ../../str.h shape) */
typedef struct { char *s; int len; } str;

#define LM_ERR(fmt, ...) fprintf(stderr, "ERR: " fmt, ##__VA_ARGS__)

#define PAY_BUF_SZ 64   /* mirrors NATS_NATIVE_VAL_BUF for the test */

/* Returns the payload pointer to hand to libnats (NUL-terminated), or
 * NULL with *rc=-1 on a rejected descriptor.  *heap is set when the
 * caller must free the result.  Mirrors the FIXED production block. */
static char *prep_payload(const str *payload, char *pay_buf, int *heap, int *rc)
{
	char *pay_ptr = pay_buf;
	*heap = 0;
	*rc = 0;

	if (payload->len < 0) {
		LM_ERR("nats_request: negative payload length (%d)\n",
			payload->len);
		*rc = -1;
		return NULL;
	}
	if (!payload->s || payload->len == 0) {
		pay_buf[0] = '\0';
	} else if ((size_t)payload->len < (size_t)PAY_BUF_SZ) {
		memcpy(pay_buf, payload->s, payload->len);
		pay_buf[payload->len] = '\0';
	} else {
		pay_ptr = malloc(payload->len + 1);
		if (!pay_ptr) { *rc = -1; return NULL; }
		memcpy(pay_ptr, payload->s, payload->len);
		pay_ptr[payload->len] = '\0';
		*heap = 1;
	}
	return pay_ptr;
}

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

int main(void)
{
	char pay_buf[PAY_BUF_SZ];
	int heap, rc;
	char *p;

	/* NULL s, len 0 -> "" */
	{
		str pl = { NULL, 0 };
		p = prep_payload(&pl, pay_buf, &heap, &rc);
		ASSERT(rc == 0 && p && p[0] == '\0' && !heap,
			"NULL payload pointer -> empty string, no crash");
	}

	/* NULL s but positive len (corrupt descriptor) -> treated as empty */
	{
		str pl = { NULL, 10 };
		p = prep_payload(&pl, pay_buf, &heap, &rc);
		ASSERT(rc == 0 && p && p[0] == '\0' && !heap,
			"NULL pointer with bogus positive len -> empty, no deref");
	}

	/* negative len -> rejected */
	{
		str pl = { "ignored", -5 };
		p = prep_payload(&pl, pay_buf, &heap, &rc);
		ASSERT(rc == -1 && p == NULL,
			"negative payload length -> rejected (-1)");
	}

	/* valid small payload */
	{
		str pl = { "hello", 5 };
		p = prep_payload(&pl, pay_buf, &heap, &rc);
		ASSERT(rc == 0 && p && strcmp(p, "hello") == 0 && !heap,
			"small payload copied to stack buffer, NUL-terminated");
	}

	/* boundary: exactly PAY_BUF_SZ-1 fits on the stack */
	{
		char src[PAY_BUF_SZ];
		memset(src, 'A', PAY_BUF_SZ - 1);
		str pl = { src, PAY_BUF_SZ - 1 };
		p = prep_payload(&pl, pay_buf, &heap, &rc);
		ASSERT(rc == 0 && p && (int)strlen(p) == PAY_BUF_SZ - 1 && !heap,
			"max stack-sized payload copied without overrun");
	}

	/* large payload -> heap */
	{
		int n = PAY_BUF_SZ + 100;
		char *src = malloc(n);
		memset(src, 'B', n);
		str pl = { src, n };
		p = prep_payload(&pl, pay_buf, &heap, &rc);
		ASSERT(rc == 0 && p && heap && (int)strlen(p) == n,
			"large payload copied to heap, exact length, NUL-terminated");
		if (heap) free(p);
		free(src);
	}

	/* empty but non-NULL s -> "" */
	{
		str pl = { "", 0 };
		p = prep_payload(&pl, pay_buf, &heap, &rc);
		ASSERT(rc == 0 && p && p[0] == '\0' && !heap,
			"zero-length non-NULL payload -> empty string");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
