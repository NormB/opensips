/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * test_parser.c -- unit tests for the bind-parameter parser.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_shim.h"
#include "../nats_handle_registry.h"
#include "../nats_handle_parse.h"

static int tests_run  = 0;
static int tests_fail = 0;

#define CHECK(cond) do { \
	tests_run++; \
	if (!(cond)) { \
		fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
		tests_fail++; \
	} \
} while (0)

static str mkstr(const char *s)
{
	str r;
	r.s = (char *)s;       /* borrowed literal -- parser only reads */
	r.len = (int)strlen(s);
	return r;
}

static int str_contains(const str *s, const char *needle)
{
	int nlen = (int)strlen(needle);
	int i;
	if (s->len < nlen) return 0;
	for (i = 0; i + nlen <= s->len; i++)
		if (memcmp(s->s + i, needle, nlen) == 0)
			return 1;
	return 0;
}

/* ── cases ────────────────────────────────────────────────────── */

static void test_minimal_durable(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	CHECK(err == NULL);
	if (h) {
		CHECK(h->type == NATS_CONSUMER_DURABLE);
		CHECK(h->id.len == 1 && h->id.s[0] == 'x');
		CHECK(h->stream.len == 1 && h->stream.s[0] == 'S');
		CHECK(h->durable.len == 1 && h->durable.s[0] == 'd');
		CHECK(h->deliver_policy == NATS_DELIVER_ALL);
		CHECK(h->ack_policy == NATS_ACK_EXPLICIT);
		nats_handle_free(h);
	}
}

static void test_ephemeral(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;ephemeral=1");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->type == NATS_CONSUMER_EPHEMERAL);
		CHECK(h->durable.len == 0);
		nats_handle_free(h);
	}
}

static void test_full_matrix(void)
{
	const char *err = NULL;
	str cfg = mkstr(
		"id=billing;stream=CALLS;durable=biller;"
		"filter=call.ended;ack_wait=30s;max_deliver=5;"
		"max_ack_pending=256;backoff=1s,5s,30s;deliver_policy=new");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->ack_wait_ms == 30000);
		CHECK(h->max_deliver == 5);
		CHECK(h->max_ack_pending == 256);
		CHECK(h->deliver_policy == NATS_DELIVER_NEW);
		CHECK(h->backoff_csv.len == (int)strlen("1s,5s,30s"));
		CHECK(memcmp(h->backoff_csv.s, "1s,5s,30s", 9) == 0);
		CHECK(h->filter.len == (int)strlen("call.ended"));
		nats_handle_free(h);
	}
}

static void test_multi_filter(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;filters=a.*,b.*");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->filters_csv.len > 0);
		CHECK(str_contains(&h->filters_csv, "a.*,b.*"));
		nats_handle_free(h);
	}
}

static void test_unknown_key(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;foo=bar");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->extra_json.len > 0);
		CHECK(str_contains(&h->extra_json, "\"foo\":\"bar\""));
		CHECK(h->extra_json.s[0] == '{');
		CHECK(h->extra_json.s[h->extra_json.len - 1] == '}');
		nats_handle_free(h);
	}
}

static void test_two_unknowns(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;foo=bar;baz=qux");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(str_contains(&h->extra_json, "\"foo\":\"bar\""));
		CHECK(str_contains(&h->extra_json, "\"baz\":\"qux\""));
		CHECK(str_contains(&h->extra_json, ","));
		nats_handle_free(h);
	}
}

static void test_missing_id(void)
{
	const char *err = NULL;
	str cfg = mkstr("stream=S;durable=d");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "missing id") != NULL);
}

static void test_missing_stream(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;durable=d");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "missing stream") != NULL);
}

static void test_durable_and_ephemeral(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;ephemeral=1");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "mutually exclusive") != NULL);
}

static void test_neither_durable_nor_ephemeral(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;filter=a.*");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err != NULL);
}

static void test_bad_duration(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;ack_wait=notaduration");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "invalid duration") != NULL);
}

static void test_bad_deliver_policy(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;deliver_policy=bogus");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "invalid deliver_policy") != NULL);
}

static void test_duplicate_key(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;id=y;stream=S;durable=d");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "duplicate key") != NULL);
}

static void test_duration_variants(void)
{
	struct { const char *cfg; int expected_ms; } cases[] = {
		{ "id=x;stream=S;durable=d;ack_wait=500ms", 500 },
		{ "id=x;stream=S;durable=d;ack_wait=5s",    5000 },
		{ "id=x;stream=S;durable=d;ack_wait=2m",    120000 },
		{ "id=x;stream=S;durable=d;ack_wait=1h",    3600000 },
	};
	size_t i;
	for (i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
		const char *err = NULL;
		str cfg = mkstr(cases[i].cfg);
		nats_handle_t *h = nats_handle_parse(&cfg, &err);
		CHECK(h != NULL);
		if (h) {
			CHECK(h->ack_wait_ms == cases[i].expected_ms);
			nats_handle_free(h);
		}
	}
}

static void test_by_start_seq_requires_seq(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;deliver_policy=by_start_seq");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "start_seq required") != NULL);
}

static void test_by_start_seq_ok(void)
{
	const char *err = NULL;
	str cfg = mkstr(
		"id=x;stream=S;durable=d;deliver_policy=by_start_seq;start_seq=4242");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->deliver_policy == NATS_DELIVER_BY_START_SEQ);
		CHECK(h->start_seq == 4242);
		nats_handle_free(h);
	}
}

int main(void)
{
	test_minimal_durable();
	test_ephemeral();
	test_full_matrix();
	test_multi_filter();
	test_unknown_key();
	test_two_unknowns();
	test_missing_id();
	test_missing_stream();
	test_durable_and_ephemeral();
	test_neither_durable_nor_ephemeral();
	test_bad_duration();
	test_bad_deliver_policy();
	test_duplicate_key();
	test_duration_variants();
	test_by_start_seq_requires_seq();
	test_by_start_seq_ok();

	fprintf(stderr, "tests: %d run, %d failed\n", tests_run, tests_fail);
	return tests_fail == 0 ? 0 : 1;
}
