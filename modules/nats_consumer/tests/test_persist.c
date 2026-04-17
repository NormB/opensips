/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * test_persist.c -- round-trip test for nats_consumer persistence.
 *
 * Binds a mix of durable and ephemeral handles, forces a synchronous
 * write via nats_persist_flush_now(), tears everything down, then
 * re-initializes + rehydrates from the same file and checks that the
 * registry holds the same configs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "test_shim.h"
#include "../nats_handle_registry.h"
#include "../nats_handle_parse.h"
#include "../nats_persist.h"

static int tests_run  = 0;
static int tests_fail = 0;

#define CHECK(cond) do { \
	tests_run++; \
	if (!(cond)) { \
		fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
		tests_fail++; \
	} \
} while (0)

static str mkstr_literal(const char *s)
{
	str r;
	r.s = (char *)s;
	r.len = (int)strlen(s);
	return r;
}

/* Helper: parse + bind one handle from a k=v config string.  On
 * success returns 0; on failure logs and returns -1. */
static int bind_from(const char *cfg_s)
{
	str cfg = mkstr_literal(cfg_s);
	const char *err = NULL;
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	if (!h) {
		fprintf(stderr, "parse failed for %s: %s\n", cfg_s,
				err ? err : "(null)");
		return -1;
	}
	int rc = nats_registry_bind(h);
	if (rc != 0) {
		fprintf(stderr, "bind failed for %s: rc=%d\n", cfg_s, rc);
		nats_handle_free(h);
		return -1;
	}
	return 0;
}

static char *make_temp_path(void)
{
	char tmpl[] = "/tmp/nats_persist_test.XXXXXX";
	int fd = mkstemp(tmpl);
	if (fd < 0) {
		perror("mkstemp");
		return NULL;
	}
	/* We only wanted the name; unlink the placeholder, nats_persist
	 * will create the file (or not) on flush.  Keep the file name. */
	close(fd);
	unlink(tmpl);
	return strdup(tmpl);
}

static void test_round_trip(void)
{
	char *path = make_temp_path();
	CHECK(path != NULL);
	if (!path) return;

	/* --- phase 1: bind, write, destroy --- */

	CHECK(nats_registry_init(16) == 0);
	CHECK(nats_persist_init(path) == 0);
	CHECK(nats_persist_enabled() == 1);

	CHECK(bind_from("id=orders;stream=ORDERS;durable=dispatcher;"
			"filter=orders.new.*;ack_wait=30s;max_deliver=5;"
			"max_ack_pending=256") == 0);
	CHECK(bind_from("id=billing;stream=CALLS;ephemeral=1;"
			"filter=call.ended;inactive_threshold=5m") == 0);
	CHECK(bind_from("id=audit;stream=AUDIT;durable=auditor;"
			"filters=a.x,a.y,a.z;ack_policy=all;"
			"deliver_policy=new;headers_only=1") == 0);

	CHECK(nats_registry_count() == 3);

	CHECK(nats_persist_flush_now() == 0);

	/* Verify the file actually exists and is non-empty. */
	struct stat st;
	CHECK(stat(path, &st) == 0);
	CHECK(st.st_size > 2);  /* at least "[]" plus content */

	nats_persist_destroy();
	nats_registry_destroy();

	/* --- phase 2: re-init + rehydrate --- */

	CHECK(nats_registry_init(16) == 0);
	CHECK(nats_persist_init(path) == 0);

	int loaded = nats_persist_rehydrate();
	CHECK(loaded == 3);
	CHECK(nats_registry_count() == 3);

	/* Validate each handle round-tripped its distinguishing fields. */
	{
		str id = mkstr_literal("orders");
		nats_handle_t *h = nats_registry_lookup(&id);
		CHECK(h != NULL);
		if (h) {
			CHECK(h->type == NATS_CONSUMER_DURABLE);
			CHECK(h->stream.len == 6 &&
					memcmp(h->stream.s, "ORDERS", 6) == 0);
			CHECK(h->durable.len == 10 &&
					memcmp(h->durable.s, "dispatcher", 10) == 0);
			CHECK(h->filter.len == 12 &&
					memcmp(h->filter.s, "orders.new.*", 12) == 0);
			CHECK(h->ack_wait_ms == 30000);
			CHECK(h->max_deliver == 5);
			CHECK(h->max_ack_pending == 256);
		}
	}

	{
		str id = mkstr_literal("billing");
		nats_handle_t *h = nats_registry_lookup(&id);
		CHECK(h != NULL);
		if (h) {
			CHECK(h->type == NATS_CONSUMER_EPHEMERAL);
			CHECK(h->durable.len == 0);
			CHECK(h->inactive_threshold_ms == 5 * 60 * 1000);
		}
	}

	{
		str id = mkstr_literal("audit");
		nats_handle_t *h = nats_registry_lookup(&id);
		CHECK(h != NULL);
		if (h) {
			CHECK(h->type == NATS_CONSUMER_DURABLE);
			CHECK(h->ack_policy == NATS_ACK_ALL);
			CHECK(h->deliver_policy == NATS_DELIVER_NEW);
			CHECK(h->headers_only == 1);
			/* filters CSV should contain all three */
			CHECK(h->filters_csv.len >= 9);
		}
	}

	nats_persist_destroy();
	nats_registry_destroy();

	unlink(path);
	free(path);
}

/* A rehydrate from a nonexistent file is a soft success returning 0. */
static void test_rehydrate_missing(void)
{
	char path[] = "/tmp/nats_persist_nope.XXXXXX";
	int fd = mkstemp(path);
	CHECK(fd >= 0);
	close(fd);
	unlink(path); /* ensure the file does not exist */

	CHECK(nats_registry_init(16) == 0);
	CHECK(nats_persist_init(path) == 0);

	int loaded = nats_persist_rehydrate();
	CHECK(loaded == 0);
	CHECK(nats_registry_count() == 0);

	nats_persist_destroy();
	nats_registry_destroy();
}

/* Persistence init with a nonexistent parent directory is a warn + -1
 * (caller treats as disabled).  Verify we do NOT start the writer. */
static void test_init_missing_dir(void)
{
	int rc = nats_persist_init("/no/such/directory/handles.json");
	CHECK(rc == -1);
	CHECK(nats_persist_enabled() == 0);
	/* destroy should be safe even though init failed */
	nats_persist_destroy();
}

/* schedule_write when persistence is disabled must be a silent no-op. */
static void test_schedule_write_noop(void)
{
	/* Not initialized. */
	nats_persist_schedule_write();
	CHECK(nats_persist_enabled() == 0);
	CHECK(nats_persist_flush_now() == 0);
}

int main(void)
{
	test_schedule_write_noop();
	test_init_missing_dir();
	test_rehydrate_missing();
	test_round_trip();

	fprintf(stderr, "tests: %d run, %d failed\n", tests_run, tests_fail);
	return tests_fail == 0 ? 0 : 1;
}
