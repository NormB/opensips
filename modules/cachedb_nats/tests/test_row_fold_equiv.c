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
 *
 * [P3.5 fold] Behavioural (ASan, REAL TUs): cdbn_row_hygiene_finalize()
 * — the single-walk fold of the update path's two passes — must be
 * BYTE-IDENTICAL to the sequential reference composition
 *     cdbn_row_finalize_metadata(cdbn_row_drop_expired_own(doc))
 * on every input, including the eligibility out-params (row_exp,
 * n_contacts, all_same), the non-usrloc byte-for-byte contract, and
 * every REV-21 / REV-34 edge (permanent sentinel, post-2038 int64,
 * negative expiry, untouched-expired no-collateral, unset pairs, the
 * NATS_MAX_DROP_IDS overflow deferral).
 *
 * The old pair stays in production (the reaper uses finalize alone), so
 * the reference is the real code, not a carried copy.  A relative
 * micro-bench (old pair vs fold, same binary) prints at the end as the
 * P3.5 profiling evidence; it asserts nothing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>

#include "../../../dprint.h"
#include "../../../mem/mem.h"
#include "../../../cachedb/cachedb_types.h"
#include "../cachedb_nats_json_internal.h"

/* ── core seams: dprint ─────────────────────────────────────────── */

static int test_log_level = L_ERR;
int *log_level = &test_log_level;
char *log_prefix = "";
int log_facility = 0;
char ctime_buf[256];
int process_no = 0;

int dp_my_pid(void) { return 0; }

void dprint(int level, int facility, const char *module, const char *func,
	char *stderr_fmt, char *syslog_fmt, char *format, ...)
{
	(void)level; (void)facility; (void)module; (void)func;
	(void)stderr_fmt; (void)syslog_fmt; (void)format;
}

/* ── core seams: pkg allocator (fn-pointer globals from mem/mem.h) ── */

void *mem_block = NULL;

static void *test_pkg_malloc(void *blk, unsigned long size)
{ (void)blk; return malloc(size); }
static void *test_pkg_realloc(void *blk, void *p, unsigned long size)
{ (void)blk; return realloc(p, size); }
static void test_pkg_free(void *blk, void *p)
{ (void)blk; free(p); }

void *(*gen_pkg_malloc)(void *blk, unsigned long size) = test_pkg_malloc;
void *(*gen_pkg_realloc)(void *blk, void *p, unsigned long size) = test_pkg_realloc;
void (*gen_pkg_free)(void *blk, void *p) = test_pkg_free;

/* Referenced by the walk TU's cdbn_safe_json_to_dict (unused here). */
int cdb_json_to_dict(const char *json, cdb_dict_t *out,
	void (*unescape)(char *inout))
{ (void)json; (void)out; (void)unescape; return -1; }

/* Module globals the ser TU references (FTS private-prefix guard). */
char *fts_json_prefix = "json_";
int fts_json_prefix_len = 5;

/* Core dict teardown the rowmeta TU references on paths not driven
 * here (last_mod widening); a real free loop keeps ASan honest if a
 * future test does drive them. */
void cdb_free_entries(cdb_dict_t *dict, void (*free_val_str)(void *val))
{ (void)dict; (void)free_val_str; }

/* ── harness ────────────────────────────────────────────────────── */

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* Build one "contacts"/<subkey> set-pair whose value dict carries an
 * integer "expires".  Storage is caller-provided (stack arrays). */
struct pair_slot {
	cdb_pair_t pair;
	cdb_pair_t exp_field;
	cdb_dict_t val_dict;
};

static void mk_contact_pair(struct pair_slot *sl, const char *subkey,
	int64_t expires, int use_i64, int unset, cdb_dict_t *into)
{
	memset(sl, 0, sizeof(*sl));
	sl->pair.key.name.s = "contacts";
	sl->pair.key.name.len = 8;
	sl->pair.subkey.s = (char *)subkey;
	sl->pair.subkey.len = (int)strlen(subkey);
	sl->pair.unset = (char)unset;
	INIT_LIST_HEAD(&sl->val_dict);
	if (!unset) {
		sl->pair.val.type = CDB_DICT;
		INIT_LIST_HEAD(&sl->pair.val.val.dict);
		sl->exp_field.key.name.s = "expires";
		sl->exp_field.key.name.len = 7;
		if (use_i64) {
			sl->exp_field.val.type = CDB_INT64;
			sl->exp_field.val.val.i64 = expires;
		} else {
			sl->exp_field.val.type = CDB_INT32;
			sl->exp_field.val.val.i32 = (int32_t)expires;
		}
		list_add_tail(&sl->exp_field.list, &sl->pair.val.val.dict);
	}
	list_add_tail(&sl->pair.list, into);
}

/* Run the sequential reference and the fold; assert byte + out-param
 * equality.  Either side may legally return NULL (malformed input) —
 * then BOTH must. */
static void check_equiv(const char *label, const char *json,
	const cdb_dict_t *pairs, time_t now, int grace)
{
	int old_len = 0, new_len = 0, tmp_len = 0;
	int64_t o_exp = -77, n_exp = -77;
	int o_n = -77, n_n = -77, o_same = -77, n_same = -77;
	char *dropped, *oldr = NULL, *newr;
	char msg[256];

	dropped = cdbn_row_drop_expired_own(json, (int)strlen(json), pairs,
		now, grace, &tmp_len);
	if (dropped) {
		oldr = cdbn_row_finalize_metadata(dropped, tmp_len, &old_len,
			&o_exp, &o_n, &o_same);
		free(dropped);
	}
	newr = cdbn_row_hygiene_finalize(json, (int)strlen(json), pairs,
		now, grace, &new_len,
		&n_exp, &n_n, &n_same);

	snprintf(msg, sizeof(msg), "%s: fold == reference", label);
	if (!oldr || !newr) {
		ASSERT(oldr == newr, msg);
	} else {
		ASSERT(old_len == new_len && memcmp(oldr, newr, old_len) == 0, msg);
		snprintf(msg, sizeof(msg), "%s: eligibility outs match "
			"(row_exp %lld/%lld n %d/%d same %d/%d)", label,
			(long long)o_exp, (long long)n_exp, o_n, n_n, o_same, n_same);
		ASSERT(o_exp == n_exp && o_n == n_n && o_same == n_same, msg);
	}
	free(oldr);
	free(newr);
}

int main(void)
{
	time_t now = 1000000;
	int grace = 30;
	cdb_dict_t pairs;
	struct pair_slot sl[4];

	/* 1. touched expired contact dropped + live survivor recomputed */
	INIT_LIST_HEAD(&pairs);
	mk_contact_pair(&sl[0], "YWxpY2U=", 999900, 0, 0, &pairs);  /* expired */
	mk_contact_pair(&sl[1], "Ym9i",     1000600, 0, 0, &pairs); /* live */
	check_equiv("drop one + survivor",
		"{\"aor\":\"alice@h\",\"contacts\":{"
		"\"YWxpY2U=\":{\"expires\":999900,\"q\":1},"
		"\"Ym9i\":{\"expires\":1000600}},"
		"\"row_exp\":42,\"schema_version\":1}", &pairs, now, grace);

	/* 2. nothing due: no-drop fast path */
	INIT_LIST_HEAD(&pairs);
	mk_contact_pair(&sl[0], "Ym9i", 1000600, 0, 0, &pairs);
	check_equiv("no drop",
		"{\"contacts\":{\"Ym9i\":{\"expires\":1000600}}}",
		&pairs, now, grace);

	/* 3. permanent contact => permanent row (sentinel 0) */
	INIT_LIST_HEAD(&pairs);
	mk_contact_pair(&sl[0], "cGVybQ==", 0, 0, 0, &pairs);
	check_equiv("permanent sentinel",
		"{\"contacts\":{\"cGVybQ==\":{\"expires\":0},"
		"\"Ym9i\":{\"expires\":1000600}}}", &pairs, now, grace);

	/* 4. all-same vs mixed expiries (TTL eligibility) */
	check_equiv("all same",
		"{\"contacts\":{\"YQ==\":{\"expires\":1000500},"
		"\"Yg==\":{\"expires\":1000500}}}", NULL, now, grace);
	check_equiv("mixed",
		"{\"contacts\":{\"YQ==\":{\"expires\":1000500},"
		"\"Yg==\":{\"expires\":1000900}}}", NULL, now, grace);

	/* 5. non-usrloc doc: byte-for-byte verbatim (odd spacing kept) */
	check_equiv("non-usrloc verbatim",
		"{ \"k\" :\t{\"x\": [1,2 ,3]} , \"y\":\"z\\\"esc\" }",
		NULL, now, grace);

	/* 6. unset pair never enters the drop set */
	INIT_LIST_HEAD(&pairs);
	mk_contact_pair(&sl[0], "YWxpY2U=", 999900, 0, 1 /* unset */, &pairs);
	check_equiv("unset pair ignored",
		"{\"contacts\":{\"YWxpY2U=\":{\"expires\":999900}}}",
		&pairs, now, grace);

	/* 7. untouched expired merged-in contact is NOT dropped */
	INIT_LIST_HEAD(&pairs);
	mk_contact_pair(&sl[0], "Ym9i", 1000600, 0, 0, &pairs);
	check_equiv("no collateral delete",
		"{\"contacts\":{\"c3RhbGU=\":{\"expires\":5},"
		"\"Ym9i\":{\"expires\":1000600}}}", &pairs, now, grace);

	/* 8. post-2038 int64 expiry survives */
	INIT_LIST_HEAD(&pairs);
	mk_contact_pair(&sl[0], "ZnV0dXJl", 4102444800LL, 1, 0, &pairs);
	check_equiv("post-2038 int64",
		"{\"contacts\":{\"ZnV0dXJl\":{\"expires\":4102444800}}}",
		&pairs, now, grace);

	/* 9. negative expiry: real candidate, dropped when touched */
	INIT_LIST_HEAD(&pairs);
	mk_contact_pair(&sl[0], "bmVn", -5, 1, 0, &pairs);
	check_equiv("negative expiry touched",
		"{\"contacts\":{\"bmVn\":{\"expires\":-5},"
		"\"Ym9i\":{\"expires\":1000600}}}", &pairs, now, grace);

	/* 10. malformed input: both sides NULL */
	check_equiv("malformed json", "{\"contacts\":{", NULL, now, grace);
	check_equiv("not an object", "[1,2,3]", NULL, now, grace);

	/* 11. empty contacts object */
	check_equiv("empty contacts", "{\"contacts\":{}}", NULL, now, grace);

	/* 12. adversarial value bytes: escapes, UTF-8, format specifiers */
	INIT_LIST_HEAD(&pairs);
	mk_contact_pair(&sl[0], "YWRz", 999900, 0, 0, &pairs);
	check_equiv("adversarial bytes",
		"{\"contacts\":{\"YWRz\":{\"expires\":999900,"
		"\"ua\":\"sipp\\\\1.0 %s %n \\u00e9\\\"x\"},"
		"\"Ym9i\":{\"expires\":1000600,\"note\":\"caf\xc3\xa9\"}},"
		"\"blob\":\"a\\\\b\"}", &pairs, now, grace);

	/* 13. duplicate top-level contacts keys (last occurrence wins) */
	INIT_LIST_HEAD(&pairs);
	mk_contact_pair(&sl[0], "YQ==", 999900, 0, 0, &pairs);
	check_equiv("duplicate contacts key",
		"{\"contacts\":{\"YQ==\":{\"expires\":999900}},"
		"\"contacts\":{\"Yg==\":{\"expires\":1000700}}}",
		&pairs, now, grace);

	/* 14. NATS_MAX_DROP_IDS overflow: 300 touched-expired contacts —
	 * excess past 256 is deferred to the reaper, identically. */
	{
		static struct pair_slot big_sl[300];
		static char keys[300][16];
		static char doc[300 * 48 + 64];
		char *w = doc;
		int i;

		INIT_LIST_HEAD(&pairs);
		w += sprintf(w, "{\"contacts\":{");
		for (i = 0; i < 300; i++) {
			sprintf(keys[i], "k%03d", i);
			mk_contact_pair(&big_sl[i], keys[i], 999900, 0, 0, &pairs);
			w += sprintf(w, "%s\"%s\":{\"expires\":999900}",
				i ? "," : "", keys[i]);
		}
		sprintf(w, "}}");
		check_equiv("drop-id overflow (300 touched)", doc, &pairs,
			now, grace);
	}

	/* 15. odd interior whitespace through both emission arms */
	INIT_LIST_HEAD(&pairs);
	mk_contact_pair(&sl[0], "YQ==", 999900, 0, 0, &pairs);
	check_equiv("whitespace, drop arm",
		"{ \"contacts\" : { \"YQ==\" :\t{ \"expires\" : 999900 } ,"
		" \"Yg==\": {\"expires\":1000700} } }", &pairs, now, grace);
	check_equiv("whitespace, bulk arm",
		"{ \"contacts\" : { \"Yg==\":\t{ \"expires\" : 1000700 } } }",
		NULL, now, grace);

	/* ── relative micro-bench (evidence, not a gate) ─────────────── */
	{
		const char *doc = "{\"aor\":\"alice@example.com\",\"contacts\":{"
			"\"YWJjZGVmZ2hpamtsbW5vcA==\":{\"expires\":1000600,\"q\":1,"
			"\"ua\":\"softphone/2.1\",\"last_mod\":1000000},"
			"\"cXJzdHV2d3h5ejEyMzQ1Ng==\":{\"expires\":1000700,"
			"\"ua\":\"deskphone/9\",\"last_mod\":1000001},"
			"\"MTIzNDU2Nzg5MGFiY2RlZg==\":{\"expires\":1000800},"
			"\"ZmVkY2JhMDk4NzY1NDMyMQ==\":{\"expires\":1000900},"
			"\"YWFhYmJiY2NjZGRkZWVlZg==\":{\"expires\":1001000}},"
			"\"row_exp\":42,\"schema_version\":1}";
		const int N = 20000;
		struct timespec t0, t1;
		long long old_ns, new_ns;
		int i, L = (int)strlen(doc), ol;
		int64_t re; int nc, as;

		INIT_LIST_HEAD(&pairs);
		mk_contact_pair(&sl[0], "YWJjZGVmZ2hpamtsbW5vcA==", 1000600, 0, 0,
			&pairs);

		clock_gettime(CLOCK_MONOTONIC, &t0);
		for (i = 0; i < N; i++) {
			int tl;
			char *d = cdbn_row_drop_expired_own(doc, L, &pairs,
				now, grace, &tl);
			char *f = cdbn_row_finalize_metadata(d, tl, &ol,
				&re, &nc, &as);
			free(d); free(f);
		}
		clock_gettime(CLOCK_MONOTONIC, &t1);
		old_ns = (t1.tv_sec - t0.tv_sec) * 1000000000LL +
			(t1.tv_nsec - t0.tv_nsec);

		clock_gettime(CLOCK_MONOTONIC, &t0);
		for (i = 0; i < N; i++) {
			char *f = cdbn_row_hygiene_finalize(doc, L, &pairs,
				now, grace, &ol, &re, &nc, &as);
			free(f);
		}
		clock_gettime(CLOCK_MONOTONIC, &t1);
		new_ns = (t1.tv_sec - t0.tv_sec) * 1000000000LL +
			(t1.tv_nsec - t0.tv_nsec);

		fprintf(stderr, "\nbench (5-contact doc, %d iters): "
			"two-pass %lld ns/op, fold %lld ns/op (%.1f%%)\n",
			N, old_ns / N, new_ns / N,
			100.0 * (double)new_ns / (double)old_ns);
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
