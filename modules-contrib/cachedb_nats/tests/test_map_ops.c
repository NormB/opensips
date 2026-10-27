/*
 * Copyright (C) 2026 Summit-2026 / cachedb_nats contributors
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
 * test_map_ops.c -- the CacheDB map API (map_get / map_set / map_remove)
 * as its users rely on it.
 *
 * The contract, as cachedb_redis and cachedb_dynamodb implement it and
 * b2b_entities / b2b_logic use it:
 *   - map_set(key, subkey, pairs) sets the fields of the map at key,
 *     keeping the others; a subkey makes key a member of the group
 *     subkey.  Values keep their type (string, int32, null).
 *   - map_get(key) returns one row per map: a single pair named after the
 *     map key (is_pk) whose value is a dict of the fields; key NULL
 *     returns every map (b2b restores this way at startup).
 *   - map_remove(key, NULL) deletes the map; (key, subkey) deletes it and
 *     its group membership; (NULL, subkey) deletes every map of the group.
 *
 * Links the REAL ../cachedb_nats_native.c against an in-memory KV that
 * applies nats.c's key rules, so a key the module composes wrongly fails
 * here as it would on a broker.  pkg allocations are balanced: freeing a
 * result the way cdb_free_rows() does must release everything.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <limits.h>

#include "../../../dprint.h"
#include "../../../mem/mem.h"
#include "../../../pvar.h"
#include "../../../mi/mi.h"
#include "../../../cachedb/cachedb.h"
#include "../../nats/nats_dl.h"
#include "../../nats/nats_pool.h"
#include "../cachedb_nats.h"
#include "../cachedb_nats_native.h"
#include "../cachedb_nats_dbase.h"
#include "../cachedb_nats_expiry.h"
#include "../../nats/tests/nats_bind_test.h"  /* nats_api -> the fakes */

/* ── core seams: dprint ─────────────────────────────────────────── */

static int test_log_level = L_WARN;
int *log_level = &test_log_level;
char *log_prefix = "";
int log_facility = 0;
char ctime_buf[256];
int process_no = 0;

int dp_my_pid(void) { return 0; }

void dprint(int level, int facility, const char *module, const char *func,
	char *stderr_fmt, char *syslog_fmt, char *format, ...)
{
	va_list ap;
	(void)level; (void)facility; (void)module; (void)func;
	(void)syslog_fmt; (void)format;
	if (!stderr_fmt)
		return;
	va_start(ap, format);
	vfprintf(stderr, stderr_fmt, ap);
	va_end(ap);
}

/* ── core seams: pkg allocator with live-balance accounting ────── */

void *mem_block = NULL;
static long pkg_live;

static void *test_pkg_malloc(void *blk, unsigned long size)
{ (void)blk; pkg_live++; return malloc(size); }
static void test_pkg_free(void *blk, void *p)
{ (void)blk; if (p) pkg_live--; free(p); }
static void *test_pkg_realloc(void *blk, void *p, unsigned long size)
{ (void)blk; if (!p) pkg_live++; return realloc(p, size); }

void *(*gen_pkg_malloc)(void *blk, unsigned long size) = test_pkg_malloc;
void (*gen_pkg_free)(void *blk, void *p) = test_pkg_free;
void *(*gen_pkg_realloc)(void *blk, void *p, unsigned long size) = test_pkg_realloc;

/* ── module globals normally defined by other TUs ───────────────── */

char *kv_bucket = "testbucket";
int kv_replicas = 1;
int kv_history = 1;
int kv_ttl = 0;

int validate_kv_key(const str *s)
{ return (s && s->s && s->len > 0) ? 0 : -1; }
static int broker_up = 1;
int nats_con_refresh_kv(nats_cachedb_con *ncon)
{ (void)ncon; return broker_up ? 0 : -1; }
void nats_cdb_disconnected_warn(const char *op) { (void)op; }

mi_response_t *init_mi_result_object(mi_item_t **obj_out)
{ (void)obj_out; return NULL; }
mi_response_t *init_mi_error_extra(int code, const char *msg, int msg_len,
	const char *details, int details_len)
{ (void)code; (void)msg; (void)msg_len; (void)details; (void)details_len;
  return NULL; }
void free_mi_response(mi_response_t *response) { (void)response; }
int add_mi_number(mi_item_t *to, char *name, int name_len, double value)
{ (void)to; (void)name; (void)name_len; (void)value; return 0; }

int nats_pool_is_connected(void) { return broker_up; }
kvStore *nats_pool_get_kv(const char *bucket, int replicas, int history,
	int64_t ttl)
{ (void)bucket; (void)replicas; (void)history; (void)ttl;
  return (kvStore *)0x1001; }
natsConnection *nats_pool_get(void) { return NULL; }
jsCtx *nats_pool_get_js(void) { return (jsCtx *)0x2001; }

enum ttl_outcome nats_kv_put_row(jsCtx *js, kvStore *kv,
	const char *bucket, const char *key,
	const char *json, int json_len,
	int got_entry, uint64_t entry_rev, int64_t ttl_ms, uint64_t *out_rev)
{ (void)js; (void)kv; (void)bucket; (void)key; (void)json; (void)json_len;
  (void)got_entry; (void)entry_rev; (void)ttl_ms; (void)out_rev;
  return TTL_DONE; }

int pv_set_value(struct sip_msg *msg, pv_spec_p sp, int op, pv_value_t *value)
{ (void)msg; (void)sp; (void)op; (void)value; return 0; }

/* ── in-memory KV with nats.c's key rules ───────────────────────── */

struct fkv { char *key; char *val; int len; int live; uint64_t rev; };
static struct fkv kvs[4096];
static int nkv;
static uint64_t kv_rev;
static int bad_keys;    /* keys the broker would have refused */

/* nats.c validKey(): [-/_=.a-zA-Z0-9\\], no leading/trailing '.', no ".." */
static int key_valid(const char *k)
{
	size_t i, n = strlen(k);
	if (!n || k[0] == '.' || k[n - 1] == '.')
		return 0;
	for (i = 0; i < n; i++) {
		char c = k[i];
		if (c == '.' && k[i + 1] == '.')
			return 0;
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '-' || c == '/' ||
		      c == '_' || c == '=' || c == '.' || c == '\\'))
			return 0;
	}
	return 1;
}

static struct fkv *kv_find(const char *k)
{
	int i;
	for (i = 0; i < nkv; i++)
		if (!strcmp(kvs[i].key, k))
			return &kvs[i];
	return NULL;
}

static natsStatus fake_Put(uint64_t *rev, kvStore *kv, const char *k,
	const void *data, int len)
{
	struct fkv *e;
	(void)kv;
	if (!key_valid(k)) { bad_keys++; return NATS_INVALID_ARG; }
	e = kv_find(k);
	if (!e) { e = &kvs[nkv++]; e->key = strdup(k); e->val = NULL; }
	free(e->val);
	e->val = malloc(len + 1);
	memcpy(e->val, data, len);
	e->val[len] = 0;
	e->len = len;
	e->live = 1;
	e->rev = ++kv_rev;
	if (rev) *rev = e->rev;
	return NATS_OK;
}
static natsStatus fake_PutString(uint64_t *rev, kvStore *kv, const char *k,
	const char *v)
{ return fake_Put(rev, kv, k, v, (int)strlen(v)); }

struct fentry { char *key; char *val; int len; uint64_t rev; };
static natsStatus fake_Get(kvEntry **out, kvStore *kv, const char *k)
{
	struct fkv *e;
	struct fentry *fe;
	(void)kv;
	if (!key_valid(k)) { bad_keys++; return NATS_INVALID_ARG; }
	e = kv_find(k);
	if (!e || !e->live)
		return NATS_NOT_FOUND;
	fe = malloc(sizeof *fe);
	fe->key = strdup(e->key);
	fe->val = malloc(e->len + 1);
	memcpy(fe->val, e->val, e->len + 1);
	fe->len = e->len;
	fe->rev = e->rev;
	*out = (kvEntry *)fe;
	return NATS_OK;
}
static natsStatus fake_Delete(kvStore *kv, const char *k)
{
	struct fkv *e;
	(void)kv;
	if (!key_valid(k)) { bad_keys++; return NATS_INVALID_ARG; }
	e = kv_find(k);
	if (e) e->live = 0;
	return NATS_OK;
}

/* subject match: '*' one token, '>' one or more trailing tokens */
static int subj_match(const char *filter, const char *key)
{
	const char *f = filter, *k = key;
	for (;;) {
		const char *fe = strchr(f, '.'), *ke = strchr(k, '.');
		size_t fl = fe ? (size_t)(fe - f) : strlen(f);
		size_t kl = ke ? (size_t)(ke - k) : strlen(k);
		if (fl == 1 && f[0] == '>')
			return 1;
		if (!(fl == 1 && f[0] == '*') && (fl != kl || strncmp(f, k, fl)))
			return 0;
		if (!fe || !ke)
			return !fe && !ke;
		f = fe + 1; k = ke + 1;
	}
}
static natsStatus fake_KeysWithFilters(kvKeysList *list, kvStore *kv,
	const char **filters, int n, const kvWatchOptions *o)
{
	int i, j;
	(void)kv; (void)o;
	list->Keys = calloc(nkv + 1, sizeof(char *));
	list->Count = 0;
	for (i = 0; i < nkv; i++) {
		if (!kvs[i].live)
			continue;
		for (j = 0; j < n; j++)
			if (subj_match(filters[j], kvs[i].key)) {
				list->Keys[list->Count++] = strdup(kvs[i].key);
				break;
			}
	}
	return NATS_OK;
}
static void fake_KeysList_Destroy(kvKeysList *list)
{
	int i;
	for (i = 0; i < list->Count; i++) free(list->Keys[i]);
	free(list->Keys);
	list->Keys = NULL; list->Count = 0;
}
static const char *fake_ValueString(const kvEntry *e)
{ return ((const struct fentry *)e)->val; }
static int fake_ValueLen(const kvEntry *e)
{ return ((const struct fentry *)e)->len; }
static const char *fake_Key(const kvEntry *e)
{ return ((const struct fentry *)e)->key; }
static uint64_t fake_Revision(const kvEntry *e)
{ return ((const struct fentry *)e)->rev; }
static void fake_Destroy(kvEntry *e)
{
	struct fentry *fe = (struct fentry *)e;
	if (!fe) return;
	free(fe->key); free(fe->val); free(fe);
}
static const char *fake_GetText(natsStatus s) { (void)s; return "fake"; }

nats_dl_funcs_t nats_dl;

static int live_keys(void)
{
	int i, n = 0;
	for (i = 0; i < nkv; i++) n += kvs[i].live;
	return n;
}

/* ── result helpers: cdb_free_rows() as the core implements it, and
 * lookups the way b2b reads a result ── */

void cdb_free_rows(cdb_res_t *res)
{
	struct list_head *a, *b, *c, *d;
	list_for_each_safe(a, b, &res->rows) {
		cdb_row_t *row = list_entry(a, cdb_row_t, list);
		list_for_each_safe(c, d, &row->dict) {
			cdb_pair_t *p = list_entry(c, cdb_pair_t, list);
			if (p->val.type == CDB_DICT) {
				struct list_head *e, *f;
				list_for_each_safe(e, f, &p->val.val.dict) {
					cdb_pair_t *q = list_entry(e, cdb_pair_t, list);
					if (q->val.type == CDB_STR)
						pkg_free(q->val.val.st.s);
					list_del(&q->list);
					pkg_free(q);
				}
			} else if (p->val.type == CDB_STR)
				pkg_free(p->val.val.st.s);
			list_del(&p->list);
			pkg_free(p);
		}
		list_del(&row->list);
		pkg_free(row);
	}
	cdb_res_init(res);
}

/* the map pair of the row whose map key is @name (NULL if absent) */
static cdb_pair_t *find_map(cdb_res_t *res, const char *name, int name_len)
{
	struct list_head *a;
	list_for_each(a, &res->rows) {
		cdb_row_t *row = list_entry(a, cdb_row_t, list);
		cdb_pair_t *p;
		if (list_empty(&row->dict))
			continue;
		p = list_last_entry(&row->dict, cdb_pair_t, list);
		if (p->key.name.len == name_len &&
		    !memcmp(p->key.name.s, name, name_len))
			return p;
	}
	return NULL;
}
static cdb_pair_t *find_field(cdb_pair_t *map, const char *name)
{
	struct list_head *a;
	if (!map || map->val.type != CDB_DICT)
		return NULL;
	list_for_each(a, &map->val.val.dict) {
		cdb_pair_t *q = list_entry(a, cdb_pair_t, list);
		if (q->key.name.len == (int)strlen(name) &&
		    !memcmp(q->key.name.s, name, q->key.name.len))
			return q;
	}
	return NULL;
}
static int field_count(cdb_pair_t *map)
{
	struct list_head *a;
	int n = 0;
	if (!map || map->val.type != CDB_DICT)
		return -1;
	list_for_each(a, &map->val.val.dict) n++;
	return n;
}
static int is_str(cdb_pair_t *f, const char *v, int len)
{ return f && f->val.type == CDB_STR && f->val.val.st.len == len &&
         (len == 0 || !memcmp(f->val.val.st.s, v, len)); }
static int is_int(cdb_pair_t *f, int v)
{ return f && f->val.type == CDB_INT32 && f->val.val.i32 == v; }

/* build a dict of pairs: "s:name=value", "i:name=123", "n:name" */
static void mk_pairs(cdb_dict_t *d, int n, const char **spec)
{
	int i;
	INIT_LIST_HEAD(d);
	for (i = 0; i < n; i++) {
		const char *s = spec[i], *eq = strchr(s + 2, '=');
		cdb_key_t key;
		cdb_pair_t *p;
		key.name.s = (char *)s + 2;
		key.name.len = eq ? (int)(eq - (s + 2)) : (int)strlen(s + 2);
		key.is_pk = 0;
		p = cdb_mk_pair(&key, NULL);
		if (s[0] == 's') {
			p->val.type = CDB_STR;
			p->val.val.st.s = (char *)eq + 1;
			p->val.val.st.len = (int)strlen(eq + 1);
		} else if (s[0] == 'i') {
			p->val.type = CDB_INT32;
			p->val.val.i32 = atoi(eq + 1);
		} else
			p->val.type = CDB_NULL;
		list_add_tail(&p->list, d);
	}
}
static void free_pairs(cdb_dict_t *d)
{
	struct list_head *a, *b;
	list_for_each_safe(a, b, d) {
		cdb_pair_t *p = list_entry(a, cdb_pair_t, list);
		list_del(&p->list);
		pkg_free(p);
	}
}

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static cachedb_con *con;

static int set(const char *key, int key_len, const char *group, int n,
	const char **spec)
{
	str k = { (char *)key, key_len }, g = { (char *)group,
		group ? (int)strlen(group) : 0 };
	cdb_dict_t d;
	int rc;
	mk_pairs(&d, n, spec);
	rc = nats_cache_map_set(con, &k, group ? &g : NULL, &d);
	free_pairs(&d);
	return rc;
}
static int del(const char *key, const char *group)
{
	str k = { (char *)key, key ? (int)strlen(key) : 0 };
	str g = { (char *)group, group ? (int)strlen(group) : 0 };
	return nats_cache_map_remove(con, key ? &k : NULL, group ? &g : NULL);
}

int main(void)
{
	nats_cachedb_con ncon;
	cachedb_con c;
	cdb_res_t res;
	str k;
	cdb_pair_t *m, *f;
	long base;
	int rc;
	static char big[10000];
	const char *odd = "b2be$1$tag.with.dots:and sp\\ce=x*>";
	int odd_len = (int)strlen(odd);

	nats_dl.kvStore_Put = fake_Put;
	nats_dl.kvStore_PutString = fake_PutString;
	nats_dl.kvStore_Get = fake_Get;
	nats_dl.kvStore_Delete = fake_Delete;
	nats_dl.kvStore_KeysWithFilters = fake_KeysWithFilters;
	nats_dl.kvKeysList_Destroy = fake_KeysList_Destroy;
	nats_dl.kvEntry_ValueString = fake_ValueString;
	nats_dl.kvEntry_ValueLen = fake_ValueLen;
	nats_dl.kvEntry_Key = fake_Key;
	nats_dl.kvEntry_Revision = fake_Revision;
	nats_dl.kvEntry_Destroy = fake_Destroy;
	nats_dl.natsStatus_GetText = fake_GetText;

	memset(&ncon, 0, sizeof ncon);
	ncon.kv = (kvStore *)0x1001;
	memset(&c, 0, sizeof c);
	c.data = &ncon;
	con = &c;

	/* keys of other users of the bucket: never part of any map */
	fake_PutString(NULL, NULL, "json_alice", "{}");
	fake_PutString(NULL, NULL, "call.123", "x");
	base = pkg_live;

	fprintf(stderr, "map_set / map_get of one map:\n");
	{
		const char *p1[] = { "s:a=x", "i:b=7", "n:c" };
		ASSERT(set("K1", 2, NULL, 3, p1) == 0, "map_set K1 {a, b, c}");
	}
	k.s = "K1"; k.len = 2;
	rc = nats_cache_map_get(con, &k, &res);
	ASSERT(rc == 0 && res.count == 1, "map_get(K1): one row per map");
	m = find_map(&res, "K1", 2);
	ASSERT(m && m->key.is_pk && m->val.type == CDB_DICT,
		"the row is the map key (is_pk) holding a dict");
	ASSERT(field_count(m) == 3, "with the three fields");
	ASSERT(is_str(find_field(m, "a"), "x", 1), "string field keeps its value");
	ASSERT(is_int(find_field(m, "b"), 7), "int32 field comes back as int32");
	f = find_field(m, "c");
	ASSERT(f && f->val.type == CDB_NULL, "null field comes back as null");
	cdb_free_rows(&res);
	ASSERT(pkg_live == base, "result freed like cdb_free_rows: no leak");

	fprintf(stderr, "map_set updates fields, keeps the others:\n");
	{
		const char *p2[] = { "i:b=8", "s:d=" };
		ASSERT(set("K1", 2, NULL, 2, p2) == 0, "map_set K1 {b=8, d=\"\"}");
	}
	nats_cache_map_get(con, &k, &res);
	m = find_map(&res, "K1", 2);
	ASSERT(field_count(m) == 4, "four fields now");
	ASSERT(is_str(find_field(m, "a"), "x", 1), "a untouched");
	ASSERT(is_int(find_field(m, "b"), 8), "b updated");
	ASSERT(is_str(find_field(m, "d"), "", 0), "empty string is a string, not null");
	cdb_free_rows(&res);
	{
		const char *p3[] = { "n:a" };
		set("K1", 2, NULL, 1, p3);
	}
	nats_cache_map_get(con, &k, &res);
	f = find_field(find_map(&res, "K1", 2), "a");
	ASSERT(f && f->val.type == CDB_NULL, "setting a field to null clears it");
	cdb_free_rows(&res);

	fprintf(stderr, "map_get(NULL) returns every map, and only maps:\n");
	{
		const char *p4[] = { "s:a=y" };
		const char *p5[] = { "s:x.y:z\\w=v.v", "i:min=-2147483648",
			"i:max=2147483647" };
		ASSERT(set("K2", 2, "G", 1, p4) == 0, "map_set K2 in group G");
		ASSERT(set(odd, odd_len, NULL, 3, p5) == 0,
			"map_set with '.', ':', '\\\\', '=', '*', '>', ' ' in key and field");
	}
	rc = nats_cache_map_get(con, NULL, &res);
	ASSERT(rc == 0, "map_get(NULL) succeeds (b2b restore)");
	ASSERT(res.count == 3, "three maps, the other keys of the bucket excluded");
	ASSERT(find_map(&res, "K1", 2) && find_map(&res, "K2", 2),
		"K1 and K2 present");
	m = find_map(&res, odd, odd_len);
	ASSERT(m != NULL, "odd map key round-trips byte-exact");
	ASSERT(is_str(find_field(m, "x.y:z\\w"), "v.v", 3), "odd field name round-trips");
	ASSERT(is_int(find_field(m, "min"), INT_MIN) && is_int(find_field(m, "max"), INT_MAX),
		"int32 limits round-trip");
	cdb_free_rows(&res);
	ASSERT(pkg_live == base, "no leak after map_get(NULL)");
	{
		/* values that are not well-formed int32 are skipped, not misread */
		const char *junk[] = { "I", "I-", "I12x", "I2147483648",
			"I-2147483649", "I99999999999", "Q1" };
		size_t j;
		str kk = { "J", 1 };
		for (j = 0; j < sizeof junk / sizeof junk[0]; j++) {
			char sub[32];
			snprintf(sub, sizeof sub, "_map.J.f%zu", j);
			fake_PutString(NULL, NULL, sub, junk[j]);
		}
		nats_cache_map_get(con, &kk, &res);
		m = find_map(&res, "J", 1);
		ASSERT(m && field_count(m) == 0,
			"malformed or out-of-range stored values are skipped");
		cdb_free_rows(&res);
		for (j = 0; j < sizeof junk / sizeof junk[0]; j++) {
			char sub[32];
			snprintf(sub, sizeof sub, "_map.J.f%zu", j);
			fake_Delete(NULL, sub);
		}
	}
	ASSERT(bad_keys == 0, "every composed key is a valid NATS KV key");

	fprintf(stderr, "binary-safe values:\n");
	memset(big, 'v', sizeof big);
	big[5] = '\0';
	{
		str kk = { "K3", 2 };
		cdb_dict_t d;
		cdb_key_t fk = { { "blob", 4 }, 0 };
		cdb_pair_t *p = cdb_mk_pair(&fk, NULL);
		p->val.type = CDB_STR;
		p->val.val.st.s = big;
		p->val.val.st.len = sizeof big;
		INIT_LIST_HEAD(&d);
		list_add_tail(&p->list, &d);
		ASSERT(nats_cache_map_set(con, &kk, NULL, &d) == 0,
			"10000-byte value with an embedded NUL stored");
		free_pairs(&d);
		nats_cache_map_get(con, &kk, &res);
		ASSERT(is_str(find_field(find_map(&res, "K3", 2), "blob"), big, sizeof big),
			"and read back whole");
		cdb_free_rows(&res);
	}

	fprintf(stderr, "map_remove:\n");
	{
		const char *p6[] = { "s:a=1" };
		set("K4", 2, "G2", 1, p6);
		set("K5", 2, "G2", 1, p6);
		set("K6", 2, NULL, 1, p6);
	}
	ASSERT(del("K2", "G") == 0, "map_remove(K2, G)");
	ASSERT(del(NULL, "G2") == 0, "map_remove(NULL, G2): the whole group");
	nats_cache_map_get(con, NULL, &res);
	ASSERT(!find_map(&res, "K2", 2), "K2 gone");
	ASSERT(!find_map(&res, "K4", 2) && !find_map(&res, "K5", 2),
		"K4 and K5 (group G2) gone");
	ASSERT(find_map(&res, "K6", 2) && find_map(&res, "K1", 2),
		"maps outside the group kept");
	cdb_free_rows(&res);
	ASSERT(del("K1", NULL) == 0, "map_remove(K1, NULL)");
	k.s = "K1"; k.len = 2;
	nats_cache_map_get(con, &k, &res);
	ASSERT(res.count == 0, "K1 gone");
	cdb_free_rows(&res);
	ASSERT(del(odd, NULL) == 0 && del("K3", NULL) == 0 && del("K6", NULL) == 0,
		"remove the rest");
	ASSERT(live_keys() == 2,
		"only the two foreign keys remain: no field or group entry left behind");
	ASSERT(del(NULL, "G2") == 0, "removing an empty group is not an error");

	fprintf(stderr, "no aliasing, no wildcard injection:\n");
	{
		const char *pa[] = { "s:c=1" }, *pb[] = { "s:b.c=2" };
		cdb_pair_t *ma, *mb;
		set("a.b", 3, NULL, 1, pa);
		set("a", 1, NULL, 1, pb);
		nats_cache_map_get(con, NULL, &res);
		ma = find_map(&res, "a.b", 3);
		mb = find_map(&res, "a", 1);
		ASSERT(ma && mb && field_count(ma) == 1 && field_count(mb) == 1,
			"map 'a.b' field 'c' and map 'a' field 'b.c' stay distinct");
		cdb_free_rows(&res);
		ASSERT(del(">", NULL) == 0 && del("*", NULL) == 0 &&
			del(NULL, ">") == 0 && del(NULL, "*") == 0,
			"removing map or group '>' / '*' succeeds");
		nats_cache_map_get(con, NULL, &res);
		ASSERT(res.count == 2, "... and deletes nothing else");
		cdb_free_rows(&res);
		del("a.b", NULL);
		del("a", NULL);
		ASSERT(live_keys() == 2, "back to the two foreign keys");
	}

	fprintf(stderr, "bad calls:\n");
	ASSERT(del(NULL, NULL) == -1, "map_remove(NULL, NULL) refused");
	{
		const char *p7[] = { "s:a=1" };
		ASSERT(set("", 0, NULL, 1, p7) == -1, "empty map key refused");
	}
	{
		str kk = { "K7", 2 };
		cdb_dict_t d;
		cdb_key_t fk = { { "sub", 3 }, 0 };
		cdb_pair_t *p = cdb_mk_pair(&fk, NULL);
		p->val.type = CDB_DICT;
		INIT_LIST_HEAD(&p->val.val.dict);
		INIT_LIST_HEAD(&d);
		list_add_tail(&p->list, &d);
		ASSERT(nats_cache_map_set(con, &kk, NULL, &d) == -1,
			"a nested dict value is refused");
		free_pairs(&d);
	}
	ASSERT(nats_cache_map_get(con, NULL, NULL) == -1, "map_get without res refused");
	broker_up = 0;
	res.count = 99;
	rc = nats_cache_map_get(con, NULL, &res);
	ASSERT(rc == -1 && res.count == 0 && list_empty(&res.rows),
		"broker down: map_get fails with an initialised, empty result");
	broker_up = 1;
	ASSERT(pkg_live == base, "pkg balance back to the start");

	fprintf(stderr, "\n%s (%d failure%s)\n", g_fails ? "FAILED" : "PASSED",
		g_fails, g_fails == 1 ? "" : "s");
	return g_fails ? 1 : 0;
}
