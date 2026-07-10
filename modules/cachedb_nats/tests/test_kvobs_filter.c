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
 * Generic KV/stream introspection MI [KVOBS]: the filter language shared by
 * nats_stream_list and nats_kv_keys.  Same shape as the nats_reg_list
 * language (';'-separated key=value, unknown keys refused, limit hard-capped
 * at 200 for the MI datagram), different key set:
 *
 *   bucket=<name>   which KV bucket to list keys from (default: the
 *                   module's kv_bucket)
 *   key=<glob>      fnmatch over KV key names       (nats_kv_keys)
 *   name=<glob>     fnmatch over stream names       (nats_stream_list)
 *   kv=0|1          only KV backing streams (KV_*)  (nats_stream_list)
 *   detail=0|1      per-key revision/created/size for the returned PAGE
 *                   (one Get per returned key -- bounded by the limit cap)
 *   limit=<n>       default 50, hard cap 200
 *   offset=<n>
 *
 *   gcc -DKVOBS_CURRENT ... -> no parser (anything accepted, defaults only)
 *                              => RED.
 *   gcc ...                 -> the FIXED parser => GREEN.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_kvobs_filter test_kvobs_filter.c
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define KVOBS_LIMIT_DEFAULT 50
#define KVOBS_LIMIT_CAP     200

struct kvobs_filter {
	char bucket[128];
	char key_glob[256];
	char name_glob[256];
	int  kv_only;
	int  detail;
	long limit;
	long offset;
	int  format;                /* [FMT] 0=json 1=csv 2=txt */
	int  eol_lf;
	int  header;
};

/* ─── carried copy of the production parser (cachedb_nats_kvobs.c) ─── */

static int kvobs_filter_kv(struct kvobs_filter *f, const char *k, int klen,
	const char *v, int vlen)
{
	char num[24];
	long n;
	char *end;

	if (vlen <= 0)
		return -1;

#define KEQ(s) (klen == (int)sizeof(s)-1 && memcmp(k, s, klen) == 0)
#define CPY(dst) do { \
		if (vlen >= (int)sizeof(dst)) return -1; \
		memcpy(dst, v, vlen); dst[vlen] = '\0'; } while (0)

	if (KEQ("bucket")) { CPY(f->bucket);    return 0; }
	if (KEQ("key"))    { CPY(f->key_glob);  return 0; }
	if (KEQ("name"))   { CPY(f->name_glob); return 0; }
	if (KEQ("format")) {
		if (vlen == 4 && memcmp(v, "json", 4) == 0) f->format = 0;
		else if (vlen == 3 && memcmp(v, "csv", 3) == 0) f->format = 1;
		else if (vlen == 3 && memcmp(v, "txt", 3) == 0) f->format = 2;
		else return -1;
		return 0;
	}
	if (KEQ("eol")) {
		if (vlen == 2 && memcmp(v, "lf", 2) == 0) f->eol_lf = 1;
		else if (vlen == 4 && memcmp(v, "crlf", 4) == 0) f->eol_lf = 0;
		else return -1;
		return 0;
	}
	if (vlen >= (int)sizeof(num))
		return -1;
	memcpy(num, v, vlen); num[vlen] = '\0';
	n = strtol(num, &end, 10);
	if (*end != '\0')
		return -1;
	if (KEQ("kv"))     { if (n != 0 && n != 1) return -1; f->kv_only = (int)n; return 0; }
	if (KEQ("detail")) { if (n != 0 && n != 1) return -1; f->detail  = (int)n; return 0; }
	if (KEQ("limit")) {
		if (n <= 0) return -1;
		f->limit = n > KVOBS_LIMIT_CAP ? KVOBS_LIMIT_CAP : n;
		return 0;
	}
	if (KEQ("offset")) { if (n < 0) return -1; f->offset = n; return 0; }
	if (KEQ("header")) { if (n != 0 && n != 1) return -1; f->header = (int)n; return 0; }
	return -1;
#undef KEQ
#undef CPY
}

static int cdbn_kvobs_filter_parse(const char *s, int len, struct kvobs_filter *f)
{
	memset(f, 0, sizeof(*f));
	f->limit = KVOBS_LIMIT_DEFAULT;
	f->header = 1;
#ifdef KVOBS_CURRENT
	(void)s; (void)len; return 0;              /* accepts anything */
#else
	{
		const char *p = s, *end = s + len;
		while (p < end) {
			const char *tok = p, *eq, *te;
			while (p < end && *p != ';')
				p++;
			te = p;
			if (p < end)
				p++;
			while (tok < te && (*tok == ' ' || *tok == '\t')) tok++;
			while (te > tok && (te[-1] == ' ' || te[-1] == '\t')) te--;
			if (tok == te)
				continue;
			for (eq = tok; eq < te && *eq != '='; eq++)
				;
			if (eq == te || eq == tok)
				return -1;
			if (kvobs_filter_kv(f, tok, (int)(eq - tok),
					eq + 1, (int)(te - eq - 1)) < 0)
				return -1;
		}
		return 0;
	}
#endif
}

/* KV backing streams are named KV_<bucket>; the operator thinks in bucket
 * names, so stream listings expose both. */
static int cdbn_kvobs_bucket_of_stream(const char *stream, int len,
	const char **bucket, int *blen)
{
#ifdef KVOBS_CURRENT
	(void)stream; (void)len; *bucket = NULL; *blen = 0; return -1;
#else
	if (len > 3 && memcmp(stream, "KV_", 3) == 0) {
		*bucket = stream + 3;
		*blen = len - 3;
		return 0;
	}
	*bucket = NULL; *blen = 0;
	return -1;
#endif
}

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
	struct kvobs_filter f;

#ifdef KVOBS_CURRENT
	printf("== carried copy: KVOBS_CURRENT (no parser) ==\n");
#else
	printf("== carried copy: FIXED parser ==\n");
#endif

	printf("[KVOBS] defaults and happy path:\n");
	CHECK(cdbn_kvobs_filter_parse("", 0, &f) == 0 && f.limit == KVOBS_LIMIT_DEFAULT &&
	      f.offset == 0 && !f.kv_only && !f.detail && !f.bucket[0],
	      "empty filter => defaults");
	{
		const char *q = "bucket=other_bucket; key=json_*;detail=1;limit=25;offset=50";
		CHECK(cdbn_kvobs_filter_parse(q, (int)strlen(q), &f) == 0 &&
		      strcmp(f.bucket, "other_bucket") == 0 &&
		      strcmp(f.key_glob, "json_*") == 0 &&
		      f.detail == 1 && f.limit == 25 && f.offset == 50,
		      "kv_keys filter round-trips (any bucket, not just the module's)");
	}
	{
		const char *q = "name=KV_*;kv=1";
		CHECK(cdbn_kvobs_filter_parse(q, (int)strlen(q), &f) == 0 &&
		      strcmp(f.name_glob, "KV_*") == 0 && f.kv_only == 1,
		      "stream_list filter round-trips");
	}

	printf("[KVOBS] fail loudly on bad input:\n");
	CHECK(cdbn_kvobs_filter_parse("wat=1", 5, &f) == -1, "unknown key => refused");
	CHECK(cdbn_kvobs_filter_parse("kv=2", 4, &f) == -1, "kv flag not 0/1 => refused");
	CHECK(cdbn_kvobs_filter_parse("detail=yes", 10, &f) == -1, "non-numeric flag => refused");
	CHECK(cdbn_kvobs_filter_parse("limit=0", 7, &f) == -1, "limit 0 => refused");
	CHECK(cdbn_kvobs_filter_parse("bucket=", 7, &f) == -1, "empty value => refused");
	CHECK(cdbn_kvobs_filter_parse("limit=999999", 12, &f) == 0 && f.limit == KVOBS_LIMIT_CAP,
	      "limit clamps to the 200 cap (not an error)");
	{
		char big[300];
		memset(big, 'b', sizeof(big));
		memcpy(big, "bucket=", 7);
		CHECK(cdbn_kvobs_filter_parse(big, (int)sizeof(big), &f) == -1,
		      "oversize bucket name refused, never truncated");
	}

	printf("[FMT] output-format keys:\n");
	{
		const char *q = "key=json_*;format=csv;eol=lf;header=0";
		CHECK(cdbn_kvobs_filter_parse(q, (int)strlen(q), &f) == 0 &&
		      f.format == 1 && f.eol_lf == 1 && f.header == 0 &&
		      strcmp(f.key_glob, "json_*") == 0,
		      "format/eol/header compose with kv keys");
	}
	CHECK(cdbn_kvobs_filter_parse("format=tsv", 10, &f) == -1,
	      "unknown format value refused");
	CHECK(cdbn_kvobs_filter_parse("", 0, &f) == 0 && f.format == 0 && f.header == 1,
	      "defaults: json + header on");

	printf("[KVOBS] KV bucket name derived from the backing-stream name:\n");
	{
		const char *b; int bl;
		CHECK(cdbn_kvobs_bucket_of_stream("KV_opensips", 11, &b, &bl) == 0 &&
		      bl == 8 && memcmp(b, "opensips", 8) == 0,
		      "KV_opensips => bucket 'opensips'");
		CHECK(cdbn_kvobs_bucket_of_stream("EVENTS", 6, &b, &bl) == -1,
		      "non-KV stream => no bucket");
		CHECK(cdbn_kvobs_bucket_of_stream("KV_", 3, &b, &bl) == -1,
		      "bare 'KV_' => no bucket (empty name)");
	}

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
