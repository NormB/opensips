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
 * Registration-observability MI [OBS]: the nats_reg_list filter language and
 * the per-contact state model.
 *
 * Operators drive the list command with ONE string parameter of
 * ';'-separated key=value pairs (avoids MI recipe explosion, stays typable):
 *
 *   aor=<glob>            fnmatch(3) over the DECODED AoR
 *   domain=<host>         case-insensitive exact match on the part after
 *                         the LAST '@' (SIP hosts compare case-insensitively);
 *                         rows without '@' match domain=(none)
 *   ua=<substr>           substring over the contact's raw user_agent value
 *   contact=<substr>      substring over the contact URI value
 *   state=active|expired|permanent|all     (default active = would be served)
 *   expiring_within=<s>   at least one contact with 0 < expires-now <= s
 *   min_contacts=<n>      stored contacts >= n
 *   sort=aor|expiry|contacts|last_mod      (+ desc=1)
 *   limit=<n> (default 50, HARD CAP 200 -- MI datagram size)  offset=<n>
 *
 * Contact state mirrors the read filter exactly [D-OBS-4]:
 *   permanent: expires == 0
 *   active:    expires + grace >  now   (would be served)
 *   expired:   expires + grace <= now   (stored-but-hidden: lingering or
 *                                        awaiting the reaper)
 * Unknown keys / malformed values REFUSE the command (fail loudly, never
 * silently list the wrong subset).
 *
 *   gcc -DREGF_CURRENT ... -> no parser/state model (everything defaults,
 *                             bad input accepted) => RED.
 *   gcc ...                -> the FIXED logic => GREEN.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_reg_filter test_reg_filter.c
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <fnmatch.h>

/* ─── carried copies of the production helpers (cachedb_nats_reg.c) ─── */

enum reg_cstate { REG_C_ACTIVE = 0, REG_C_EXPIRED = 1, REG_C_PERMANENT = 2 };
enum reg_sortkey { REG_SORT_AOR = 0, REG_SORT_EXPIRY = 1,
                   REG_SORT_CONTACTS = 2, REG_SORT_LAST_MOD = 3 };
enum reg_statef { REG_F_ACTIVE = 0, REG_F_EXPIRED = 1, REG_F_PERMANENT = 2,
                  REG_F_ALL = 3 };

#define REG_LIMIT_DEFAULT 50
#define REG_LIMIT_CAP     200

struct reg_filter {
	char aor_glob[256];
	char domain[192];
	char ua[128];
	char contact[192];
	int  state;                 /* enum reg_statef */
	long expiring_within;       /* 0 = off */
	long min_contacts;          /* 0 = off */
	int  sort;                  /* enum reg_sortkey */
	int  desc;
	long limit;
	long offset;
	int  format;                /* [FMT] 0=json 1=csv 2=txt */
	int  eol_lf;                /* [FMT-7] 0=CRLF 1=LF */
	int  header;                /* [FMT-5] header record on/off */
};

static int cdbn_reg_contact_state(int64_t expires, time_t now, int grace)
{
#ifdef REGF_CURRENT
	(void)expires; (void)now; (void)grace;
	return REG_C_ACTIVE;                       /* no state model */
#else
	if (expires == 0)
		return REG_C_PERMANENT;
	return (expires + (int64_t)grace > (int64_t)now)
		? REG_C_ACTIVE : REG_C_EXPIRED;
#endif
}

static int cdbn_reg_domain_of(const char *aor, int len,
	const char **dom, int *dlen)
{
#ifdef REGF_CURRENT
	(void)aor; (void)len; *dom = NULL; *dlen = 0; return -1;
#else
	int i;
	for (i = len - 1; i >= 0; i--) {
		if (aor[i] == '@') {
			*dom = aor + i + 1;
			*dlen = len - i - 1;
			return 0;
		}
	}
	*dom = NULL; *dlen = 0;
	return -1;                                 /* no domain part */
#endif
}

static int cdbn_reg_ci_eq(const char *a, int alen, const char *b, int blen)
{
	int i;
	if (alen != blen)
		return 0;
	for (i = 0; i < alen; i++) {
		char ca = a[i], cb = b[i];
		if (ca >= 'A' && ca <= 'Z') ca += 32;
		if (cb >= 'A' && cb <= 'Z') cb += 32;
		if (ca != cb)
			return 0;
	}
	return 1;
}

/* one key=value token; 0 ok, -1 reject */
static int reg_filter_kv(struct reg_filter *f, const char *k, int klen,
	const char *v, int vlen)
{
	char num[24];
	long n;
	char *end;

	if (vlen <= 0)
		return -1;                             /* empty value: reject */

#define KEQ(s) (klen == (int)sizeof(s)-1 && memcmp(k, s, klen) == 0)
#define CPY(dst) do { \
		if (vlen >= (int)sizeof(dst)) return -1; \
		memcpy(dst, v, vlen); dst[vlen] = '\0'; } while (0)

	if (KEQ("aor"))      { CPY(f->aor_glob); return 0; }
	if (KEQ("domain"))   { CPY(f->domain);   return 0; }
	if (KEQ("ua"))       { CPY(f->ua);       return 0; }
	if (KEQ("contact"))  { CPY(f->contact);  return 0; }
	if (KEQ("state")) {
		if (vlen == 6 && memcmp(v, "active", 6) == 0) f->state = REG_F_ACTIVE;
		else if (vlen == 7 && memcmp(v, "expired", 7) == 0) f->state = REG_F_EXPIRED;
		else if (vlen == 9 && memcmp(v, "permanent", 9) == 0) f->state = REG_F_PERMANENT;
		else if (vlen == 3 && memcmp(v, "all", 3) == 0) f->state = REG_F_ALL;
		else return -1;
		return 0;
	}
	if (KEQ("sort")) {
		if (vlen == 3 && memcmp(v, "aor", 3) == 0) f->sort = REG_SORT_AOR;
		else if (vlen == 6 && memcmp(v, "expiry", 6) == 0) f->sort = REG_SORT_EXPIRY;
		else if (vlen == 8 && memcmp(v, "contacts", 8) == 0) f->sort = REG_SORT_CONTACTS;
		else if (vlen == 8 && memcmp(v, "last_mod", 8) == 0) f->sort = REG_SORT_LAST_MOD;
		else return -1;
		return 0;
	}
	/* numeric keys */
	if (vlen >= (int)sizeof(num))
		return -1;
	memcpy(num, v, vlen); num[vlen] = '\0';
	n = strtol(num, &end, 10);
	if (*end != '\0')
		return -1;                             /* not a clean number */
	if (KEQ("expiring_within")) { if (n <= 0) return -1; f->expiring_within = n; return 0; }
	if (KEQ("min_contacts"))    { if (n < 0) return -1; f->min_contacts = n; return 0; }
	if (KEQ("desc"))            { if (n != 0 && n != 1) return -1; f->desc = (int)n; return 0; }
	if (KEQ("limit")) {
		if (n <= 0) return -1;
		f->limit = n > REG_LIMIT_CAP ? REG_LIMIT_CAP : n;   /* clamp, not error */
		return 0;
	}
	if (KEQ("offset"))          { if (n < 0) return -1; f->offset = n; return 0; }
	if (KEQ("header"))          { if (n != 0 && n != 1) return -1; f->header = (int)n; return 0; }
	return -1;                                 /* unknown key: fail loudly */
#undef KEQ
#undef CPY
}

/* [FMT-4/7] string-valued format keys, shared shape with the kvobs parser */
static int reg_filter_fmt_kv(struct reg_filter *f, const char *k, int klen,
	const char *v, int vlen)
{
	if (klen == 6 && memcmp(k, "format", 6) == 0) {
		if (vlen == 4 && memcmp(v, "json", 4) == 0) f->format = 0;
		else if (vlen == 3 && memcmp(v, "csv", 3) == 0) f->format = 1;
		else if (vlen == 3 && memcmp(v, "txt", 3) == 0) f->format = 2;
		else return -1;
		return 0;
	}
	if (klen == 3 && memcmp(k, "eol", 3) == 0) {
		if (vlen == 2 && memcmp(v, "lf", 2) == 0) f->eol_lf = 1;
		else if (vlen == 4 && memcmp(v, "crlf", 4) == 0) f->eol_lf = 0;
		else return -1;
		return 0;
	}
	return 1;                                  /* not a format key */
}

/* ';'-separated key=value list; whitespace around tokens tolerated.
 * 0 ok, -1 reject (unknown key / malformed / oversize value). */
static int cdbn_reg_filter_parse(const char *s, int len, struct reg_filter *f)
{
	memset(f, 0, sizeof(*f));
	f->state = REG_F_ACTIVE;
	f->limit = REG_LIMIT_DEFAULT;
	f->header = 1;
#ifdef REGF_CURRENT
	(void)s; (void)len; return 0;              /* accepts anything, no-op */
#else
	{
		const char *p = s, *end = s + len;
		while (p < end) {
			const char *tok = p, *eq, *te;
			while (p < end && *p != ';')
				p++;
			te = p;
			if (p < end)
				p++;                           /* skip ';' */
			while (tok < te && (*tok == ' ' || *tok == '\t')) tok++;
			while (te > tok && (te[-1] == ' ' || te[-1] == '\t')) te--;
			if (tok == te)
				continue;                      /* empty token (";;") ok */
			for (eq = tok; eq < te && *eq != '='; eq++)
				;
			if (eq == te || eq == tok)
				return -1;                     /* no '=' or empty key */
			{
				int r = reg_filter_fmt_kv(f, tok, (int)(eq - tok),
					eq + 1, (int)(te - eq - 1));
				if (r < 0)
					return -1;
				if (r == 0)
					continue;
			}
			if (reg_filter_kv(f, tok, (int)(eq - tok),
					eq + 1, (int)(te - eq - 1)) < 0)
				return -1;
		}
		return 0;
	}
#endif
}

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
	struct reg_filter f;
	const time_t NOW = 1000000;
	const int G = 5;

#ifdef REGF_CURRENT
	printf("== carried copy: REGF_CURRENT (no parser/state model) ==\n");
#else
	printf("== carried copy: FIXED filter + state model ==\n");
#endif

	printf("[D-OBS-4] contact state mirrors the read filter (grace, never linger):\n");
	CHECK(cdbn_reg_contact_state(0, NOW, G) == REG_C_PERMANENT, "expires=0 => permanent");
	CHECK(cdbn_reg_contact_state(NOW + 100, NOW, G) == REG_C_ACTIVE, "future => active");
	CHECK(cdbn_reg_contact_state(NOW - 2, NOW, G) == REG_C_ACTIVE,
	      "within grace => STILL active (served)");
	CHECK(cdbn_reg_contact_state(NOW - 5, NOW, G) == REG_C_EXPIRED,
	      "exactly expires+grace==now => expired (boundary)");
	CHECK(cdbn_reg_contact_state(NOW - 500, NOW, G) == REG_C_EXPIRED, "long past => expired");

	printf("[D-OBS-3] domain = after the LAST '@', case-insensitive compare:\n");
	{
		const char *d; int dl;
		CHECK(cdbn_reg_domain_of("alice@example.com", 17, &d, &dl) == 0 &&
		      dl == 11 && memcmp(d, "example.com", 11) == 0, "user@host => host");
		CHECK(cdbn_reg_domain_of("we@ird@example.com", 18, &d, &dl) == 0 &&
		      dl == 11 && memcmp(d, "example.com", 11) == 0,
		      "'@' in user part: LAST '@' wins");
		CHECK(cdbn_reg_domain_of("nodomain", 8, &d, &dl) == -1, "no '@' => no domain");
		CHECK(cdbn_reg_domain_of("trailing@", 9, &d, &dl) == 0 && dl == 0,
		      "trailing '@' => empty domain (matches nothing)");
		CHECK(cdbn_reg_ci_eq("Example.COM", 11, "example.com", 11) == 1,
		      "SIP hosts compare case-insensitively");
		CHECK(cdbn_reg_ci_eq("example.com", 11, "example.co", 10) == 0,
		      "length mismatch never equal");
	}

	printf("[OBS] filter parse — defaults and happy path:\n");
	CHECK(cdbn_reg_filter_parse("", 0, &f) == 0 && f.state == REG_F_ACTIVE &&
	      f.limit == REG_LIMIT_DEFAULT && f.offset == 0 && f.sort == REG_SORT_AOR,
	      "empty filter => defaults (state=active, limit=50, sort=aor)");
	{
		const char *q = "domain=Example.COM; state=all ;sort=expiry;desc=1;limit=10;offset=20";
		CHECK(cdbn_reg_filter_parse(q, (int)strlen(q), &f) == 0 &&
		      strcmp(f.domain, "Example.COM") == 0 && f.state == REG_F_ALL &&
		      f.sort == REG_SORT_EXPIRY && f.desc == 1 &&
		      f.limit == 10 && f.offset == 20,
		      "full filter round-trips (spaces around tokens tolerated)");
	}
	{
		const char *q = "ua=friendly panda 1.2;aor=*@example.com";
		CHECK(cdbn_reg_filter_parse(q, (int)strlen(q), &f) == 0 &&
		      strcmp(f.ua, "friendly panda 1.2") == 0 &&
		      strcmp(f.aor_glob, "*@example.com") == 0,
		      "spaces INSIDE a value survive (';' is the separator)");
		CHECK(fnmatch(f.aor_glob, "bob@example.com", 0) == 0,
		      "aor glob is fnmatch semantics");
		CHECK(fnmatch(f.aor_glob, "bob@other.net", 0) != 0,
		      "glob rejects non-matching AoR");
	}
	{
		const char *q = "aor=lit\\=eral";   /* '=' inside a value */
		CHECK(cdbn_reg_filter_parse(q, (int)strlen(q), &f) == 0 &&
		      strcmp(f.aor_glob, "lit\\=eral") == 0,
		      "first '=' splits key/value; later '=' belongs to the value");
	}
	CHECK(cdbn_reg_filter_parse(";;", 2, &f) == 0, "empty tokens (';;') tolerated");

	printf("[OBS] filter parse — fail loudly, never list the wrong subset:\n");
	CHECK(cdbn_reg_filter_parse("bogus=1", 7, &f) == -1, "unknown key => refused");
	CHECK(cdbn_reg_filter_parse("state=zombie", 12, &f) == -1, "bad enum value => refused");
	CHECK(cdbn_reg_filter_parse("sort=up", 7, &f) == -1, "bad sort key => refused");
	CHECK(cdbn_reg_filter_parse("limit=abc", 9, &f) == -1, "non-numeric number => refused");
	CHECK(cdbn_reg_filter_parse("limit=0", 7, &f) == -1, "limit 0 => refused");
	CHECK(cdbn_reg_filter_parse("limit=-5", 8, &f) == -1, "negative limit => refused");
	CHECK(cdbn_reg_filter_parse("offset=-1", 9, &f) == -1, "negative offset => refused");
	CHECK(cdbn_reg_filter_parse("expiring_within=0", 17, &f) == -1,
	      "expiring_within=0 => refused (meaningless)");
	CHECK(cdbn_reg_filter_parse("domain=", 7, &f) == -1, "empty value => refused");
	CHECK(cdbn_reg_filter_parse("=x", 2, &f) == -1, "empty key => refused");
	CHECK(cdbn_reg_filter_parse("aor", 3, &f) == -1, "token without '=' => refused");

	printf("[OBS] limit hard cap (MI datagram size):\n");
	CHECK(cdbn_reg_filter_parse("limit=200", 9, &f) == 0 && f.limit == 200,
	      "limit=200 (the cap) accepted verbatim");
	CHECK(cdbn_reg_filter_parse("limit=100000", 12, &f) == 0 && f.limit == 200,
	      "limit above the cap CLAMPS to 200 (not an error)");

	printf("[FMT] output-format keys in the filter language:\n");
	CHECK(cdbn_reg_filter_parse("", 0, &f) == 0 && f.format == 0 &&
	      f.eol_lf == 0 && f.header == 1,
	      "defaults: json, CRLF, header on");
	{
		const char *q = "format=csv;eol=lf;header=0;sort=expiry";
		CHECK(cdbn_reg_filter_parse(q, (int)strlen(q), &f) == 0 &&
		      f.format == 1 && f.eol_lf == 1 && f.header == 0 &&
		      f.sort == REG_SORT_EXPIRY,
		      "format/eol/header compose with the other keys");
	}
	CHECK(cdbn_reg_filter_parse("format=txt", 10, &f) == 0 && f.format == 2,
	      "format=txt accepted");
	CHECK(cdbn_reg_filter_parse("format=cvs", 10, &f) == -1,
	      "typo'd format REFUSED (never silently json)");
	CHECK(cdbn_reg_filter_parse("eol=cr", 6, &f) == -1, "bad eol refused");
	CHECK(cdbn_reg_filter_parse("header=2", 8, &f) == -1, "bad header refused");

	printf("[OBS] oversize values are refused, not truncated:\n");
	{
		char big[600];
		memset(big, 'a', sizeof(big));
		memcpy(big, "aor=", 4);
		CHECK(cdbn_reg_filter_parse(big, (int)sizeof(big), &f) == -1,
		      "256+ byte glob => refused (silent truncation would mis-filter)");
	}

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
