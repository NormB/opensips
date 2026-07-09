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
 * P2.7 / SPEC.md §4.1-step-4 [REV-21 + REV-1]: skew-safe write-side hygiene.
 *
 * On update(), drop an already-expired contact ONLY IF it is among the subkeys
 * THIS update explicitly set/unset, and only when `expires != 0 && expires + S
 * <= now` (S = max skew = nats_reap_grace).  The writer MUST NOT iterate the
 * other, merged-in contacts and delete ones it judges expired by node-local
 * `now`: usrloc flushes only a delta, so a node whose clock leads by S would
 * otherwise collaterally delete another node's still-live binding — a wrongful,
 * unrecoverable deletion.  Bulk expiry of untouched contacts is the reaper's job.
 *
 * The safety property is STRUCTURAL: the drop set is built only from the touched
 * pairs, so an untouched contact is never even considered — proven below by
 * keeping an untouched-yet-expired contact while dropping a touched-and-expired
 * one in the same row.
 *
 *   gcc -DHYGIENE_CURRENT ... -> today: no write hygiene (_contact_is_expired
 *                                disabled) => expired-own contact kept => RED.
 *   gcc ...                  -> the FIXED hygiene => GREEN.
 *
 * Rule 6: the AUTHORITATIVE proof is the Tier-2 e2e (a node with a leading clock
 * must not delete another node's live binding) vs the production merge.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_write_hygiene_scope test_write_hygiene_scope.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* ─── carried copy: the expiry decision (rowmeta TU) ────────────── */
static int _contact_is_expired(int64_t expires, long now, int grace)
{
#ifdef HYGIENE_CURRENT
	(void)expires; (void)now; (void)grace; return 0;  /* today: no hygiene */
#else
	/* 0 = permanent (never auto-expires); else expired once the absolute
	 * expiry plus the skew grace S has passed node-local now. */
	return expires != 0 && (expires + (int64_t)grace) <= (int64_t)now;
#endif
}

/* ─── carried copy: JSON walkers + minimal sink ─────────────────── */
static const char *cdbn_skip_ws(const char *p, const char *end)
{ while (p < end && (*p==' '||*p=='\t'||*p=='\n'||*p=='\r')) p++; return p; }
static const char *cdbn_parse_json_string(const char *p, const char *end,
	const char **out, int *out_len)
{
	const char *start;
	if (p >= end || *p != '"') return NULL;
	p++; start = p;
	while (p < end && *p != '"') { if (*p=='\\'){p++; if(p>=end)return NULL;} p++; }
	if (p >= end) return NULL;
	*out = start; *out_len = (int)(p - start); return p + 1;
}
static const char *cdbn_skip_json_value(const char *p, const char *end)
{
	int depth;
	p = cdbn_skip_ws(p, end);
	if (p >= end) return NULL;
	switch (*p) {
	case '"':
		p++;
		while (p < end && *p != '"') { if (*p=='\\'){p++; if(p>=end)return NULL;} p++; }
		return (p < end) ? p + 1 : NULL;
	case '{': case '[':
		depth = 1; p++;
		while (p < end && depth > 0) {
			if (*p=='{'||*p=='[') depth++;
			else if (*p=='}'||*p==']') depth--;
			else if (*p=='"') { p++; while(p<end&&*p!='"'){if(*p=='\\'){p++;if(p>=end)return NULL;}p++;} if(p>=end)return NULL; }
			p++;
		}
		return p;
	default:
		while (p<end && *p!=','&&*p!='}'&&*p!=']'&&*p!=' '&&*p!='\t'&&*p!='\n'&&*p!='\r') p++;
		return p;
	}
}
typedef struct { char *buf; int len; int cap; int oom; } json_sink_t;
static int cdbn_sink_init(json_sink_t *s, int n){ s->buf=malloc(n>0?n:16); if(!s->buf)return -1; s->len=0; s->cap=n>0?n:16; s->oom=0; return 0; }
static int _sink_grow(json_sink_t *s,int need){ int c=s->cap; char *b; while(c-s->len<need)c*=2; b=realloc(s->buf,c); if(!b){s->oom=1;return -1;} s->buf=b; s->cap=c; return 0; }
static int cdbn_sink_write(json_sink_t *s,const char *p,int n){ if(s->oom)return -1; if(s->cap-s->len<n&&_sink_grow(s,n)<0)return -1; memcpy(s->buf+s->len,p,n); s->len+=n; return 0; }
static int cdbn_sink_putc(json_sink_t *s,char c){ return cdbn_sink_write(s,&c,1); }
static int cdbn_sink_emit_raw_string(json_sink_t *s,const char *p,int n){ if(cdbn_sink_putc(s,'"')<0)return -1; if(cdbn_sink_write(s,p,n)<0)return -1; return cdbn_sink_putc(s,'"'); }
static char *cdbn_sink_take(json_sink_t *s,int *out_len){ if(s->oom){free(s->buf);return NULL;} if(cdbn_sink_putc(s,'\0')<0)return NULL; if(out_len)*out_len=s->len-1; return s->buf; }

/* ─── carried copy: contacts-subkey removal (rowmeta TU) ─────────── */
static int _emit_contacts_minus(json_sink_t *s, const char *cvs, const char *cve,
	const char **ids, const int *id_lens, int n_ids)
{
	const char *p = cdbn_skip_ws(cvs, cve), *end = cve;
	int first = 1;
	if (p >= end || *p != '{') return -1;
	if (cdbn_sink_putc(s, '{') < 0) return -1;
	p++;
	while (p < end) {
		const char *name, *vs; int nlen, i, drop = 0;
		p = cdbn_skip_ws(p, end);
		if (p >= end) return -1;
		if (*p == '}') break;
		if (*p == ',') { p++; continue; }
		p = cdbn_parse_json_string(p, end, &name, &nlen);
		if (!p) return -1;
		p = cdbn_skip_ws(p, end);
		if (p >= end || *p != ':') return -1;
		p++;
		p = cdbn_skip_ws(p, end);
		vs = p;
		p = cdbn_skip_json_value(p, end);
		if (!p) return -1;
		for (i = 0; i < n_ids; i++)
			if (nlen == id_lens[i] && memcmp(name, ids[i], nlen) == 0) { drop = 1; break; }
		if (drop) continue;
		if (!first && cdbn_sink_putc(s, ',') < 0) return -1;
		first = 0;
		if (cdbn_sink_emit_raw_string(s, name, nlen) < 0) return -1;
		if (cdbn_sink_putc(s, ':') < 0) return -1;
		if (cdbn_sink_write(s, vs, (int)(p - vs)) < 0) return -1;
	}
	if (cdbn_sink_putc(s, '}') < 0) return -1;
	return 0;
}
static char *_contacts_drop_subkeys(const char *json, int len,
	const char **ids, const int *id_lens, int n_ids, int *out_len)
{
	const char *p, *end;
	json_sink_t s;
	int first = 1;
	if (!json || len <= 0) return NULL;
	end = json + len;
	p = cdbn_skip_ws(json, end);
	if (p >= end || *p != '{') return NULL;
	if (cdbn_sink_init(&s, len + 16) < 0) return NULL;
	if (cdbn_sink_putc(&s, '{') < 0) goto fail;
	p++;
	while (p < end) {
		const char *name, *vs; int nlen;
		p = cdbn_skip_ws(p, end);
		if (p >= end) goto fail;
		if (*p == '}') break;
		if (*p == ',') { p++; continue; }
		p = cdbn_parse_json_string(p, end, &name, &nlen);
		if (!p) goto fail;
		p = cdbn_skip_ws(p, end);
		if (p >= end || *p != ':') goto fail;
		p++;
		p = cdbn_skip_ws(p, end);
		vs = p;
		p = cdbn_skip_json_value(p, end);
		if (!p) goto fail;
		if (!first && cdbn_sink_putc(&s, ',') < 0) goto fail;
		first = 0;
		if (cdbn_sink_emit_raw_string(&s, name, nlen) < 0) goto fail;
		if (cdbn_sink_putc(&s, ':') < 0) goto fail;
		if (nlen == 8 && memcmp(name, "contacts", 8) == 0) {
			if (_emit_contacts_minus(&s, vs, p, ids, id_lens, n_ids) < 0) goto fail;
		} else {
			if (cdbn_sink_write(&s, vs, (int)(p - vs)) < 0) goto fail;
		}
	}
	if (cdbn_sink_putc(&s, '}') < 0) goto fail;
	return cdbn_sink_take(&s, out_len);
fail:
	free(s.buf); return NULL;
}

/* ─── assertions ─────────────────────────────────────────────── */
static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)
static int has(const char *hay, const char *needle){ return strstr(hay,needle)!=NULL; }
static char *drop1(const char *doc, const char *id)
{ const char *ids[1]={id}; int il[1]={(int)strlen(id)}; return _contacts_drop_subkeys(doc,(int)strlen(doc),ids,il,1,NULL); }

int main(void)
{
#ifdef HYGIENE_CURRENT
	printf("== carried copy: HYGIENE_CURRENT (no write hygiene) ==\n");
#else
	printf("== carried copy: FIXED hygiene ==\n");
#endif

	printf("[REV-21/1] expiry decision (now=1000, grace S=5):\n");
	CHECK(_contact_is_expired(990, 1000, 5) == 1, "990+5<=1000 => expired");
	CHECK(_contact_is_expired(995, 1000, 5) == 1, "995+5==1000 boundary => expired");
	CHECK(_contact_is_expired(996, 1000, 5) == 0, "996+5>1000 => live (within skew)");
	CHECK(_contact_is_expired(2000, 1000, 5) == 0, "future expiry => live");
	CHECK(_contact_is_expired(0, 1000, 5) == 0, "expires==0 (permanent) => never expired");
	CHECK(_contact_is_expired(5000000000LL, 1000, 5) == 0, "int64 future expiry => live");

	/* The removal transform itself is not toggled (it is mechanical); it always
	 * drops exactly the subkeys it is given and nothing else. */
	printf("[REV-21] _contacts_drop_subkeys removes exactly the named subkeys:\n");
	{ char *o = drop1("{\"contacts\":{\"a\":{\"expires\":1},\"b\":{\"expires\":2},\"c\":{\"expires\":3}},\"aorhash\":7}", "b");
	  CHECK(o && has(o,"\"a\":") && has(o,"\"c\":") && !has(o,"\"b\":"), "drop middle 'b' keeps a,c");
	  CHECK(o && has(o,"\"aorhash\":7"), "aorhash preserved"); free(o); }
	{ char *o = drop1("{\"contacts\":{\"a\":{\"expires\":1},\"b\":{\"expires\":2}},\"aorhash\":7}", "a");
	  CHECK(o && !has(o,"\"a\":") && has(o,"\"b\":"), "drop head 'a'"); free(o); }
	{ const char *ids[2]={"a","b"}; int il[2]={1,1};
	  char *o=_contacts_drop_subkeys("{\"contacts\":{\"a\":{\"expires\":1},\"b\":{\"expires\":2}}}",(int)strlen("{\"contacts\":{\"a\":{\"expires\":1},\"b\":{\"expires\":2}}}"),ids,il,2,NULL);
	  CHECK(o && has(o,"\"contacts\":{}"), "drop all => empty contacts {}"); free(o); }
	{ char *o = drop1("{\"contacts\":{\"a\":{\"expires\":1}},\"aorhash\":7}", "zzz");
	  CHECK(o && has(o,"\"a\":"), "drop nonexistent id => unchanged"); free(o); }
	{ char *o = drop1("{\"foo\":1,\"bar\":\"x\"}", "a");
	  CHECK(o && strcmp(o,"{\"foo\":1,\"bar\":\"x\"}")==0, "non-contacts doc unchanged"); free(o); }

	/* Integration: drop set built ONLY from the touched contacts via the
	 * (toggled) decision.  An untouched-yet-expired contact is never considered. */
	printf("[REV-21] scope: touched-expired dropped, touched-live + UNTOUCHED kept:\n");
	{
		const char *doc =
		  "{\"contacts\":{"
		    "\"own_exp\":{\"expires\":900},"   /* touched, expired -> drop  */
		    "\"own_live\":{\"expires\":2000},"  /* touched, live    -> keep  */
		    "\"other_exp\":{\"expires\":100}"   /* UNTOUCHED, expired-> keep! */
		  "},\"aorhash\":7}";
		/* touched set = {own_exp:900, own_live:2000}; other_exp is NOT touched. */
		struct { const char *id; int64_t exp; } touched[] = {
			{"own_exp", 900}, {"own_live", 2000} };
		const char *ids[4]; int il[4], n = 0, k;
		for (k = 0; k < 2; k++)
			if (_contact_is_expired(touched[k].exp, 1000, 5)) {
				ids[n] = touched[k].id; il[n] = (int)strlen(touched[k].id); n++;
			}
		char *o = _contacts_drop_subkeys(doc, (int)strlen(doc), ids, il, n, NULL);
		CHECK(o && !has(o, "\"own_exp\":"), "touched + expired 'own_exp' dropped");
		CHECK(o && has(o, "\"own_live\":"), "touched + live 'own_live' kept");
		CHECK(o && has(o, "\"other_exp\":"), "UNTOUCHED expired 'other_exp' KEPT (no collateral delete)");
		free(o);
	}

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
