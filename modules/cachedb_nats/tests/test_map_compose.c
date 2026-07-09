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
 * Coverage for TODO #74 / #40: the map subject structure
 *   enc(map_key) '.' enc(field)
 * and its inverse (filter "enc(map_key).>", strip the prefix, decode the
 * remainder back to the field) had encode/decode coverage but no test of
 * the compose -> extract round trip or the new/legacy format disjointness.
 *
 * Carries the encode/decode + compose/extract and checks:
 *   - compose then extract recovers the field byte-exact (incl. '.', ':', '%');
 *   - a composed new-format key contains no raw ':' (so the legacy "key:"
 *     scan never matches it) and a legacy "key:field" key is not matched by
 *     the new-format "enc(key)." prefix -- the two formats are disjoint, so
 *     the dual-read pass cannot double-count.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_map_compose test_map_compose.c
 */

#include <stdio.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	char line[4096];
	int hit = 0;
	if (!f) return 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

/* ---- carried encode/decode (mirror of nats_map_encode/decode) ------ */

static int safe(unsigned char c)
{
	if ((c>='0'&&c<='9')||(c>='A'&&c<='Z')||(c>='a'&&c<='z')) return 1;
	switch (c) { case '-': case '_': case '/': case '\\': return 1; }
	return 0;
}
static int enc(const char *in, int n, char *out)
{
	static const char hx[]="0123456789ABCDEF";
	int i,p=0;
	for (i=0;i<n;i++){ unsigned char c=in[i];
		if (safe(c)) out[p++]=c; else { out[p++]='='; out[p++]=hx[c>>4]; out[p++]=hx[c&15]; } }
	out[p]='\0'; return p;
}
static int hexv(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='A'&&c<='F')return c-'A'+10; if(c>='a'&&c<='f')return c-'a'+10; return -1; }
static int dec(const char *in, int n, char *out)
{
	int i=0,p=0;
	while(i<n){ if(in[i]=='='){ if(i+2>=n)return -1; int hi=hexv(in[i+1]),lo=hexv(in[i+2]); if(hi<0||lo<0)return -1; out[p++]=(char)((hi<<4)|lo); i+=3; } else out[p++]=in[i++]; }
	out[p]='\0'; return p;
}

/* compose enc(key) '.' enc(field) */
static int compose(const char *key, int klen, const char *field, int flen, char *out)
{
	int p = enc(key, klen, out);
	out[p++]='.';
	p += enc(field, flen, out+p);
	return p;
}

/* extract: given composed and the same key, recover the field */
static int extract(const char *composed, const char *key, int klen, char *field_out)
{
	char encprefix[256];
	int ep = enc(key, klen, encprefix);
	encprefix[ep++]='.';
	encprefix[ep]='\0';
	int clen = (int)strlen(composed);
	if (clen <= ep || strncmp(composed, encprefix, ep) != 0) return -1;
	return dec(composed + ep, clen - ep, field_out);
}

static void roundtrip(const char *key, const char *field, const char *label)
{
	char comp[512], got[256];
	char m[128];
	int n = compose(key, (int)strlen(key), field, (int)strlen(field), comp);
	int fl = extract(comp, key, (int)strlen(key), got);
	(void)n;
	snprintf(m, sizeof(m), "%s: field recovered byte-exact", label);
	ASSERT(fl == (int)strlen(field) && strcmp(got, field) == 0, m);
	snprintf(m, sizeof(m), "%s: composed key has no raw ':'", label);
	ASSERT(strchr(comp, ':') == NULL, m);
}

int main(void)
{
	/* ---- compose -> extract round trips ------------------------ */
	roundtrip("usrloc", "alice", "plain");
	roundtrip("user.1@host", "x:y", "key with dot/@ + field with colon");
	roundtrip("m", "sub:field", "legacy-style subkey:pair field");
	roundtrip("a%b", "c=d", "percent + equals");

	/* ---- new/legacy format disjointness ------------------------ */
	{
		char comp[512], encpref[256];
		int ep;
		/* new key for map "a.b" */
		compose("a.b", 3, "c", 1, comp);
		ep = enc("a.b", 3, encpref); encpref[ep++]='.'; encpref[ep]='\0';
		ASSERT(strncmp(comp, encpref, (size_t)ep) == 0,
			"new key starts with enc(key)'.' (server-side filterable)");
		/* a legacy "a.b:c" key (raw ':') must NOT match the new prefix */
		ASSERT(strncmp("a.b:c", encpref, (size_t)ep) != 0,
			"legacy ':' key is not matched by the new-format prefix");
		/* the new key must NOT match the legacy "a.b:" raw prefix */
		ASSERT(strncmp(comp, "a.b:", 4) != 0,
			"new key is not matched by the legacy 'key:' scan");
	}

	/* ---- production wiring -------------------------------------- */
	{
		const char *n = "../cachedb_nats_native.c";
		ASSERT(file_contains(n, "nats_map_compose"),
			"map ops compose via nats_map_compose");
		ASSERT(file_contains(n, "nats_map_decode(k + ep_len"),
			"map_get extracts the field via decode of the post-prefix tail");
		ASSERT(file_contains(n, "kvStore_KeysWithFilters"),
			"map_get/remove use the server-side filtered list");
	}

	if (g_fails == 0) fprintf(stderr, "\n=== ALL PASS (fails=0) ===\n");
	else              fprintf(stderr, "\n=== FAILS=%d ===\n", g_fails);
	return g_fails ? 1 : 0;
}
