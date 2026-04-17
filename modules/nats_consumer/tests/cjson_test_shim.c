/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * A minimal drop-in implementation of the subset of cJSON APIs that
 * nats_persist.c uses, so the persist unit test can run without pulling
 * in the opensips core that lib/cJSON.c depends on.  Functionally
 * equivalent to the real library for the persist code paths; not a
 * general-purpose cJSON replacement.
 *
 * Only pulled in when TEST_SHIM is defined.  The production build uses
 * ../../lib/cJSON.c via the module Makefile.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Match the symbol mangling used by the real header (CJSON_PREFIX=os_) */
#include "../../../lib/cJSON.h"

/* Tiny dynamic buffer used by the printer. */
typedef struct strbuf {
	char *buf;
	size_t len;
	size_t cap;
} strbuf_t;

static int sb_grow(strbuf_t *s, size_t need)
{
	if (s->len + need + 1 <= s->cap) return 0;
	size_t ncap = s->cap ? s->cap * 2 : 128;
	while (ncap < s->len + need + 1) ncap *= 2;
	char *nb = (char *)realloc(s->buf, ncap);
	if (!nb) return -1;
	s->buf = nb;
	s->cap = ncap;
	return 0;
}

static int sb_puts(strbuf_t *s, const char *p, size_t n)
{
	if (sb_grow(s, n) < 0) return -1;
	memcpy(s->buf + s->len, p, n);
	s->len += n;
	s->buf[s->len] = '\0';
	return 0;
}

static int sb_putc(strbuf_t *s, char c)
{
	return sb_puts(s, &c, 1);
}

/* ── create / delete ────────────────────────────────────────── */

static cJSON *new_node(int type)
{
	cJSON *n = (cJSON *)calloc(1, sizeof(*n));
	if (!n) return NULL;
	n->type = type;
	return n;
}

cJSON *cJSON_CreateObject(void)  { return new_node(cJSON_Object); }
cJSON *cJSON_CreateArray(void)   { return new_node(cJSON_Array);  }
cJSON *cJSON_CreateNull(void)    { return new_node(cJSON_NULL);   }
cJSON *cJSON_CreateTrue(void)    { return new_node(cJSON_True);   }
cJSON *cJSON_CreateFalse(void)   { return new_node(cJSON_False);  }
cJSON *cJSON_CreateBool(int b)   { return new_node(b ? cJSON_True : cJSON_False); }

cJSON *cJSON_CreateNumber(double num)
{
	cJSON *n = new_node(cJSON_Number);
	if (!n) return NULL;
	n->valuedouble = num;
	n->valueint = (int)num;
	return n;
}

cJSON *cJSON_CreateString(const char *s)
{
	cJSON *n = new_node(cJSON_String);
	if (!n) return NULL;
	n->valuestring = strdup(s ? s : "");
	return n;
}

cJSON *cJSON_CreateStr(const char *s, size_t len)
{
	cJSON *n = new_node(cJSON_String);
	if (!n) return NULL;
	n->valuestring = (char *)malloc(len + 1);
	if (!n->valuestring) { free(n); return NULL; }
	if (len) memcpy(n->valuestring, s, len);
	n->valuestring[len] = '\0';
	return n;
}

void cJSON_Delete(cJSON *c)
{
	cJSON *cur, *next;
	if (!c) return;
	cur = c->child;
	while (cur) {
		next = cur->next;
		cJSON_Delete(cur);
		cur = next;
	}
	if (c->valuestring) free(c->valuestring);
	if (c->string)      free(c->string);
	free(c);
}

/* ── append helpers ─────────────────────────────────────────── */

static void append_child(cJSON *parent, cJSON *item)
{
	if (!parent || !item) return;
	item->next = NULL;
	item->prev = NULL;
	if (!parent->child) {
		parent->child = item;
		return;
	}
	cJSON *last = parent->child;
	while (last->next) last = last->next;
	last->next = item;
	item->prev = last;
}

void cJSON_AddItemToArray(cJSON *arr, cJSON *item)
{
	append_child(arr, item);
}

void cJSON_AddItemToObject(cJSON *obj, const char *name, cJSON *item)
{
	if (!item) return;
	if (item->string) free(item->string);
	item->string = strdup(name ? name : "");
	append_child(obj, item);
}

void _cJSON_AddItemToObject(cJSON *obj, const str *name, cJSON *item)
{
	if (!item) return;
	if (item->string) free(item->string);
	if (name && name->s && name->len > 0) {
		item->string = (char *)malloc(name->len + 1);
		memcpy(item->string, name->s, name->len);
		item->string[name->len] = '\0';
	} else {
		item->string = strdup("");
	}
	append_child(obj, item);
}

int cJSON_GetArraySize(const cJSON *arr)
{
	int n = 0;
	if (!arr) return 0;
	for (cJSON *c = arr->child; c; c = c->next) n++;
	return n;
}

cJSON *cJSON_GetArrayItem(const cJSON *arr, int i)
{
	if (!arr) return NULL;
	cJSON *c = arr->child;
	while (c && i > 0) { c = c->next; i--; }
	return c;
}

cJSON *cJSON_GetObjectItem(const cJSON *obj, const char *name)
{
	if (!obj || !name) return NULL;
	for (cJSON *c = obj->child; c; c = c->next) {
		if (c->string && strcasecmp(c->string, name) == 0)
			return c;
	}
	return NULL;
}

/* ── printer ────────────────────────────────────────────────── */

static int print_string(strbuf_t *s, const char *p)
{
	if (sb_putc(s, '"') < 0) return -1;
	if (!p) goto end;
	for (; *p; p++) {
		char c = *p;
		if (c == '"' || c == '\\') {
			if (sb_putc(s, '\\') < 0) return -1;
			if (sb_putc(s, c) < 0) return -1;
		} else if ((unsigned char)c < 0x20) {
			char buf[8];
			snprintf(buf, sizeof(buf), "\\u%04x", c);
			if (sb_puts(s, buf, strlen(buf)) < 0) return -1;
		} else {
			if (sb_putc(s, c) < 0) return -1;
		}
	}
end:
	return sb_putc(s, '"');
}

static int print_node(strbuf_t *s, const cJSON *n);

static int print_object(strbuf_t *s, const cJSON *obj, int is_array)
{
	if (sb_putc(s, is_array ? '[' : '{') < 0) return -1;
	int first = 1;
	for (cJSON *c = obj->child; c; c = c->next) {
		if (!first) {
			if (sb_putc(s, ',') < 0) return -1;
		}
		first = 0;
		if (!is_array) {
			if (print_string(s, c->string) < 0) return -1;
			if (sb_putc(s, ':') < 0) return -1;
		}
		if (print_node(s, c) < 0) return -1;
	}
	return sb_putc(s, is_array ? ']' : '}');
}

static int print_node(strbuf_t *s, const cJSON *n)
{
	char numbuf[64];
	if (!n) return sb_puts(s, "null", 4);

	if (n->type & cJSON_String) {
		return print_string(s, n->valuestring);
	}
	if (n->type & cJSON_Number) {
		int nn = snprintf(numbuf, sizeof(numbuf), "%g", n->valuedouble);
		return sb_puts(s, numbuf, (size_t)nn);
	}
	if (n->type & cJSON_True)  return sb_puts(s, "true", 4);
	if (n->type & cJSON_False) return sb_puts(s, "false", 5);
	if (n->type & cJSON_NULL)  return sb_puts(s, "null", 4);
	if (n->type & cJSON_Object) return print_object(s, n, 0);
	if (n->type & cJSON_Array)  return print_object(s, n, 1);
	return -1;
}

char *cJSON_Print(const cJSON *root)
{
	strbuf_t s = { NULL, 0, 0 };
	if (print_node(&s, root) < 0) {
		free(s.buf);
		return NULL;
	}
	return s.buf;
}

char *cJSON_PrintUnformatted(const cJSON *root)
{
	return cJSON_Print(root);
}

void cJSON_PurgeString(char *p)
{
	free(p);
}

/* ── parser (minimal) ───────────────────────────────────────── */

static const char *g_err_ptr = NULL;

const char *cJSON_GetErrorPtr(void)
{
	return g_err_ptr;
}

static const char *skip_ws(const char *p)
{
	while (*p && isspace((unsigned char)*p)) p++;
	return p;
}

static cJSON *parse_value(const char **pp);

static char *parse_string_literal(const char **pp)
{
	const char *p = *pp;
	if (*p != '"') { g_err_ptr = p; return NULL; }
	p++;
	const char *start = p;
	size_t extra = 0;
	while (*p && *p != '"') {
		if (*p == '\\') { p++; if (!*p) { g_err_ptr = p; return NULL; } extra++; }
		p++;
	}
	if (*p != '"') { g_err_ptr = p; return NULL; }
	size_t raw_len = (size_t)(p - start);
	char *out = (char *)malloc(raw_len + 1);
	if (!out) return NULL;
	size_t oi = 0;
	const char *q = start;
	while (q < p) {
		if (*q == '\\' && q + 1 < p) {
			q++;
			switch (*q) {
				case '"':  out[oi++] = '"';  break;
				case '\\': out[oi++] = '\\'; break;
				case '/':  out[oi++] = '/';  break;
				case 'n':  out[oi++] = '\n'; break;
				case 't':  out[oi++] = '\t'; break;
				case 'r':  out[oi++] = '\r'; break;
				case 'b':  out[oi++] = '\b'; break;
				case 'f':  out[oi++] = '\f'; break;
				default:   out[oi++] = *q;   break;
			}
			q++;
		} else {
			out[oi++] = *q++;
		}
	}
	out[oi] = '\0';
	(void)extra;
	*pp = p + 1;
	return out;
}

static cJSON *parse_string(const char **pp)
{
	char *s = parse_string_literal(pp);
	if (!s) return NULL;
	cJSON *n = new_node(cJSON_String);
	if (!n) { free(s); return NULL; }
	n->valuestring = s;
	return n;
}

static cJSON *parse_number(const char **pp)
{
	char *end;
	double v = strtod(*pp, &end);
	if (end == *pp) { g_err_ptr = *pp; return NULL; }
	cJSON *n = new_node(cJSON_Number);
	if (!n) return NULL;
	n->valuedouble = v;
	n->valueint = (int)v;
	*pp = end;
	return n;
}

static cJSON *parse_array(const char **pp)
{
	cJSON *arr = new_node(cJSON_Array);
	if (!arr) return NULL;
	const char *p = *pp + 1; /* skip '[' */
	p = skip_ws(p);
	if (*p == ']') { *pp = p + 1; return arr; }
	for (;;) {
		*pp = p;
		cJSON *it = parse_value(pp);
		if (!it) { cJSON_Delete(arr); return NULL; }
		append_child(arr, it);
		p = skip_ws(*pp);
		if (*p == ',') { p = skip_ws(p + 1); continue; }
		if (*p == ']') { *pp = p + 1; return arr; }
		g_err_ptr = p;
		cJSON_Delete(arr);
		return NULL;
	}
}

static cJSON *parse_object(const char **pp)
{
	cJSON *obj = new_node(cJSON_Object);
	if (!obj) return NULL;
	const char *p = *pp + 1; /* skip '{' */
	p = skip_ws(p);
	if (*p == '}') { *pp = p + 1; return obj; }
	for (;;) {
		p = skip_ws(p);
		*pp = p;
		char *key = parse_string_literal(pp);
		if (!key) { cJSON_Delete(obj); return NULL; }
		p = skip_ws(*pp);
		if (*p != ':') { free(key); cJSON_Delete(obj); g_err_ptr = p; return NULL; }
		p = skip_ws(p + 1);
		*pp = p;
		cJSON *val = parse_value(pp);
		if (!val) { free(key); cJSON_Delete(obj); return NULL; }
		val->string = key;
		append_child(obj, val);
		p = skip_ws(*pp);
		if (*p == ',') { p = p + 1; continue; }
		if (*p == '}') { *pp = p + 1; return obj; }
		g_err_ptr = p;
		cJSON_Delete(obj);
		return NULL;
	}
}

static cJSON *parse_value(const char **pp)
{
	const char *p = skip_ws(*pp);
	*pp = p;
	if (*p == '"')             return parse_string(pp);
	if (*p == '[')             return parse_array(pp);
	if (*p == '{')             return parse_object(pp);
	if (*p == '-' || (*p >= '0' && *p <= '9'))
	                           return parse_number(pp);
	if (strncmp(p, "true", 4) == 0)  { *pp = p + 4; return new_node(cJSON_True); }
	if (strncmp(p, "false", 5) == 0) { *pp = p + 5; return new_node(cJSON_False); }
	if (strncmp(p, "null", 4) == 0)  { *pp = p + 4; return new_node(cJSON_NULL); }
	g_err_ptr = p;
	return NULL;
}

cJSON *cJSON_Parse(const char *value)
{
	if (!value) return NULL;
	g_err_ptr = NULL;
	const char *p = value;
	return parse_value(&p);
}
