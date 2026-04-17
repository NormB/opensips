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
 */

/*
 * nats_rpc.c -- Phase 6 script surface: NATS headers, reply-to, and
 * sync caller RPC.  This file grows incrementally across the Phase 6
 * commit chain:
 *     1. $nats_hdr pvar + nats_hdr_set script function (this commit).
 *     2. nats_reply (plain core publish onto the reply-to).
 *     3. nats_request (sync core RPC).
 *
 * Headers (read)
 *   The ring slot carries a compact serialized header stream (see
 *   nats_ring.h).  pv_get_nats_hdr scans it lazily on each read: most
 *   messages carry a handful of headers so the O(n) scan per get is
 *   cheaper than building a hash on every fetch.  Keys compare
 *   case-insensitively per the NATS / HTTP convention.
 *
 * Headers (write)
 *   A per-worker static array g_staged[NATS_MAX_STAGED_HDRS] holds
 *   script-staged (name, value) pairs.  Both bytes are deep-copied
 *   into pkg_malloc buffers owned by the worker; later publish paths
 *   transfer them onto a natsMsg via natsMsgHeader_Set and clear the
 *   table.  Replacing an existing entry frees its old value buffer
 *   before installing the new one.
 */

#include <string.h>
#include <strings.h>
#include <stdio.h>

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../pvar.h"
#include "../../sr_module.h"

#include "nats_fetch.h"
#include "nats_rpc.h"

/* ── helpers shared across Phase 6 ───────────────────────────── */

/* Case-insensitive byte compare of two str-like inputs.  Inlined on
 * the hot path (every $nats_hdr(Name) read calls this per header in
 * the stream). */
static inline int hdr_name_eq_ci(const char *a, int alen,
                                 const char *b, int blen)
{
	int i;
	if (alen != blen) return 0;
	for (i = 0; i < alen; i++) {
		unsigned char ca = (unsigned char)a[i];
		unsigned char cb = (unsigned char)b[i];
		if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca + 32);
		if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb + 32);
		if (ca != cb) return 0;
	}
	return 1;
}

/* ── $nats_hdr: name parse + get ─────────────────────────────── */

/* Static pvar-name parser.  The name must be a plain literal: nested
 * $pvar(...) expansion inside $nats_hdr() is not supported yet. */
int pv_parse_nats_hdr_name(pv_spec_p sp, const str *in)
{
	if (!sp || !in || in->len <= 0 || !in->s)
		return -1;

	/* Static name -- we do NOT support dynamic expansion for Phase 6.
	 * If a caller passes $pvar(Name) they'll see the literal characters
	 * "$pvar(Name)" here because we don't parse them. */
	sp->pvp.pvn.type         = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.type = AVP_NAME_STR;
	sp->pvp.pvn.u.isname.name.s = *in;
	return 0;
}

/*
 * Scan the serialized header stream in `cur->slot.headers` for a name
 * matching `name` and, on hit, set `*value` to a pointer into the
 * slot's buffer.  Returns 1 on hit, 0 on miss.  The returned `value`
 * bytes live as long as the current message (i.e. until the next
 * nats_fetch / nats_fetch_clear); callers that need the value beyond
 * that must copy it.
 */
static int hdr_stream_find(const nats_cur_msg_t *cur, const str *name,
                           str *value)
{
	const char *p;
	const char *end;
	uint16_t    count;
	uint16_t    i;

	if (!cur || !cur->has_message) return 0;
	if (cur->slot.headers_len < 2)  return 0;
	if (!name || name->len <= 0)    return 0;

	p   = cur->slot.headers;
	end = p + cur->slot.headers_len;

	count = (uint16_t)((unsigned char)p[0] |
		((unsigned char)p[1] << 8));
	p += 2;

	for (i = 0; i < count && p + 2 <= end; i++) {
		uint16_t    klen;
		uint16_t    vlen;
		const char *kstart;
		const char *vstart;

		if (p + 2 > end) return 0;
		klen = (uint16_t)((unsigned char)p[0] |
			((unsigned char)p[1] << 8));
		p += 2;
		if (p + klen > end) return 0;
		kstart = p;
		p += klen;

		if (p + 2 > end) return 0;
		vlen = (uint16_t)((unsigned char)p[0] |
			((unsigned char)p[1] << 8));
		p += 2;
		if (p + vlen > end) return 0;
		vstart = p;
		p += vlen;

		if (hdr_name_eq_ci(kstart, klen, name->s, name->len)) {
			value->s   = (char *)vstart;
			value->len = (int)vlen;
			return 1;
		}
	}
	return 0;
}

int pv_get_nats_hdr(struct sip_msg *msg, pv_param_t *param,
                    pv_value_t *res)
{
	const nats_cur_msg_t *cur = nats_fetch_current();
	str                   name = {0, 0};
	str                   value = {0, 0};

	if (!res || !param) return -1;
	if (!cur || !cur->has_message) return pv_get_null(msg, param, res);

	/* Only static names are parsed in Phase 6 (see
	 * pv_parse_nats_hdr_name). */
	if (param->pvn.type == PV_NAME_INTSTR)
		name = param->pvn.u.isname.name.s;
	else
		return pv_get_null(msg, param, res);

	if (name.len <= 0 || !name.s) return pv_get_null(msg, param, res);

	if (!hdr_stream_find(cur, &name, &value))
		return pv_get_null(msg, param, res);

	return pv_get_strval(msg, param, res, &value);
}

/* ── per-worker outbound header staging ──────────────────────── */

typedef struct nats_staged_hdr {
	str     name;    /* pkg_malloc'd, NUL-terminated */
	str     value;   /* pkg_malloc'd, NUL-terminated */
	int     in_use;
} nats_staged_hdr_t;

static nats_staged_hdr_t g_staged[NATS_MAX_STAGED_HDRS];

/* Free a staged entry's buffers and mark it free.  Safe on already-
 * free entries (no-op when in_use == 0). */
static void staged_free_entry(nats_staged_hdr_t *e)
{
	if (!e) return;
	if (e->name.s)  pkg_free(e->name.s);
	if (e->value.s) pkg_free(e->value.s);
	e->name.s = NULL;   e->name.len  = 0;
	e->value.s = NULL;  e->value.len = 0;
	e->in_use = 0;
}

void nats_rpc_staged_clear(void)
{
	int i;
	for (i = 0; i < NATS_MAX_STAGED_HDRS; i++)
		staged_free_entry(&g_staged[i]);
}

/* pkg-alloc a NUL-terminated copy of `src` and stash in `dst`. */
static int staged_dup(str *dst, const str *src)
{
	char *p;
	if (!dst || !src || src->len < 0) return -1;
	p = (char *)pkg_malloc((size_t)src->len + 1);
	if (!p) return -1;
	if (src->len > 0 && src->s) memcpy(p, src->s, src->len);
	p[src->len] = '\0';
	dst->s   = p;
	dst->len = src->len;
	return 0;
}

/*
 * Script entry point: stage a header onto the worker's outbound
 * buffer.  Replaces an existing entry with the same name (case-
 * insensitive -- matches the read-side behavior of $nats_hdr).
 * Returns 1 on success, -1 on OOM or full table (and DBGs why).
 */
int w_nats_hdr_set(struct sip_msg *msg, str *name, str *value)
{
	int i, free_slot = -1;
	str empty = { NULL, 0 };
	str *v = value ? value : &empty;

	(void)msg;

	if (!name || name->len <= 0 || !name->s) {
		LM_DBG("nats_hdr_set: empty/null name\n");
		return -1;
	}

	/* First pass: replace an existing entry (case-insensitive) and
	 * also note the first free slot for the fall-through branch. */
	for (i = 0; i < NATS_MAX_STAGED_HDRS; i++) {
		if (!g_staged[i].in_use) {
			if (free_slot < 0) free_slot = i;
			continue;
		}
		if (hdr_name_eq_ci(g_staged[i].name.s, g_staged[i].name.len,
				name->s, name->len)) {
			str new_val = {0, 0};
			if (staged_dup(&new_val, v) < 0) {
				LM_ERR("nats_hdr_set: pkg_malloc failed for value\n");
				return -1;
			}
			if (g_staged[i].value.s) pkg_free(g_staged[i].value.s);
			g_staged[i].value = new_val;
			return 1;
		}
	}

	if (free_slot < 0) {
		LM_WARN("nats_hdr_set: staged-header table full "
			"(cap=%d); dropping '%.*s'\n",
			NATS_MAX_STAGED_HDRS, name->len, name->s);
		return -1;
	}

	if (staged_dup(&g_staged[free_slot].name,  name) < 0 ||
	    staged_dup(&g_staged[free_slot].value, v) < 0) {
		staged_free_entry(&g_staged[free_slot]);
		LM_ERR("nats_hdr_set: pkg_malloc failed for header "
			"'%.*s'\n", name->len, name->s);
		return -1;
	}
	g_staged[free_slot].in_use = 1;
	return 1;
}
