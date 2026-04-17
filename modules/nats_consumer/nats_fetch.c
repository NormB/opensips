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
 * nats_fetch.c -- implementation of the script-callable fetch path
 * and the per-worker current-message state.
 *
 * Sync path: a single pop attempt plus an optional blocking short-poll
 * on the eventfd for timeout_ms > 0.  Intended for timer_routes and
 * polling scripts; do NOT use from request_route because it blocks
 * the SIP worker.
 *
 * Async path: short-circuits on ring hit; otherwise registers the
 * per-handle ring eventfd with the reactor and yields.  The resume
 * callback drains the eventfd counter, tries one more pop, and either
 * populates the current-message state (success) or reports empty (the
 * broker fed us nothing in this window).
 *
 * LIMITATION carried to Phase 5:
 *   The async timeout_ms argument is accepted but not fully enforced
 *   by an independent timer -- the OpenSIPS async framework's
 *   timeout_s field is in seconds and we feed it (timeout_ms+999)/1000
 *   for the worst-case upper bound.  Sub-second precision for the
 *   "no message arrived" timeout path lands with Phase 5 when we can
 *   justify allocating a per-fetch timerfd.
 */

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <poll.h>
#include <time.h>

#include "../../dprint.h"
#include "../../async.h"
#include "../../pvar.h"
#include "../../mem/shm_mem.h"
#include "../../sr_module.h"

#include "nats_handle_registry.h"
#include "nats_ring.h"
#include "nats_fetch.h"
#include "nats_ack.h"

/* ── per-worker current-message ──────────────────────────────── */

/* Per-process static: SIP workers are single-threaded so this has
 * thread-local semantics for free. */
static nats_cur_msg_t   g_cur;
static nats_cur_batch_t g_batch;

nats_cur_msg_t *nats_fetch_current(void)
{
	return &g_cur;
}

void nats_fetch_clear(void)
{
	memset(&g_cur, 0, sizeof(g_cur));
}

nats_cur_batch_t *nats_fetch_current_batch(void)
{
	return &g_batch;
}

void nats_fetch_clear_batch(void)
{
	memset(&g_batch, 0, sizeof(g_batch));
	g_batch.selected = -1;
}

/* ── helpers ─────────────────────────────────────────────────── */

/* Drain the eventfd counter to rearm the reactor.  The ring signals
 * exactly once per empty->non-empty edge so a single read suffices;
 * if the counter is already zero (spurious wake / eventfd saturated)
 * we silently ignore EAGAIN. */
static inline void evfd_drain(int fd)
{
	uint64_t sink;
	ssize_t r;
	if (fd < 0)
		return;
	do {
		r = read(fd, &sink, sizeof(sink));
	} while (r < 0 && errno == EINTR);
	/* r == -1 && errno == EAGAIN is the "nothing to drain" path --
	 * benign and expected after the ring pop consumed the edge. */
}

/* Populate g_cur from a freshly-popped ring slot.
 * Returns 1 on success (the script convention for "got a message"). */
static int cur_set_from_slot(uint16_t handle_idx, const nats_ring_slot_t *slot)
{
	g_cur.has_message = 1;
	g_cur.handle_idx  = handle_idx;
	g_cur.ack_token   = slot->ack_token;
	g_cur.slot        = *slot;
	return 1;
}

/* ── sync fetch ─────────────────────────────────────────────── */

int w_nats_fetch(struct sip_msg *msg, str *id, int *timeout_ms)
{
	nats_handle_t    *h;
	nats_ring_slot_t  slot;
	int               rc;
	int               tmo;
	int               fd;

	(void)msg;

	nats_fetch_clear();

	h = nats_registry_lookup(id);
	if (!h) {
		LM_DBG("nats_fetch: unknown handle '%.*s'\n", id->len, id->s);
		return -3;
	}
	if (!h->ring) {
		LM_DBG("nats_fetch: handle '%.*s' has no ring\n",
			id->len, id->s);
		return -3;
	}

	rc = nats_ring_pop(h->ring, &slot);
	if (rc == 0) {
		/* Do NOT drain the eventfd here -- the ring's eventfd is
		 * shared across all worker processes and the consumer
		 * process.  If another worker is blocked on the fd, draining
		 * would steal its wake-up.  The eventfd is edge-triggered
		 * by the ring's empty->non-empty transition; draining is
		 * only the responsibility of the process that ACTUALLY
		 * blocked on the fd and woke from it. */
		return cur_set_from_slot(h->index, &slot);
	}

	tmo = timeout_ms ? *timeout_ms : 0;
	if (tmo <= 0)
		return 0;   /* non-blocking poll miss */

	/* Short sync loop: block on the eventfd for up to tmo ms with a
	 * single poll(), then retry the pop.  This path is only intended
	 * for timer_routes and polling scripts -- it stalls the worker.
	 *
	 * The caller cares about total wall-clock time more than fairness,
	 * so we do a single wait + single retry.  If still empty after
	 * the wait, report miss; the script can loop itself. */
	fd = nats_ring_eventfd(h->ring);
	if (fd >= 0) {
		struct pollfd pfd;
		pfd.fd = fd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		/* poll(2) handles EINTR internally only on modern kernels;
		 * use the simple restartable pattern. */
		int prc;
		do {
			prc = poll(&pfd, 1, tmo);
		} while (prc < 0 && errno == EINTR);
		evfd_drain(fd);
	}

	rc = nats_ring_pop(h->ring, &slot);
	if (rc == 0)
		return cur_set_from_slot(h->index, &slot);

	return 0;
}

/* ── async fetch ────────────────────────────────────────────── */

typedef struct nats_fetch_async_param {
	uint16_t  handle_idx;
	int       evfd;
	/* Borrowed refs into the registry-owned handle.  Phase 5 pending_ops
	 * guards against unbind-while-in-flight: the param holds a pending
	 * ref across the reactor round-trip and the resume path releases it.
	 * A Phase 7 refcount will replace this stop-gap with a proper
	 * get/put pair keyed on handle identity. */
	nats_handle_t *h_ref;
	nats_ring_t   *ring;
} nats_fetch_async_param_t;

static int resume_nats_fetch(int fd, struct sip_msg *msg, void *param)
{
	nats_fetch_async_param_t *p = (nats_fetch_async_param_t *)param;
	nats_ring_slot_t slot;
	int rc;

	(void)msg;

	/* Default: we are done with this fd.  The async core will tear
	 * the reactor registration down unless we explicitly ask to
	 * continue via async_status = ASYNC_CONTINUE. */
	async_status = ASYNC_DONE;

	if (!p) {
		LM_ERR("nats_fetch: resume with NULL param\n");
		return -1;
	}

	/* Drain the eventfd counter so the next edge wakes us again.
	 * The ring signals exactly once per empty->non-empty edge; a
	 * single read clears the counter. */
	evfd_drain(fd);

	rc = nats_ring_pop(p->ring, &slot);
	if (rc == 0) {
		cur_set_from_slot(p->handle_idx, &slot);
		nats_handle_pending_dec(p->h_ref);
		shm_free(p);
		return 1;    /* script rc=1, "got a message" */
	}

	/* Spurious wake -- another consumer raced us to the pop.
	 * Re-arm by asking the reactor to keep us registered and try
	 * again on the next edge.  This is Phase 4's substitute for a
	 * dedicated timerfd; if this loops forever (unlikely, because
	 * another worker already consumed the message), the only cost is
	 * a wasted wakeup.  Phase 5 adds the timerfd. */
	async_status = ASYNC_CONTINUE;
	return 0;
}

int w_nats_fetch_async(struct sip_msg *msg, async_ctx *ctx,
                       str *id, int *timeout_ms)
{
	nats_handle_t             *h;
	nats_ring_slot_t           slot;
	nats_fetch_async_param_t  *p;
	int                        rc;
	int                        tmo;
	int                        fd;

	(void)msg;

	nats_fetch_clear();

	h = nats_registry_lookup(id);
	if (!h) {
		LM_DBG("nats_fetch_async: unknown handle '%.*s'\n",
			id->len, id->s);
		async_status = ASYNC_NO_IO;
		return -3;
	}
	if (!h->ring) {
		LM_DBG("nats_fetch_async: handle '%.*s' has no ring\n",
			id->len, id->s);
		async_status = ASYNC_NO_IO;
		return -3;
	}

	/* Fast path: ring already has a message.  Skip the reactor round
	 * trip entirely and report sync-completion.  We intentionally do
	 * NOT drain the eventfd -- other workers may be blocked on it
	 * awaiting the next edge. */
	rc = nats_ring_pop(h->ring, &slot);
	if (rc == 0) {
		cur_set_from_slot(h->index, &slot);
		async_status = ASYNC_SYNC;
		return 1;
	}

	fd = nats_ring_eventfd(h->ring);
	if (fd < 0) {
		LM_ERR("nats_fetch_async: handle '%.*s' has no eventfd\n",
			id->len, id->s);
		async_status = ASYNC_NO_IO;
		return -1;
	}

	p = (nats_fetch_async_param_t *)shm_malloc(sizeof(*p));
	if (!p) {
		LM_ERR("nats_fetch_async: oom for resume param\n");
		async_status = ASYNC_NO_IO;
		return -1;
	}
	p->handle_idx = h->index;
	p->evfd       = fd;
	p->ring       = h->ring;
	p->h_ref      = h;
	/* Hold the handle across the reactor round-trip so unbind defers. */
	nats_handle_pending_inc(h);

	tmo = timeout_ms ? *timeout_ms : 0;
	if (tmo > 0) {
		/* round up to seconds for the async core's coarse timer */
		ctx->timeout_s = (unsigned int)((tmo + 999) / 1000);
	} else {
		ctx->timeout_s = 0;
	}

	ctx->resume_f     = resume_nats_fetch;
	ctx->resume_param = p;

	/* Tell the reactor: "read-monitor this fd on our behalf and
	 * invoke resume_f when it becomes readable." */
	async_status = fd;
	return 1;
}

/* ── batch fetch ─────────────────────────────────────────────── */

typedef struct batch_opts {
	int count;        /* cap NATS_BATCH_MAX */
	int expires_ms;   /* 0 = non-blocking */
	int max_bytes;    /* advisory */
	int no_wait;      /* 0/1 */
} batch_opts_t;

/* Duration syntax matches nats_handle_parse: <int>(ms|s|m|h|d), no
 * suffix = ms. */
static int batch_parse_duration_ms(const char *s, int len, int *out)
{
	int i = 0, digits = 0;
	long long v = 0;
	long long mult;

	while (i < len && s[i] >= '0' && s[i] <= '9') {
		v = v * 10 + (s[i] - '0');
		digits++;
		i++;
	}
	if (!digits) return -1;

	if (i == len)                             mult = 1LL;
	else if (i + 2 == len && s[i]=='m' && s[i+1]=='s') mult = 1LL;
	else if (i + 1 == len && s[i]=='s') mult = 1000LL;
	else if (i + 1 == len && s[i]=='m') mult = 60LL * 1000LL;
	else if (i + 1 == len && s[i]=='h') mult = 60LL * 60LL * 1000LL;
	else if (i + 1 == len && s[i]=='d') mult = 24LL * 60LL * 60LL * 1000LL;
	else return -1;

	v *= mult;
	if (v < 0 || v > (long long)0x7FFFFFFFLL) return -1;
	*out = (int)v;
	return 0;
}

static int batch_parse_int(const char *s, int len, int *out)
{
	int i = 0;
	long long v = 0;
	if (len <= 0) return -1;
	while (i < len) {
		if (s[i] < '0' || s[i] > '9') return -1;
		v = v * 10 + (s[i] - '0');
		if (v > 0x7FFFFFFFLL) return -1;
		i++;
	}
	*out = (int)v;
	return 0;
}

static int batch_parse_opts(const str *opts, batch_opts_t *out)
{
	const char *p, *end, *pair_end, *eq;
	if (!opts || opts->len <= 0 || !opts->s) return 0; /* accept empty */

	p = opts->s;
	end = p + opts->len;
	while (p < end) {
		while (p < end && (*p == ' ' || *p == '\t' || *p == ';'))
			p++;
		if (p >= end) break;
		pair_end = memchr(p, ';', end - p);
		if (!pair_end) pair_end = end;
		eq = memchr(p, '=', pair_end - p);
		if (!eq) return -1;

		{
			const char *key = p;
			int keylen = (int)(eq - p);
			const char *val = eq + 1;
			int vallen = (int)(pair_end - val);

			while (keylen > 0 && (key[keylen-1]==' '||key[keylen-1]=='\t'))
				keylen--;
			while (vallen > 0 && (val[0]==' '||val[0]=='\t')) {
				val++; vallen--;
			}
			while (vallen > 0 && (val[vallen-1]==' '||val[vallen-1]=='\t'))
				vallen--;

			if (keylen == 5 && memcmp(key, "count", 5) == 0) {
				if (batch_parse_int(val, vallen, &out->count) < 0)
					return -1;
			} else if (keylen == 7 && memcmp(key, "expires", 7) == 0) {
				if (batch_parse_duration_ms(val, vallen,
						&out->expires_ms) < 0)
					return -1;
			} else if (keylen == 9 && memcmp(key, "max_bytes", 9) == 0) {
				if (batch_parse_int(val, vallen, &out->max_bytes) < 0)
					return -1;
			} else if (keylen == 7 && memcmp(key, "no_wait", 7) == 0) {
				if (vallen == 1 && val[0] == '1') out->no_wait = 1;
				else if (vallen == 1 && val[0] == '0') out->no_wait = 0;
				else return -1;
			} else {
				/* Unknown key: ignore silently for forward-compat. */
				LM_DBG("nats_fetch_batch: unknown opt '%.*s'\n",
					keylen, key);
			}
		}
		p = pair_end;
	}
	return 0;
}

static int batch_push_slot(uint16_t handle_idx, const nats_ring_slot_t *slot)
{
	if (g_batch.count >= NATS_BATCH_MAX) return -1;
	g_batch.msgs[g_batch.count].has_message = 1;
	g_batch.msgs[g_batch.count].handle_idx  = handle_idx;
	g_batch.msgs[g_batch.count].ack_token   = slot->ack_token;
	g_batch.msgs[g_batch.count].slot        = *slot;
	g_batch.count++;
	g_batch.handle_idx = handle_idx;
	return 0;
}

/* Sync batch fetch.  Drains up to opts.count messages; if expires>0
 * and fewer are ready, blocks on the eventfd for the remaining budget.
 * Returns the number of messages populated into g_batch. */
int w_nats_fetch_batch(struct sip_msg *msg, str *id, str *opts)
{
	nats_handle_t   *h;
	batch_opts_t     bo = { .count = 1, .expires_ms = 0 };
	nats_ring_slot_t slot;
	int              cap, fd;
	int              deadline_remaining;

	(void)msg;

	nats_fetch_clear();
	nats_fetch_clear_batch();

	h = nats_registry_lookup(id);
	if (!h || !h->ring) {
		LM_DBG("nats_fetch_batch: unknown / no-ring handle '%.*s'\n",
			id->len, id->s);
		return -3;
	}

	if (batch_parse_opts(opts, &bo) < 0) {
		LM_ERR("nats_fetch_batch: bad opts '%.*s'\n",
			opts ? opts->len : 0, opts ? opts->s : "");
		return -1;
	}
	if (bo.count <= 0) bo.count = 1;
	cap = bo.count < NATS_BATCH_MAX ? bo.count : NATS_BATCH_MAX;

	/* Phase 1: drain whatever is already visible. */
	while (g_batch.count < cap) {
		if (nats_ring_pop(h->ring, &slot) != 0) break;
		batch_push_slot(h->index, &slot);
	}
	if (g_batch.count >= cap)
		return g_batch.count;
	if (bo.no_wait || bo.expires_ms <= 0)
		return g_batch.count;

	/* Phase 2: wait up to expires_ms total.  We loop on poll() so a
	 * spurious wake (another worker raced us) doesn't exit early. */
	fd = nats_ring_eventfd(h->ring);
	if (fd < 0) return g_batch.count;

	deadline_remaining = bo.expires_ms;
	while (g_batch.count < cap && deadline_remaining > 0) {
		struct pollfd pfd;
		int prc;
		struct timespec t0, t1;
		int elapsed;

		pfd.fd = fd;
		pfd.events = POLLIN;
		pfd.revents = 0;

		clock_gettime(CLOCK_MONOTONIC, &t0);
		do {
			prc = poll(&pfd, 1, deadline_remaining);
		} while (prc < 0 && errno == EINTR);
		clock_gettime(CLOCK_MONOTONIC, &t1);

		evfd_drain(fd);

		while (g_batch.count < cap) {
			if (nats_ring_pop(h->ring, &slot) != 0) break;
			batch_push_slot(h->index, &slot);
		}

		elapsed = (int)((t1.tv_sec - t0.tv_sec) * 1000 +
			(t1.tv_nsec - t0.tv_nsec) / 1000000);
		if (elapsed <= 0) elapsed = 1;
		deadline_remaining -= elapsed;
		if (prc == 0) break; /* timeout */
	}

	return g_batch.count;
}

/* Async batch fetch parameter -- lives in SHM across resume. */
typedef struct nats_batch_async_param {
	uint16_t       handle_idx;
	int            evfd;
	int            cap;
	nats_ring_t   *ring;
	nats_handle_t *h_ref;  /* pending_ops guard across resume */
} nats_batch_async_param_t;

static int resume_nats_fetch_batch(int fd, struct sip_msg *msg, void *param)
{
	nats_batch_async_param_t *p = (nats_batch_async_param_t *)param;
	nats_ring_slot_t slot;

	(void)msg;

	async_status = ASYNC_DONE;

	if (!p) {
		LM_ERR("nats_fetch_batch: resume with NULL param\n");
		return -1;
	}

	evfd_drain(fd);

	while (g_batch.count < p->cap) {
		if (nats_ring_pop(p->ring, &slot) != 0) break;
		batch_push_slot(p->handle_idx, &slot);
	}

	if (g_batch.count > 0) {
		nats_handle_pending_dec(p->h_ref);
		shm_free(p);
		return g_batch.count;
	}

	/* Spurious wake -- another worker drained the ring before we could.
	 * Re-arm.  Phase 5 share: the async-core timeout_s is coarse; the
	 * deadline-aware timerfd would make this cleaner.  For now the
	 * reactor times the whole fetch out and we return 0. */
	async_status = ASYNC_CONTINUE;
	return 0;
}

int w_nats_fetch_batch_async(struct sip_msg *msg, async_ctx *ctx,
                             str *id, str *opts)
{
	nats_handle_t             *h;
	batch_opts_t               bo = { .count = 1, .expires_ms = 0 };
	nats_ring_slot_t           slot;
	nats_batch_async_param_t  *p;
	int                        cap, fd;

	(void)msg;

	nats_fetch_clear();
	nats_fetch_clear_batch();

	h = nats_registry_lookup(id);
	if (!h || !h->ring) {
		LM_DBG("nats_fetch_batch_async: unknown handle '%.*s'\n",
			id->len, id->s);
		async_status = ASYNC_NO_IO;
		return -3;
	}

	if (batch_parse_opts(opts, &bo) < 0) {
		async_status = ASYNC_NO_IO;
		return -1;
	}
	if (bo.count <= 0) bo.count = 1;
	cap = bo.count < NATS_BATCH_MAX ? bo.count : NATS_BATCH_MAX;

	while (g_batch.count < cap) {
		if (nats_ring_pop(h->ring, &slot) != 0) break;
		batch_push_slot(h->index, &slot);
	}

	if (g_batch.count > 0 || bo.no_wait || bo.expires_ms <= 0) {
		async_status = ASYNC_SYNC;
		return g_batch.count;
	}

	fd = nats_ring_eventfd(h->ring);
	if (fd < 0) {
		async_status = ASYNC_NO_IO;
		return -1;
	}

	p = (nats_batch_async_param_t *)shm_malloc(sizeof(*p));
	if (!p) {
		async_status = ASYNC_NO_IO;
		return -1;
	}
	p->handle_idx = h->index;
	p->evfd       = fd;
	p->cap        = cap;
	p->ring       = h->ring;
	p->h_ref      = h;
	nats_handle_pending_inc(h);

	ctx->timeout_s    = (unsigned int)((bo.expires_ms + 999) / 1000);
	ctx->resume_f     = resume_nats_fetch_batch;
	ctx->resume_param = p;

	async_status = fd;
	return 0;
}

/* Point g_cur at batch slot `index`.  This is the script's hook to
 * iterate through a batch: subsequent ack/nak/$nats_* reads see that
 * slot's data.  Returns 1 on success, -1 on bad index. */
int w_nats_batch_select(struct sip_msg *msg, int *index)
{
	int i;

	(void)msg;

	if (!index) return -1;
	i = *index;

	if (g_batch.count <= 0) {
		LM_DBG("nats_batch_select: no batch current\n");
		return -1;
	}
	if (i < 0 || i >= g_batch.count) {
		LM_DBG("nats_batch_select: index %d out of range [0,%d)\n",
			i, g_batch.count);
		return -1;
	}

	/* Copy the chosen slot into g_cur so ack/nak/pvar getters use it.
	 * Record the selected index in g_batch so the ack path knows which
	 * batch slot to drop when the worker acks. */
	g_cur = g_batch.msgs[i];
	g_batch.selected = i;
	return 1;
}

/* ── pseudo-var getters ─────────────────────────────────────── */

static inline int pv_null(pv_value_t *res)
{
	if (!res)
		return -1;
	memset(res, 0, sizeof(*res));
	res->flags = PV_VAL_NULL;
	return 0;
}

int pv_get_nats_subject(struct sip_msg *msg, pv_param_t *p, pv_value_t *res)
{
	str s;
	if (!g_cur.has_message)
		return pv_null(res);
	s.s   = g_cur.slot.subject;
	s.len = (int)g_cur.slot.subject_len;
	return pv_get_strval(msg, p, res, &s);
}

int pv_get_nats_data(struct sip_msg *msg, pv_param_t *p, pv_value_t *res)
{
	str s;
	if (!g_cur.has_message)
		return pv_null(res);
	s.s   = g_cur.slot.data;
	s.len = (int)g_cur.slot.data_len;
	return pv_get_strval(msg, p, res, &s);
}

int pv_get_nats_reply_to(struct sip_msg *msg, pv_param_t *p, pv_value_t *res)
{
	str s;
	if (!g_cur.has_message || !g_cur.slot.has_reply)
		return pv_null(res);
	s.s   = g_cur.slot.reply_to;
	s.len = (int)g_cur.slot.reply_to_len;
	return pv_get_strval(msg, p, res, &s);
}

int pv_get_nats_seq(struct sip_msg *msg, pv_param_t *p, pv_value_t *res)
{
	if (!g_cur.has_message)
		return pv_null(res);
	return pv_get_uintval(msg, p, res,
		(unsigned int)g_cur.slot.stream_seq);
}

int pv_get_nats_consumer_seq(struct sip_msg *msg, pv_param_t *p,
                             pv_value_t *res)
{
	if (!g_cur.has_message)
		return pv_null(res);
	return pv_get_uintval(msg, p, res,
		(unsigned int)g_cur.slot.consumer_seq);
}

int pv_get_nats_delivered(struct sip_msg *msg, pv_param_t *p, pv_value_t *res)
{
	if (!g_cur.has_message)
		return pv_null(res);
	return pv_get_uintval(msg, p, res,
		(unsigned int)g_cur.slot.delivered);
}

int pv_get_nats_pending(struct sip_msg *msg, pv_param_t *p, pv_value_t *res)
{
	if (!g_cur.has_message)
		return pv_null(res);
	return pv_get_uintval(msg, p, res,
		(unsigned int)g_cur.slot.pending);
}

int pv_get_nats_token(struct sip_msg *msg, pv_param_t *p, pv_value_t *res)
{
	/* The token is a 64-bit opaque value; the pv system exposes
	 * integers as `unsigned int` which is 32 bits.  We render it as
	 * hex string so scripts don't lose the handle index or generation
	 * bits.  The token is rarely used from scripts anyway -- the
	 * normal path is implicit (ack() reads g_cur.ack_token directly);
	 * this pvar is mostly for diagnostics. */
	static char buf[24];
	str s;

	if (!g_cur.has_message)
		return pv_null(res);

	s.s   = buf;
	s.len = snprintf(buf, sizeof(buf), "0x%016lx",
		(unsigned long)g_cur.ack_token);
	return pv_get_strval(msg, p, res, &s);
}
