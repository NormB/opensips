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
 * nats_consumer_proc.c -- dedicated JetStream pull consumer process.
 *
 *   The process owns one natsConnection (from the shared pool) and one
 *   jsCtx.  Every bound handle gets a single pull subscription owned by
 *   this process; the subscription pointer lives in process-local
 *   memory (g_subs) rather than in the SHM handle because the nats.c
 *   library's subscription objects are not SHM-safe.
 *
 *   On each iteration:
 *     1. reconcile_subs() walks the registry, creating a
 *        proc_sub_state_t + natsSubscription for any handle it has not
 *        yet seen.
 *     2. pull_one_batch() fetches up to PHASE3_FETCH_BATCH messages per
 *        subscription with a PHASE3_FETCH_TIMEOUT_MS timeout and pushes
 *        each into the handle's SHM ring.
 *     3. drain_ack_ipc() is a stub until Phase 4.
 *
 *   Back-pressure: when nats_ring_push returns -1 (ring full) we do
 *   not ack the message, so the broker will redeliver it after
 *   ack_wait.  We do NOT retry in a tight loop; the next outer
 *   iteration tries again.
 *
 *   PHASE 3 AUTO-ACK CAVEAT
 *   -----------------------
 *   Until Phase 4 wires a real ack_token + worker->consumer ack IPC,
 *   this process auto-acks every successfully-pushed message.  This
 *   keeps the consumer from burning through max_deliver instantly
 *   during bring-up -- BUT it is incorrect end-to-end semantics: a SIP
 *   worker that crashes between pop() and processing will never see
 *   that message again.  Phase 4 replaces natsMsg_Ack here with a
 *   stash-the-ref / issue-a-token sequence, and acks in drain_ack_ipc
 *   on the worker's command.
 */

#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include <nats/nats.h>

#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../lib/nats/nats_pool.h"

#include "nats_handle_registry.h"
#include "nats_ring.h"
#include "nats_ack_ipc.h"
#include "nats_consumer_proc.h"

/* ── tuning ──────────────────────────────────────────────────── */

#define PHASE3_FETCH_BATCH        10     /* messages per fetch */
#define PHASE3_FETCH_TIMEOUT_MS   1000   /* block up to 1 s per fetch */
#define PHASE3_IDLE_SLEEP_US      50000  /* 50 ms between empty rounds */

/* ── process-local state ─────────────────────────────────────── */

typedef struct proc_sub_state {
	str                   id;              /* copy of registry handle id
	                                        * (process-local buffer, NOT
	                                        *  shared) */
	natsSubscription     *sub;             /* active pull subscription */
	struct nats_ring     *ring;            /* borrowed ref to handle ring */
	time_t                last_fetch;

	/* counters -- local to this process, included in mi_info in Phase 4 */
	uint64_t              total_pulled;
	uint64_t              total_pushed;
	uint64_t              total_dropped_backpressure;
	uint64_t              total_fetch_errors;

	struct proc_sub_state *next;
} proc_sub_state_t;

static proc_sub_state_t *g_subs = NULL;
static natsConnection   *g_nc   = NULL;
static jsCtx            *g_js   = NULL;

/* ── forward declarations ────────────────────────────────────── */

static int  reconcile_subs_cb(nats_handle_t *h, void *user);
static int  ensure_subscription_for_handle(nats_handle_t *h);
static int  pull_one_batch(proc_sub_state_t *ss);
static void drain_ack_ipc(void);
static proc_sub_state_t *find_sub_by_id(const str *id);

/* ── enum mapping helpers ────────────────────────────────────── */

static jsDeliverPolicy map_deliver_policy(nats_deliver_policy_e p)
{
	switch (p) {
		case NATS_DELIVER_ALL:              return js_DeliverAll;
		case NATS_DELIVER_LAST:             return js_DeliverLast;
		case NATS_DELIVER_NEW:              return js_DeliverNew;
		case NATS_DELIVER_LAST_PER_SUBJECT: return js_DeliverLastPerSubject;
		case NATS_DELIVER_BY_START_SEQ:     return js_DeliverByStartSequence;
		case NATS_DELIVER_BY_START_TIME:    return js_DeliverByStartTime;
	}
	return js_DeliverAll;
}

static jsAckPolicy map_ack_policy(nats_ack_policy_e p)
{
	switch (p) {
		case NATS_ACK_EXPLICIT: return js_AckExplicit;
		case NATS_ACK_NONE:     return js_AckNone;
		case NATS_ACK_ALL:      return js_AckAll;
	}
	return js_AckExplicit;
}

static jsReplayPolicy map_replay_policy(nats_replay_policy_e p)
{
	switch (p) {
		case NATS_REPLAY_INSTANT:  return js_ReplayInstant;
		case NATS_REPLAY_ORIGINAL: return js_ReplayOriginal;
	}
	return js_ReplayInstant;
}

/* ── helpers ─────────────────────────────────────────────────── */

/* Return NULL-terminated const char * from a str, or NULL if the str
 * is empty.  nats.c expects NUL-terminated C strings in its config
 * structs; registry str buffers are not guaranteed to be NUL-terminated,
 * so we allocate a process-local copy for each subscription we set up.
 * Since subscriptions are long-lived (one per handle for the life of
 * the process), leaking these copies on unbind is acceptable in Phase
 * 3.  A proper cleanup path lands with unbind wiring in Phase 7. */
static char *str_to_cstr(const str *s)
{
	char *out;
	if (!s || s->len <= 0 || !s->s)
		return NULL;
	out = (char *)malloc((size_t)s->len + 1);
	if (!out)
		return NULL;
	memcpy(out, s->s, s->len);
	out[s->len] = '\0';
	return out;
}

static int dup_str_local(str *dst, const str *src)
{
	dst->s = (char *)malloc((size_t)src->len);
	if (!dst->s)
		return -1;
	memcpy(dst->s, src->s, src->len);
	dst->len = src->len;
	return 0;
}

static proc_sub_state_t *find_sub_by_id(const str *id)
{
	proc_sub_state_t *s;
	for (s = g_subs; s; s = s->next) {
		if (s->id.len == id->len &&
		    memcmp(s->id.s, id->s, id->len) == 0)
			return s;
	}
	return NULL;
}

/* ── subscription setup ──────────────────────────────────────── */

/*
 * Create a pull subscription for `h` if this process has not already
 * done so.  Succeeds idempotently: if we already have a proc_sub_state
 * for this id, returns 0 without touching the server.
 *
 * The c-string fields passed into nats.c config structs are leaked
 * intentionally (see str_to_cstr comment) -- Phase 3 has no unbind-
 * aware cleanup.
 */
static int ensure_subscription_for_handle(nats_handle_t *h)
{
	proc_sub_state_t *ss;
	jsConsumerConfig  cc;
	jsSubOptions      so;
	natsStatus        s;
	char             *durable_c = NULL;
	char             *filter_c  = NULL;
	char             *stream_c  = NULL;

	if (!h || !h->ring)
		return 0;   /* handle still being constructed or TEST_SHIM */

	if (find_sub_by_id(&h->id))
		return 0;   /* already subscribed */

	ss = (proc_sub_state_t *)calloc(1, sizeof(*ss));
	if (!ss) {
		LM_ERR("nats_consumer_proc: proc_sub_state calloc failed\n");
		return -1;
	}
	if (dup_str_local(&ss->id, &h->id) < 0) {
		LM_ERR("nats_consumer_proc: id dup failed\n");
		free(ss);
		return -1;
	}
	ss->ring = h->ring;

	/* Build jsConsumerConfig.  Phase 3 covers the critical fields;
	 * Phase 5 fills in the rest (backoff, sample_freq, rate_limit,
	 * filters_csv multi-filter, inactive_threshold, js_domain,
	 * api_prefix, extra_json). */
	jsConsumerConfig_Init(&cc);

	durable_c = str_to_cstr(&h->durable);
	filter_c  = str_to_cstr(&h->filter);
	stream_c  = str_to_cstr(&h->stream);

	if (h->type == NATS_CONSUMER_DURABLE && durable_c)
		cc.Durable = durable_c;
	if (filter_c)
		cc.FilterSubject = filter_c;

	cc.DeliverPolicy  = map_deliver_policy(h->deliver_policy);
	cc.AckPolicy      = map_ack_policy(h->ack_policy);
	cc.ReplayPolicy   = map_replay_policy(h->replay_policy);

	if (h->ack_wait_ms > 0)
		cc.AckWait = (int64_t)h->ack_wait_ms * 1000000LL;
	if (h->max_deliver > 0)
		cc.MaxDeliver = (int64_t)h->max_deliver;
	if (h->max_ack_pending > 0)
		cc.MaxAckPending = (int64_t)h->max_ack_pending;

	if (h->deliver_policy == NATS_DELIVER_BY_START_SEQ)
		cc.OptStartSeq = h->start_seq;
	if (h->deliver_policy == NATS_DELIVER_BY_START_TIME)
		cc.OptStartTime = h->start_time_unix_ns;

	jsSubOptions_Init(&so);
	so.Stream    = stream_c;
	so.Config    = cc;
	/* We drive acks ourselves (Phase 3 auto-acks after push to ring). */
	so.ManualAck = true;

	s = js_PullSubscribe(&ss->sub, g_js,
		filter_c /* subject -- may be NULL when Config has FilterSubject */,
		durable_c /* durable -- may be NULL for ephemeral */,
		NULL /* jsOptions */,
		&so,
		NULL /* jsErrCode */);
	if (s != NATS_OK) {
		LM_ERR("nats_consumer_proc: js_PullSubscribe('%.*s') failed: %s\n",
			h->id.len, h->id.s, natsStatus_GetText(s));
		free(ss->id.s);
		free(ss);
		/* durable_c / filter_c / stream_c are leaked on failure --
		 * acceptable for the short-lived failure path; Phase 7 will
		 * tidy this. */
		return -1;
	}

	ss->last_fetch = 0;
	ss->next = g_subs;
	g_subs = ss;

	/* Publish the subscription pointer back to the handle so MI can
	 * introspect it (read-only).  This is a process-local pointer the
	 * SIP workers must not dereference; they just observe non-NULL as
	 * "consumer process has a live sub". */
	h->subscription = (void *)ss->sub;

	LM_INFO("nats_consumer_proc: subscribed id='%.*s' stream='%.*s' "
		"filter='%.*s' durable='%.*s'\n",
		h->id.len, h->id.s,
		h->stream.len, h->stream.s,
		h->filter.len, h->filter.s,
		h->durable.len, h->durable.s);

	return 0;
}

static int reconcile_subs_cb(nats_handle_t *h, void *user)
{
	(void)user;
	/* ignore individual-handle failures; Phase 3 retries next tick
	 * because find_sub_by_id() keeps returning NULL for that id */
	(void)ensure_subscription_for_handle(h);
	return 0;
}

/* ── fetch loop ──────────────────────────────────────────────── */

static int pull_one_batch(proc_sub_state_t *ss)
{
	natsMsgList  list;
	natsStatus   s;
	int          pushed = 0;
	int          i;

	if (!ss || !ss->sub || !ss->ring)
		return 0;

	memset(&list, 0, sizeof(list));
	s = natsSubscription_Fetch(&list, ss->sub,
	        PHASE3_FETCH_BATCH, PHASE3_FETCH_TIMEOUT_MS, NULL);

	/* Fast path on idle: timeout is the steady-state condition when
	 * the broker has nothing to send us. */
	if (s == NATS_TIMEOUT)
		return 0;

	if (s == NATS_CONNECTION_CLOSED) {
		LM_DBG("nats_consumer_proc: connection closed during fetch "
			"on id='%.*s'\n", ss->id.len, ss->id.s);
		return 0;
	}

	if (s != NATS_OK && list.Count == 0) {
		/* Non-fatal per-sub error; log at DBG to avoid flooding logs
		 * when e.g. max_ack_pending gates us out. */
		ss->total_fetch_errors++;
		LM_DBG("nats_consumer_proc: fetch id='%.*s': %s\n",
			ss->id.len, ss->id.s, natsStatus_GetText(s));
		return 0;
	}

	ss->total_pulled += (uint64_t)list.Count;
	ss->last_fetch = time(NULL);

	for (i = 0; i < list.Count; i++) {
		natsMsg    *m = list.Msgs[i];
		const char *subject;
		const char *data;
		const char *reply;
		int         data_len;
		size_t      subject_len;
		size_t      reply_len;

		jsMsgMetaData *md = NULL;
		uint64_t  stream_seq   = 0;
		uint64_t  consumer_seq = 0;
		uint64_t  delivered    = 0;
		uint64_t  pending      = 0;
		int64_t   timestamp_ns = 0;
		uint64_t  ack_token    = 0;   /* Phase 4 will assign */

		int rc;

		if (!m)
			continue;

		subject     = natsMsg_GetSubject(m);
		data        = natsMsg_GetData(m);
		data_len    = natsMsg_GetDataLength(m);
		reply       = natsMsg_GetReply(m);
		subject_len = subject ? strlen(subject) : 0;
		reply_len   = reply   ? strlen(reply)   : 0;

		if (natsMsg_GetMetaData(&md, m) == NATS_OK && md) {
			stream_seq   = md->Sequence.Stream;
			consumer_seq = md->Sequence.Consumer;
			delivered    = md->NumDelivered;
			pending      = md->NumPending;
			timestamp_ns = md->Timestamp;
			jsMsgMetaData_Destroy(md);
		}

		rc = nats_ring_push(ss->ring,
			subject ? subject : "", (uint32_t)subject_len,
			data    ? data    : "", (uint32_t)data_len,
			stream_seq, consumer_seq, delivered, pending,
			timestamp_ns, ack_token,
			reply   ? reply   : "", (uint32_t)reply_len);

		if (rc == 0) {
			pushed++;
			ss->total_pushed++;

			/* --------------------------------------------------
			 * PHASE 3 AUTO-ACK
			 * --------------------------------------------------
			 * Without ack_token plumbing, workers cannot issue
			 * acks yet.  Auto-ack here prevents max_deliver
			 * exhaustion during bring-up.  REPLACE in Phase 4
			 * with: stash `m` under a freshly minted ack_token
			 * (don't destroy it here), and ack in
			 * drain_ack_ipc() on worker request.
			 * -------------------------------------------------- */
			(void)natsMsg_Ack(m, NULL);
		} else if (rc == -1) {
			/* Ring full: don't ack.  Broker redelivers after
			 * ack_wait.  Don't spin fetching more for this
			 * handle this tick -- the outer loop rate-limits. */
			ss->total_dropped_backpressure++;
			LM_DBG("nats_consumer_proc: ring full id='%.*s', "
				"deferring message\n",
				ss->id.len, ss->id.s);
		} else {
			/* -2 / -3: payload or subject too large.  These are
			 * permanently undeliverable on the current ring
			 * geometry; terminate the message so the broker
			 * doesn't redeliver forever. */
			ss->total_dropped_backpressure++;
			LM_WARN("nats_consumer_proc: oversize message on "
				"id='%.*s' (subject_len=%zu data_len=%d rc=%d); "
				"terminating\n",
				ss->id.len, ss->id.s,
				subject_len, data_len, rc);
			(void)natsMsg_Term(m, NULL);
		}

		natsMsg_Destroy(m);
		list.Msgs[i] = NULL;
	}

	/* natsMsgList_Destroy walks the Msgs array and destroys any
	 * non-NULL entries; we've already destroyed ours above, so this
	 * just frees the Msgs array itself. */
	natsMsgList_Destroy(&list);

	return pushed;
}

/* ── ack IPC drain stub ──────────────────────────────────────── */

static void drain_ack_ipc(void)
{
	/* Phase 3 stub.  The SHM queue is allocated in mod_init but has
	 * no producers; Phase 4 will read pending ack requests here and
	 * route them to natsMsg_Ack / Nak / Term / InProgress. */
	nats_ack_ipc_drain();
}

/* ── main loop ───────────────────────────────────────────────── */

void nats_consumer_proc_main(int rank)
{
	LM_INFO("nats_consumer_proc: starting (pid=%d rank=%d)\n",
		(int)getpid(), rank);

	g_nc = nats_pool_get();
	if (!g_nc) {
		LM_ERR("nats_consumer_proc: no NATS connection in "
			"consumer process\n");
		return;
	}
	g_js = nats_pool_get_js();
	if (!g_js) {
		LM_ERR("nats_consumer_proc: no JetStream context in "
			"consumer process\n");
		return;
	}

	LM_INFO("nats_consumer_proc: pool ready, entering main loop\n");

	for (;;) {
		proc_sub_state_t *ss;
		int any_work = 0;

		/* 1. Reconcile subscriptions with the registry.  New binds
		 *    land here on the next tick; unbinds leave a dangling
		 *    proc_sub_state_t whose ring pointer is stale -- Phase 7
		 *    adds the teardown path. */
		(void)nats_registry_foreach(reconcile_subs_cb, NULL);

		/* 2. Fetch + push for every live subscription.  A ring-full
		 *    handle contributes 0 to any_work so the idle sleep
		 *    applies and we don't burn CPU spinning on it. */
		for (ss = g_subs; ss; ss = ss->next) {
			int pushed = pull_one_batch(ss);
			if (pushed > 0)
				any_work = 1;
		}

		/* 3. Service pending ack requests (stub in Phase 3). */
		drain_ack_ipc();

		if (!any_work)
			usleep(PHASE3_IDLE_SLEEP_US);
	}
}
