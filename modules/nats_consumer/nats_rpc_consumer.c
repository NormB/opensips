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
 * nats_rpc_consumer.c -- consumer-process side of the phase-5
 * async nats_request transport.  See nats_rpc_consumer.h for
 * the architecture rationale.
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdatomic.h>
#include <unistd.h>
#include <errno.h>

#include <nats/nats.h>

#include "../../dprint.h"
#include "../../lib/nats/nats_pool.h"

#include "nats_rpc_consumer.h"
#include "nats_rpc_slot.h"
#include "nats_rpc_ipc.h"
#include "nats_ring.h"     /* NATS_RING_*_MAX */

/* Shared headers helper -- promoted to public in nats_rpc.c so
 * the sync, async-worker (phase 1/2), and async-consumer (phase 5)
 * reply paths produce byte-identical serialised header streams. */
extern int nats_rpc_hdr_serialize_from_reply(natsMsg *m, char *out, int cap,
                                              int *truncated, int *count_out);

/*
 * Persistent inbox subscription handle.  Lives only inside the
 * consumer process; the file descriptor / thread state is owned
 * by libnats.  Cleared on consumer shutdown.
 */
static natsSubscription *g_inbox_sub = NULL;

/* Cached consumer-side inbox prefix used to (a) format the
 * SUBSCRIBE subject and (b) parse the slot_idx out of incoming
 * reply subjects.  Format: "_INBOX.opensips.<pid>".  The reply
 * subject pattern is "<prefix>.<slot_idx>". */
#define NATS_RPC_INBOX_PREFIX "_INBOX.opensips"
static char g_inbox_prefix[64];
static int  g_inbox_prefix_len;

/* ── reply callback (libnats thread) ─────────────────────────── */

/*
 * Parse the slot_idx suffix from a reply subject.  Returns -1 on
 * malformed input.  Format expected:
 *
 *     <g_inbox_prefix>.<decimal-slot-idx>
 *
 * The prefix already contains the consumer pid so we don't need
 * to revalidate it.  We only need the slot_idx.
 */
static int parse_slot_idx(const char *subject, int subject_len,
                          uint32_t *out_slot)
{
	const char *dot;
	long        v;
	int         i;
	const char *p;

	if (!subject || subject_len <= 0 || !out_slot) return -1;

	/* find the LAST '.' which separates the slot_idx suffix */
	dot = NULL;
	for (i = subject_len - 1; i >= 0; i--) {
		if (subject[i] == '.') { dot = subject + i; break; }
	}
	if (!dot || dot >= subject + subject_len - 1)
		return -1;

	/* digit-only scan of the tail */
	v = 0;
	for (p = dot + 1; p < subject + subject_len; p++) {
		if (*p < '0' || *p > '9') return -1;
		v = v * 10 + (*p - '0');
		if (v > 0x7fffffffL) return -1;   /* clamp */
	}
	*out_slot = (uint32_t)v;
	return 0;
}

/*
 * libnats subscription callback.  Runs on a libnats internal
 * thread INSIDE the consumer process -- safe for libnats use
 * but MUST NOT touch OpenSIPS APIs that are worker-private.
 *
 * We only touch the SHM slot (via the slot_idx parsed from the
 * reply subject suffix): copy the reply payload into the slot,
 * transition state INFLIGHT -> DELIVERED with release ordering.
 * The worker side polls slot->state on each tick of a
 * worker-private timerfd (phase 5b wake mechanism); we do not
 * signal any fd from this callback.
 */
static void on_inbox_reply(natsConnection *nc, natsSubscription *sub,
                            natsMsg *msg, void *closure)
{
	const char *subject;
	const char *data;
	const char *reply_to;
	int         data_len;
	int         subj_len;
	int         reply_len = 0;
	uint32_t    slot_idx = 0;
	nats_rpc_slot_t *s;

	(void)nc; (void)sub; (void)closure;

	if (!msg) return;

	subject  = natsMsg_GetSubject(msg);
	subj_len = subject ? (int)strlen(subject) : 0;
	data     = natsMsg_GetData(msg);
	data_len = natsMsg_GetDataLength(msg);
	reply_to = natsMsg_GetReply(msg);
	if (reply_to) reply_len = (int)strlen(reply_to);

	if (parse_slot_idx(subject, subj_len, &slot_idx) < 0) {
		/* malformed reply subject -- drop quietly.  Could be
		 * an unrelated message that matched our wildcard or a
		 * malicious peer; either way, no slot to deliver to. */
		natsMsg_Destroy(msg);
		return;
	}

	s = nats_rpc_slot_lookup(slot_idx);
	if (!s) {
		/* slot is FREE or out of range -- either the worker
		 * timed out and freed the slot before the reply
		 * arrived, or a stale reply from a previous use of
		 * the same slot.  Drop silently. */
		natsMsg_Destroy(msg);
		return;
	}

	/* Refuse to overwrite if the worker already ABANDONED or
	 * the slot somehow transitioned to a non-INFLIGHT state.
	 * The slot's state field is the source of truth. */
	{
		int cur = atomic_load_explicit(&s->state, memory_order_acquire);
		if (cur != NATS_RPC_SLOT_INFLIGHT) {
			natsMsg_Destroy(msg);
			return;
		}
	}

	/* Copy subject (bounded). */
	if (subj_len > NATS_RING_SUBJECT_MAX) subj_len = NATS_RING_SUBJECT_MAX;
	if (subj_len > 0 && subject)
		memcpy(s->reply_subject, subject, subj_len);
	s->reply_subject_len = (uint32_t)subj_len;

	/* Copy payload (bounded). */
	if (data_len < 0) data_len = 0;
	if (data_len > NATS_RING_PAYLOAD_MAX) data_len = NATS_RING_PAYLOAD_MAX;
	if (data_len > 0 && data)
		memcpy(s->reply_data, data, data_len);
	s->reply_data_len = (uint32_t)data_len;

	/* Copy reply-to if present. */
	if (reply_to && reply_len > 0) {
		if (reply_len > NATS_RING_SUBJECT_MAX)
			reply_len = NATS_RING_SUBJECT_MAX;
		memcpy(s->reply_to, reply_to, reply_len);
		s->reply_to_len = (uint32_t)reply_len;
		s->reply_has_reply_to = 1;
	} else {
		s->reply_to_len = 0;
		s->reply_has_reply_to = 0;
	}

	/* Serialise headers using the shared helper -- same wire
	 * format as the sync nats_reply / fetch paths. */
	{
		int trunc = 0, count = 0;
		int hdr_len = nats_rpc_hdr_serialize_from_reply(msg,
			s->reply_headers, NATS_RING_HEADERS_MAX,
			&trunc, &count);
		if (hdr_len < 0) hdr_len = 0;
		s->reply_headers_len       = (uint16_t)hdr_len;
		s->reply_headers_truncated = (uint8_t)(trunc ? 1 : 0);
	}

	/* Publish the slot transition.  Release ordering ensures the
	 * worker (acquire on state load in the resume function) sees
	 * the reply_* fields on its next timerfd-tick poll. */
	atomic_store_explicit(&s->state, NATS_RPC_SLOT_DELIVERED,
		memory_order_release);

	natsMsg_Destroy(msg);
}

/* ── public API ──────────────────────────────────────────────── */

int nats_rpc_consumer_subscribe(void)
{
	natsConnection *nc;
	natsStatus      s;
	char            wildcard[80];
	int             n;
	pid_t           pid;

	if (g_inbox_sub) {
		LM_DBG("nats_rpc_consumer_subscribe: already subscribed\n");
		return 0;
	}

	nc = nats_pool_get();
	if (!nc) {
		LM_ERR("nats_rpc_consumer_subscribe: no NATS connection\n");
		return -1;
	}

	pid = getpid();
	g_inbox_prefix_len = snprintf(g_inbox_prefix, sizeof(g_inbox_prefix),
		"%s.%d", NATS_RPC_INBOX_PREFIX, (int)pid);
	if (g_inbox_prefix_len <= 0 ||
	    g_inbox_prefix_len >= (int)sizeof(g_inbox_prefix)) {
		LM_ERR("nats_rpc_consumer_subscribe: prefix overflow\n");
		return -1;
	}

	n = snprintf(wildcard, sizeof(wildcard), "%s.>", g_inbox_prefix);
	if (n <= 0 || n >= (int)sizeof(wildcard)) {
		LM_ERR("nats_rpc_consumer_subscribe: wildcard overflow\n");
		return -1;
	}

	s = natsConnection_Subscribe(&g_inbox_sub, nc, wildcard,
		on_inbox_reply, NULL);
	if (s != NATS_OK || !g_inbox_sub) {
		LM_ERR("nats_rpc_consumer_subscribe: Subscribe(%s) failed: %s\n",
			wildcard, natsStatus_GetText(s));
		g_inbox_sub = NULL;
		return -1;
	}

	LM_INFO("nats_rpc_consumer: subscribed inbox %s\n", wildcard);
	return 0;
}

void nats_rpc_consumer_unsubscribe(void)
{
	if (g_inbox_sub) {
		natsSubscription_Unsubscribe(g_inbox_sub);
		natsSubscription_Destroy(g_inbox_sub);
		g_inbox_sub = NULL;
	}
}

/* ── IPC drain ───────────────────────────────────────────────── */

/*
 * Build the outbound natsMsg from a slot's out_* fields and
 * publish it with reply-to pointing at our inbox subject so the
 * remote responder echoes a reply back into us.
 *
 * Header staging is intentionally NOT handled here -- the
 * worker already applied any script-staged headers BEFORE the
 * publish (via the existing nats_rpc_staged_apply_and_clear_on
 * path during w_nats_request_async).  Wait, actually in phase 5
 * the worker does NOT call PublishMsg; it queues a slot to the
 * consumer.  So we need to think about header propagation:
 * we'd want to embed the staged headers in the slot's
 * out_headers buffer (which the worker fills before publish)
 * and have THIS function attach them via natsMsgHeader_Set
 * before publishing.
 *
 * Phase-5 step 3 (this commit) leaves headers as a TODO --
 * the slot has out_headers space and the worker is wired to
 * fill it in step 4, but the actual natsMsgHeader_Set
 * deserialise loop is not yet wired here.  The first
 * end-to-end test of phase 5 (no custom headers, just the
 * UUIDv7 inbox subject) will work; richer header propagation
 * lands in step 4.
 */
static void publish_cb(const nats_rpc_ipc_msg_t *msg, void *user)
{
	nats_rpc_slot_t *s;
	natsMsg         *out = NULL;
	natsStatus       st;
	char             reply_subject[80 + 16];
	natsConnection  *nc = (natsConnection *)user;
	char             subj_c[NATS_RING_SUBJECT_MAX + 1];
	int              n;

	if (!msg || !nc) return;

	s = nats_rpc_slot_lookup(msg->slot_idx);
	if (!s) {
		LM_DBG("nats_rpc_consumer: drained publish for free slot %u "
			"(worker timed out?)\n", (unsigned)msg->slot_idx);
		return;
	}

	/* Defensive: only proceed if the slot is INFLIGHT.  A worker
	 * that ABANDONED before the consumer drained the IPC
	 * (e.g. on a tight timeout race) should not get its publish
	 * sent. */
	{
		int cur = atomic_load_explicit(&s->state, memory_order_acquire);
		if (cur != NATS_RPC_SLOT_INFLIGHT)
			return;
	}

	/* Format the reply-to inbox subject pointing back at us. */
	n = snprintf(reply_subject, sizeof(reply_subject), "%s.%u",
		g_inbox_prefix, (unsigned)s->slot_idx);
	if (n <= 0 || n >= (int)sizeof(reply_subject)) {
		LM_ERR("nats_rpc_consumer: reply-subject overflow for slot %u\n",
			(unsigned)s->slot_idx);
		atomic_store_explicit(&s->state, NATS_RPC_SLOT_ABANDONED,
			memory_order_release);
		return;
	}

	/* Subject must be NUL-terminated for libnats; copy from the
	 * slot's bounded buffer with explicit NUL. */
	if (s->out_subject_len > NATS_RING_SUBJECT_MAX) {
		LM_ERR("nats_rpc_consumer: subject overflow on slot %u\n",
			(unsigned)s->slot_idx);
		atomic_store_explicit(&s->state, NATS_RPC_SLOT_ABANDONED,
			memory_order_release);
		return;
	}
	memcpy(subj_c, s->out_subject, s->out_subject_len);
	subj_c[s->out_subject_len] = '\0';

	st = natsMsg_Create(&out, subj_c, reply_subject,
		(const char *)s->out_data, (int)s->out_data_len);
	if (st != NATS_OK || !out) {
		LM_ERR("nats_rpc_consumer: natsMsg_Create failed for slot %u: %s\n",
			(unsigned)s->slot_idx, natsStatus_GetText(st));
		atomic_store_explicit(&s->state, NATS_RPC_SLOT_ABANDONED,
			memory_order_release);
		return;
	}

	st = natsConnection_PublishMsg(nc, out);
	natsMsg_Destroy(out);
	if (st != NATS_OK) {
		LM_ERR("nats_rpc_consumer: PublishMsg failed for slot %u: %s\n",
			(unsigned)s->slot_idx, natsStatus_GetText(st));
		atomic_store_explicit(&s->state, NATS_RPC_SLOT_ABANDONED,
			memory_order_release);
		return;
	}
	/* Slot stays INFLIGHT; the reply (matching reply_subject)
	 * will land in on_inbox_reply and transition the slot to
	 * DELIVERED.  The worker side polls the slot state on each
	 * tick of its private timerfd; no fd signaling needed. */
}

int nats_rpc_consumer_drain_ipc(void)
{
	natsConnection *nc = nats_pool_get();
	if (!nc) return 0;
	return nats_rpc_ipc_drain(publish_cb, (void *)nc);
}
