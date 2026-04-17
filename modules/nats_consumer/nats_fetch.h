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
 * nats_fetch.h -- script-callable fetch functions and per-worker
 * current-message state.
 *
 * The per-worker `nats_cur_msg_t` is module-global (static in
 * nats_fetch.c).  OpenSIPS SIP workers are single-threaded processes,
 * so a plain static gives us thread-local semantics without the
 * __thread keyword.  A fetch populates it; subsequent ack/nak/pvar
 * reads consume it.
 *
 * Phase 4 exposes two entry points for fetching:
 *   - w_nats_fetch          (sync, cmd_export)
 *   - w_nats_fetch_async    (async, acmd_export with async_ctx)
 *
 * Batch fetch is deferred to Phase 5.
 */

#ifndef NATS_FETCH_H
#define NATS_FETCH_H

#include <stdint.h>

#include "../../str.h"
#include "../../async.h"
#include "../../parser/msg_parser.h"
#include "../../pvar.h"

#include "nats_ring.h"

/*
 * Per-worker "current message" state.  Populated by a successful fetch
 * and consumed by the ack / nak / pvar exports.  SIP workers are
 * single-threaded so the static has process-local semantics.
 */
typedef struct nats_cur_msg {
	int      has_message;          /* 1 iff the rest is valid */
	uint16_t handle_idx;           /* index of the source handle */
	uint64_t ack_token;             /* opaque token for ack/nak */

	/* A payload slot copy taken from the ring.  We keep the whole
	 * slot so pvar getters can reach the reply-to and broker metadata
	 * without a second pop. */
	nats_ring_slot_t slot;
} nats_cur_msg_t;

/*
 * Phase 5 batch fetch: cap of NATS_BATCH_MAX drained slots kept in a
 * per-worker buffer.  The script iterates by calling nats_batch_select(i)
 * which points g_cur at slot i before ack/nak/pvar reads.
 *
 * The cap is bounded to keep the per-worker SHM footprint predictable;
 * 32 slots ~= 32 * ~17 KB = ~540 KB per worker, matching the per-ring
 * slot size in nats_ring.h.
 */
#define NATS_BATCH_MAX 32

typedef struct nats_cur_batch {
	int             count;     /* number of valid slots */
	int             selected;  /* -1 = none selected yet */
	uint16_t        handle_idx; /* shared across the batch */
	nats_cur_msg_t  msgs[NATS_BATCH_MAX];
} nats_cur_batch_t;

/* Get / clear the current-message state for this worker. */
nats_cur_msg_t *nats_fetch_current(void);
void            nats_fetch_clear(void);

/* Get the per-worker batch buffer (read-mostly for the ack path). */
nats_cur_batch_t *nats_fetch_current_batch(void);
void              nats_fetch_clear_batch(void);

/* Script-callable: sync-fetch.
 *   timeout_ms == 0  -> non-blocking poll; returns 1 on hit, 0 on empty.
 *   timeout_ms > 0   -> blocks the worker up to timeout_ms; returns 1/0.
 * Returns -3 on handle-not-found, -1 on internal error. */
int w_nats_fetch(struct sip_msg *msg, str *id, int *timeout_ms);

/* Script-callable: async fetch.  Short-circuits to success if the
 * ring has data already; otherwise registers the ring eventfd with
 * the async reactor and yields the worker. */
int w_nats_fetch_async(struct sip_msg *msg, async_ctx *ctx,
                       str *id, int *timeout_ms);

/* Script-callable: sync batch fetch.
 *   `opts` is a k=v;k=v string; recognized keys:
 *     count=<n>         -- request up to n messages (cap NATS_BATCH_MAX)
 *     expires=<dur>     -- total wait budget (ms unless suffixed)
 *     max_bytes=<n>     -- byte cap (advisory, passed through)
 *     no_wait=<0|1>     -- if 1, return immediately with whatever is ready
 * Returns the number of messages retrieved (0..NATS_BATCH_MAX).
 * Populates the per-worker batch buffer; does NOT set g_cur.
 * Returns -3 on unknown handle, -1 on parse / internal error. */
int w_nats_fetch_batch(struct sip_msg *msg, str *id, str *opts);

/* Script-callable: async batch fetch.  Same semantics as above; yields
 * the worker if no messages are currently ready and `expires` > 0. */
int w_nats_fetch_batch_async(struct sip_msg *msg, async_ctx *ctx,
                             str *id, str *opts);

/* Script-callable: select slot i of the current batch.  Sets g_cur to
 * point at msgs[i] so subsequent ack/nak/$nats_* reads see that slot's
 * metadata.  Returns 1 on success, -1 if i is out of range or no batch
 * is current. */
int w_nats_batch_select(struct sip_msg *msg, int *index);

/* ── pseudo-var getters ─────────────────────────────────────────
 * Exposed to the pvar table; all read g_cur. */
int pv_get_nats_subject  (struct sip_msg *msg, pv_param_t *p, pv_value_t *res);
int pv_get_nats_data     (struct sip_msg *msg, pv_param_t *p, pv_value_t *res);
int pv_get_nats_reply_to (struct sip_msg *msg, pv_param_t *p, pv_value_t *res);
int pv_get_nats_seq      (struct sip_msg *msg, pv_param_t *p, pv_value_t *res);
int pv_get_nats_delivered(struct sip_msg *msg, pv_param_t *p, pv_value_t *res);
int pv_get_nats_pending  (struct sip_msg *msg, pv_param_t *p, pv_value_t *res);
int pv_get_nats_token    (struct sip_msg *msg, pv_param_t *p, pv_value_t *res);
int pv_get_nats_consumer_seq(struct sip_msg *msg, pv_param_t *p, pv_value_t *res);

#endif /* NATS_FETCH_H */
