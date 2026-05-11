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
 * nats_ack.c -- script-callable ack / nak / term / in_progress.
 *
 * Pattern: build a nats_ack_ipc_msg_t from the per-worker current
 * message's ack_token and the requested action, enqueue it into the
 * SHM queue, and clear the current-message state.  The consumer
 * process drains the queue and calls the corresponding natsMsg_*.
 *
 * `nats_in_progress()` does NOT clear the current-message state --
 * that action tells the broker "still working on this, reset the
 * ack_wait timer" but the worker still intends to ack/nak later.
 * The others (ack/nak/term) clear it so an accidental second call
 * fails with -1 instead of sending a duplicate IPC.
 */

#include "../../dprint.h"

#include "nats_ack.h"
#include "nats_fetch.h"
#include "nats_ack_ipc.h"

static int send_ack_ipc(uint64_t token, nats_ack_action_e action,
                        uint32_t delay_ms)
{
	nats_ack_ipc_msg_t m;
	m.ack_token = token;
	m.action    = (uint32_t)action;
	m.delay_ms  = delay_ms;
	if (nats_ack_ipc_enqueue(&m) < 0) {
		LM_ERR("nats_ack: IPC enqueue failed for token=0x%016lx "
			"action=%d (queue full?)\n",
			(unsigned long)token, (int)action);
		return -2;
	}
	return 1;
}

/* Batch-aware clear.  If the currently-selected batch slot is finalized
 * (ack/nak/term), invalidate it so an unguarded re-select doesn't
 * resubmit the same token. */
static void finalize_current(void)
{
	nats_cur_batch_t *bt = nats_fetch_current_batch();

	if (bt && bt->selected >= 0 && bt->selected < bt->count) {
		/* Mark the batch slot as consumed so a second select+ack on
		 * the same index is a no-op.  Keep count + handle_idx so the
		 * script can still iterate the remaining slots. */
		bt->msgs[bt->selected].has_message = 0;
		bt->msgs[bt->selected].ack_token   = 0;
		bt->selected = -1;
	}
	nats_fetch_clear();
}

int w_nats_ack(struct sip_msg *msg)
{
	nats_cur_msg_t *cur = nats_fetch_current();
	int rc;

	(void)msg;

	if (!cur || !cur->has_message) {
		LM_DBG("nats_ack: no current message to ack\n");
		return -1;
	}
	rc = send_ack_ipc(cur->ack_token, NATS_ACK_ACTION_ACK, 0);
	if (rc == 1)
		finalize_current();
	return rc;
}

int w_nats_nak(struct sip_msg *msg)
{
	nats_cur_msg_t *cur = nats_fetch_current();
	int rc;

	(void)msg;

	if (!cur || !cur->has_message) {
		LM_DBG("nats_nak: no current message to nak\n");
		return -1;
	}
	rc = send_ack_ipc(cur->ack_token, NATS_ACK_ACTION_NAK, 0);
	if (rc == 1)
		finalize_current();
	return rc;
}

int w_nats_nak_delay(struct sip_msg *msg, int *delay_ms)
{
	nats_cur_msg_t *cur = nats_fetch_current();
	uint32_t dly;
	int rc;

	(void)msg;

	if (!cur || !cur->has_message) {
		LM_DBG("nats_nak_delay: no current message\n");
		return -1;
	}
	dly = (delay_ms && *delay_ms > 0) ? (uint32_t)*delay_ms : 0;
	rc = send_ack_ipc(cur->ack_token, NATS_ACK_ACTION_NAK_DELAY, dly);
	if (rc == 1)
		finalize_current();
	return rc;
}

int w_nats_term(struct sip_msg *msg)
{
	nats_cur_msg_t *cur = nats_fetch_current();
	int rc;

	(void)msg;

	if (!cur || !cur->has_message) {
		LM_DBG("nats_term: no current message\n");
		return -1;
	}
	rc = send_ack_ipc(cur->ack_token, NATS_ACK_ACTION_TERM, 0);
	if (rc == 1)
		finalize_current();
	return rc;
}

int w_nats_in_progress(struct sip_msg *msg)
{
	nats_cur_msg_t *cur = nats_fetch_current();

	(void)msg;

	if (!cur || !cur->has_message) {
		LM_DBG("nats_in_progress: no current message\n");
		return -1;
	}
	/* Deliberately DO NOT clear the current message on in_progress --
	 * the worker is telling the broker "still working on it", so the
	 * subsequent ack/nak still needs g_cur. */
	return send_ack_ipc(cur->ack_token, NATS_ACK_ACTION_IN_PROGRESS, 0);
}

/* Alias for the canonical name. */
int w_nats_ack_progress(struct sip_msg *msg)
{
	return w_nats_in_progress(msg);
}

int w_nats_ack_next(struct sip_msg *msg)
{
	nats_cur_msg_t *cur = nats_fetch_current();
	int rc;

	(void)msg;

	if (!cur || !cur->has_message) {
		LM_DBG("nats_ack_next: no current message\n");
		return -1;
	}
	/* Action ACK_NEXT: consumer-process treats this as an ack followed
	 * by an immediate refill hint for the subscription.  On the wire
	 * it is a plain ack -- nats.c 3.13 has no direct +NXT payload API. */
	rc = send_ack_ipc(cur->ack_token, NATS_ACK_ACTION_ACK_NEXT, 0);
	if (rc == 1)
		finalize_current();
	return rc;
}
