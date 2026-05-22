/*
 * Copyright (C) 2025 Summit-2026 / event_nats contributors
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
 * nats_consumer.c — NATS subscription consumer process
 *
 * Follows the rabbitmq_consumer pattern:
 *   1. Dedicated process (proc_export_t) subscribes to NATS
 *   2. nats.c async callbacks fire on received messages
 *   3. Message data is copied to SHM and dispatched via ipc_dispatch_rpc()
 *   4. SIP worker receives IPC, calls evi_raise_event() → event_route[E_*]
 *
 * Parameters accessible in event_route:
 *   $param(subject) — NATS subject the message arrived on
 *   $param(data)    — message payload (string)
 */

#include <string.h>
#include <unistd.h>

#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../ipc.h"
#include "../../evi/evi.h"
#include "../../evi/evi_params.h"
#include "../../lib/nats/nats_pool.h"
#include "nats_consumer.h"

/* ── Global subscription list ────────────────────────────────────── */

nats_subscription_t nats_subscriptions[NATS_MAX_SUBSCRIPTIONS];
int nats_subscription_count = 0;

/* ── EVI parameter names ─────────────────────────────────────────── */

static str evi_subject_name = str_init("subject");
static str evi_data_name = str_init("data");

/* ── IPC event structure (allocated in SHM) ──────────────────────── */

typedef struct nats_ipc_event {
	event_id_t event_id;
	char *subject;     /* SHM-allocated copy */
	int subject_len;
	char *data;        /* SHM-allocated copy */
	int data_len;
} nats_ipc_event_t;

/* ── Forward declarations ────────────────────────────────────────── */

static void nats_msg_handler(natsConnection *nc, natsSubscription *sub,
	natsMsg *msg, void *closure);
static void nats_ipc_raise_event(int sender, void *param);

/* ── Modparam parser ─────────────────────────────────────────────── */

int nats_consumer_parse_subscribe(modparam_t type, void *val)
{
	char *str_val = (char *)val;
	char *p, *tok;
	char buf[512];
	nats_subscription_t *s;

	if (!str_val || !str_val[0]) {
		LM_ERR("empty subscribe parameter\n");
		return -1;
	}

	if (nats_subscription_count >= NATS_MAX_SUBSCRIPTIONS) {
		LM_ERR("too many subscriptions (max %d)\n",
			NATS_MAX_SUBSCRIPTIONS);
		return -1;
	}

	s = &nats_subscriptions[nats_subscription_count];
	memset(s, 0, sizeof(*s));

	/* Copy to writable buffer for strsep */
	if (strlen(str_val) >= sizeof(buf)) {
		LM_ERR("subscribe value too long\n");
		return -1;
	}
	strcpy(buf, str_val);

	/* Parse key=value pairs separated by semicolons */
	p = buf;
	while ((tok = strsep(&p, ";")) != NULL) {
		char *eq = strchr(tok, '=');
		if (!eq) continue;
		*eq = '\0';

		/* Trim leading spaces */
		while (*tok == ' ') tok++;
		char *val_str = eq + 1;
		while (*val_str == ' ') val_str++;

		if (strcmp(tok, "subject") == 0) {
			if (s->subject[0]) {
				LM_ERR("duplicate 'subject=' in subscribe\n");
				return -1;
			}
			if (strlen(val_str) >= sizeof(s->subject)) {
				LM_ERR("subject too long: %s\n", val_str);
				return -1;
			}
			strcpy(s->subject, val_str);
		} else if (strcmp(tok, "event") == 0) {
			if (s->event_name[0]) {
				LM_ERR("duplicate 'event=' in subscribe\n");
				return -1;
			}
			if (strlen(val_str) >= sizeof(s->event_name)) {
				LM_ERR("event name too long: %s\n", val_str);
				return -1;
			}
			strcpy(s->event_name, val_str);
		} else if (strcmp(tok, "queue") == 0) {
			if (s->queue_group[0]) {
				LM_ERR("duplicate 'queue=' in subscribe\n");
				return -1;
			}
			if (strlen(val_str) >= sizeof(s->queue_group)) {
				LM_ERR("queue group too long: %s\n", val_str);
				return -1;
			}
			strcpy(s->queue_group, val_str);
		} else {
			LM_WARN("unknown subscribe key: %s\n", tok);
		}
	}

	/* Validate required fields */
	if (!s->subject[0]) {
		LM_ERR("subscribe param missing 'subject' field\n");
		return -1;
	}
	if (!s->event_name[0]) {
		LM_ERR("subscribe param missing 'event' field\n");
		return -1;
	}

	LM_INFO("parsed subscribe: subject=%s event=%s queue=%s\n",
		s->subject, s->event_name,
		s->queue_group[0] ? s->queue_group : "(none)");

	nats_subscription_count++;
	return 0;
}

/* ── Event registration ──────────────────────────────────────────── */

int nats_consumer_register_events(void)
{
	int i;
	str event_name;

	for (i = 0; i < nats_subscription_count; i++) {
		event_name.s = nats_subscriptions[i].event_name;
		event_name.len = strlen(nats_subscriptions[i].event_name);

		nats_subscriptions[i].event_id =
			evi_publish_event(event_name);
		if (nats_subscriptions[i].event_id == EVI_ERROR) {
			LM_ERR("cannot register event '%s'\n",
				nats_subscriptions[i].event_name);
			return -1;
		}

		LM_INFO("registered event '%s' (id=%d) for subject '%s'\n",
			nats_subscriptions[i].event_name,
			nats_subscriptions[i].event_id,
			nats_subscriptions[i].subject);
	}

	return 0;
}

/* ── Consumer process main loop ──────────────────────────────────── */

void nats_consumer_process(int rank)
{
	natsConnection *nc;
	natsStatus s;
	int i;

	LM_INFO("NATS consumer process starting (pid=%d)\n", getpid());

	/* No subscriptions configured: block forever on pause() rather
	 * than returning.  Returning from a proc_export entry triggers
	 * SIGCHLD in the attendant, which OpenSIPS treats as a fatal
	 * child exit and shuts the whole instance down.  pause() blocks
	 * until any signal is delivered; if the signal terminates the
	 * process, control never returns to us, and if it's caught and
	 * the handler returns we just loop and pause() again. */
	if (nats_subscription_count == 0) {
		for (;;)
			pause();
	}

	/* Get NATS connection from shared pool */
	nc = nats_pool_get();
	if (!nc) {
		LM_ERR("cannot get NATS connection for consumer process\n");
		return;
	}

	/* Subscribe to all configured subjects */
	for (i = 0; i < nats_subscription_count; i++) {
		nats_subscription_t *sub = &nats_subscriptions[i];

		if (sub->queue_group[0]) {
			/* Queue subscribe — load-balanced across group members */
			s = nats_dl.natsConnection_QueueSubscribe(&sub->sub, nc,
				sub->subject, sub->queue_group,
				nats_msg_handler, sub);
		} else {
			/* Regular subscribe */
			s = nats_dl.natsConnection_Subscribe(&sub->sub, nc,
				sub->subject, nats_msg_handler, sub);
		}

		if (s != NATS_OK) {
			LM_ERR("subscribe to '%s' failed: %s\n",
				sub->subject, nats_dl.natsStatus_GetText(s));
			continue;
		}

		LM_INFO("subscribed to '%s' %s→ event '%s'\n",
			sub->subject,
			sub->queue_group[0] ? "(queue) " : "",
			sub->event_name);
	}

	/* Block forever -- nats.c fires the per-subscription callbacks on
	 * its internal threads, so this process just needs to stay alive
	 * AND react to reconnects.
	 *
	 * Loop cadence: 5 s.  cnats handles the actual reconnect on a
	 * background thread; we poll the pool's atomic reconnect epoch.
	 * When it advances, walk every subscription, and if cnats has
	 * marked it invalid (server-side state was lost across the
	 * reconnect), destroy it and re-subscribe.  Subscriptions that
	 * survived the reconnect on the broker side report
	 * nats_dl.natsSubscription_IsValid()=true and are left alone. */
	{
		int last_epoch = nats_pool_get_reconnect_epoch();
		int prev_connected = nats_pool_is_connected();

		for (;;) {
			sleep(5);

			int cur_epoch = nats_pool_get_reconnect_epoch();
			int cur_connected = nats_pool_is_connected();

			if (cur_epoch != last_epoch) {
				LM_INFO("NATS consumer: reconnect detected (epoch "
					"%d -> %d); checking subscriptions\n",
					last_epoch, cur_epoch);
				for (i = 0; i < nats_subscription_count; i++) {
					nats_subscription_t *sub =
						&nats_subscriptions[i];
					if (sub->sub &&
					    nats_dl.natsSubscription_IsValid(sub->sub))
						continue;
					if (sub->sub) {
						nats_dl.natsSubscription_Destroy(sub->sub);
						sub->sub = NULL;
					}
					if (sub->queue_group[0]) {
						s = nats_dl.natsConnection_QueueSubscribe(
							&sub->sub, nc, sub->subject,
							sub->queue_group,
							nats_msg_handler, sub);
					} else {
						s = nats_dl.natsConnection_Subscribe(
							&sub->sub, nc, sub->subject,
							nats_msg_handler, sub);
					}
					if (s == NATS_OK) {
						LM_INFO("NATS consumer: "
							"re-subscribed to '%s'\n",
							sub->subject);
					} else {
						LM_ERR("NATS consumer: "
							"resubscribe to '%s' "
							"failed: %s\n",
							sub->subject,
							nats_dl.natsStatus_GetText(s));
					}
				}
				last_epoch = cur_epoch;
			}

			if (prev_connected && !cur_connected) {
				LM_WARN("NATS consumer: connection lost, "
					"awaiting reconnect...\n");
			} else if (!prev_connected && cur_connected) {
				LM_INFO("NATS consumer: connection restored\n");
			}
			prev_connected = cur_connected;
		}
	}
}

/* ── nats.c message callback ─────────────────────────────────────── */

/*
 * Called by nats.c on its internal I/O thread when a message arrives.
 * MUST NOT call OpenSIPS APIs (LM_*, pkg_malloc, etc.) — only SHM
 * operations and ipc_dispatch_rpc().
 *
 * Pattern: copy message to SHM → ipc_dispatch_rpc() → worker handles it.
 */
static void nats_msg_handler(natsConnection *nc, natsSubscription *sub,
	natsMsg *msg, void *closure)
{
	nats_subscription_t *nsub = (nats_subscription_t *)closure;
	nats_ipc_event_t *evt;
	const char *subject;
	const char *data;
	int subject_len, data_len;

	subject = nats_dl.natsMsg_GetSubject(msg);
	data = nats_dl.natsMsg_GetData(msg);
	data_len = nats_dl.natsMsg_GetDataLength(msg);
	subject_len = subject ? strlen(subject) : 0;

	/* Allocate IPC event in shared memory */
	evt = shm_malloc(sizeof(nats_ipc_event_t));
	if (!evt) {
		nats_dl.natsMsg_Destroy(msg);
		return;
	}
	memset(evt, 0, sizeof(*evt));
	evt->event_id = nsub->event_id;

	/* Copy subject — all-or-nothing: if any required field fails to
	 * allocate, drop the message rather than dispatching with a NULL
	 * field that the script would silently see as undefined. */
	if (subject_len > 0) {
		evt->subject = shm_malloc(subject_len + 1);
		if (!evt->subject) {
			nats_dl.natsMsg_Destroy(msg);
			shm_free(evt);
			return;
		}
		memcpy(evt->subject, subject, subject_len);
		evt->subject[subject_len] = '\0';
		evt->subject_len = subject_len;
	}

	/* Copy data */
	if (data && data_len > 0) {
		evt->data = shm_malloc(data_len + 1);
		if (!evt->data) {
			nats_dl.natsMsg_Destroy(msg);
			if (evt->subject) shm_free(evt->subject);
			shm_free(evt);
			return;
		}
		memcpy(evt->data, data, data_len);
		evt->data[data_len] = '\0';
		evt->data_len = data_len;
	}

	nats_dl.natsMsg_Destroy(msg);

	/* Dispatch to next available SIP worker */
	if (ipc_dispatch_rpc(nats_ipc_raise_event, evt) < 0) {
		/* IPC dispatch failed — free SHM */
		if (evt->subject) shm_free(evt->subject);
		if (evt->data) shm_free(evt->data);
		shm_free(evt);
	}
}

/* ── IPC handler (runs in SIP worker process) ────────────────────── */

/*
 * Called by a SIP worker via IPC. This is in OpenSIPS process context,
 * so all OpenSIPS APIs are available.
 *
 * Builds EVI params and calls evi_raise_event() which triggers
 * event_route[E_*] handlers in the routing script.
 */
static void nats_ipc_raise_event(int sender, void *param)
{
	nats_ipc_event_t *evt = (nats_ipc_event_t *)param;
	evi_params_p evi_params = NULL;

	if (!evt) return;

	/* Build EVI parameters */
	evi_params = evi_get_params();
	if (!evi_params) {
		LM_ERR("cannot create EVI params\n");
		goto cleanup;
	}

	/* $param(subject) */
	if (evt->subject && evt->subject_len > 0) {
		str subject_str = {evt->subject, evt->subject_len};
		if (evi_param_add_str(evi_params, &evi_subject_name,
				&subject_str) < 0) {
			LM_ERR("cannot add 'subject' param\n");
			goto cleanup;
		}
	}

	/* $param(data) */
	if (evt->data && evt->data_len > 0) {
		str data_str = {evt->data, evt->data_len};
		if (evi_param_add_str(evi_params, &evi_data_name,
				&data_str) < 0) {
			LM_ERR("cannot add 'data' param\n");
			goto cleanup;
		}
	}

	/* Raise the event — this triggers event_route[E_*] */
	if (evi_raise_event(evt->event_id, evi_params) < 0) {
		LM_ERR("cannot raise event %d\n", evt->event_id);
	}

	/* evi_raise_event takes ownership of params — don't free them */
	evi_params = NULL;

cleanup:
	if (evi_params)
		evi_free_params(evi_params);
	if (evt->subject)
		shm_free(evt->subject);
	if (evt->data)
		shm_free(evt->data);
	shm_free(evt);
}
