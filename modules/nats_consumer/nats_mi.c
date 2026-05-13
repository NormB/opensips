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
 * nats_mi.c -- MI command handlers for the consumer-handle registry.
 *
 *   nats_consumer_bind   {config}         201 OK / 400 parse / 409 dup / 500 oom
 *   nats_consumer_unbind {id}             200 OK / 404 missing
 *   nats_consumer_list                    JSON array of handles
 */

#include <string.h>

#include "../../dprint.h"
#include "../../mi/item.h"
#include "../../mi/mi.h"

#include "nats_handle_registry.h"
#include "nats_handle_parse.h"
#include "nats_mi.h"
#include "nats_persist.h"
#include "nats_consumer_proc.h"

#include <stdatomic.h>
#include <time.h>

/* ── enum -> string helpers ───────────────────────────────────── */

static const char *type_str(nats_consumer_type_e t)
{
	switch (t) {
		case NATS_CONSUMER_DURABLE:   return "durable";
		case NATS_CONSUMER_EPHEMERAL: return "ephemeral";
		case NATS_CONSUMER_ORDERED:   return "ordered";
	}
	return "unknown";
}

static const char *deliver_str(nats_deliver_policy_e d)
{
	switch (d) {
		case NATS_DELIVER_ALL:               return "all";
		case NATS_DELIVER_LAST:              return "last";
		case NATS_DELIVER_NEW:               return "new";
		case NATS_DELIVER_LAST_PER_SUBJECT:  return "last_per_subject";
		case NATS_DELIVER_BY_START_SEQ:      return "by_start_seq";
		case NATS_DELIVER_BY_START_TIME:     return "by_start_time";
	}
	return "unknown";
}

static const char *ack_str(nats_ack_policy_e a)
{
	switch (a) {
		case NATS_ACK_EXPLICIT: return "explicit";
		case NATS_ACK_NONE:     return "none";
		case NATS_ACK_ALL:      return "all";
	}
	return "unknown";
}

/* ── bind ─────────────────────────────────────────────────────── */

mi_response_t *mi_consumer_bind(const mi_params_t *params,
		struct mi_handler *async)
{
	str config;
	const char *err = NULL;
	nats_handle_t *h;
	int rc;
	(void)async;

	if (get_mi_string_param(params, "config", &config.s, &config.len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'config' parameter"));

	h = nats_handle_parse(&config, &err);
	if (!h) {
		if (!err) err = "parse error";
		return init_mi_error(400, (char *)err, (int)strlen(err));
	}

	rc = nats_registry_bind(h);
	if (rc == -1) {
		nats_handle_free(h);
		return init_mi_error(409, MI_SSTR("duplicate id"));
	}
	if (rc == -2) {
		nats_handle_free(h);
		return init_mi_error(500, MI_SSTR("registry internal error"));
	}

	LM_INFO("nats_consumer: bound handle id=%.*s stream=%.*s\n",
		h->id.len, h->id.s, h->stream.len, h->stream.s);
	return init_mi_result_ok();
}

/* ── unbind ───────────────────────────────────────────────────── */

mi_response_t *mi_consumer_unbind(const mi_params_t *params,
		struct mi_handler *async)
{
	str id;
	(void)async;

	if (get_mi_string_param(params, "id", &id.s, &id.len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'id' parameter"));

	if (nats_registry_unbind(&id) < 0)
		return init_mi_error(404, MI_SSTR("no such handle"));

	LM_INFO("nats_consumer: unbound handle id=%.*s\n", id.len, id.s);
	return init_mi_result_ok();
}

/* ── list ─────────────────────────────────────────────────────── */

struct list_ctx {
	mi_item_t *arr;
	int err;
};

static int list_cb(nats_handle_t *h, void *user)
{
	struct list_ctx *c = (struct list_ctx *)user;
	mi_item_t *obj;

	obj = add_mi_object(c->arr, NULL, 0);
	if (!obj) { c->err = 1; return -1; }

	#define ADD_S(name, sp) do { \
		if ((sp)->len > 0 && \
				add_mi_string(obj, MI_SSTR(name), (sp)->s, (sp)->len) < 0) { \
			c->err = 1; return -1; \
		} \
	} while (0)
	#define ADD_S_ALWAYS(name, sp) do { \
		if (add_mi_string(obj, MI_SSTR(name), \
				(sp)->s ? (sp)->s : "", (sp)->len) < 0) { \
			c->err = 1; return -1; \
		} \
	} while (0)
	#define ADD_N(name, v) do { \
		if (add_mi_number(obj, MI_SSTR(name), (double)(v)) < 0) { \
			c->err = 1; return -1; \
		} \
	} while (0)
	#define ADD_STATIC_STR(name, cstr) do { \
		const char *_s = (cstr); \
		if (add_mi_string(obj, MI_SSTR(name), _s, (int)strlen(_s)) < 0) { \
			c->err = 1; return -1; \
		} \
	} while (0)

	ADD_S_ALWAYS("id", &h->id);
	ADD_S_ALWAYS("stream", &h->stream);
	ADD_S_ALWAYS("durable", &h->durable);
	ADD_STATIC_STR("type", type_str(h->type));
	ADD_S_ALWAYS("filter", &h->filter);
	ADD_S_ALWAYS("filters", &h->filters_csv);
	ADD_STATIC_STR("deliver_policy", deliver_str(h->deliver_policy));
	ADD_STATIC_STR("ack_policy", ack_str(h->ack_policy));
	ADD_N("ack_wait_ms", h->ack_wait_ms);
	ADD_N("max_deliver", h->max_deliver);
	ADD_N("max_ack_pending", h->max_ack_pending);

	/* runtime counters -- take the per-handle read lock */
	lock_start_read(h->rlock);
	ADD_N("created_at",     (double)h->created_at);
	ADD_N("last_used_at",   (double)h->last_used_at);
	ADD_N("pulls_requested", h->pulls_requested);
	ADD_N("msgs_delivered",  h->msgs_delivered);
	ADD_N("acks",            h->acks);
	ADD_N("naks",            h->naks);
	ADD_N("terms",           h->terms);
	ADD_N("redeliveries",    h->redeliveries);
	lock_stop_read(h->rlock);

	/* Backoff state for ensure_subscription_for_handle() retries.
	 * Written only by the consumer process from reconcile_subs_cb()
	 * without taking the rlock -- consistent with the existing
	 * pulls_requested / msgs_delivered counters above, which are
	 * also writer-side lockless.  Worst case MI sees a tear/stale
	 * read; ensure_failures is a small counter and ensure_next_retry_at
	 * is monotonically nondecreasing within a single failure run, so
	 * either field is operator-actionable even when slightly stale.
	 *
	 * Non-zero ensure_failures means the handle is currently failing;
	 * ensure_failures >= 7 means the backoff has saturated at the 60 s
	 * cap (mirrors the WARN threshold in reconcile_subs_cb).  The same
	 * value reported as 0 means the handle is healthy. */
	ADD_N("ensure_failures",      h->ensure_failures);
	ADD_N("ensure_next_retry_at", (double)h->ensure_next_retry_at);

	#undef ADD_S
	#undef ADD_S_ALWAYS
	#undef ADD_N
	#undef ADD_STATIC_STR
	return 0;
}

mi_response_t *mi_consumer_list(const mi_params_t *params,
		struct mi_handler *async)
{
	mi_response_t *resp;
	mi_item_t *arr;
	struct list_ctx ctx;
	(void)params;
	(void)async;

	resp = init_mi_result_array(&arr);
	if (!resp)
		return NULL;

	ctx.arr = arr;
	ctx.err = 0;

	nats_registry_foreach(list_cb, &ctx);

	if (ctx.err) {
		free_mi_response(resp);
		return init_mi_error(500, MI_SSTR("list internal error"));
	}

	return resp;
}

/* ── handle_reload ────────────────────────────────────────────── */

/* Re-read the persist file and merge any new bindings into the live
 * registry.  Does NOT clear the existing registry -- new handles are
 * added; ids that already exist keep their current state.  We do not
 * implement "full replacement" semantics (no way to represent "unbind
 * id X" from a snapshot).
 *
 * Refuses with 400 if persistence was not enabled via modparam. */
mi_response_t *mi_handle_reload(const mi_params_t *params,
		struct mi_handler *async)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	int loaded;
	(void)params;
	(void)async;

	if (!nats_persist_enabled())
		return init_mi_error(400, MI_SSTR("persistence disabled"));

	loaded = nats_persist_rehydrate();
	if (loaded < 0)
		return init_mi_error(500, MI_SSTR("reload failed"));

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;
	if (add_mi_number(resp_obj, MI_SSTR("loaded"), (double)loaded) < 0) {
		free_mi_response(resp);
		return init_mi_error(500, MI_SSTR("reload result alloc failed"));
	}
	return resp;
}

/* nats_consumer_health -- consumer-process liveness snapshot.
 *
 * Returns a JSON object:
 *   { "tick": N,
 *     "consumer_pid": PID,
 *     "last_tick_ms_ago": MS,    // monotonic ms since last tick
 *     "stale": true|false        // last_tick_ms_ago > 5000 (>5x loop tick)
 *   }
 *
 * Operators / external watchdogs poll this and treat stale=true as
 * "consumer process wedged or crashed" -- since the SHM ring's
 * eventfd-blocked workers cannot raise the alarm themselves. */
mi_response_t *mi_consumer_health(const mi_params_t *params,
		struct mi_handler *async)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	(void)params; (void)async;

	resp = init_mi_result_object(&resp_obj);
	if (!resp) return NULL;

	if (!nats_consumer_hb) {
		if (add_mi_string(resp_obj, MI_SSTR("error"),
				MI_SSTR("heartbeat block not initialized")) < 0)
			goto err;
		return resp;
	}

	{
		unsigned long tick = atomic_load_explicit(&nats_consumer_hb->tick,
			memory_order_relaxed);
		long long last_us = atomic_load_explicit(
			&nats_consumer_hb->last_tick_us, memory_order_relaxed);
		int pid = atomic_load_explicit(&nats_consumer_hb->consumer_pid,
			memory_order_relaxed);
		struct timespec ts;
		long long now_us = 0;
		long long ms_ago;
		int stale;

		if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
			now_us = (long long)ts.tv_sec * 1000000LL +
			         (long long)ts.tv_nsec / 1000LL;
		ms_ago = (last_us > 0 && now_us >= last_us) ?
		         (now_us - last_us) / 1000LL : -1;
		stale = (ms_ago < 0 || ms_ago > 5000);

		if (add_mi_number(resp_obj, MI_SSTR("tick"), (double)tick) < 0) goto err;
		if (add_mi_number(resp_obj, MI_SSTR("consumer_pid"),
				(double)pid) < 0) goto err;
		if (add_mi_number(resp_obj, MI_SSTR("last_tick_ms_ago"),
				(double)ms_ago) < 0) goto err;
		if (stale) {
			if (add_mi_string(resp_obj, MI_SSTR("stale"),
					MI_SSTR("true")) < 0) goto err;
		} else {
			if (add_mi_string(resp_obj, MI_SSTR("stale"),
					MI_SSTR("false")) < 0) goto err;
		}
	}
	return resp;
err:
	free_mi_response(resp);
	return NULL;
}

/* ── MI export table ──────────────────────────────────────────── */

const mi_export_t nats_consumer_mi_cmds[] = {
	{ "nats_consumer_bind",
	  "bind or update a consumer handle", 0, 0, {
		{ mi_consumer_bind, {"config", 0} },
		{ EMPTY_MI_RECIPE }
	  }, { 0 }
	},
	{ "nats_consumer_unbind",
	  "remove a consumer handle", 0, 0, {
		{ mi_consumer_unbind, {"id", 0} },
		{ EMPTY_MI_RECIPE }
	  }, { 0 }
	},
	{ "nats_consumer_list",
	  "list all registered handles", 0, 0, {
		{ mi_consumer_list, {0} },
		{ EMPTY_MI_RECIPE }
	  }, { 0 }
	},
	{ "nats_handle_reload",
	  "re-read the persistence file and merge new bindings", 0, 0, {
		{ mi_handle_reload, {0} },
		{ EMPTY_MI_RECIPE }
	  }, { 0 }
	},
	{ "nats_consumer_health",
	  "consumer-process heartbeat snapshot for watchdog use",
	  0, 0, {
		{ mi_consumer_health, {0} },
		{ EMPTY_MI_RECIPE }
	  }, { 0 }
	},
	{ EMPTY_MI_EXPORT }
};
