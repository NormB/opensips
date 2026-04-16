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
 *
 */

/*
 * event_nats.c -- EVI transport module for NATS messaging
 *
 * This module registers a "nats" EVI (Event Virtual Interface) transport
 * with OpenSIPS, allowing any OpenSIPS event to be published to a NATS
 * subject.  It also exports a script function nats_publish() for direct
 * NATS publishing from opensips.cfg routing scripts.
 *
 * Transport registration:
 *   mod_init() registers the transport callbacks (parse, raise, match,
 *   free, print) with the EVI subsystem via register_event_mod().  Once
 *   registered, scripts can subscribe events to NATS destinations using
 *   the "nats:<subject>" socket syntax.
 *
 * Connection management:
 *   child_init() obtains a NATS connection (and optional JetStream context)
 *   from the shared nats_pool.  Connections are per-process; the pool
 *   handles reconnection automatically.
 *
 * Rank filtering:
 *   Only SIP UDP workers (rank 1..udp_workers_no) and the HTTPD/MI
 *   process (PROC_MODULE) initialize NATS.  TCP/WSS receivers are
 *   excluded because nats.c's internal I/O threads cause heap corruption
 *   in processes that also run OpenSSL for WSS.
 *
 * MI commands:
 *   nats_status  -- connection state and server info
 *   nats_stats   -- publish/fail counters
 *   nats_reconnect -- informational (auto-reconnect is always active)
 */

#include <string.h>

#include "../../sr_module.h"
#include "../../globals.h"
#include "../../evi/evi_transport.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../mod_fix.h"
#include <nats/nats.h>
#include "event_nats.h"
#include "nats_producer.h"
#include "nats_stats.h"
#include "nats_consumer.h"
#include "../../lib/nats/nats_pool.h"

/* module lifecycle */
static int mod_init(void);
static int child_init(int rank);
static void mod_destroy(void);

/* EVI transport callbacks */
static evi_reply_sock *nats_evi_parse(str socket);
static int nats_evi_raise(struct sip_msg *msg, str *ev_name,
	evi_reply_sock *sock, evi_params_t *params, evi_async_ctx_t *async_ctx);
static int nats_evi_match(evi_reply_sock *sock1, evi_reply_sock *sock2);
static void nats_evi_free(evi_reply_sock *sock);
static str nats_evi_print(evi_reply_sock *sock);

/* script function */
static int w_nats_publish(struct sip_msg *msg, str *subject, str *payload);

/* module parameters (non-static, accessed by nats_stats.c) */
char *nats_url = NATS_DEFAULT_URL;
int nats_jetstream = 0;
int nats_reconnect_wait = 2000;   /* ms */
int nats_max_reconnect = 60;

/* TLS parameters */
int nats_tls_skip_verify = 1;     /* skip server cert verification (default: yes) */
char *nats_tls_ca = NULL;         /* CA certificate file for verification */
char *nats_tls_cert = NULL;       /* client certificate file (mutual TLS) */
char *nats_tls_key = NULL;        /* client private key file (mutual TLS) */
char *nats_tls_hostname = NULL;   /* expected server cert hostname (overrides URL host) */

/* OpenSSL lifecycle -- when 1, nats.c skips OpenSSL init/cleanup
 * (the host application manages it). Set to 0 only if no other
 * OpenSIPS module loads OpenSSL (unusual). */
int nats_skip_openssl_init = 1;

static const param_export_t mod_params[] = {
	{"nats_url",            STR_PARAM, &nats_url},
	{"jetstream",           INT_PARAM, &nats_jetstream},
	{"reconnect_wait",      INT_PARAM, &nats_reconnect_wait},
	{"max_reconnect",       INT_PARAM, &nats_max_reconnect},
	{"tls_skip_verify",     INT_PARAM, &nats_tls_skip_verify},
	{"tls_ca",              STR_PARAM, &nats_tls_ca},
	{"tls_cert",            STR_PARAM, &nats_tls_cert},
	{"tls_key",             STR_PARAM, &nats_tls_key},
	{"tls_hostname",        STR_PARAM, &nats_tls_hostname},
	{"skip_openssl_init",   INT_PARAM, &nats_skip_openssl_init},
	{"subscribe",           STR_PARAM|USE_FUNC_PARAM,
	                        (void *)nats_consumer_parse_subscribe},
	{0,0,0}
};

/* MI commands */
static const mi_export_t mi_cmds[] = {
	{ "nats_status", 0, 0, 0, {
		{mi_nats_status, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "nats_stats", 0, 0, 0, {
		{mi_nats_stats, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "nats_reconnect", 0, 0, 0, {
		{mi_nats_reconnect, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static const cmd_export_t cmds[] = {
	{"nats_publish", (cmd_function)w_nats_publish, {
		{CMD_PARAM_STR, 0, 0},  /* subject (required) */
		{CMD_PARAM_STR, 0, 0},  /* payload (required) */
		{0,0,0}},
	ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

/* Consumer process — spawned only if subscribe modparams are configured.
 * The 'no' field is set dynamically in mod_init based on
 * nats_subscription_count > 0. */
static const proc_export_t procs[] = {
	{"NATS consumer", 0, 0, nats_consumer_process, 1, 0},
	{0, 0, 0, 0, 0, 0}
};

struct module_exports exports = {
	"event_nats",               /* module name */
	MOD_TYPE_DEFAULT,           /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	0,                          /* load function */
	NULL,                       /* OpenSIPS module dependencies */
	cmds,                       /* exported functions */
	0,                          /* exported async functions */
	mod_params,                 /* exported parameters */
	0,                          /* exported statistics */
	mi_cmds,                    /* exported MI functions */
	0,                          /* exported pseudo-variables */
	0,                          /* exported transformations */
	procs,                      /* extra processes — NATS consumer */
	0,                          /* module pre-initialization function */
	mod_init,                   /* module initialization function */
	0,                          /* response handling function */
	mod_destroy,                /* destroy function */
	child_init,                 /* per-child init function */
	0                           /* reload confirm function */
};

/* EVI transport export -- registers the callback table with the EVI
 * subsystem so that "nats:<subject>" sockets are recognized. */
static const evi_export_t trans_export_nats = {
	NATS_STR,                   /* transport module name */
	nats_evi_raise,             /* raise function */
	nats_evi_parse,             /* parse function */
	nats_evi_match,             /* sockets match function */
	nats_evi_free,              /* free function */
	nats_evi_print,             /* print socket */
	NATS_FLAG                   /* flags */
};

/**
 * mod_init() -- Module initialization (pre-fork).
 *
 * Initializes publish statistics, registers the NATS EVI transport with
 * the OpenSIPS event subsystem, and registers this module with the
 * shared NATS connection pool (including TLS configuration).
 *
 * Called once in the main (attendant) process before forking workers.
 *
 * @return  0 on success, -1 on error (aborts module loading).
 */
static int mod_init(void)
{
	nats_tls_opts tls_opts;

	LM_NOTICE("initializing event_nats module ...\n");

	if (nats_stats_init() < 0) {
		LM_ERR("cannot init stats\n");
		return -1;
	}

	/* Register the NATS transport callback table with EVI so that
	 * event subscriptions using "nats:<subject>" are handled by us */
	if (register_event_mod(&trans_export_nats)) {
		LM_ERR("cannot register transport functions for NATS\n");
		return -1;
	}

	/* Build TLS opts from modparam globals and register with pool */
	memset(&tls_opts, 0, sizeof(tls_opts));
	tls_opts.ca = nats_tls_ca;
	tls_opts.cert = nats_tls_cert;
	tls_opts.key = nats_tls_key;
	tls_opts.hostname = nats_tls_hostname;
	tls_opts.skip_verify = nats_tls_skip_verify;
	tls_opts.skip_openssl_init = nats_skip_openssl_init;

	if (nats_pool_register(nats_url, &tls_opts, "event_nats",
			nats_reconnect_wait, nats_max_reconnect) < 0) {
		LM_ERR("cannot register with NATS connection pool\n");
		return -1;
	}

	LM_INFO("NATS URL: %s, JetStream: %s, TLS verify: %s, "
		"skip_openssl_init: %s\n",
		nats_url,
		nats_jetstream ? "enabled" : "disabled",
		nats_tls_skip_verify ? "off" : "on",
		nats_skip_openssl_init ? "yes" : "no");

	/* Register EVI events for all configured subscriptions */
	if (nats_subscription_count > 0) {
		if (nats_consumer_register_events() < 0) {
			LM_ERR("cannot register NATS consumer events\n");
			return -1;
		}
		LM_INFO("NATS consumer: %d subscription(s) configured\n",
			nats_subscription_count);
	}

	return 0;
}

/**
 * child_init() -- Per-child process initialization (post-fork).
 *
 * Obtains a NATS connection from the shared pool and optionally a
 * JetStream context, then registers them with the producer module.
 *
 * Rank filtering: only SIP UDP workers (rank 1..udp_workers_no) and the
 * HTTPD/MI process (PROC_MODULE) initialize NATS.  TCP/WSS receivers
 * (ranks above udp_workers_no) are excluded because nats.c's internal
 * I/O threads cause heap corruption in processes that also handle
 * OpenSSL for WSS.
 *
 * @param rank  OpenSIPS process rank (1-based for SIP workers).
 * @return      0 on success, -1 on error (kills the child process).
 */
static int child_init(int rank)
{
	natsConnection *nc;
	jsCtx *js;

	/* Rank filtering: skip non-SIP processes (attendant, timer, TCP main).
	 * UDP workers, TCP/WSS receivers, and the MI/HTTPD process all need
	 * NATS access so that events are published regardless of transport. */
	if (rank != PROC_MODULE && rank < 1) {
		LM_DBG("skipping NATS init for process rank=%d\n", rank);
		return 0;
	}

	LM_INFO("initializing NATS for process rank=%d pid=%d\n",
		rank, getpid());
	nc = nats_pool_get();
	if (!nc) {
		LM_ERR("cannot get NATS connection from pool\n");
		return -1;
	}
	nats_producer_set_connection(nc);

	if (nats_jetstream) {
		js = nats_pool_get_js();
		if (!js) {
			LM_ERR("cannot get JetStream context from pool\n");
			return -1;
		}
		nats_producer_set_js(js);
	}

	return 0;
}

/**
 * mod_destroy() -- Module cleanup on OpenSIPS shutdown.
 *
 * Frees publish statistics and tears down the NATS connection pool.
 */
static void mod_destroy(void)
{
	LM_NOTICE("destroying event_nats module ...\n");
	nats_stats_destroy();
	nats_pool_destroy();
}

/**
 * nats_evi_parse() -- Parse a NATS EVI socket string.
 *
 * Accepts a socket in the format "nats:<subject_prefix>" and allocates
 * an evi_reply_sock with the subject prefix stored in sock->address.
 * The socket is allocated in shared memory so it persists across
 * process boundaries.
 *
 * @param socket  The socket string (subject prefix) to parse.
 * @return        Allocated evi_reply_sock on success, NULL on error.
 */
static evi_reply_sock *nats_evi_parse(str socket)
{
	evi_reply_sock *sock = NULL;

	if (!socket.len || !socket.s) {
		LM_ERR("no socket specified\n");
		return NULL;
	}

	LM_DBG("parsing NATS socket: %.*s\n", socket.len, socket.s);

	sock = shm_malloc(sizeof(evi_reply_sock) + socket.len);
	if (!sock) {
		LM_ERR("oom!\n");
		return NULL;
	}
	memset(sock, 0, sizeof(evi_reply_sock) + socket.len);

	/* store subject prefix in address */
	sock->address.s = (char *)(sock + 1);
	memcpy(sock->address.s, socket.s, socket.len);
	sock->address.len = socket.len;

	sock->flags |= EVI_ADDRESS | EVI_EXPIRE | EVI_ASYNC_STATUS;

	return sock;
}

/**
 * nats_evi_raise() -- Publish an EVI event to a NATS subject.
 *
 * Builds a JSON payload from the EVI parameters, copies the subject
 * into a null-terminated stack buffer, and publishes via the pool
 * connection.  If the subject exceeds the 511-byte buffer, the publish
 * is rejected with an error (not silently truncated).
 *
 * Supports both core NATS publish and JetStream async publish depending
 * on the nats_jetstream module parameter.
 *
 * @param msg        Current SIP message (unused by NATS transport).
 * @param ev_name    Event name (included in the JSON payload).
 * @param sock       EVI socket containing the NATS subject prefix.
 * @param params     EVI parameter list to serialize as JSON.
 * @param async_ctx  Async status callback context (may be NULL).
 * @return           0 on success, -1 on error.
 */
static int nats_evi_raise(struct sip_msg *msg, str *ev_name,
	evi_reply_sock *sock, evi_params_t *params, evi_async_ctx_t *async_ctx)
{
	char *payload;
	int payload_len;
	char subj_buf[512];
	int subj_len;
	int rc;

	if (!sock) {
		LM_ERR("invalid evi socket\n");
		return -1;
	}

	payload = evi_build_payload(params, ev_name, 0, NULL, NULL);
	if (!payload) {
		LM_ERR("failed to build event payload\n");
		return -1;
	}
	payload_len = strlen(payload);

	/* null-terminate subject in a stack buffer; reject if too long */
	subj_len = sock->address.len;
	if (subj_len >= (int)sizeof(subj_buf)) {
		LM_ERR("NATS subject too long (%d bytes, max %d): %.*s\n",
			subj_len, (int)sizeof(subj_buf) - 1,
			sock->address.len, sock->address.s);
		evi_free_payload(payload);
		return -1;
	}
	memcpy(subj_buf, sock->address.s, subj_len);
	subj_buf[subj_len] = '\0';

	/* publish directly */
	if (nats_jetstream)
		rc = nats_js_publish_async(subj_buf, payload, payload_len);
	else
		rc = nats_publish(subj_buf, payload, payload_len);

	evi_free_payload(payload);

	/* update per-type stats on success */
	if (rc == 0 && nats_stats)
		nats_stats->evi_published++;

	/* report async status -- non-blocking publish, report immediately */
	if (async_ctx && async_ctx->status_cb) {
		async_ctx->status_cb(async_ctx->cb_param,
			rc == 0 ? EVI_STATUS_SUCCESS : EVI_STATUS_FAIL);
	}

	return rc;
}

/**
 * nats_evi_match() -- Compare two NATS EVI sockets for equality.
 *
 * Two sockets match if they have the same subject prefix (byte-exact
 * comparison).  Used by the EVI subsystem to deduplicate subscriptions.
 *
 * @param sock1  First socket to compare.
 * @param sock2  Second socket to compare.
 * @return       1 if sockets match, 0 otherwise.
 */
static int nats_evi_match(evi_reply_sock *sock1, evi_reply_sock *sock2)
{
	if (!sock1 || !sock2)
		return 0;

	if (!(sock1->flags & EVI_ADDRESS) || !(sock2->flags & EVI_ADDRESS))
		return 0;

	if (sock1->address.len != sock2->address.len)
		return 0;

	if (memcmp(sock1->address.s, sock2->address.s, sock1->address.len) != 0)
		return 0;

	return 1;
}

/**
 * nats_evi_free() -- Free a NATS EVI socket.
 *
 * Releases the shared-memory allocation for the socket.  The address
 * string is embedded in the same allocation, so a single shm_free
 * releases everything.
 *
 * @param sock  Socket to free (may be NULL).
 */
static void nats_evi_free(evi_reply_sock *sock)
{
	if (!sock)
		return;

	LM_DBG("freeing NATS socket: %.*s\n",
		sock->address.len, sock->address.s);

	shm_free(sock);
}

/**
 * nats_evi_print() -- Return a printable representation of a NATS EVI socket.
 *
 * Returns the subject prefix stored in sock->address.  Used by the EVI
 * subsystem for logging and MI output.
 *
 * @param sock  Socket to print.
 * @return      str containing the subject prefix.
 */
static str nats_evi_print(evi_reply_sock *sock)
{
	/* address.s is embedded right after the sock struct */
	return sock->address;
}

/**
 * w_nats_publish() -- Script function: nats_publish(subject, payload).
 *
 * Publishes a message to a NATS subject directly from an opensips.cfg
 * routing script.  The subject is copied into a null-terminated stack
 * buffer; if it exceeds the 511-byte limit, the publish is rejected
 * with an error (not silently truncated).
 *
 * Uses JetStream async publish when the jetstream module parameter is
 * enabled, otherwise uses core NATS publish.
 *
 * @param msg      Current SIP message context.
 * @param subject  NATS subject to publish to.
 * @param payload  Message payload (typically JSON).
 * @return         1 on success, -1 on error (OpenSIPS script convention).
 */
static int w_nats_publish(struct sip_msg *msg, str *subject, str *payload)
{
	char subj_buf[512];
	int subj_len;
	int rc;

	if (!subject || !subject->len || !subject->s) {
		LM_ERR("missing NATS subject\n");
		return -1;
	}
	if (!payload || !payload->len || !payload->s) {
		LM_ERR("missing NATS payload\n");
		return -1;
	}

	/* null-terminate subject in a stack buffer; reject if too long */
	subj_len = subject->len;
	if (subj_len >= (int)sizeof(subj_buf)) {
		LM_ERR("NATS subject too long (%d bytes, max %d): %.*s\n",
			subj_len, (int)sizeof(subj_buf) - 1,
			subject->len, subject->s);
		return -1;
	}
	memcpy(subj_buf, subject->s, subj_len);
	subj_buf[subj_len] = '\0';

	/* publish directly */
	if (nats_jetstream)
		rc = nats_js_publish_async(subj_buf, payload->s, payload->len);
	else
		rc = nats_publish(subj_buf, payload->s, payload->len);

	/* update per-type stats on success */
	if (rc == 0 && nats_stats)
		nats_stats->script_published++;

	return rc == 0 ? 1 : -1;
}
