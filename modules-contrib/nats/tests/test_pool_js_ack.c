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
 *
 * test_pool_js_ack.c -- what the shared pool's JetStream ack handler does
 * with each ack: a stored message (or a duplicate of a stored one) is
 * reported and destroyed; a message whose ack did not arrive in time, or
 * that no JetStream server answered, is resent -- the same natsMsg, so
 * with the same Nats-Msg-Id header, and with the ack wait again -- at most
 * js_publish_retries times, then reported as failed; a resend that
 * libnats refuses is reported by its cause.
 *
 * Links the REAL ../nats_pool.c and ../nats_js_retry.c against a fake
 * libnats table; the handler is the one nats_pool_get_js() installs in
 * the jsOptions.  The libnats thread that calls it in production is not
 * needed: the handler is called directly, as libnats would.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/wait.h>

#include "../../../dprint.h"
#include "../../../mem/mem.h"
#include "../../../mem/shm_mem.h"
#include "../../../sr_module.h"
#include "../nats_dl.h"
#include "../nats_pool.h"
#include "../nats_js_retry.h"

/* ── core seams ─────────────────────────────────────────────────── */

static int test_log_level = L_WARN;
int *log_level = &test_log_level;
char *log_prefix = "";
int log_facility = 0;
char ctime_buf[256];
int process_no = 0;
int dp_my_pid(void) { return getpid(); }
void dprint(int level, int facility, const char *module, const char *func,
	char *stderr_fmt, char *syslog_fmt, char *format, ...)
{
	va_list ap;
	(void)level; (void)facility; (void)module; (void)func;
	(void)syslog_fmt; (void)format;
	if (!stderr_fmt)
		return;
	va_start(ap, format);
	vfprintf(stderr, stderr_fmt, ap);
	va_end(ap);
}

void *shm_block = NULL;
gen_lock_t *mem_lock = NULL;
int shm_use_global_lock = 0;
long event_shm_threshold = 0;
long *event_shm_last = NULL;
int *event_shm_pending = NULL;
static void *t_shm_malloc(void *blk, unsigned long size) { (void)blk; return malloc(size); }
static void t_shm_free(void *blk, void *p) { (void)blk; free(p); }
static unsigned long t_shm_size(void *blk) { (void)blk; return 1UL << 30; }
static unsigned long t_shm_rused(void *blk) { (void)blk; return 0; }
void *(*gen_shm_malloc)(void *blk, unsigned long size) = t_shm_malloc;
void (*gen_shm_free)(void *blk, void *p) = t_shm_free;
unsigned long (*gen_shm_get_size)(void *blk) = t_shm_size;
unsigned long (*gen_shm_get_rused)(void *blk) = t_shm_rused;
void shm_event_raise(long used, long size, long perc)
{ (void)used; (void)size; (void)perc; }

cmd_function find_export(const char *name, int flags)
{ (void)name; (void)flags; return NULL; }
int nats_dl_load(const char *path) { (void)path; return 0; }
const char *nats_dl_path(void) { return "fake"; }

/* ── fake libnats ───────────────────────────────────────────────── */

static int fake_obj;
static jsPubAckHandler g_handler;

static natsStatus f_nats_Open(int64_t s) { (void)s; return NATS_OK; }
static natsStatus f_OptCreate(natsOptions **o) { *o = (natsOptions *)&fake_obj; return NATS_OK; }
static void f_OptDestroy(natsOptions *o) { (void)o; }
static natsStatus f_ok_cb(natsOptions *o, void *cb, void *cl) { (void)o; (void)cb; (void)cl; return NATS_OK; }
static natsStatus f_ok_int(natsOptions *o, int v) { (void)o; (void)v; return NATS_OK; }
static natsStatus f_ok_i64(natsOptions *o, int64_t v) { (void)o; (void)v; return NATS_OK; }
static natsStatus f_ok_bool(natsOptions *o, bool v) { (void)o; (void)v; return NATS_OK; }
static natsStatus f_retry(natsOptions *o, bool r, void *cb, void *cl)
{ (void)o; (void)r; (void)cb; (void)cl; return NATS_OK; }
static natsStatus f_jitter(natsOptions *o, int64_t a, int64_t b)
{ (void)o; (void)a; (void)b; return NATS_OK; }
static natsStatus f_servers(natsOptions *o, const char **s, int n)
{ (void)o; (void)s; (void)n; return NATS_OK; }
static natsStatus f_Connect(natsConnection **nc, natsOptions *o)
{ (void)o; *nc = (natsConnection *)&fake_obj; return NATS_OK; }
static natsStatus f_ConnUrl(natsConnection *nc, char *buf, size_t len)
{ (void)nc; snprintf(buf, len, "nats://fake:4222"); return NATS_OK; }
static const char *f_GetText(natsStatus s) { (void)s; return "fake"; }
static const char *f_ErrStack(char *b, size_t l) { (void)b; (void)l; return ""; }
static void f_Sleep(int64_t ms) { (void)ms; }
static natsStatus f_jsOptInit(jsOptions *o) { memset(o, 0, sizeof *o); return NATS_OK; }
static natsStatus f_PubOptInit(jsPubOptions *o) { memset(o, 0, sizeof *o); return NATS_OK; }
static natsStatus f_JetStream(jsCtx **js, natsConnection *nc, jsOptions *o)
{
	(void)nc;
	g_handler = o->PublishAsync.AckHandler;
	*js = (jsCtx *)&fake_obj;
	return NATS_OK;
}

/* messages are plain objects; the fake counts what happens to each */
#define NMSG 4
static char msgs[NMSG];
static int destroyed[NMSG];
static void f_MsgDestroy(natsMsg *m)
{
	if (m)
		destroyed[(char *)m - msgs]++;
}

/* js_PublishMsgAsync: on success libnats takes the message (clears the
 * caller's pointer); on failure the caller keeps it */
static int n_resend;
static natsMsg *last_resent;
static int64_t last_maxwait = -1;
static const char *last_msgid = "unset";
static natsStatus resend_status = NATS_OK;
static natsStatus f_PubMsgAsync(jsCtx *js, natsMsg **m, jsPubOptions *o)
{
	(void)js;
	n_resend++;
	last_resent = *m;
	last_maxwait = o ? o->MaxWait : -1;
	last_msgid = o ? o->MsgId : "no-options";
	if (resend_status == NATS_OK)
		*m = NULL;
	return resend_status;
}

nats_dl_funcs_t nats_dl;

static void fill_table(void)
{
	nats_dl.nats_Open = f_nats_Open;
	nats_dl.natsOptions_Create = f_OptCreate;
	nats_dl.natsOptions_Destroy = f_OptDestroy;
	nats_dl.natsOptions_SetDisconnectedCB = (void *)f_ok_cb;
	nats_dl.natsOptions_SetReconnectedCB = (void *)f_ok_cb;
	nats_dl.natsOptions_SetMaxPingsOut = (void *)f_ok_int;
	nats_dl.natsOptions_SetMaxReconnect = (void *)f_ok_int;
	nats_dl.natsOptions_SetNoRandomize = (void *)f_ok_bool;
	nats_dl.natsOptions_SetPingInterval = (void *)f_ok_i64;
	nats_dl.natsOptions_SetReconnectWait = (void *)f_ok_i64;
	nats_dl.natsOptions_SetReconnectJitter = (void *)f_jitter;
	nats_dl.natsOptions_SetReconnectBufSize = (void *)f_ok_int;
	nats_dl.natsOptions_SetRetryOnFailedConnect = (void *)f_retry;
	nats_dl.natsOptions_SetSecure = (void *)f_ok_bool;
	nats_dl.natsOptions_SetServers = (void *)f_servers;
	nats_dl.natsConnection_Connect = f_Connect;
	nats_dl.natsConnection_GetConnectedUrl = (void *)f_ConnUrl;
	nats_dl.natsStatus_GetText = f_GetText;
	nats_dl.nats_GetLastErrorStack = (void *)f_ErrStack;
	nats_dl.nats_Sleep = f_Sleep;
	nats_dl.jsOptions_Init = f_jsOptInit;
	nats_dl.jsPubOptions_Init = f_PubOptInit;
	nats_dl.natsConnection_JetStream = f_JetStream;
	nats_dl.natsMsg_Destroy = f_MsgDestroy;
	nats_dl.js_PublishMsgAsync = f_PubMsgAsync;
}

/* ── module callback: records the outcomes ─────────────────────── */

static int outcomes[8];
static int last_outcome = -1;
static void ack_cb(int outcome)
{
	if (outcome >= 0 && outcome < 8)
		outcomes[outcome]++;
	last_outcome = outcome;
}

static int g_fails;
#define ASSERT(c, m) do { if (!(c)) { fprintf(stderr, "FAIL: %s\n", m); g_fails++; } \
	else fprintf(stderr, "  ok: %s\n", m); } while (0)

/* one ack, as libnats delivers it: pa on success, pae on error */
static void ack_ok(int i, bool duplicate)
{
	jsPubAck pa;

	memset(&pa, 0, sizeof pa);
	pa.Stream = "S";
	pa.Sequence = 1;
	pa.Duplicate = duplicate;
	g_handler((jsCtx *)&fake_obj, (natsMsg *)&msgs[i], &pa, NULL, NULL);
}

static void ack_err(int i, natsStatus err, int jerr)
{
	jsPubAckErr pae;

	memset(&pae, 0, sizeof pae);
	pae.Err = err;
	pae.ErrCode = (jsErrCode)jerr;
	pae.ErrText = "fake error";
	g_handler((jsCtx *)&fake_obj, (natsMsg *)&msgs[i], NULL, &pae, NULL);
}

static void reset(void)
{
	memset(outcomes, 0, sizeof outcomes);
	memset(destroyed, 0, sizeof destroyed);
	n_resend = 0;
	last_resent = NULL;
	last_maxwait = -1;
	last_msgid = "unset";
	last_outcome = -1;
	resend_status = NATS_OK;
}

int main(void)
{
	int i;

	fill_table();
	nats_pool_js_ack_timeout_ms = 700;
	nats_pool_js_publish_retries = 3;
	nats_pool_set_pub_ack_cb(ack_cb);

	if (nats_pool_register("nats://127.0.0.1:4222", "test", 2000, 3) != 0 ||
	    !nats_pool_get() || !nats_pool_get_js() || !g_handler) {
		fprintf(stderr, "FAIL: pool setup\n");
		return 1;
	}

	fprintf(stderr, "stored and duplicate acks:\n");
	reset();
	ack_ok(0, false);
	ASSERT(last_outcome == NATS_PUB_ACK_OK, "a positive ack reports OK");
	ASSERT(destroyed[0] == 1 && n_resend == 0, "...and destroys the message, no resend");
	reset();
	ack_ok(0, true);
	ASSERT(last_outcome == NATS_PUB_ACK_DUPLICATE,
		"an ack flagged duplicate reports DUPLICATE");
	ASSERT(destroyed[0] == 1 && n_resend == 0, "...and destroys the message");

	fprintf(stderr, "a missing ack is retried, bounded:\n");
	reset();
	ack_err(1, NATS_TIMEOUT, 0);
	ASSERT(n_resend == 1 && last_resent == (natsMsg *)&msgs[1],
		"a timed-out ack resends the same natsMsg");
	ASSERT(last_maxwait == 700, "the resend waits js_ack_timeout_ms for its ack");
	ASSERT(last_msgid == NULL,
		"the resend sets no new MsgId (the message keeps its Nats-Msg-Id header)");
	ASSERT(last_outcome == NATS_PUB_ACK_RETRIED && destroyed[1] == 0,
		"...reports RETRIED and leaves the message to libnats");
	ack_err(1, NATS_TIMEOUT, 0);
	ack_err(1, NATS_TIMEOUT, 0);
	ASSERT(n_resend == 3 && outcomes[NATS_PUB_ACK_RETRIED] == 3,
		"three timeouts, three resends (js_publish_retries=3)");
	ack_err(1, NATS_TIMEOUT, 0);
	ASSERT(n_resend == 3, "the fourth timeout is not resent");
	ASSERT(last_outcome == NATS_PUB_ACK_FAILED && destroyed[1] == 1,
		"...reports FAILED and destroys the message");
	ASSERT(nats_js_retry_tracked() == 0, "...and the retry table forgets it");

	fprintf(stderr, "a retried message that is then stored:\n");
	reset();
	ack_err(2, NATS_NO_RESPONDERS, 0);
	ASSERT(n_resend == 1 && last_outcome == NATS_PUB_ACK_RETRIED,
		"no responders is resent");
	ack_ok(2, true);
	ASSERT(last_outcome == NATS_PUB_ACK_DUPLICATE && destroyed[2] == 1,
		"the resend acked as a duplicate reports DUPLICATE");
	ASSERT(nats_js_retry_tracked() == 0, "...and the retry table forgets it");
	reset();
	ack_err(2, NATS_ERR, JSClusterNotAvailErr);
	ASSERT(n_resend == 1, "JetStream temporarily unavailable is resent");
	ack_ok(2, false);
	ASSERT(nats_js_retry_tracked() == 0 && destroyed[2] == 1,
		"stored after a resend: forgotten and destroyed");
	reset();
	for (i = 0; i < 3; i++)
		ack_err(2, NATS_TIMEOUT, 0);
	ack_ok(2, false);
	ack_err(2, NATS_TIMEOUT, 0);
	ASSERT(n_resend == 4,
		"a message stored after its retries starts a fresh count if reused");
	ack_ok(2, false);

	fprintf(stderr, "errors that are not retried:\n");
	reset();
	ack_err(3, NATS_ERR, JSStreamMessageExceedsMaximumErr);
	ASSERT(n_resend == 0 && last_outcome == NATS_PUB_ACK_FAILED &&
		destroyed[3] == 1, "message too big: FAILED, not resent");
	reset();
	ack_err(3, NATS_ERR, JSStreamNotFoundErr);
	ASSERT(n_resend == 0 && last_outcome == NATS_PUB_ACK_FAILED,
		"no stream: FAILED, not resent");

	fprintf(stderr, "a resend that libnats refuses:\n");
	reset();
	resend_status = NATS_INSUFFICIENT_BUFFER;
	ack_err(0, NATS_TIMEOUT, 0);
	ASSERT(n_resend == 1 && last_outcome == NATS_PUB_ACK_FAILED_BUFFER_FULL,
		"reconnect buffer full: FAILED_BUFFER_FULL");
	ASSERT(destroyed[0] == 1 && nats_js_retry_tracked() == 0,
		"...the message is destroyed and forgotten");
	reset();
	resend_status = NATS_TIMEOUT;
	ack_err(0, NATS_TIMEOUT, 0);
	ASSERT(last_outcome == NATS_PUB_ACK_FAILED_PENDING_FULL && destroyed[0] == 1,
		"too many acks pending: FAILED_PENDING_FULL");
	reset();
	resend_status = NATS_CONNECTION_CLOSED;
	ack_err(0, NATS_TIMEOUT, 0);
	ASSERT(last_outcome == NATS_PUB_ACK_FAILED && destroyed[0] == 1,
		"any other refusal: FAILED");
	ASSERT(nats_js_retry_tracked() == 0, "nothing left in the retry table");

	fprintf(stderr, "js_publish_retries=0:\n");
	reset();
	nats_pool_js_publish_retries = 0;
	ack_err(1, NATS_TIMEOUT, 0);
	ASSERT(n_resend == 0 && last_outcome == NATS_PUB_ACK_FAILED &&
		destroyed[1] == 1, "a timeout is FAILED at once");

	fprintf(stderr, "no module callback:\n");
	reset();
	nats_pool_set_pub_ack_cb(NULL);
	ack_ok(0, false);
	ASSERT(destroyed[0] == 1 && last_outcome == -1,
		"without a callback the message is still destroyed");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
