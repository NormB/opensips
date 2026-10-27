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
 * test_nats_bind_test_helper.c -- nats_bind_test.h, the helper the NATS
 * modules' unit tests use to run module sources against fakes, points
 * every member of `nats_api` at the fake of the same name, so a module
 * call through the API reaches the test's fake.
 */

#include <stdio.h>
#include <string.h>

#include "nats_bind_test.h"

/* one fake per API member, under the usual names */
nats_dl_funcs_t nats_dl;
int nats_pool_register(const char *u, const char *m, int w, int r) { (void)u; (void)m; (void)w; (void)r; return 0; }
int nats_pool_register_default(const char *u, const char *m, int w, int r) { (void)u; (void)m; (void)w; (void)r; return 0; }
void nats_pool_unregister(void) {}
void nats_pool_bind_tls(const char *m) { (void)m; }
natsConnection *nats_pool_get(void) { return NULL; }
jsCtx *nats_pool_get_js(void) { return NULL; }
kvStore *nats_pool_get_kv(const char *b, int r, int h, int64_t t) { (void)b; (void)r; (void)h; (void)t; return NULL; }
int nats_pool_is_connected(void) { return 1; }
int nats_pool_get_reconnect_epoch(void) { return 7; }
int nats_pool_has_servers(void) { return 1; }
int nats_pool_is_registered(void) { return 1; }
int nats_pool_should_init(int rank) { (void)rank; return 1; }
const char *nats_pool_get_server_info(void) { return ""; }
void nats_pool_set_pub_ack_cb(void (*cb)(int outcome)) { (void)cb; }
int nats_pool_bucket_maxage_ns(const char *b, int64_t *o) { (void)b; (void)o; return 0; }
int nats_pool_bucket_mmps(const char *b, int64_t *o) { (void)b; (void)o; return 0; }
void nats_pool_kv_request_ttl_below_marker(int s) { (void)s; }
int nats_pool_kv_ttl_below_marker_state(void) { return 0; }
void nats_pool_kv_ttl_below_marker_mark_broken(void) {}
int nats_pool_auth_configured(void) { return 0; }
int nats_pool_js_ack_timeout_ms, nats_pool_js_publish_retries,
	nats_pool_kv_op_timeout_ms, nats_pool_drain_timeout_ms,
	nats_pool_no_randomize;
void nats_redact_url(const char *u, char *o, size_t n) { (void)u; (void)o; (void)n; }
void nats_redact_key(const char *k, char *o, size_t n) { (void)k; (void)o; (void)n; }
int nats_validate_publish_subject(const char *s, int l) { (void)s; (void)l; return 0; }
int nats_validate(const char *s, int l, nats_validate_mode_t m) { (void)s; (void)l; (void)m; return 0; }

static int g_fails, g_checks;
#define WIRED(member, fake) do { \
	g_checks++; \
	if ((const void *)nats_api.member != (const void *)(fake)) { \
		fprintf(stderr, "FAIL: nats_api." #member " is not " #fake "\n"); \
		g_fails++; \
	} \
} while (0)

int main(void)
{
	WIRED(dl, &nats_dl);
	WIRED(pool_register, nats_pool_register);
	WIRED(pool_register_default, nats_pool_register_default);
	WIRED(pool_unregister, nats_pool_unregister);
	WIRED(pool_bind_tls, nats_pool_bind_tls);
	WIRED(pool_get, nats_pool_get);
	WIRED(pool_get_js, nats_pool_get_js);
	WIRED(pool_get_kv, nats_pool_get_kv);
	WIRED(pool_is_connected, nats_pool_is_connected);
	WIRED(pool_get_reconnect_epoch, nats_pool_get_reconnect_epoch);
	WIRED(pool_has_servers, nats_pool_has_servers);
	WIRED(pool_is_registered, nats_pool_is_registered);
	WIRED(pool_should_init, nats_pool_should_init);
	WIRED(pool_get_server_info, nats_pool_get_server_info);
	WIRED(pool_set_pub_ack_cb, nats_pool_set_pub_ack_cb);
	WIRED(pool_bucket_maxage_ns, nats_pool_bucket_maxage_ns);
	WIRED(pool_bucket_mmps, nats_pool_bucket_mmps);
	WIRED(pool_kv_request_ttl_below_marker, nats_pool_kv_request_ttl_below_marker);
	WIRED(pool_kv_ttl_below_marker_state, nats_pool_kv_ttl_below_marker_state);
	WIRED(pool_kv_ttl_below_marker_mark_broken, nats_pool_kv_ttl_below_marker_mark_broken);
	WIRED(pool_auth_configured, nats_pool_auth_configured);
	WIRED(js_ack_timeout_ms, &nats_pool_js_ack_timeout_ms);
	WIRED(js_publish_retries, &nats_pool_js_publish_retries);
	WIRED(kv_op_timeout_ms, &nats_pool_kv_op_timeout_ms);
	WIRED(drain_timeout_ms, &nats_pool_drain_timeout_ms);
	WIRED(no_randomize, &nats_pool_no_randomize);
	WIRED(redact_url, nats_redact_url);
	WIRED(redact_key, nats_redact_key);
	WIRED(validate_publish_subject, nats_validate_publish_subject);
	WIRED(validate, nats_validate);

	/* every member but set_param (the nats module's own, never faked):
	 * a member added to struct nats_binds needs a line above */
	g_checks++;
	if ((unsigned)g_checks - 1 != sizeof(struct nats_binds) / sizeof(void *) - 1) {
		fprintf(stderr, "FAIL: %d members checked, struct nats_binds has %zu\n",
			g_checks - 1, sizeof(struct nats_binds) / sizeof(void *));
		g_fails++;
	}

	fprintf(stderr, "%d checks\n=== %s (fails=%d) ===\n", g_checks,
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
