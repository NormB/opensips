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
 * nats_bind_test.h -- for a unit test that compiles a NATS module's
 * sources against fakes of the nats module.
 *
 * The module sources call the nats module through `nats_api`
 * (nats_bind.h).  Include this header in the test after the module
 * headers: it removes the nats_bind.h name mappings, so the test defines
 * its fakes under the usual names (nats_pool_get(), nats_dl, ...), and
 * defines `nats_api` wired to whichever of them the test defines (weak
 * references: a fake the test does not define stays NULL).
 */

#ifndef NATS_BIND_TEST_H
#define NATS_BIND_TEST_H

#include "../nats_bind.h"

#undef nats_dl
#undef nats_pool_register
#undef nats_pool_register_default
#undef nats_pool_unregister
#undef nats_pool_bind_tls
#undef nats_pool_get
#undef nats_pool_get_js
#undef nats_pool_get_kv
#undef nats_pool_is_connected
#undef nats_pool_get_reconnect_epoch
#undef nats_pool_has_servers
#undef nats_pool_is_registered
#undef nats_pool_should_init
#undef nats_pool_get_server_info
#undef nats_pool_set_pub_ack_cb
#undef nats_pool_bucket_maxage_ns
#undef nats_pool_bucket_mmps
#undef nats_pool_kv_request_ttl_below_marker
#undef nats_pool_kv_ttl_below_marker_state
#undef nats_pool_kv_ttl_below_marker_mark_broken
#undef nats_pool_auth_configured
#undef nats_pool_js_ack_timeout_ms
#undef nats_pool_js_publish_retries
#undef nats_pool_kv_op_timeout_ms
#undef nats_pool_drain_timeout_ms
#undef nats_pool_no_randomize
#undef nats_redact_url
#undef nats_redact_key
#undef nats_validate_publish_subject
#undef nats_validate

struct nats_binds nats_api;

#define NBT_WEAK __attribute__((weak))
extern nats_dl_funcs_t nats_dl NBT_WEAK;
int nats_pool_register(const char *url, const char *module,
	int reconnect_wait, int max_reconnect) NBT_WEAK;
int nats_pool_register_default(const char *url, const char *module,
	int reconnect_wait, int max_reconnect) NBT_WEAK;
void nats_pool_unregister(void) NBT_WEAK;
void nats_pool_bind_tls(const char *modname) NBT_WEAK;
natsConnection *nats_pool_get(void) NBT_WEAK;
jsCtx *nats_pool_get_js(void) NBT_WEAK;
kvStore *nats_pool_get_kv(const char *bucket, int replicas, int history,
	int64_t ttl_secs) NBT_WEAK;
int nats_pool_is_connected(void) NBT_WEAK;
int nats_pool_get_reconnect_epoch(void) NBT_WEAK;
int nats_pool_has_servers(void) NBT_WEAK;
int nats_pool_is_registered(void) NBT_WEAK;
int nats_pool_should_init(int rank) NBT_WEAK;
const char *nats_pool_get_server_info(void) NBT_WEAK;
void nats_pool_set_pub_ack_cb(void (*cb)(int outcome)) NBT_WEAK;
int nats_pool_bucket_maxage_ns(const char *bucket, int64_t *out_ns) NBT_WEAK;
int nats_pool_bucket_mmps(const char *bucket, int64_t *out_mmps) NBT_WEAK;
void nats_pool_kv_request_ttl_below_marker(int marker_ttl_secs) NBT_WEAK;
int nats_pool_kv_ttl_below_marker_state(void) NBT_WEAK;
void nats_pool_kv_ttl_below_marker_mark_broken(void) NBT_WEAK;
int nats_pool_auth_configured(void) NBT_WEAK;
extern int nats_pool_js_ack_timeout_ms NBT_WEAK;
extern int nats_pool_js_publish_retries NBT_WEAK;
extern int nats_pool_kv_op_timeout_ms NBT_WEAK;
extern int nats_pool_drain_timeout_ms NBT_WEAK;
extern int nats_pool_no_randomize NBT_WEAK;
void nats_redact_url(const char *url, char *out, size_t out_sz) NBT_WEAK;
void nats_redact_key(const char *key, char *out, size_t out_sz) NBT_WEAK;
int nats_validate_publish_subject(const char *s, int len) NBT_WEAK;
int nats_validate(const char *s, int len, nats_validate_mode_t mode) NBT_WEAK;

/* runs before main(): point nats_api at the test's fakes */
__attribute__((constructor)) static void nats_bind_test_wire(void)
{
	nats_api.dl = &nats_dl;
	nats_api.pool_register = nats_pool_register;
	nats_api.pool_register_default = nats_pool_register_default;
	nats_api.pool_unregister = nats_pool_unregister;
	nats_api.pool_bind_tls = nats_pool_bind_tls;
	nats_api.pool_get = nats_pool_get;
	nats_api.pool_get_js = nats_pool_get_js;
	nats_api.pool_get_kv = nats_pool_get_kv;
	nats_api.pool_is_connected = nats_pool_is_connected;
	nats_api.pool_get_reconnect_epoch = nats_pool_get_reconnect_epoch;
	nats_api.pool_has_servers = nats_pool_has_servers;
	nats_api.pool_is_registered = nats_pool_is_registered;
	nats_api.pool_should_init = nats_pool_should_init;
	nats_api.pool_get_server_info = nats_pool_get_server_info;
	nats_api.pool_set_pub_ack_cb = nats_pool_set_pub_ack_cb;
	nats_api.pool_bucket_maxage_ns = nats_pool_bucket_maxage_ns;
	nats_api.pool_bucket_mmps = nats_pool_bucket_mmps;
	nats_api.pool_kv_request_ttl_below_marker = nats_pool_kv_request_ttl_below_marker;
	nats_api.pool_kv_ttl_below_marker_state = nats_pool_kv_ttl_below_marker_state;
	nats_api.pool_kv_ttl_below_marker_mark_broken = nats_pool_kv_ttl_below_marker_mark_broken;
	nats_api.pool_auth_configured = nats_pool_auth_configured;
	nats_api.js_ack_timeout_ms = &nats_pool_js_ack_timeout_ms;
	nats_api.js_publish_retries = &nats_pool_js_publish_retries;
	nats_api.kv_op_timeout_ms = &nats_pool_kv_op_timeout_ms;
	nats_api.drain_timeout_ms = &nats_pool_drain_timeout_ms;
	nats_api.no_randomize = &nats_pool_no_randomize;
	nats_api.redact_url = nats_redact_url;
	nats_api.redact_key = nats_redact_key;
	nats_api.validate_publish_subject = nats_validate_publish_subject;
	nats_api.validate = nats_validate;
}

#endif /* NATS_BIND_TEST_H */
