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
 * nats_jetstream.c — JetStream Management MI Commands
 *
 * Implements MI commands for managing JetStream streams, consumers,
 * messages, and querying account info. All commands use the shared
 * connection pool from lib/nats via nats_pool_get_js().
 */

#include <string.h>
#include <nats/nats.h>

#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../mi/mi.h"
#include "../../lib/nats/nats_pool.h"
#include "nats_jetstream.h"

/* Helper: get JetStream context, return MI error if unavailable */
static jsCtx *_get_js(void)
{
	jsCtx *js = nats_pool_get_js();
	if (!js)
		LM_ERR("JetStream context not available\n");
	return js;
}

/* Helper: map retention enum to string */
static const char *_retention_str(jsRetentionPolicy r)
{
	switch (r) {
	case js_LimitsPolicy:    return "limits";
	case js_InterestPolicy:  return "interest";
	case js_WorkQueuePolicy: return "workqueue";
	default:                 return "unknown";
	}
}

/* Helper: map storage enum to string */
static const char *_storage_str(jsStorageType s)
{
	switch (s) {
	case js_FileStorage:   return "file";
	case js_MemoryStorage: return "memory";
	default:               return "unknown";
	}
}

/* Helper: parse retention string to enum */
static jsRetentionPolicy _parse_retention(const char *s, int len)
{
	if (len == 8 && strncasecmp(s, "interest", 8) == 0)
		return js_InterestPolicy;
	if (len == 9 && strncasecmp(s, "workqueue", 9) == 0)
		return js_WorkQueuePolicy;
	return js_LimitsPolicy; /* default */
}

/* Helper: parse storage string to enum */
static jsStorageType _parse_storage(const char *s, int len)
{
	if (len == 6 && strncasecmp(s, "memory", 6) == 0)
		return js_MemoryStorage;
	return js_FileStorage; /* default */
}

/* ── nats_account_info ──────────────────────────────────────── */

mi_response_t *mi_nats_account_info(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	jsAccountInfo *ai = NULL;
	jsErrCode jerr;
	natsStatus s;
	mi_response_t *resp;
	mi_item_t *resp_obj, *api_obj, *limits_obj;

	js = _get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	s = js_GetAccountInfo(&ai, js, NULL, &jerr);
	if (s != NATS_OK || !ai) {
		LM_ERR("js_GetAccountInfo failed: %s (jerr=%d)\n",
			natsStatus_GetText(s), (int)jerr);
		return init_mi_error(500, MI_SSTR("GetAccountInfo failed"));
	}

	resp = init_mi_result_object(&resp_obj);
	if (!resp) goto cleanup;

	if (add_mi_number(resp_obj, MI_SSTR("memory"), (double)ai->Memory) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("storage"), (double)ai->Store) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("streams"), (double)ai->Streams) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("consumers"), (double)ai->Consumers) < 0)
		goto error;

	/* API stats */
	api_obj = add_mi_object(resp_obj, MI_SSTR("api"));
	if (!api_obj) goto error;
	if (add_mi_number(api_obj, MI_SSTR("total"), (double)ai->API.Total) < 0)
		goto error;
	if (add_mi_number(api_obj, MI_SSTR("errors"), (double)ai->API.Errors) < 0)
		goto error;

	/* Limits */
	limits_obj = add_mi_object(resp_obj, MI_SSTR("limits"));
	if (!limits_obj) goto error;
	if (add_mi_number(limits_obj, MI_SSTR("max_memory"),
			(double)ai->Limits.MaxMemory) < 0)
		goto error;
	if (add_mi_number(limits_obj, MI_SSTR("max_storage"),
			(double)ai->Limits.MaxStore) < 0)
		goto error;
	if (add_mi_number(limits_obj, MI_SSTR("max_streams"),
			(double)ai->Limits.MaxStreams) < 0)
		goto error;
	if (add_mi_number(limits_obj, MI_SSTR("max_consumers"),
			(double)ai->Limits.MaxConsumers) < 0)
		goto error;

	jsAccountInfo_Destroy(ai);
	return resp;

error:
	free_mi_response(resp);
cleanup:
	if (ai) jsAccountInfo_Destroy(ai);
	return NULL;
}

/* ── nats_stream_list ───────────────────────────────────────── */

mi_response_t *mi_nats_stream_list(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	jsStreamInfoList *list = NULL;
	jsErrCode jerr;
	natsStatus s;
	mi_response_t *resp;
	mi_item_t *resp_obj, *arr, *item;
	int i;

	js = _get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	s = js_Streams(&list, js, NULL, &jerr);
	if (s != NATS_OK || !list) {
		LM_ERR("js_Streams failed: %s (jerr=%d)\n",
			natsStatus_GetText(s), (int)jerr);
		return init_mi_error(500, MI_SSTR("Streams list failed"));
	}

	resp = init_mi_result_object(&resp_obj);
	if (!resp) goto cleanup;

	if (add_mi_number(resp_obj, MI_SSTR("count"), (double)list->Count) < 0)
		goto error;

	arr = add_mi_array(resp_obj, MI_SSTR("streams"));
	if (!arr) goto error;

	for (i = 0; i < list->Count; i++) {
		jsStreamInfo *si = list->List[i];
		if (!si || !si->Config) continue;

		item = add_mi_object(arr, NULL, 0);
		if (!item) goto error;

		if (add_mi_string(item, MI_SSTR("name"),
				si->Config->Name, strlen(si->Config->Name)) < 0)
			goto error;
		if (add_mi_number(item, MI_SSTR("messages"),
				(double)si->State.Msgs) < 0)
			goto error;
		if (add_mi_number(item, MI_SSTR("bytes"),
				(double)si->State.Bytes) < 0)
			goto error;
		if (add_mi_number(item, MI_SSTR("consumers"),
				(double)si->State.Consumers) < 0)
			goto error;
		if (add_mi_number(item, MI_SSTR("replicas"),
				(double)si->Config->Replicas) < 0)
			goto error;
	}

	jsStreamInfoList_Destroy(list);
	return resp;

error:
	free_mi_response(resp);
cleanup:
	if (list) jsStreamInfoList_Destroy(list);
	return NULL;
}

/* ── nats_stream_info ───────────────────────────────────────── */

mi_response_t *mi_nats_stream_info(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	jsStreamInfo *si = NULL;
	jsErrCode jerr;
	natsStatus s;
	mi_response_t *resp;
	mi_item_t *resp_obj, *cfg_obj, *state_obj, *cluster_obj, *subj_arr;
	char *stream_name;
	int stream_name_len;
	int i;

	if (try_get_mi_string_param(params, "stream",
			&stream_name, &stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'stream' parameter"));

	js = _get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	/* stream_name from MI is not null-terminated — copy it */
	char name_buf[256];
	if (stream_name_len >= (int)sizeof(name_buf))
		return init_mi_error(400, MI_SSTR("stream name too long"));
	memcpy(name_buf, stream_name, stream_name_len);
	name_buf[stream_name_len] = '\0';

	s = js_GetStreamInfo(&si, js, name_buf, NULL, &jerr);
	if (s != NATS_OK || !si) {
		if (jerr == 10059) /* stream not found */
			return init_mi_error(404, MI_SSTR("stream not found"));
		LM_ERR("js_GetStreamInfo(%s) failed: %s (jerr=%d)\n",
			name_buf, natsStatus_GetText(s), (int)jerr);
		return init_mi_error(500, MI_SSTR("GetStreamInfo failed"));
	}

	resp = init_mi_result_object(&resp_obj);
	if (!resp) goto cleanup;

	/* Config */
	cfg_obj = add_mi_object(resp_obj, MI_SSTR("config"));
	if (!cfg_obj) goto error;

	if (add_mi_string(cfg_obj, MI_SSTR("name"),
			si->Config->Name, strlen(si->Config->Name)) < 0)
		goto error;
	if (add_mi_number(cfg_obj, MI_SSTR("replicas"),
			(double)si->Config->Replicas) < 0)
		goto error;
	{
		const char *ret = _retention_str(si->Config->Retention);
		if (add_mi_string(cfg_obj, MI_SSTR("retention"), ret, strlen(ret)) < 0)
			goto error;
	}
	{
		const char *stor = _storage_str(si->Config->Storage);
		if (add_mi_string(cfg_obj, MI_SSTR("storage"), stor, strlen(stor)) < 0)
			goto error;
	}
	if (add_mi_number(cfg_obj, MI_SSTR("max_msgs"),
			(double)si->Config->MaxMsgs) < 0)
		goto error;
	if (add_mi_number(cfg_obj, MI_SSTR("max_bytes"),
			(double)si->Config->MaxBytes) < 0)
		goto error;

	/* Subjects array */
	subj_arr = add_mi_array(cfg_obj, MI_SSTR("subjects"));
	if (!subj_arr) goto error;
	for (i = 0; i < si->Config->SubjectsLen; i++) {
		if (add_mi_string(subj_arr, NULL, 0,
				si->Config->Subjects[i],
				strlen(si->Config->Subjects[i])) < 0)
			goto error;
	}

	/* State */
	state_obj = add_mi_object(resp_obj, MI_SSTR("state"));
	if (!state_obj) goto error;
	if (add_mi_number(state_obj, MI_SSTR("messages"),
			(double)si->State.Msgs) < 0)
		goto error;
	if (add_mi_number(state_obj, MI_SSTR("bytes"),
			(double)si->State.Bytes) < 0)
		goto error;
	if (add_mi_number(state_obj, MI_SSTR("first_seq"),
			(double)si->State.FirstSeq) < 0)
		goto error;
	if (add_mi_number(state_obj, MI_SSTR("last_seq"),
			(double)si->State.LastSeq) < 0)
		goto error;
	if (add_mi_number(state_obj, MI_SSTR("consumers"),
			(double)si->State.Consumers) < 0)
		goto error;

	/* Cluster */
	if (si->Cluster) {
		cluster_obj = add_mi_object(resp_obj, MI_SSTR("cluster"));
		if (!cluster_obj) goto error;
		if (si->Cluster->Leader) {
			if (add_mi_string(cluster_obj, MI_SSTR("leader"),
					si->Cluster->Leader,
					strlen(si->Cluster->Leader)) < 0)
				goto error;
		}
		if (si->Cluster->ReplicasLen > 0) {
			mi_item_t *rep_arr = add_mi_array(cluster_obj,
				MI_SSTR("replicas"));
			if (!rep_arr) goto error;
			for (i = 0; i < si->Cluster->ReplicasLen; i++) {
				jsPeerInfo *peer = si->Cluster->Replicas[i];
				if (!peer || !peer->Name) continue;
				mi_item_t *peer_obj = add_mi_object(rep_arr, NULL, 0);
				if (!peer_obj) goto error;
				if (add_mi_string(peer_obj, MI_SSTR("name"),
						peer->Name, strlen(peer->Name)) < 0)
					goto error;
				if (add_mi_number(peer_obj, MI_SSTR("lag"),
						(double)peer->Lag) < 0)
					goto error;
				if (add_mi_bool(peer_obj, MI_SSTR("current"),
						peer->Current) < 0)
					goto error;
				if (add_mi_bool(peer_obj, MI_SSTR("offline"),
						peer->Offline) < 0)
					goto error;
			}
		}
	}

	jsStreamInfo_Destroy(si);
	return resp;

error:
	free_mi_response(resp);
cleanup:
	if (si) jsStreamInfo_Destroy(si);
	return NULL;
}

/* ── nats_stream_create ─────────────────────────────────────── */

mi_response_t *mi_nats_stream_create(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	jsStreamInfo *si = NULL;
	jsStreamConfig cfg;
	jsErrCode jerr;
	natsStatus s;
	char *name, *subjects_str;
	int name_len, subjects_len;
	char name_buf[256], subj_buf[1024];
	int replicas_int = 0;
	double max_msgs_d = 0, max_bytes_d = 0, max_age_d = 0;
	char *retention_str = NULL, *storage_str = NULL;
	int retention_len = 0, storage_len = 0;

	if (try_get_mi_string_param(params, "name", &name, &name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'name' parameter"));
	if (try_get_mi_string_param(params, "subjects",
			&subjects_str, &subjects_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'subjects' parameter"));

	if (name_len >= (int)sizeof(name_buf))
		return init_mi_error(400, MI_SSTR("name too long"));
	memcpy(name_buf, name, name_len);
	name_buf[name_len] = '\0';

	if (subjects_len >= (int)sizeof(subj_buf))
		return init_mi_error(400, MI_SSTR("subjects too long"));
	memcpy(subj_buf, subjects_str, subjects_len);
	subj_buf[subjects_len] = '\0';

	js = _get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	jsStreamConfig_Init(&cfg);
	cfg.Name = name_buf;

	/* Parse comma-separated subjects */
	const char *subj_ptrs[32];
	int subj_count = 0;
	{
		char *p = subj_buf;
		while (*p && subj_count < 32) {
			while (*p == ' ' || *p == ',') p++;
			if (!*p) break;
			subj_ptrs[subj_count++] = p;
			while (*p && *p != ',') p++;
			if (*p == ',') *p++ = '\0';
		}
	}
	if (subj_count == 0)
		return init_mi_error(400, MI_SSTR("subjects cannot be empty"));
	cfg.Subjects = subj_ptrs;
	cfg.SubjectsLen = subj_count;

	/* Optional params */
	if (try_get_mi_int_param(params, "replicas", &replicas_int) == 0)
		cfg.Replicas = replicas_int;
	if (try_get_mi_string_param(params, "retention",
			&retention_str, &retention_len) == 0)
		cfg.Retention = _parse_retention(retention_str, retention_len);
	if (try_get_mi_string_param(params, "storage",
			&storage_str, &storage_len) == 0)
		cfg.Storage = _parse_storage(storage_str, storage_len);

	/* Optional numeric params */
	{
		int val;
		if (try_get_mi_int_param(params, "max_msgs", &val) == 0)
			cfg.MaxMsgs = (int64_t)val;
		if (try_get_mi_int_param(params, "max_bytes", &val) == 0)
			cfg.MaxBytes = (int64_t)val;
		if (try_get_mi_int_param(params, "max_age", &val) == 0)
			cfg.MaxAge = (int64_t)val * 1000000000LL; /* seconds → nanoseconds */
	}

	s = js_AddStream(&si, js, &cfg, NULL, &jerr);
	if (s != NATS_OK) {
		LM_ERR("js_AddStream(%s) failed: %s (jerr=%d)\n",
			name_buf, natsStatus_GetText(s), (int)jerr);
		return init_mi_error(500, MI_SSTR("AddStream failed"));
	}

	mi_response_t *resp;
	mi_item_t *resp_obj;
	resp = init_mi_result_object(&resp_obj);
	if (!resp) { jsStreamInfo_Destroy(si); return NULL; }

	if (add_mi_string(resp_obj, MI_SSTR("status"),
			MI_SSTR("created")) < 0 ||
		add_mi_string(resp_obj, MI_SSTR("name"),
			name_buf, strlen(name_buf)) < 0) {
		free_mi_response(resp);
		jsStreamInfo_Destroy(si);
		return NULL;
	}

	jsStreamInfo_Destroy(si);
	return resp;
}

/* ── nats_stream_delete ─────────────────────────────────────── */

mi_response_t *mi_nats_stream_delete(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	jsErrCode jerr;
	natsStatus s;
	char *stream_name;
	int stream_name_len;
	char name_buf[256];

	if (try_get_mi_string_param(params, "stream",
			&stream_name, &stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'stream' parameter"));

	if (stream_name_len >= (int)sizeof(name_buf))
		return init_mi_error(400, MI_SSTR("stream name too long"));
	memcpy(name_buf, stream_name, stream_name_len);
	name_buf[stream_name_len] = '\0';

	js = _get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	s = js_DeleteStream(js, name_buf, NULL, &jerr);
	if (s != NATS_OK) {
		if (jerr == 10059)
			return init_mi_error(404, MI_SSTR("stream not found"));
		LM_ERR("js_DeleteStream(%s) failed: %s (jerr=%d)\n",
			name_buf, natsStatus_GetText(s), (int)jerr);
		return init_mi_error(500, MI_SSTR("DeleteStream failed"));
	}

	return init_mi_result_ok();
}

/* ── nats_stream_purge ──────────────────────────────────────── */

mi_response_t *mi_nats_stream_purge(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	jsErrCode jerr;
	natsStatus s;
	char *stream_name;
	int stream_name_len;
	char name_buf[256];

	if (try_get_mi_string_param(params, "stream",
			&stream_name, &stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'stream' parameter"));

	if (stream_name_len >= (int)sizeof(name_buf))
		return init_mi_error(400, MI_SSTR("stream name too long"));
	memcpy(name_buf, stream_name, stream_name_len);
	name_buf[stream_name_len] = '\0';

	js = _get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	s = js_PurgeStream(js, name_buf, NULL, &jerr);
	if (s != NATS_OK) {
		if (jerr == 10059)
			return init_mi_error(404, MI_SSTR("stream not found"));
		LM_ERR("js_PurgeStream(%s) failed: %s (jerr=%d)\n",
			name_buf, natsStatus_GetText(s), (int)jerr);
		return init_mi_error(500, MI_SSTR("PurgeStream failed"));
	}

	return init_mi_result_ok();
}

/* ── nats_consumer_list ─────────────────────────────────────── */

mi_response_t *mi_nats_consumer_list(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	jsConsumerInfoList *list = NULL;
	jsErrCode jerr;
	natsStatus s;
	mi_response_t *resp;
	mi_item_t *resp_obj, *arr, *item;
	char *stream_name;
	int stream_name_len;
	char name_buf[256];
	int i;

	if (try_get_mi_string_param(params, "stream",
			&stream_name, &stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'stream' parameter"));

	if (stream_name_len >= (int)sizeof(name_buf))
		return init_mi_error(400, MI_SSTR("stream name too long"));
	memcpy(name_buf, stream_name, stream_name_len);
	name_buf[stream_name_len] = '\0';

	js = _get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	/* Verify stream exists first (js_Consumers returns NATS_NOT_FOUND
	 * for both missing streams and empty consumer lists) */
	{
		jsStreamInfo *_si = NULL;
		jsErrCode _je;
		natsStatus _ss = js_GetStreamInfo(&_si, js, name_buf, NULL, &_je);
		if (_si) jsStreamInfo_Destroy(_si);
		if (_ss != NATS_OK)
			return init_mi_error(404, MI_SSTR("stream not found"));
	}

	s = js_Consumers(&list, js, name_buf, NULL, &jerr);
	if (s != NATS_OK || !list) {
		/* Stream exists but has no consumers — return empty list */
		if (s == NATS_NOT_FOUND || (list && list->Count == 0)) {
			mi_response_t *r;
			mi_item_t *ro;
			r = init_mi_result_object(&ro);
			if (!r) return NULL;
			if (add_mi_number(ro, MI_SSTR("count"), 0) < 0 ||
				!add_mi_array(ro, MI_SSTR("consumers"))) {
				free_mi_response(r);
				return NULL;
			}
			if (list) jsConsumerInfoList_Destroy(list);
			return r;
		}
		LM_ERR("js_Consumers(%s) failed: %s (jerr=%d)\n",
			name_buf, natsStatus_GetText(s), (int)jerr);
		return init_mi_error(500, MI_SSTR("Consumers list failed"));
	}

	resp = init_mi_result_object(&resp_obj);
	if (!resp) goto cleanup;

	if (add_mi_number(resp_obj, MI_SSTR("count"), (double)list->Count) < 0)
		goto error;

	arr = add_mi_array(resp_obj, MI_SSTR("consumers"));
	if (!arr) goto error;

	for (i = 0; i < list->Count; i++) {
		jsConsumerInfo *ci = list->List[i];
		if (!ci) continue;

		item = add_mi_object(arr, NULL, 0);
		if (!item) goto error;

		if (ci->Name &&
			add_mi_string(item, MI_SSTR("name"),
				ci->Name, strlen(ci->Name)) < 0)
			goto error;
		if (add_mi_number(item, MI_SSTR("num_pending"),
				(double)ci->NumPending) < 0)
			goto error;
		if (add_mi_number(item, MI_SSTR("num_ack_pending"),
				(double)ci->NumAckPending) < 0)
			goto error;
	}

	jsConsumerInfoList_Destroy(list);
	return resp;

error:
	free_mi_response(resp);
cleanup:
	if (list) jsConsumerInfoList_Destroy(list);
	return NULL;
}

/* ── nats_consumer_info ─────────────────────────────────────── */

mi_response_t *mi_nats_consumer_info(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	jsConsumerInfo *ci = NULL;
	jsErrCode jerr;
	natsStatus s;
	mi_response_t *resp;
	mi_item_t *resp_obj, *cfg_obj, *del_obj, *ack_obj;
	char *stream_name, *consumer_name;
	int stream_name_len, consumer_name_len;
	char stream_buf[256], consumer_buf[256];

	if (try_get_mi_string_param(params, "stream",
			&stream_name, &stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'stream' parameter"));
	if (try_get_mi_string_param(params, "consumer",
			&consumer_name, &consumer_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'consumer' parameter"));

	if (stream_name_len >= (int)sizeof(stream_buf))
		return init_mi_error(400, MI_SSTR("stream name too long"));
	memcpy(stream_buf, stream_name, stream_name_len);
	stream_buf[stream_name_len] = '\0';

	if (consumer_name_len >= (int)sizeof(consumer_buf))
		return init_mi_error(400, MI_SSTR("consumer name too long"));
	memcpy(consumer_buf, consumer_name, consumer_name_len);
	consumer_buf[consumer_name_len] = '\0';

	js = _get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	s = js_GetConsumerInfo(&ci, js, stream_buf, consumer_buf, NULL, &jerr);
	if (s != NATS_OK || !ci) {
		if (jerr == 10014 || jerr == 10059)
			return init_mi_error(404, MI_SSTR("consumer not found"));
		LM_ERR("js_GetConsumerInfo(%s/%s) failed: %s (jerr=%d)\n",
			stream_buf, consumer_buf, natsStatus_GetText(s), (int)jerr);
		return init_mi_error(500, MI_SSTR("GetConsumerInfo failed"));
	}

	resp = init_mi_result_object(&resp_obj);
	if (!resp) goto cleanup;

	if (ci->Stream &&
		add_mi_string(resp_obj, MI_SSTR("stream"),
			ci->Stream, strlen(ci->Stream)) < 0)
		goto error;
	if (ci->Name &&
		add_mi_string(resp_obj, MI_SSTR("name"),
			ci->Name, strlen(ci->Name)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("num_pending"),
			(double)ci->NumPending) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("num_ack_pending"),
			(double)ci->NumAckPending) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("num_redelivered"),
			(double)ci->NumRedelivered) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("num_waiting"),
			(double)ci->NumWaiting) < 0)
		goto error;

	/* Config subset */
	if (ci->Config) {
		cfg_obj = add_mi_object(resp_obj, MI_SSTR("config"));
		if (!cfg_obj) goto error;
		{
			const char *dp;
			switch (ci->Config->DeliverPolicy) {
			case js_DeliverAll:       dp = "all"; break;
			case js_DeliverLast:      dp = "last"; break;
			case js_DeliverNew:       dp = "new"; break;
			case js_DeliverByStartSequence: dp = "by_start_sequence"; break;
			case js_DeliverByStartTime:     dp = "by_start_time"; break;
			case js_DeliverLastPerSubject:   dp = "last_per_subject"; break;
			default: dp = "unknown";
			}
			if (add_mi_string(cfg_obj, MI_SSTR("deliver_policy"),
					dp, strlen(dp)) < 0)
				goto error;
		}
		{
			const char *ap;
			switch (ci->Config->AckPolicy) {
			case js_AckExplicit: ap = "explicit"; break;
			case js_AckNone:     ap = "none"; break;
			case js_AckAll:      ap = "all"; break;
			default: ap = "unknown";
			}
			if (add_mi_string(cfg_obj, MI_SSTR("ack_policy"),
					ap, strlen(ap)) < 0)
				goto error;
		}
	}

	/* Delivered / AckFloor */
	del_obj = add_mi_object(resp_obj, MI_SSTR("delivered"));
	if (!del_obj) goto error;
	if (add_mi_number(del_obj, MI_SSTR("consumer"),
			(double)ci->Delivered.Consumer) < 0)
		goto error;
	if (add_mi_number(del_obj, MI_SSTR("stream"),
			(double)ci->Delivered.Stream) < 0)
		goto error;

	ack_obj = add_mi_object(resp_obj, MI_SSTR("ack_floor"));
	if (!ack_obj) goto error;
	if (add_mi_number(ack_obj, MI_SSTR("consumer"),
			(double)ci->AckFloor.Consumer) < 0)
		goto error;
	if (add_mi_number(ack_obj, MI_SSTR("stream"),
			(double)ci->AckFloor.Stream) < 0)
		goto error;

	jsConsumerInfo_Destroy(ci);
	return resp;

error:
	free_mi_response(resp);
cleanup:
	if (ci) jsConsumerInfo_Destroy(ci);
	return NULL;
}

/* ── nats_consumer_create ───────────────────────────────────── */

mi_response_t *mi_nats_consumer_create(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	jsConsumerInfo *ci = NULL;
	jsConsumerConfig cfg;
	jsErrCode jerr;
	natsStatus s;
	char *stream_name, *consumer_name;
	int stream_name_len, consumer_name_len;
	char stream_buf[256], consumer_buf[256];
	char *filter_subject = NULL;
	int filter_subject_len = 0;
	char filter_buf[512];

	if (try_get_mi_string_param(params, "stream",
			&stream_name, &stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'stream' parameter"));
	if (try_get_mi_string_param(params, "name",
			&consumer_name, &consumer_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'name' parameter"));

	if (stream_name_len >= (int)sizeof(stream_buf))
		return init_mi_error(400, MI_SSTR("stream name too long"));
	memcpy(stream_buf, stream_name, stream_name_len);
	stream_buf[stream_name_len] = '\0';

	if (consumer_name_len >= (int)sizeof(consumer_buf))
		return init_mi_error(400, MI_SSTR("consumer name too long"));
	memcpy(consumer_buf, consumer_name, consumer_name_len);
	consumer_buf[consumer_name_len] = '\0';

	js = _get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	jsConsumerConfig_Init(&cfg);
	cfg.Durable = consumer_buf;
	cfg.Name = consumer_buf;

	/* Optional filter_subject */
	if (try_get_mi_string_param(params, "filter_subject",
			&filter_subject, &filter_subject_len) == 0) {
		if (filter_subject_len >= (int)sizeof(filter_buf))
			return init_mi_error(400, MI_SSTR("filter_subject too long"));
		memcpy(filter_buf, filter_subject, filter_subject_len);
		filter_buf[filter_subject_len] = '\0';
		cfg.FilterSubject = filter_buf;
	}

	/* Optional deliver_policy */
	{
		char *dp_str = NULL;
		int dp_len = 0;
		if (try_get_mi_string_param(params, "deliver_policy",
				&dp_str, &dp_len) == 0) {
			if (dp_len == 3 && strncasecmp(dp_str, "all", 3) == 0)
				cfg.DeliverPolicy = js_DeliverAll;
			else if (dp_len == 4 && strncasecmp(dp_str, "last", 4) == 0)
				cfg.DeliverPolicy = js_DeliverLast;
			else if (dp_len == 3 && strncasecmp(dp_str, "new", 3) == 0)
				cfg.DeliverPolicy = js_DeliverNew;
			else if (dp_len == 16 && strncasecmp(dp_str, "last_per_subject", 16) == 0)
				cfg.DeliverPolicy = js_DeliverLastPerSubject;
		}
	}

	/* Optional ack_policy */
	{
		char *ap_str = NULL;
		int ap_len = 0;
		if (try_get_mi_string_param(params, "ack_policy",
				&ap_str, &ap_len) == 0) {
			if (ap_len == 8 && strncasecmp(ap_str, "explicit", 8) == 0)
				cfg.AckPolicy = js_AckExplicit;
			else if (ap_len == 4 && strncasecmp(ap_str, "none", 4) == 0)
				cfg.AckPolicy = js_AckNone;
			else if (ap_len == 3 && strncasecmp(ap_str, "all", 3) == 0)
				cfg.AckPolicy = js_AckAll;
		}
	}

	s = js_AddConsumer(&ci, js, stream_buf, &cfg, NULL, &jerr);
	if (s != NATS_OK) {
		LM_ERR("js_AddConsumer(%s/%s) failed: %s (jerr=%d)\n",
			stream_buf, consumer_buf, natsStatus_GetText(s), (int)jerr);
		return init_mi_error(500, MI_SSTR("AddConsumer failed"));
	}

	mi_response_t *resp;
	mi_item_t *resp_obj;
	resp = init_mi_result_object(&resp_obj);
	if (!resp) { jsConsumerInfo_Destroy(ci); return NULL; }

	if (add_mi_string(resp_obj, MI_SSTR("status"),
			MI_SSTR("created")) < 0 ||
		add_mi_string(resp_obj, MI_SSTR("name"),
			consumer_buf, strlen(consumer_buf)) < 0) {
		free_mi_response(resp);
		jsConsumerInfo_Destroy(ci);
		return NULL;
	}

	jsConsumerInfo_Destroy(ci);
	return resp;
}

/* ── nats_consumer_delete ───────────────────────────────────── */

mi_response_t *mi_nats_consumer_delete(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	jsErrCode jerr;
	natsStatus s;
	char *stream_name, *consumer_name;
	int stream_name_len, consumer_name_len;
	char stream_buf[256], consumer_buf[256];

	if (try_get_mi_string_param(params, "stream",
			&stream_name, &stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'stream' parameter"));
	if (try_get_mi_string_param(params, "consumer",
			&consumer_name, &consumer_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'consumer' parameter"));

	if (stream_name_len >= (int)sizeof(stream_buf))
		return init_mi_error(400, MI_SSTR("stream name too long"));
	memcpy(stream_buf, stream_name, stream_name_len);
	stream_buf[stream_name_len] = '\0';

	if (consumer_name_len >= (int)sizeof(consumer_buf))
		return init_mi_error(400, MI_SSTR("consumer name too long"));
	memcpy(consumer_buf, consumer_name, consumer_name_len);
	consumer_buf[consumer_name_len] = '\0';

	js = _get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	s = js_DeleteConsumer(js, stream_buf, consumer_buf, NULL, &jerr);
	if (s != NATS_OK) {
		if (jerr == 10014 || jerr == 10059)
			return init_mi_error(404, MI_SSTR("consumer not found"));
		LM_ERR("js_DeleteConsumer(%s/%s) failed: %s (jerr=%d)\n",
			stream_buf, consumer_buf, natsStatus_GetText(s), (int)jerr);
		return init_mi_error(500, MI_SSTR("DeleteConsumer failed"));
	}

	return init_mi_result_ok();
}

/* ── nats_msg_get ───────────────────────────────────────────── */

mi_response_t *mi_nats_msg_get(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	natsMsg *msg = NULL;
	jsErrCode jerr;
	natsStatus s;
	mi_response_t *resp;
	mi_item_t *resp_obj;
	char *stream_name;
	int stream_name_len;
	int seq_int;
	char name_buf[256];

	if (try_get_mi_string_param(params, "stream",
			&stream_name, &stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'stream' parameter"));
	if (try_get_mi_int_param(params, "seq", &seq_int) < 0)
		return init_mi_error(400, MI_SSTR("missing 'seq' parameter"));

	if (stream_name_len >= (int)sizeof(name_buf))
		return init_mi_error(400, MI_SSTR("stream name too long"));
	memcpy(name_buf, stream_name, stream_name_len);
	name_buf[stream_name_len] = '\0';

	js = _get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	s = js_GetMsg(&msg, js, name_buf, (uint64_t)seq_int, NULL, &jerr);
	if (s != NATS_OK || !msg) {
		if (jerr == 10037 || jerr == 10059)
			return init_mi_error(404, MI_SSTR("message not found"));
		LM_ERR("js_GetMsg(%s, %d) failed: %s (jerr=%d)\n",
			name_buf, seq_int, natsStatus_GetText(s), (int)jerr);
		return init_mi_error(404, MI_SSTR("message not found"));
	}

	resp = init_mi_result_object(&resp_obj);
	if (!resp) { natsMsg_Destroy(msg); return NULL; }

	{
		const char *subj = natsMsg_GetSubject(msg);
		if (subj && add_mi_string(resp_obj, MI_SSTR("subject"),
				subj, strlen(subj)) < 0)
			goto error;
	}
	{
		const char *data = natsMsg_GetData(msg);
		int data_len = natsMsg_GetDataLength(msg);
		if (data && add_mi_string(resp_obj, MI_SSTR("data"),
				data, data_len) < 0)
			goto error;
	}
	if (add_mi_number(resp_obj, MI_SSTR("sequence"), (double)seq_int) < 0)
		goto error;

	natsMsg_Destroy(msg);
	return resp;

error:
	free_mi_response(resp);
	natsMsg_Destroy(msg);
	return NULL;
}

/* ── nats_msg_delete ────────────────────────────────────────── */

mi_response_t *mi_nats_msg_delete(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	jsErrCode jerr;
	natsStatus s;
	char *stream_name;
	int stream_name_len;
	int seq_int;
	char name_buf[256];

	if (try_get_mi_string_param(params, "stream",
			&stream_name, &stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'stream' parameter"));
	if (try_get_mi_int_param(params, "seq", &seq_int) < 0)
		return init_mi_error(400, MI_SSTR("missing 'seq' parameter"));

	if (stream_name_len >= (int)sizeof(name_buf))
		return init_mi_error(400, MI_SSTR("stream name too long"));
	memcpy(name_buf, stream_name, stream_name_len);
	name_buf[stream_name_len] = '\0';

	js = _get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	s = js_DeleteMsg(js, name_buf, (uint64_t)seq_int, NULL, &jerr);
	if (s != NATS_OK) {
		if (jerr == 10037 || jerr == 10059)
			return init_mi_error(404, MI_SSTR("message not found"));
		LM_ERR("js_DeleteMsg(%s, %d) failed: %s (jerr=%d)\n",
			name_buf, seq_int, natsStatus_GetText(s), (int)jerr);
		return init_mi_error(500, MI_SSTR("DeleteMsg failed"));
	}

	return init_mi_result_ok();
}
