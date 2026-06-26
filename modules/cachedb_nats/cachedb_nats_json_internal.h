/*
 * Copyright (C) 2025 Summit-2026 / cachedb_nats contributors
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
 * cachedb_nats_json_internal.h — private cross-TU declarations for the
 * JSON index / serializer / query+update translation units (the
 * NATS_TODO #60 split of cachedb_nats_json.c).  Nothing here is module
 * API: modules outside cachedb_nats must use cachedb_nats_json.h.
 */

#ifndef CACHEDB_NATS_JSON_INTERNAL_H
#define CACHEDB_NATS_JSON_INTERNAL_H

#include <stdint.h>

#include "../../cachedb/cachedb.h"
#include "cachedb_nats_json.h"

/* --- search index internals (cachedb_nats_json_index.c) ----------- */

/* The process-global SHM search index; query/update read it directly
 * (under the shard locks below).  NULL until nats_json_index_init(). */
extern nats_search_idx *g_idx;

/* djb2 over "field:value"; returns a bucket in [0, nats_idx_buckets). */
unsigned int _hash(const char *s, int len);

/* Iterative JSON scanners used to pre-validate broker-supplied bytes
 * before the recursive cJSON parser (and to walk documents in the
 * single-pass update). */
const char *_skip_ws(const char *p, const char *end);
const char *_skip_json_value(const char *p, const char *end);

/* Scan a JSON quoted string (escape-aware); *out / *out_len get the raw
 * slice inside the quotes.  Returns past the closing quote or NULL. */
const char *_parse_json_string(const char *p, const char *end,
	const char **out, int *out_len);

/* Depth/size-guarded JSON -> cdb_dict_t conversion. */
int _safe_json_to_dict(const char *data, int data_len, cdb_dict_t *out);

/* Locate the index entry for a composite "field:value" key.  Caller
 * must hold the entry's shard lock. */
nats_idx_entry *_find_entry(const char *fv, int fv_len);

/* Shard-locking helpers.  Whole-index ops acquire shards in index
 * order to keep the lock hierarchy consistent.  The lock set itself
 * is SHM-backed so cross-process synchronisation is safe. */
static inline void _idx_lock_shard(nats_search_idx *idx, int shard)
{
	lock_set_get(idx->shard_locks, shard);
}
static inline void _idx_unlock_shard(nats_search_idx *idx, int shard)
{
	lock_set_release(idx->shard_locks, shard);
}

/* --- JSON sink / serializer (cachedb_nats_json_ser.c) -------------- */

typedef struct {
	char *buf;
	int   len;
	int   cap;
	int   oom;     /* sticky: once set, all subsequent ops are no-ops */
} json_sink_t;

int   _sink_init(json_sink_t *s, int initial);
int   _sink_write(json_sink_t *s, const char *p, int n);
int   _sink_putc(json_sink_t *s, char c);
int   _sink_emit_string(json_sink_t *s, const char *p, int n);
int   _sink_emit_raw_string(json_sink_t *s, const char *p, int n);
int   _sink_emit_int(json_sink_t *s, int64_t v);
char *_sink_take(json_sink_t *s, int *out_len);

/* cdb_dict_t -> malloc'd JSON object text. */
char *_serialize_cdb_dict(const cdb_dict_t *dict, int *out_len);

/* Percent-encode arbitrary bytes into a NATS-KV-safe key. */
char *_kv_encode_key(const char *in, int in_len, int *out_len);

/* [REV-23] Validate an encoded row key (AoR portion): reject empty key or any
 * empty subject token (leading/trailing/double '.'). 0 = ok, -1 = reject. */
int _kv_key_validate(const char *enc, int enc_len);

/* "<fts_json_prefix>" + encoded PK value, stack buffer with heap
 * fallback (sets *heap when the caller must free). */
char *_pk_target_key(const char *val, int val_len,
	char *stackbuf, int stackcap, int *heap);

/* Minimal {"field":"value"} seed document for update-creates-doc. */
char *_build_seed_doc(const char *field, int flen,
	const char *val, int vlen, int *out_len);

#endif /* CACHEDB_NATS_JSON_INTERNAL_H */
