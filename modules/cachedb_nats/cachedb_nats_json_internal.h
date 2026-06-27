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
#include <time.h>

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

/* --- usrloc row metadata (cachedb_nats_json_rowmeta.c) ------------- */

/* P2.3 [REV-20] (SPEC §4.1 step 0): 1 if any incoming contact field value
 * carries an embedded NUL (a raw 0x00 or the escaped "\u0000" cJSON would
 * decode to 0x00) at any nesting depth.  Checked before any merge / kvStore op
 * so the save is refused cleanly (no partial row); the value cannot round-trip
 * (the reader's strlen truncates it). */
int _dict_has_nul_field(const cdb_dict_t *dict);

/* P2.4 [REV-15/REV-30] (SPEC §3.1 Option A): the shared cdb_json_to_dict clamps
 * every JSON number to CDB_INT32, silently narrowing a `last_mod` > INT32_MAX
 * (a usrloc CDB_INT64).  Re-parse `last_mod` as int64 from the raw row @json and
 * overwrite each contact's last_mod pair in @row_dict to CDB_INT64.  Only
 * last_mod is widened (expires stays int32-bounded, REV-30).  No-op for a
 * document without a top-level "contacts" object. */
void _row_patch_last_mod_int64(const char *json, int len, cdb_dict_t *row_dict);

/* P2.5 [REV-26] (SPEC §4.2): classify a stored KV value on read.  An EMPTY
 * value (zero-length / all-whitespace) is a legitimate server-side delete
 * marker (absent); an OBJECT is parsed; a non-empty value that is not a JSON
 * object is POISON — a hard integrity error that must NOT be masked as an
 * empty AoR (silent deregistration). */
enum nats_val_class { NATS_VAL_EMPTY = 0, NATS_VAL_OBJECT = 1, NATS_VAL_POISON = 2 };
int _value_classify(const char *data, int len);

/* P2.6 [REV-18/REV-35] (SPEC §4.2 step 3): strip the cachedb_nats-private
 * top-level peers (row_exp, schema_version) from a freshly parsed read row so
 * usrloc sees exactly {contacts, aorhash}.  Frees each removed pair completely
 * (it is no longer reachable from cdb_free_rows). */
void _row_strip_private_keys(cdb_dict_t *row_dict);

/* P2.7 [REV-21] (SPEC §4.1 step 4): skew-safe write-side hygiene.  Drop from the
 * merged @json only those contacts THIS update set/unset (@pairs) whose own
 * `expires != 0 && expires + grace <= now` — never an untouched merged-in
 * contact (the drop set is built solely from @pairs).  @grace is the max-skew
 * margin S (nats_reap_grace).  Returns a fresh doc (caller frees), unchanged
 * when nothing is due; NULL on error. */
char *_row_drop_expired_own(const char *json, int len, const cdb_dict_t *pairs,
	time_t now, int grace, int *out_len);

/* P2.2 [REV-8] (SPEC §4.1 step 2): same-contact-subkey merge ordering.  Returns
 * 1 if the NEW value supersedes the OLD (higher cseq, tie-broken by higher
 * last_mod), else 0 (the stale write is discarded, existing kept).  Engages only
 * when BOTH values carry a cseq (usrloc contacts); otherwise returns 1
 * (last-writer-wins) — unchanged behavior for non-usrloc subkeys / non-objects. */
int _cseq_new_wins(const char *new_json, int new_len,
	const char *old_json, int old_len);

/* P3 [REV-5] (SPEC §3.2/§4.1): 1 if a serialized value of @len bytes is within
 * the payload bound @max (<= 0 disables the guard).  Checked on the final merged
 * row before the CAS write so an oversize save fails cleanly. */
int _value_size_ok(int len, int max);

/* P4 [REV-3/1/26] (SPEC §4.2): omit expired contacts from a parsed read row
 * before usrloc sees them — expires==0 kept (permanent), expires+grace<=now
 * omitted, absent/non-integer expires omitted (fail-closed).  Pure read
 * mutation, NO writes.  An all-expired row keeps an empty contacts dict. */
void _row_filter_expired_contacts(cdb_dict_t *row_dict, time_t now, int grace);

/* P2.1 [REV-34/REV-25] (SPEC §3.3/§4.1 step 3): recompute the
 * cachedb_nats-private row_exp / schema_version top-level peers over the
 * merged contact set.  Returns a freshly malloc'd document (caller frees):
 * a usrloc row (top-level "contacts" object present) gets row_exp = min of the
 * non-zero per-contact `expires` (0 if any permanent, int64, no 2038 clamp)
 * and schema_version=1, replacing any stale peers; a document with no
 * top-level "contacts" is returned byte-for-byte unchanged.  NULL on
 * malformed input or OOM. */
/* P8: out_row_exp/out_n_contacts/out_all_same (all NULL-able) expose the
 * per-message-TTL eligibility inputs computed during finalize (§5). */
char *_row_finalize_metadata(const char *json, int len, int *out_len,
	int64_t *out_row_exp, int *out_n_contacts, int *out_all_same);

/* Contact-object field parsers (rowmeta TU) shared with the reaper TU.
 *   _contact_expires(): read the int64 `expires` of one contact-object slice
 *     [vstart,vend); 0 + *out on success, -1 if absent/not-an-integer.
 *   _contact_field_int64(): read any named int64 field of an object slice. */
int _contact_expires(const char *vstart, const char *vend, int64_t *out);
int _contact_field_int64(const char *vstart, const char *vend,
	const char *fname, int flen, int64_t *out);

#endif /* CACHEDB_NATS_JSON_INTERNAL_H */
