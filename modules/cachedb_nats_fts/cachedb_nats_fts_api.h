/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Implementation of the SHM string intern table -- see header
 * for the rationale.  ~half of all opensips CPU at 100k AoRs
 * was sem_wait -> hp_shm_malloc on the watcher's _entry_add_key
 * path; this module collapses those allocations into a single
 * intern-or-acquire per unique doc key, with refcounted release.
 */

/*
 * cachedb_nats_fts_api.h — the binds API cachedb_nats uses to reach the
 * optional FTS/search-index module (P1.2 split).  When the module is
 * not loaded every hook stays NULL and cachedb_nats runs PK-only: the
 * flagship usrloc path never touches any of this.
 */

#ifndef CACHEDB_NATS_FTS_API_H
#define CACHEDB_NATS_FTS_API_H

#include "../../cachedb/cachedb.h"

/* identical to nats.h's typedef; C11 permits the redefinition */
typedef struct __kvStore kvStore;

typedef struct cdbn_fts_api {
	/* full builds over the bucket (cachedb owns the KV handle + the
	 * doc-key prefix; the FTS module owns the index storage) */
	int (*build)(kvStore *kv, const char *prefix);
	int (*rebuild)(kvStore *kv, const char *prefix);
	/* write-side index maintenance */
	int  (*add)(const char *key, const char *json_str, int json_len);
	int  (*remove)(const char *key);
	int  (*remove_by_revmap)(const char *key);
	int  (*remove_fields)(const char *key, const char *json, int len);
	int  (*count)(void);
	/* query side: non-PK filter -> retained doc-key snapshot.
	 * Returned keys are interned refs; hand them back via
	 * release_keyset() at every cleanup site. */
	int  (*query_match_keys)(const cdb_filter_t *filter,
	                         char ***out_keys, int *out_count);
	void (*release_keyset)(char **keys, int count);
	/* single-key resolve for update(): first indexed doc key matching
	 * field=val, copied into out (pkg-independent stack buffer).
	 * 1 = hit, 0 = miss, -1 = error/overflow. */
	int  (*resolve_key)(const str *field, const str *val,
	                    char *out, int out_len);
} cdbn_fts_api_t;

typedef int (*cdbn_fts_bind_f)(cdbn_fts_api_t *api);

#endif /* CACHEDB_NATS_FTS_API_H */
