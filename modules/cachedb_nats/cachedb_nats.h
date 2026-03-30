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
 *
 */

#ifndef CACHEDB_NATS_H
#define CACHEDB_NATS_H

#include <nats/nats.h>
#include "../../cachedb/cachedb.h"

typedef struct _nats_cachedb_con {
    /* ------ Fixed cachedb header (must be first, exact order) ------ */
    struct cachedb_id *id;
    unsigned int ref;
    struct cachedb_pool_con_t *next;
    /* ------ NATS-specific fields ------ */
    kvStore *kv;
    char *bucket_name;
} nats_cachedb_con;

/* cachedb API functions — implemented in cachedb_nats_dbase.c */
cachedb_con* nats_cachedb_init(str *url);
void nats_cachedb_destroy(cachedb_con *con);

int nats_cache_get(cachedb_con *con, str *attr, str *val);
int nats_cache_set(cachedb_con *con, str *attr, str *val, int expires);
int nats_cache_remove(cachedb_con *con, str *attr);
int nats_cache_add(cachedb_con *con, str *attr, int val, int expires, int *new_val);
int nats_cache_sub(cachedb_con *con, str *attr, int val, int expires, int *new_val);
int nats_cache_get_counter(cachedb_con *con, str *attr, int *val);

/* raw_query and map operations — implemented in cachedb_nats_native.c */
int nats_cache_raw_query_impl(cachedb_con *con, str *attr, cdb_raw_entry ***reply, int expected_kv_no, int *reply_no);
int nats_cache_map_get(cachedb_con *con, const str *key, cdb_res_t *res);
int nats_cache_map_set(cachedb_con *con, const str *key, const str *subkey, const cdb_dict_t *pairs);
int nats_cache_map_remove(cachedb_con *con, const str *key, const str *subkey);

#endif /* CACHEDB_NATS_H */
