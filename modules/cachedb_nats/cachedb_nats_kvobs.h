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
 * cachedb_nats_kvobs.h — generic JetStream/KV introspection MI [KVOBS].
 * See cachedb_nats_kvobs.c for the command surface; the [OBS] design
 * invariants (cachedb_nats_reg.h) apply: read-only, bind-never-create,
 * fail-loudly filters, hard-capped pagination.
 */

#ifndef CACHEDB_NATS_KVOBS_H
#define CACHEDB_NATS_KVOBS_H

#include "../../mi/mi.h"

#define KVOBS_LIMIT_DEFAULT 50
#define KVOBS_LIMIT_CAP     200   /* MI datagram size bound */

struct kvobs_filter {
	char bucket[128];
	char key_glob[256];
	char name_glob[256];
	int  kv_only;
	int  detail;
	long limit;
	long offset;
	int  format;                /* [FMT] enum fmt_kind, default FMT_JSON */
	int  eol_lf;
	int  header;
};

/* pure helpers, unit-locked in tests/test_kvobs_filter.c */
int _kvobs_filter_parse(const char *s, int len, struct kvobs_filter *f);
int _kvobs_bucket_of_stream(const char *stream, int len,
	const char **bucket, int *blen);

/* MI handlers (registered in cachedb_nats.c) */
mi_response_t *mi_nats_stream_list(const mi_params_t *params,
	struct mi_handler *async_hdl);
mi_response_t *mi_nats_stream_info(const mi_params_t *params,
	struct mi_handler *async_hdl);
mi_response_t *mi_nats_kv_keys(const mi_params_t *params,
	struct mi_handler *async_hdl);

#endif /* CACHEDB_NATS_KVOBS_H */
