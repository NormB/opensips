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
 * cachedb_nats_reg.h — registration observability [OBS].
 *
 * In usrloc full-sharing-cachedb mode the in-memory urecord is freed after
 * every flush, so usrloc's own MI (ul_dump & friends) is empty BY DESIGN and
 * the only truth about registrations is the KV bucket.  This TU gives
 * operators that view back:
 *
 *   nats_reg_summary [domains=1]   high level: totals + per-domain table
 *   nats_reg_list    [filter]      per-AoR rows with filter/sort/pagination
 *   nats_reg_show    aor=<aor>     every stored attribute of one AoR
 *
 * plus reaper-piggybacked gauges in nats_cdb_stats (the reaper already Gets
 * every key each pass — recording totals there costs nothing extra on the
 * broker and gives monitoring a registration time series every
 * nats_reap_interval seconds) [D-OBS-2].
 *
 * Design invariants:
 *   [D-OBS-1] the bucket is the source of truth: MI scans on demand
 *             (kvStore_Keys + Get, the reaper's index-independent pattern);
 *             per-instance incremental gauges cannot represent a shared
 *             multi-writer bucket.
 *   [D-OBS-4] "active" == "would be served": expires==0 or expires+grace>now,
 *             identical to the read filter; linger NEVER affects it.
 */

#ifndef CACHEDB_NATS_REG_H
#define CACHEDB_NATS_REG_H

#include <stdint.h>
#include <time.h>

#include "../../mi/mi.h"

#define REG_NO_EXPIRY INT64_MAX

enum reg_cstate { REG_C_ACTIVE = 0, REG_C_EXPIRED = 1, REG_C_PERMANENT = 2 };
enum reg_sortkey { REG_SORT_AOR = 0, REG_SORT_EXPIRY = 1,
                   REG_SORT_CONTACTS = 2, REG_SORT_LAST_MOD = 3 };
enum reg_statef { REG_F_ACTIVE = 0, REG_F_EXPIRED = 1, REG_F_PERMANENT = 2,
                  REG_F_ALL = 3 };

#define REG_LIMIT_DEFAULT 50
#define REG_LIMIT_CAP     200   /* MI datagram size bound */

struct reg_filter {
	char aor_glob[256];
	char domain[192];
	char ua[128];
	char contact[192];
	int  state;                 /* enum reg_statef, default ACTIVE */
	long expiring_within;       /* 0 = off */
	long min_contacts;          /* 0 = off */
	int  sort;                  /* enum reg_sortkey, default AOR */
	int  desc;
	long limit;                 /* default 50, clamped to REG_LIMIT_CAP */
	long offset;
	int  format;                /* [FMT] enum fmt_kind, default FMT_JSON */
	int  eol_lf;                /* [FMT-7] 0=CRLF 1=LF */
	int  header;                /* [FMT-5] header record on/off (default 1) */
};

/* One-pass summary of a stored usrloc row (slices point into the doc). */
struct reg_row_info {
	const char *aor; int aor_len;
	int n_contacts, n_active, n_expired, n_perm;
	int64_t soonest_exp;        /* min upcoming (active) expiry, or sentinel */
	int64_t last_mod;           /* max over contacts, 0 if absent */
	int ua_hit, ct_hit;         /* filter needles matched some contact */
};

/* ---- pure helpers (unit-locked in tests/test_reg_*.c) ------------- */
int  _reg_contact_state(int64_t expires, time_t now, int grace);
int  _reg_domain_of(const char *aor, int len, const char **dom, int *dlen);
int  _reg_ci_eq(const char *a, int alen, const char *b, int blen);
int  _reg_substr(const char *hay, int hlen, const char *nee, int nlen);
int  _reg_filter_parse(const char *s, int len, struct reg_filter *f);
void _reg_page(long total, long limit, long offset, long *start, long *count);
int  _reg_row_cmp(const struct reg_row_info *a, const struct reg_row_info *b,
	int sort, int desc);
int  _reg_row_scan(const char *json, int len, time_t now, int grace,
	const char *ua_nee, int ua_len, const char *ct_nee, int ct_len,
	struct reg_row_info *out);

/* ---- MI handlers (registered in cachedb_nats.c) ------------------- */
mi_response_t *mi_nats_reg_summary(const mi_params_t *params,
	struct mi_handler *async_hdl);
mi_response_t *mi_nats_reg_list(const mi_params_t *params,
	struct mi_handler *async_hdl);
mi_response_t *mi_nats_reg_show(const mi_params_t *params,
	struct mi_handler *async_hdl);

#endif /* CACHEDB_NATS_REG_H */
