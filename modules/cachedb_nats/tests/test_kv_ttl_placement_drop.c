/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression: REGISTER segfault on a pre-2.11 broker (P8 TTL setup path).
 *
 * A single-node nats-server <2.11 returns a stream config whose Placement is
 * non-NULL but with Cluster == NULL (an empty placement stub).  libnats'
 * _marshalPlacement() does natsBuf_Append(buf, Placement->Cluster, -1), i.e.
 * strlen(Cluster), with NO null guard -- so handing that server-returned config
 * straight back to js_UpdateStream() segfaults during marshaling.  That is
 * exactly what nats_pool_kv_setup_msg_ttl() did on the first REGISTER against
 * nats-server 2.10.27:
 *   cdb_flush_urecord -> nats_cache_update -> nats_kv_write_row_cas
 *     -> nats_pool_kv_setup_msg_ttl -> js_UpdateStream
 *        -> js_marshalStreamConfig -> natsBuf_Append -> strlen(NULL)  [SIGSEGV]
 * (nats-1 2.11.10 returns Placement==NULL, so it never crashed there.)
 *
 * Fix: before js_UpdateStream, DROP a Placement whose Cluster is NULL (it is an
 * empty stub, carries no information, and is the marshaler's NULL-deref source).
 * This locks the drop predicate and that a modeled marshal no longer derefs NULL.
 *
 *   gcc -DPLACEMENT_BUG ... -> the pre-fix no-op sanitizer; the modeled marshal
 *                              would strlen(NULL) => RED.
 *   gcc ...                 -> the sanitizer drops the stub placement => GREEN.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_kv_ttl_placement_drop test_kv_ttl_placement_drop.c
 */
#include <stdio.h>
#include <stddef.h>
#include <string.h>

/* ── carried minimal model of the cnats jsPlacement / jsStreamConfig fields ── */
typedef struct { const char *Cluster; const char **Tags; int TagsLen; } jsPlacement;
typedef struct { const char *Name; jsPlacement *Placement; } jsStreamConfig;

/* production predicate (nats_pool.c): a Placement whose Cluster is NULL crashes
 * libnats' marshaler -- treat it as unmarshalable so the caller drops it. */
static int _placement_unmarshalable(const jsPlacement *p)
{
	return p != NULL && p->Cluster == NULL;
}

/* production fix path: drop the stub placement before js_UpdateStream, returning
 * the saved pointer so the caller can restore it for jsStreamInfo_Destroy. */
static jsPlacement *sanitize_placement(jsStreamConfig *cfg)
{
#ifdef PLACEMENT_BUG
	(void)cfg; return NULL;                 /* pre-fix: no-op (the crash) */
#else
	if (_placement_unmarshalable(cfg->Placement)) {
		jsPlacement *saved = cfg->Placement;
		cfg->Placement = NULL;
		return saved;
	}
	return NULL;
#endif
}

/* model of libnats _marshalPlacement(): strlen(Cluster) with NO null guard.
 * Returns -1 if it WOULD segfault (Cluster==NULL), else the marshaled length. */
static long marshal_placement_modeled(const jsStreamConfig *cfg)
{
	if (cfg->Placement == NULL) return 0;             /* libnats: if (Placement != NULL) */
	if (cfg->Placement->Cluster == NULL) return -1;   /* the strlen(NULL) crash */
	return (long)strlen(cfg->Placement->Cluster);
}

static int fails = 0;
#define OK(cond, msg) do { if (cond) printf("  ok: %s\n", msg); \
	else { printf("  FAIL: %s\n", msg); fails++; } } while (0)

int main(void)
{
	/* 1) the proven crash config: Placement != NULL, Cluster == NULL, no tags */
	{
		jsPlacement pl = { .Cluster = NULL, .Tags = NULL, .TagsLen = 0 };
		jsStreamConfig cfg = { .Name = "KV_x", .Placement = &pl };
		jsPlacement *saved = sanitize_placement(&cfg);
		OK(marshal_placement_modeled(&cfg) >= 0,
			"stub placement (Cluster=NULL) does NOT crash the marshal after sanitize");
		if (saved) cfg.Placement = saved;   /* restore for jsStreamInfo_Destroy */
		OK(cfg.Placement == &pl, "dropped placement pointer is restored for cleanup (no leak)");
	}
	/* 2) NULL placement: nothing to do, no crash */
	{
		jsStreamConfig cfg = { .Name = "KV_x", .Placement = NULL };
		sanitize_placement(&cfg);
		OK(marshal_placement_modeled(&cfg) == 0, "NULL placement marshals (no-op)");
	}
	/* 3) real placement (Cluster set): preserved, marshals fine */
	{
		jsPlacement pl = { .Cluster = "c1", .Tags = NULL, .TagsLen = 0 };
		jsStreamConfig cfg = { .Name = "KV_x", .Placement = &pl };
		sanitize_placement(&cfg);
		OK(cfg.Placement == &pl, "non-empty placement (Cluster set) is preserved");
		OK(marshal_placement_modeled(&cfg) == 2, "real placement marshals its cluster");
	}
	/* 4) predicate edge cases (NULL / empty-string cluster) */
	OK(_placement_unmarshalable(NULL) == 0, "NULL placement is not flagged");
	{
		jsPlacement e = { .Cluster = NULL };
		OK(_placement_unmarshalable(&e) == 1, "Cluster=NULL placement flagged unmarshalable");
		jsPlacement f = { .Cluster = "" };
		OK(_placement_unmarshalable(&f) == 0, "empty-string cluster is marshalable (strlen ok)");
	}
	printf("\n%s (fails=%d)\n", fails ? "FAILED" : "ALL PASS", fails);
	return fails ? 1 : 0;
}
