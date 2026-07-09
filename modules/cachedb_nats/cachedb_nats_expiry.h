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
 * cachedb_nats_expiry.h — declarations for the module's single expiry
 * TU (P1.5b merge of cachedb_nats_ttl.h and cachedb_nats_reaper.h).
 */

#ifndef CACHEDB_NATS_EXPIRY_H
#define CACHEDB_NATS_EXPIRY_H

/*
 * cachedb_nats_ttl.h — pure logic for the native NATS per-key TTL mechanism
 * (TTL-SOLUTION-SPEC.md).  These helpers are broker-less and side-effect-free:
 * eligibility, TTL/unit computation, the marker-aware CAS predicate, and
 * js_PublishMsg outcome classification.  The actual raw-publish wiring (the
 * js_PublishMsg / js_UpdateStream bindings) is added later (P6+); keeping the
 * decision logic pure makes it exhaustively unit-testable without a server.
 */


#include <stdint.h>

#define NATS_NS_PER_S 1000000000LL

/* ---- marker-aware CAS predicate (§2.2 [TREV-2/2a], [REV-27]) ------ */

/* Which JetStream publish precondition to use.  An empty-value entry is a
 * server-side delete marker — it must CAS at its revision, NOT be treated as
 * absent; and a NATS_NOT_FOUND that still has a head sequence (a DEL/PURGE
 * marker filtered by kvStore_Get) must CAS at the head, not use ExpectNoMessage
 * (which the server rejects over a marker, [REV-27]). */
enum ttl_cas_pred {
	TTL_CAS_NO_MESSAGE = 0,   /* ExpectNoMessage — provably empty subject */
	TTL_CAS_LAST_SEQ   = 1,   /* ExpectLastSubjectSeq = *out_seq */
};

/* @got_entry: kvStore_Get returned an entry (any @value_len, incl. 0 marker).
 * @entry_rev: that entry's kvEntry_Revision.  @head_seq: the subject's resolved
 * head sequence when !got_entry (0 if provably empty).  Sets *out_seq. */
enum ttl_cas_pred cdbn_ttl_cas_predicate(int got_entry, int value_len,
	uint64_t entry_rev, uint64_t head_seq, uint64_t *out_seq);

/* ---- js_PublishMsg outcome classification (§2.2.1 [TREV-13]) ------ */

/* Normalized publish status (the caller maps natsStatus: NATS_OK -> OK,
 * NATS_TIMEOUT/NATS_CONNECTION_CLOSED -> CONN_DOWN, else -> JS_ERR), so this TU
 * stays free of the nats.h status-enum coupling. */
enum ttl_pub_status {
	TTL_PUB_OK        = 0,
	TTL_PUB_CONN_DOWN = 1,
	TTL_PUB_JS_ERR    = 2,
};
enum ttl_outcome {
	TTL_DONE       = 0,   /* committed */
	TTL_RETRY      = 1,   /* CAS conflict (10071) — re-read + retry */
	TTL_FAIL_SAVE  = 4,   /* broker down / unknown — non-2xx, client retries */
};
enum ttl_outcome cdbn_ttl_classify(enum ttl_pub_status st, int jerr);

/* ---- delete / purge as a publish (§2.5) -------------------------- */
#define NATS_KV_OP_HDR   "KV-Operation"
#define NATS_KV_OP_DEL   "DEL"
#define NATS_KV_OP_PURGE "PURGE"
/* The KV-Operation value for a publish-delete: PURGE (drop history) when
 * @purge, else DEL (tombstone, keep history). */
const char *cdbn_ttl_delete_op(int purge);

/* ---- startup guard + capability latch (§5.3 [REV-7], §6 [TREV-8]) -- */

/* [REV-7] kv_ttl (bucket MaxAge) MUST be 0: a non-zero bucket TTL becomes
 * stream MaxAge, which caps per-key TTL and silently expires permanent
 * (expires==0) contacts.  Returns 0 if ok, -1 if the value must be refused. */
int cdbn_kv_ttl_guard(int kv_ttl);

/* P11b [REV-25]: policy for a PRE-EXISTING bucket already carrying a non-zero
 * backing-stream MaxAge (the cdbn_kv_ttl_guard modparam check only stops THIS module
 * from creating one).  A non-zero MaxAge silently expires permanent (expires==0)
 * contacts.  @maxage_ns = bound stream MaxAge (ns).  Returns 1 if a startup WARN
 * is warranted (non-zero), 0 if clean (MaxAge==0). */
int cdbn_kv_legacy_bucket_maxage_warn(int64_t maxage_ns);

/* [D6/HREV-6] mod_init guard: 0 ok, -1 refuse. */
int cdbn_linger_guard(int linger);          /* nats_expired_linger: 0..86400 */

/* ---- key -> JetStream subject (§2.1 [TREV-5]) -------------------- */

/* Build "$KV.<bucket>.<key>" for a row key into @buf (NUL-terminated); returns
 * the written length, or -1 if @buf is too small.  @key is the already
 * P1-encoded, KV-safe row key.  MUST be byte-identical to the subject
 * kvStore_Put/Get uses for the same key (one mapping, three consumers), else a
 * raw-published value lands where the reader never looks (split-brain). */
int nats_kv_key_to_subject(const char *bucket, const char *key,
	char *buf, int buflen);

/* ---- the one usrloc-row write helper (§2.0 invariant) ----------- */

/* Single-shot CAS publish.  EVERY usrloc-row write (registration + reaper
 * survivor-write) goes through this; no kvStore_UpdateString may remain on
 * the usrloc row path.  Implemented in cachedb_nats_ttl_put.c.
 * Forward-declare the cnats opaque handles (identical to nats.h's typedefs;
 * C11 permits the redefinition) so this header stays usable by pure TUs
 * that don't pull in <nats/nats.h>. */
typedef struct __jsCtx   jsCtx;
typedef struct __kvStore kvStore;
enum ttl_outcome nats_kv_put_row(jsCtx *js, kvStore *kv,
	const char *bucket, const char *key,
	const char *json, int json_len,
	int got_entry, uint64_t entry_rev, int64_t ttl_ms, uint64_t *out_rev);

/* [TTL-BELOW-MARKER] pure TTL-derivation helpers (resurrected from the
 * pre-P1.5a native-TTL path; TTL-SOLUTION-SPEC §2.3/§5).  A row is
 * TTL-eligible only when non-empty, non-permanent, and single-contact or
 * uniform-expiry (mixed rows stay reaper-owned); the ms value floors at
 * the server's 1 s minimum so an already-expired-at-write row still
 * self-expires (RC-6). */
int cdbn_ttl_eligible(int64_t row_exp, int n_contacts, int all_same_expiry);
int64_t cdbn_ttl_seconds(int64_t row_exp, int64_t now, int grace);
int64_t cdbn_ttl_msgttl_ms(int64_t ttl_seconds);

/* The §2.0 write entry point every row writer uses.  rev==0 is the "no
 * prior message" sentinel [HREV-2] (JetStream sequences are 1-based): the
 * write becomes a CREATE; rev>0 CAS-updates at that revision.
 * @row_exp/@n_contacts/@all_same are the row's finalized metadata and
 * @grace the physical-reclamation slack (nats_reap_grace +
 * nats_expired_linger): when kv_ttl_below_marker is on AND the broker
 * probe latched SUPPORTED, the write re-asserts a native per-key TTL
 * derived from them (§2.0 invariant); otherwise they are ignored and the
 * write is TTL-less exactly as before.
 * 0 = done, 1 = CAS conflict (re-read + retry), -1 = fail.  *out_rev set
 * on success. */
int nats_kv_write_row_cas(kvStore *kv, const char *bucket, const char *key,
	const char *json, int json_len, uint64_t rev,
	int64_t row_exp, int n_contacts, int all_same, int grace,
	uint64_t *out_rev);

/*
 * cachedb_nats_reaper.h — the reaper: the AUTHORITATIVE per-contact expiry
 * mechanism (SPEC.md §4.3A).  Native per-message TTL (TTL-SOLUTION-SPEC.md) is
 * only an opportunistic optimization; the reaper is what actually guarantees an
 * expired contact is reclaimed (and the only correct behavior for servers <2.11,
 * mixed-expiry rows, and #6959/#1994 regressions).
 *
 * This header currently exposes the broker-less DECISION helpers (row-due
 * selection, per-row action, interval guard).  The reaper loop / process host
 * (its own register_timer [REV-17], the bounded KeysWithFilters scan [REV-28],
 * the in-SHM (row_exp,key) index, the CAS-prune via nats_kv_put_row [TREV-3]
 * with the CAS-guarded publish-delete [REV-16]) integrates on top and is gated
 * on the opensips+nats e2e harness.
 */


#include <stdint.h>
#include <time.h>

/* (§4.3A [REV-1]) A row is a reap candidate iff row_exp != 0 && row_exp + slack
 * <= now.  row_exp == 0 is permanent and is NEVER due.  The slack the caller
 * passes is nats_reap_grace + nats_expired_linger [HREV-3]: the skew margin
 * keeps the reaper from purging within S of an expiry, the linger keeps it
 * from defeating the operator's physical-retention window. */
int cdbn_reap_row_due(int64_t row_exp, time_t now, int grace);

/* (§4.3A [REV-16/31]) What the reaper does with a due row after pruning its
 * expired contacts. */
enum reap_action {
	REAP_WRITE_SURVIVORS = 0,   /* CAS survivor-write via nats_kv_put_row     */
	REAP_DELETE_EMPTY    = 1,   /* CAS-guarded publish-delete (never blind)   */
};
enum reap_action cdbn_reap_row_action(int n_live_survivors);

/* (F2 [PREV-26/REV-2], extended [D6/HREV-6]) nats_reap_interval guard.
 * Returns 0 to start, -1 to refuse: interval <= 0 (reaper-off, TTL-only) is
 * unsupported unless the operator explicitly sets nats_unsafe_ttl_only (which
 * LM_WARNs #6959/#1994) -- and never supported with nats_native_ttl=0, which
 * would leave no expiry mechanism at all. */
int cdbn_reap_interval_guard(int interval);

/* [P2.7] The reaper pass body (P9 host); the SINGLE expiry mechanism.
 * [P3.3] Runs in the dedicated reaper process (nats_cdb_reaper_proc_main),
 * NOT the shared core timer process -- a full-bucket pass (one
 * value-carrying watch pass + CAS) at scale would stall usrloc/tm/dialog timers
 * system-wide.  The (ticks, param) signature is kept from its
 * register_timer era so the body needs no churn. */
void nats_cdb_reaper_tick(unsigned int ticks, void *param);

/* [P3.3] Dedicated reaper process entry point (proc_export_t, same
 * pattern as the KV watcher).  Hosts BOTH periodic O(bucket) jobs: the
 * reaper pass every nats_reap_interval and -- when the FTS module is
 * bound and index_resync_interval_secs > 0 -- the periodic index
 * resync.  Never returns. */
void nats_cdb_reaper_proc_main(int rank);

/*
 * [P3.3] Due-scheduler for the reaper process's periodic jobs.  Plain
 * elapsed-interval gating: a job fires when its interval is positive
 * and at least one full interval has passed since its stamp; firing
 * resets the stamp to @now (never to now - k*interval, so a stalled
 * process runs each due job ONCE on catch-up, no burst).  Intervals
 * <= 0 disable the job.  Process-local, single-threaded.
 */
typedef struct nats_cdb_proc_sched {
	time_t last_reap;
	time_t last_resync;
} nats_cdb_proc_sched_t;

/*
 * First-fire stagger for the reaper.  Multi-instance deployments boot
 * every proxy with the same nats_reap_interval; without a per-instance
 * offset all reapers start their first O(bucket) pass at the same
 * uptime and hit the broker together.  Returns a deterministic offset
 * in [0, interval/4] derived from @seed (callers pass the pid);
 * degenerate intervals (< 4 s) return 0.
 */
static inline int nats_cdb_reap_first_jitter(int interval_s,
	unsigned int seed)
{
	unsigned int span;

	if (interval_s < 4)
		return 0;                     /* a quarter of nothing is nothing */
	span = (unsigned int)(interval_s / 4);
	/* Knuth multiplicative hash: cheap, deterministic, spreads
	 * consecutive pids (fork order!) across the whole span. */
	return (int)(((seed * 2654435761u) >> 16) % (span + 1));
}

static inline void nats_cdb_proc_sched_due(nats_cdb_proc_sched_t *sc,
	time_t now, int reap_iv, int resync_iv,
	int *run_reap, int *run_resync)
{
	*run_reap   = 0;
	*run_resync = 0;
	if (reap_iv > 0 && now - sc->last_reap >= reap_iv) {
		*run_reap = 1;
		sc->last_reap = now;
	}
	if (resync_iv > 0 && now - sc->last_resync >= resync_iv) {
		*run_resync = 1;
		sc->last_resync = now;
	}
}

#endif /* CACHEDB_NATS_EXPIRY_H */
