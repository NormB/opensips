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

/**
 * Choose the marker-aware CAS predicate for a row write (§2.2).
 *
 * @param got_entry  kvStore_Get returned an entry (any @value_len,
 *                   including a 0-length delete marker).
 * @param value_len  that entry's value length (currently unused: an
 *                   empty marker and a live value both CAS at the rev).
 * @param entry_rev  the entry's kvEntry_Revision when @got_entry.
 * @param head_seq   the subject's resolved head sequence when
 *                   !@got_entry (0 if provably empty).
 * @param out_seq    [out] sequence to CAS at (0 for NO_MESSAGE).
 * @return TTL_CAS_LAST_SEQ to CAS at *out_seq, or TTL_CAS_NO_MESSAGE
 *         for a provably empty subject.
 *
 * Pure decision helper: no allocation, no locking, no broker I/O;
 * callable from any process context.
 */
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

/**
 * Classify a normalized publish outcome (§2.2.1 [TREV-13]).
 *
 * @param st    normalized publish status (see enum ttl_pub_status).
 * @param jerr  the jsErrCode from js_PublishMsg (only consulted for
 *              TTL_PUB_JS_ERR; 10071 = JSStreamWrongLastSequenceErr).
 * @return TTL_DONE on OK; TTL_RETRY on a CAS conflict (10071);
 *         TTL_FAIL_SAVE for broker-down or any unrecognized JS error.
 *
 * Pure: no allocation, no locking; any process context.
 */
enum ttl_outcome cdbn_ttl_classify(enum ttl_pub_status st, int jerr);

/* ---- delete / purge as a publish (§2.5) -------------------------- */
#define NATS_KV_OP_HDR   "KV-Operation"
#define NATS_KV_OP_DEL   "DEL"
#define NATS_KV_OP_PURGE "PURGE"

/**
 * The KV-Operation header value for a publish-delete (§2.5).
 *
 * @param purge  non-zero selects PURGE (drop history), zero DEL
 *               (tombstone, keep history).
 * @return pointer to a static string constant ("PURGE" or "DEL");
 *         never freed by anyone.
 *
 * Pure: no allocation, no locking; any process context.
 */
const char *cdbn_ttl_delete_op(int purge);

/* ---- startup guard + capability latch (§5.3 [REV-7], §6 [TREV-8]) -- */

/**
 * [REV-7] kv_ttl (bucket MaxAge) MUST be 0: a non-zero bucket TTL becomes
 * stream MaxAge, which caps per-key TTL and silently expires permanent
 * (expires==0) contacts.
 *
 * @param kv_ttl  the kv_ttl modparam value.
 * @return 0 if ok (kv_ttl == 0), -1 if the value must be refused.
 *
 * Pure: no allocation, no locking.  Context: mod_init (pre-fork)
 * modparam validation in cachedb_nats.c.
 */
int cdbn_kv_ttl_guard(int kv_ttl);

/**
 * P11b [REV-25]: policy for a PRE-EXISTING bucket already carrying a
 * non-zero backing-stream MaxAge (the cdbn_kv_ttl_guard modparam check
 * only stops THIS module from creating one).  A non-zero MaxAge
 * silently expires permanent (expires==0) contacts.
 *
 * @param maxage_ns  the bound bucket's backing-stream MaxAge in ns.
 * @return 1 if a startup WARN (or refusal, per
 *         require_usrloc_safe_bucket) is warranted (non-zero MaxAge),
 *         0 if clean (MaxAge == 0).
 *
 * Pure: no allocation, no locking.  Context: called from child_init
 * (rank 1) after the bucket bind; safe anywhere.
 */
int cdbn_kv_legacy_bucket_maxage_warn(int64_t maxage_ns);

/**
 * [D6/HREV-6] nats_expired_linger range guard: negative is meaningless,
 * > 1 day (86400 s) is almost certainly a typo'd epoch in the config.
 *
 * @param linger  the nats_expired_linger modparam value.
 * @return 0 ok (0..86400), -1 refuse.
 *
 * Pure: no allocation, no locking.  Context: mod_init (pre-fork).
 */
int cdbn_linger_guard(int linger);          /* nats_expired_linger: 0..86400 */

/* ---- key -> JetStream subject (§2.1 [TREV-5]) -------------------- */

/**
 * Build "$KV.<bucket>.<key>" for a row key into @buf (NUL-terminated).
 * MUST be byte-identical to the subject kvStore_Put/Get uses for the
 * same key (one mapping, three consumers), else a raw-published value
 * lands where the reader never looks (split-brain).
 *
 * @param bucket  KV bucket name.
 * @param key     the already P1-encoded, KV-safe row key.
 * @param buf     caller-owned output buffer (nothing allocated).
 * @param buflen  capacity of @buf in bytes.
 * @return the written length (excluding the NUL), or -1 if @buf is too
 *         small (callers MUST fail the write, never truncate).
 *
 * Pure: no allocation, no locking; any process context.
 */
int nats_kv_key_to_subject(const char *bucket, const char *key,
	char *buf, int buflen);

/* ---- the one usrloc-row write helper (§2.0 invariant) ----------- */

/* Single-shot CAS publish.  EVERY usrloc-row write (registration + reaper
 * survivor-write) goes through this; no kvStore_UpdateString may remain on
 * the usrloc row path.  Implemented in cachedb_nats_expiry.c.
 * Forward-declare the cnats opaque handles (identical to nats.h's typedefs;
 * C11 permits the redefinition) so this header stays usable by pure TUs
 * that don't pull in <nats/nats.h>. */
typedef struct __jsCtx   jsCtx;
typedef struct __kvStore kvStore;

/**
 * Single-shot CAS publish of a usrloc-row value (§2.0/§2.2).
 *
 * Routes to kvStore_CreateWithTTL() when the CAS predicate resolves to
 * NO_MESSAGE (absent subject / DEL-PURGE marker head), otherwise
 * CAS-publishes via js_PublishMsg with ExpectLastSubjectSeq set to the
 * revision read by the caller.  @ttl_ms > 0 carries a native
 * per-message TTL on either path; <= 0 writes TTL-less.
 *
 * @param js         JetStream context (pool-owned, e.g. from
 *                   nats_pool_get_js(); borrowed, never released here).
 * @param kv         KV bucket handle (pool-owned; borrowed).
 * @param bucket     bucket name (forms the "$KV.<bucket>.<key>" subject).
 * @param key        encoded, KV-safe row key.
 * @param json       row value bytes (need not be NUL-terminated).
 * @param json_len   value length in bytes.
 * @param got_entry  the caller's prior read found an entry (NATS_OK).
 * @param entry_rev  that entry's revision (CAS predicate target).
 * @param ttl_ms     per-message TTL in ms; <= 0 for none.
 * @param out_rev    [out, NULL-able] new KV revision on TTL_DONE.
 * @return TTL_DONE committed; TTL_RETRY on a CAS conflict / lost
 *         concurrent create (caller re-reads + retries); TTL_FAIL_SAVE
 *         on broker-down, subject overflow, or a hard JS error.
 *
 * Ownership: nothing is handed to the caller (transient natsMsg /
 * jsPubAck are created and destroyed internally).  Blocks up to the
 * pool's JetStream request timeout.  Locking: none — the pool handles
 * are process-local and MUST only be used single-threaded within one
 * process.  Context: SIP workers (row update via nats_kv_write_row_cas,
 * native raw-CAS path in cachedb_nats_native.c) and the dedicated
 * reaper process (survivor-write); never cnats callback threads.
 */
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

/**
 * [REV-6/F6] (§5) per-message-TTL eligibility of a finalized row.
 *
 * @param row_exp          the row's finalized row_exp (0 = permanent).
 * @param n_contacts       contact count after merge/projection.
 * @param all_same_expiry  1 when every contact shares one expiry.
 * @return 1 eligible (non-empty, non-permanent, single-contact or
 *         uniform expiry), 0 not (write TTL-less, reaper-owned).
 *
 * Pure: no allocation, no locking; any process context.
 */
int cdbn_ttl_eligible(int64_t row_exp, int n_contacts, int all_same_expiry);

/**
 * (§2.3) ttl_seconds = row_exp - now + grace.
 *
 * @param row_exp  the row's earliest expiry (epoch seconds).
 * @param now      node-local current time (epoch seconds).
 * @param grace    physical-reclamation slack in seconds.
 * @return the (possibly negative) TTL in seconds; the caller feeds it
 *         to cdbn_ttl_msgttl_ms() which floors it.
 *
 * Pure: no allocation, no locking; any process context.
 */
int64_t cdbn_ttl_seconds(int64_t row_exp, int64_t now, int grace);

/**
 * (§2.3 [TREV-12] / [HREV-3]) Convert a TTL in seconds to the MsgTTL
 * milliseconds value: <= 0 floors to the 1 s server minimum so an
 * already-expired-at-write row still self-expires instead of being
 * written TTL-less (RC-6); the multiplication is overflow-capped.
 *
 * @param ttl_seconds  TTL in seconds (any value).
 * @return MsgTTL in ms, always >= 1000.
 *
 * Pure: no allocation, no locking; any process context.
 */
int64_t cdbn_ttl_msgttl_ms(int64_t ttl_seconds);

/**
 * The §2.0 write entry point every row writer uses.  rev==0 is the "no
 * prior message" sentinel [HREV-2] (JetStream sequences are 1-based):
 * the write becomes a CREATE; rev>0 CAS-updates at that revision.
 *
 * When kv_ttl_below_marker is on AND the broker probe latched
 * SUPPORTED, the write re-asserts a native per-key TTL derived from
 * @row_exp/@n_contacts/@all_same and @grace (§2.0 invariant); otherwise
 * they are ignored and the write is TTL-less exactly as before.
 *
 * @param kv          KV bucket handle (pool-owned; borrowed).
 * @param bucket      bucket name.
 * @param key         encoded, KV-safe row key.
 * @param json        row value bytes.
 * @param json_len    value length.
 * @param rev         prior revision; 0 = create, > 0 = CAS-update.
 * @param row_exp     the row's finalized row_exp (TTL eligibility).
 * @param n_contacts  contact count (TTL eligibility).
 * @param all_same    1 when all contacts share one expiry.
 * @param grace       physical-reclamation slack (nats_reap_grace +
 *                    nats_expired_linger).
 * @param out_rev     [out, NULL-able] new revision on success.
 * @return 0 = committed, 1 = CAS conflict (caller re-reads + retries),
 *         -1 = fail the save.
 *
 * Ownership: nothing handed to the caller.  Reads the
 * kv_ttl_below_marker modparam and the per-process pool TTL latch, and
 * acquires the JetStream ctx via nats_pool_get_js() itself.  Blocks up
 * to the JetStream request timeout.  Locking: none (process-local pool
 * handles, single-threaded use).  Context: SIP worker update path
 * (cachedb_nats_json.c) and the dedicated reaper process
 * (survivor-write); never cnats callback threads.
 */
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

/**
 * (§4.3A [REV-1]) Row-due selection: a row is a reap candidate iff
 * row_exp != 0 && row_exp + slack <= now.  row_exp == 0 is permanent
 * and is NEVER due.  The slack the caller passes is nats_reap_grace +
 * nats_expired_linger [HREV-3]: the skew margin keeps the reaper from
 * purging within S of an expiry, the linger keeps it from defeating the
 * operator's physical-retention window.
 *
 * @param row_exp  the row's earliest expiry (0 = permanent).
 * @param now      node-local current time.
 * @param grace    the slack in seconds.
 * @return 1 due, 0 not due / permanent.
 *
 * Pure: no allocation, no locking; any process context.
 */
int cdbn_reap_row_due(int64_t row_exp, time_t now, int grace);

/* (§4.3A [REV-16/31]) What the reaper does with a due row after pruning its
 * expired contacts. */
enum reap_action {
	REAP_WRITE_SURVIVORS = 0,   /* CAS survivor-write via nats_kv_put_row     */
	REAP_DELETE_EMPTY    = 1,   /* CAS-guarded publish-delete (never blind)   */
};

/**
 * (§4.3A [REV-16/31]) Per-row action after pruning expired contacts.
 *
 * @param n_live_survivors  contact count after the projection.
 * @return REAP_WRITE_SURVIVORS when any contact survives,
 *         REAP_DELETE_EMPTY when none do.
 *
 * Pure: no allocation, no locking; any process context.
 */
enum reap_action cdbn_reap_row_action(int n_live_survivors);

/**
 * (F2 [PREV-26/REV-2], extended [D6/HREV-6]) nats_reap_interval guard.
 * The reaper is the SINGLE expiry mechanism (the native per-message-TTL
 * path was deleted, P1.5), so a non-positive interval leaves nothing to
 * reclaim expired records and is refused unconditionally.
 *
 * @param interval  the nats_reap_interval modparam value.
 * @return 0 to start, -1 to refuse (interval <= 0).
 *
 * Pure: no allocation, no locking.  Context: mod_init (pre-fork).
 */
int cdbn_reap_interval_guard(int interval);

/**
 * [P2.7] The reaper pass body (P9 host); the SINGLE expiry mechanism.
 * Scans the bucket once (one value-carrying watch pass via
 * nats_kv_enum_live_values) and, for each DUE usrloc row, either
 * CAS-rewrites it to its survivors or CAS-deletes it when nothing
 * survives.  Malformed/poison rows are left in place (the read path
 * alarms them).
 *
 * @param ticks  unused (signature kept from the register_timer era).
 * @param param  unused.
 *
 * O(bucket) and blocking (watch-pass drain + CAS writes).  Acquires
 * KV/JS handles from the per-process pool; a NULL handle (broker down)
 * skips just this pass.  Publishes the reap_last_* gauges into THIS
 * process's SHM stats slot (relaxed atomics).  Locking: none.
 * Context: [P3.3] the dedicated reaper process ONLY
 * (nats_cdb_reaper_proc_main) — NOT the shared core timer process: a
 * full-bucket pass at scale would stall usrloc/tm/dialog timers
 * system-wide, and the pool is process-single-threaded.
 */
void nats_cdb_reaper_tick(unsigned int ticks, void *param);

/**
 * [P3.3] Dedicated reaper process entry point (proc_export_t, same
 * pattern as the KV watcher).  Hosts BOTH periodic O(bucket) jobs: the
 * reaper pass every nats_reap_interval and — when the FTS module is
 * bound and index_resync_interval_secs > 0 — the periodic index
 * resync.  Also arms the [TTL-BELOW-MARKER] broker-truth canary once.
 *
 * @param rank  core fork-loop rank (single instance declared; unused).
 *
 * Never returns: loops on a 1 s sleep with the elapsed-interval
 * due-scheduler; shutdown rides the core's SIGTERM delivery, orphaning
 * is prevented by nats_cdb_dedicated_proc_guard().  Owns this process's
 * NATS pool connection (lazily opened by the guard).  Locking: none.
 * Context: called ONCE by the OpenSIPS core fork loop, in the freshly
 * forked reaper process (post-fork, post-mod_init).
 */
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

/**
 * First-fire stagger for the reaper.  Multi-instance deployments boot
 * every proxy with the same nats_reap_interval; without a per-instance
 * offset all reapers start their first O(bucket) pass at the same
 * uptime and hit the broker together.
 *
 * @param interval_s  the reap interval in seconds; < 4 returns 0
 *                    (a quarter of nothing is nothing).
 * @param seed        per-instance seed (callers pass the pid); hashed
 *                    with a Knuth multiplicative hash so consecutive
 *                    pids (fork order!) spread across the whole span.
 * @return a deterministic offset in [0, interval_s/4] seconds.
 *
 * Pure: no allocation, no locking; any process context.
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

/**
 * Evaluate which periodic jobs are due and reset their stamps (see the
 * due-scheduler note above the typedef).
 *
 * @param sc          scheduler state (caller-owned, process-local;
 *                    mutated in place: a firing job's stamp resets to
 *                    @now).
 * @param now         current time.
 * @param reap_iv     reap interval in seconds (<= 0 disables).
 * @param resync_iv   index-resync interval in seconds (<= 0 disables).
 * @param run_reap    [out] 1 when the reap job must run now, else 0.
 * @param run_resync  [out] 1 when the resync job must run now, else 0.
 *
 * Pure struct update on caller memory: no allocation, no locking.
 * Context: the dedicated reaper process's main loop (single-threaded).
 */
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
