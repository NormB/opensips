# Unit tests for cachedb_nats.
# Each test_*.c is self-contained with its own main().
#
# TESTS is AUTO-DISCOVERED from the test_*.c glob and every test builds via the
# single pattern rule below (default flags: ASan).  Adding a test = drop in
# test_foo.c; there is no per-test list or rule to maintain here.  (The previous
# hand-kept TESTS list + 70-odd identical build rules + check list drifted out of
# date as tests were added -- see the note in .gitignore.)  Per-test build-FLAG
# exceptions are declared once as target-specific variables, not as new rules.

CC      ?= cc
CFLAGS  ?= -g -O0 -Wall
ASAN    := -fsanitize=address

.PHONY: all check check-tsan clean

# One extensionless binary per test_*.c in this directory.
TESTS := $(patsubst %.c,%,$(wildcard test_*.c))

# --- per-test build-flag exceptions (target-specific vars override the pattern) ---
# Default is ASan; SAN/EXTRA below override it for the few tests that differ.
SAN   := $(ASAN)
EXTRA :=

# (1) Built WITHOUT a sanitizer (structural / source-pattern / behavioural tests
#     that don't need ASan, plus those wrapped by the CI TSan job).
NOASAN := test_disconnected_fastfail \
          test_index_stale_recovery test_resync_modparams test_enable_search_index \
          test_dedicated_watcher_proc test_intern_wiring test_entry_blob_combine \
          test_watch_null_key_guard test_sink_emit_string test_allops_fastfail \
          test_native_key_validation test_nats_request_rename test_intern_scaling \
          test_cas_retry_policy test_resync_timer test_op_stats test_index_converge \
          test_watcher_leak_stat test_watcher_pkg_mem test_json_tu_split \
          test_query_res_init test_outparam_contracts test_ttl_write_invariant \
          test_rebuild_thread_safe
$(NOASAN): SAN :=

# (2) pthread, no ASan -- the canonical TSan target (races atomic_exchange).
test_watcher_atomic_race: SAN :=
test_watcher_atomic_race: EXTRA := -pthread

# (3) ASan + UBSan + pthread.
test_revmap_delete: SAN   := -fsanitize=address,undefined
test_revmap_delete: EXTRA := -pthread

# (4) Behavioral tests that compile and link a PRODUCTION TU (no carried
#     copies).  CORE_DEFS mirrors the flag set the module build uses; the
#     production sources resolve their core includes relative to their own
#     path, so no extra -I is needed beyond the libnats headers on the
#     default search path.
CORE_DEFS := -fPIC -DPIC \
             -DNAME='"opensips"' -DVERSION='"test"' -DARCH='"x86_64"' \
             -DOS='"linux"' -DCOMPILER='"cc"' -DCFG_DIR='"/etc/opensips/"' \
             -DVERSIONTYPE='"git"' -DTHISREVISION='"test"' \
             -D__CPU_x86_64 -D__OS_linux -DPKG_MALLOC -DSHM_MMAP \
             -DF_MALLOC -DQ_MALLOC -DHP_MALLOC -DF_PARALLEL_MALLOC \
             -DFAST_LOCK -DADAPTIVE_WAIT -DADAPTIVE_WAIT_LOOPS=1024 \
             -DUSE_MCAST -DDISABLE_NAGLE -DSTATISTICS -DHAVE_RESOLV_RES

# [P2.5] the shared top-level JSON field iterator: #includes the
# production walker TU, whose core includes need the full define set.
test_json_foreach: EXTRA := $(CORE_DEFS)
test_json_foreach: ../cachedb_nats_json_walk.c ../cachedb_nats_json_internal.h

# Reaper watch-pass enumeration: #includes the production TU and drives
# it against a scripted fake nats_dl (zero per-key Get is the contract).
test_reap_watch_enum: EXTRA := $(CORE_DEFS)
test_reap_watch_enum: ../cachedb_nats_reap_enum.c ../cachedb_nats_reap_enum.h

# Reaper first-fire jitter: the helper is a static inline in the header
# (and the wiring assert slurps the expiry TU) -- depend on both.
test_reap_first_jitter: ../cachedb_nats_expiry.h ../cachedb_nats_expiry.c

# [P3.5] _sink_emit_int divide-loop: links the REAL ser TU and
# characterizes every edge value (incl. INT64_MIN) against printf.
test_sink_emit_int: EXTRA := $(CORE_DEFS) ../cachedb_nats_json_ser.c -D_GNU_SOURCE
test_sink_emit_int: ../cachedb_nats_json_ser.c ../cachedb_nats_json_internal.h

# P0.1: kv_epoch must not latch on a failed refresh — links the real
# nats_con_refresh_kv() from ../cachedb_nats_dbase.c with a fake pool.
test_kv_epoch_refresh: EXTRA := $(CORE_DEFS) ../cachedb_nats_dbase.c ../../../lib/nats/nats_redact.c
test_kv_epoch_refresh: ../cachedb_nats_dbase.c ../cachedb_nats.h

# P0.4: kv_put/kv_update fast-fail must not leak the pkg value copy;
# kv_get must fail when the pvar write fails.  Links ../cachedb_nats_native.c.
test_kv_put_fastfail_leak: EXTRA := $(CORE_DEFS) ../cachedb_nats_native.c ../../../lib/nats/nats_redact.c
test_kv_put_fastfail_leak: ../cachedb_nats_native.c ../cachedb_nats_native.h

# P0.6: a KV snapshot stalling mid-stream must fail the index build/rebuild
# and keep the prior live index.  Links the real json_index + intern TUs.
test_index_partial_snapshot: EXTRA := $(CORE_DEFS) ../../cachedb_nats_fts/fts_index.c ../../cachedb_nats_fts/fts_intern.c ../cachedb_nats_json_walk.c
test_index_partial_snapshot: ../../cachedb_nats_fts/fts_index.c ../../cachedb_nats_fts/fts_intern.c ../cachedb_nats_json_walk.c ../cachedb_nats_json.h

# test_intersect_uaf and test_kvget_copy_pattern both deliberately
# exercise a use-after-free on their "buggy" arm and assert that
# AddressSanitizer trips.  TSan has no UAF detection, so the buggy
# arm completes silently and the assertion fails.  Skip both under
# TSan -- the regression they catch is an ASan-only contract.
TESTS_TSAN_SAFE = test_json_escape \
                  test_disconnected_fastfail \
                  test_cas_backoff test_index_stale_recovery \
                  test_kv_key_encode test_resync_modparams \
                  test_enable_search_index test_dedicated_watcher_proc \
                  test_intern_wiring test_intern_unit test_entry_blob_combine \
                  test_watcher_atomic_race test_watch_null_key_guard \
                  test_sink_emit_string test_json_parse_guard \
                  test_allops_fastfail test_watcher_pkg_mem test_json_tu_split test_query_res_init test_outparam_contracts \
                  test_kv_key_validate test_row_exp_compute test_p35_len_threading test_reject_nul_field test_last_mod_int64 test_poison_value test_strip_private_keys test_write_hygiene_scope test_cseq_merge_ordering test_oversize_row test_read_expiry_filter test_ttl_cas_predicate test_ttl_errcode_classify test_ttl_delete_header test_ttl_dl_bindings test_kv_ttl_zero_guard test_ttl_key_subject test_reap_select test_reap_interval_zero_guard test_reap_project test_insecure_url_warn test_ttl_watch_marker test_ttl_fetch_marker test_ttl_write_invariant test_remove_stub test_index_count test_schema_version_legacy test_kv_ttl_legacy_bucket test_index_add_idempotent

# test_watcher_atomic_race is the canonical TSan target for the watcher
# claim-once property -- it spawns threads racing atomic_exchange and is
# built WITHOUT ASan so the CI TSan job can wrap it.  The other new
# tests (json_name_passthrough, entry_add_key_oom, kv_history_bounds,
# request_payload_guard) are ASan'd to surface the corruption / OOB /
# leak they guard against -- ASan-only contracts, kept out of the TSan
# subset like the other ASan tests above.

all: $(TESTS)

# Single build rule for every test.  SAN defaults to ASan; the target-specific
# overrides above blank it (or swap in UBSan) and add -pthread where needed.
test_%: test_%.c
	$(CC) $(CFLAGS) $(SAN) $(EXTRA) -o $@ $<

check: all
	@for t in $(TESTS); do echo "  ./$$t"; ./$$t || exit 1; done

# Run only the TSan-compatible subset.  Used by .github/workflows/nats-sanitizers.yml.
check-tsan: $(TESTS_TSAN_SAFE)
	@for t in $(TESTS_TSAN_SAFE); do echo "  ./$$t"; ./$$t || exit 1; done

clean:
	rm -f $(TESTS)
