# Unit tests for cachedb_nats.
# Each test_*.c is self-contained with its own main().

CC      ?= cc
CFLAGS  ?= -g -O0 -Wall
ASAN    := -fsanitize=address

.PHONY: all check check-tsan clean

TESTS = test_intersect_uaf test_kvget_copy_pattern test_json_escape \
        test_reply_size_cap test_disconnected_fastfail test_timeout_normalize \
        test_update_nested_dict test_update_creates_doc test_cas_backoff \
        test_index_stale_recovery test_kv_key_encode test_resync_modparams \
        test_enable_search_index test_dedicated_watcher_proc \
        test_intern_wiring test_intern_unit test_entry_blob_combine \
        test_json_name_passthrough test_entry_add_key_oom \
        test_watcher_atomic_race test_watch_null_key_guard \
        test_kv_history_bounds test_request_payload_guard \
        test_sink_emit_string test_json_parse_guard test_allops_fastfail \
        test_counter_overflow test_native_key_validation \
        test_nats_request_rename test_intern_scaling \
        test_revmap_delete test_cas_retry_policy \
        test_pk_stack_key test_resync_timer test_op_stats test_index_converge \
        test_query_keyset_refcount test_watcher_leak_stat \
        test_map_key_encode test_map_migrate test_map_compose test_raw_query_cols test_rebuild_thread_safe \
        test_watcher_pkg_mem test_json_tu_split test_query_res_init \
        test_outparam_contracts test_kv_key_validate test_row_exp_compute test_reject_nul_field test_last_mod_int64 test_poison_value test_strip_private_keys test_write_hygiene_scope test_cseq_merge_ordering test_oversize_row test_read_expiry_filter

# test_intersect_uaf and test_kvget_copy_pattern both deliberately
# exercise a use-after-free on their "buggy" arm and assert that
# AddressSanitizer trips.  TSan has no UAF detection, so the buggy
# arm completes silently and the assertion fails.  Skip both under
# TSan -- the regression they catch is an ASan-only contract.
TESTS_TSAN_SAFE = test_json_escape test_reply_size_cap \
                  test_disconnected_fastfail test_timeout_normalize \
                  test_cas_backoff test_index_stale_recovery \
                  test_kv_key_encode test_resync_modparams \
                  test_enable_search_index test_dedicated_watcher_proc \
                  test_intern_wiring test_intern_unit test_entry_blob_combine \
                  test_watcher_atomic_race test_watch_null_key_guard \
                  test_sink_emit_string test_json_parse_guard \
                  test_allops_fastfail test_watcher_pkg_mem test_json_tu_split test_query_res_init test_outparam_contracts \
                  test_kv_key_validate test_row_exp_compute test_reject_nul_field test_last_mod_int64 test_poison_value test_strip_private_keys test_write_hygiene_scope test_cseq_merge_ordering test_oversize_row test_read_expiry_filter

# test_watcher_atomic_race is the canonical TSan target for the watcher
# claim-once property -- it spawns threads racing atomic_exchange and is
# built WITHOUT ASan so the CI TSan job can wrap it.  The other four new
# tests (json_name_passthrough, entry_add_key_oom, kv_history_bounds,
# request_payload_guard) are ASan'd to surface the corruption / OOB /
# leak they guard against -- ASan-only contracts, kept out of the TSan
# subset like the other ASan tests above.

all: $(TESTS)

test_intersect_uaf: test_intersect_uaf.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

test_kvget_copy_pattern: test_kvget_copy_pattern.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

test_json_escape: test_json_escape.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

test_reply_size_cap: test_reply_size_cap.c
	$(CC) $(CFLAGS) -o $@ $<

test_disconnected_fastfail: test_disconnected_fastfail.c
	$(CC) $(CFLAGS) -o $@ $<

test_timeout_normalize: test_timeout_normalize.c
	$(CC) $(CFLAGS) -o $@ $<

test_update_nested_dict: test_update_nested_dict.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

test_update_creates_doc: test_update_creates_doc.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

test_cas_backoff: test_cas_backoff.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

test_index_stale_recovery: test_index_stale_recovery.c
	$(CC) $(CFLAGS) -o $@ $<

test_kv_key_encode: test_kv_key_encode.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

test_resync_modparams: test_resync_modparams.c
	$(CC) $(CFLAGS) -o $@ $<

test_enable_search_index: test_enable_search_index.c
	$(CC) $(CFLAGS) -o $@ $<

test_dedicated_watcher_proc: test_dedicated_watcher_proc.c
	$(CC) $(CFLAGS) -o $@ $<

test_intern_wiring: test_intern_wiring.c
	$(CC) $(CFLAGS) -o $@ $<

# Behavioural unit test for the intern table -- carries a stripped-
# down copy of the production logic so it can run as a normal
# binary without linking OpenSIPS.  ASan'd so leaks / UAF show.
test_intern_unit: test_intern_unit.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

# Structural test for the single-allocation entry blob layout
# (entry struct + field_value + inline keys[] -> one shm_malloc).
test_entry_blob_combine: test_entry_blob_combine.c
	$(CC) $(CFLAGS) -o $@ $<

# Behavioural + structural: existing JSON field/subkey NAMES are copied
# through RAW (not re-escaped) on a KV-doc update.
test_json_name_passthrough: test_json_name_passthrough.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

# Behavioural: _entry_add_key must not leak the interned doc-key ref
# when the keys[] array growth fails (OOM).  ASan'd.
test_entry_add_key_oom: test_entry_add_key_oom.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

# Behavioural (atomic claim-once) + structural: the kvWatcher* handle is
# _Atomic and torn down via atomic_exchange so overlapping shutdown can't
# double-free.  pthread, no ASan -> safe under TSan.
test_watcher_atomic_race: test_watcher_atomic_race.c
	$(CC) $(CFLAGS) -pthread -o $@ $<

# Structural: every kvEntry_Key(entry) call site has a NULL guard.
test_watch_null_key_guard: test_watch_null_key_guard.c
	$(CC) $(CFLAGS) -o $@ $<

# Behavioural: w_nats_kv_history's snprintf chain never lets `pos`
# underflow the remaining-size and overrun the buffer.  ASan'd.
test_kv_history_bounds: test_kv_history_bounds.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

# Behavioural: w_nats_request guards NULL / negative-length payloads
# before memcpy.  ASan'd.
test_sink_emit_string: test_sink_emit_string.c
	$(CC) $(CFLAGS) -o $@ $<

test_request_payload_guard: test_request_payload_guard.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

# Behavioural: broker JSON is depth/size/NUL-guarded before it reaches
# the recursive cJSON_Parse, preventing a stack-exhaustion crash.  ASan'd.
test_json_parse_guard: test_json_parse_guard.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

# Source-pattern test: every con->data op refreshes the KV handle and
# every w_nats_kv_* wrapper gates on connectivity (fast-fail on outage).
test_allops_fastfail: test_allops_fastfail.c
	$(CC) $(CFLAGS) -o $@ $<

# Behavioural: counter ops range-check the broker value and reject an
# overflowing/truncating increment instead of wrapping it.
test_counter_overflow: test_counter_overflow.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

# Source-pattern: native/map/raw KV paths validate keys (reject ':' map
# separator and wildcards reaching Purge).
test_native_key_validation: test_native_key_validation.c
	$(CC) $(CFLAGS) -o $@ $<

# Source-pattern: cachedb's blocking RPC is renamed nats_cdb_request and
# restricted off the SIP request path (de-conflicts with nats_consumer).
test_nats_request_rename: test_nats_request_rename.c
	$(CC) $(CFLAGS) -o $@ $<

# Source-pattern: the intern table sizes its buckets from index_buckets
# and caches each node's hash (no fixed 1024, no re-hash on release).
test_intern_scaling: test_intern_scaling.c
	$(CC) $(CFLAGS) -o $@ $<

# Behavioural (ASan+UBSan, threaded) + source-pattern: the doc-key reverse
# map gives O(fields) delete-by-key, the reverse and forward lock sets are
# never held together, and the watcher uses it with a full-walk fallback.
test_revmap_delete: test_revmap_delete.c
	$(CC) -g -O0 -fsanitize=address,undefined -Wall -pthread -o $@ $<

# Behavioural policy + source-pattern: CAS loops retry only on conflicts,
# bailing on timeout/connection errors instead of burning the retry budget.
test_cas_retry_policy: test_cas_retry_policy.c
	$(CC) $(CFLAGS) -o $@ $<

# Behavioural (ASan) + source-pattern: the PK fast path builds the target
# key in a stack buffer (heap only for rare long keys).
test_pk_stack_key: test_pk_stack_key.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

# Source-pattern: the periodic resync handler no longer dead-gates on the
# process-local connected flag (it lazily connects).
test_resync_timer: test_resync_timer.c
	$(CC) $(CFLAGS) -o $@ $<

test_op_stats: test_op_stats.c
	$(CC) $(CFLAGS) -o $@ $<

test_index_converge: test_index_converge.c
	$(CC) $(CFLAGS) -o $@ $<

# Refcount-balance model + source-pattern: the non-PK query snapshots
# interned key pointers with a refcount bump instead of strdup under the
# shard lock; every cleanup site stays balanced (ASan).
test_query_keyset_refcount: test_query_keyset_refcount.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

# Source-pattern + model: the disconnected-teardown watcher-handle leak is
# counted (watcher_handle_leaks) so the per-flap leak is observable.
test_watcher_leak_stat: test_watcher_leak_stat.c
	$(CC) $(CFLAGS) -o $@ $<

# Round-trip + edge cases for the map subject hex-escaper (=HH), incl. the
# structural invariant that an encoded component has no raw '.' (ASan).
test_map_key_encode: test_map_key_encode.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

# Carried model (split-on-first-':' + idempotency) + source-pattern for the
# nats_map_migrate MI command.
test_map_migrate: test_map_migrate.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

test_map_compose: test_map_compose.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

test_raw_query_cols: test_raw_query_cols.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

test_rebuild_thread_safe: test_rebuild_thread_safe.c
	$(CC) -g -O0 -Wall -o $@ $<

# Source-pattern (NATS_TODO #71): the watcher's _watch_patterns array is
# pkg_malloc/pkg_free'd (not raw libc malloc/free), and the unreachable
# _num_patterns==0 logging branch in the dedicated proc is gone.
test_watcher_pkg_mem: test_watcher_pkg_mem.c
	$(CC) $(CFLAGS) -o $@ $<

# Structural (NATS_TODO #60): cachedb_nats_json.c is split into
# index / serializer / query+update TUs with an internal header.
test_json_tu_split: test_json_tu_split.c
	$(CC) $(CFLAGS) -o $@ $<

# Regression (e2e 040_broker_bounce segfault): query/map_get init the
# cdb_res_t BEFORE any failure return -- usrloc cdb_free_rows()s the
# res on ANY failure, so an uninit res is a worker SIGSEGV.
test_query_res_init: test_query_res_init.c
	$(CC) $(CFLAGS) -o $@ $<

# Out-param contracts: raw_query zeroes *reply/*reply_no at entry,
# get() zeroes *val -- every failure return leaves them deterministic.
test_outparam_contracts: test_outparam_contracts.c
	$(CC) $(CFLAGS) -o $@ $<

# [REV-23] key encoder/validator: '\\' escaped, empty/edge-dot tokens rejected,
# injective round-trip. ASan'd (malloc/free in the round-trip path).
test_kv_key_validate: test_kv_key_validate.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

# P2.1 [REV-34/REV-25/REV-18] row_exp = min(non-zero expires), 0 if any
# permanent; int64 (no 2038 clamp); finalize emits row_exp+schema_version
# top-level peers and leaves a non-usrloc doc unchanged. ASan'd (malloc path).
test_row_exp_compute: test_row_exp_compute.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

# P2.3 [REV-20] reject-at-write NUL: raw 0x00 and escaped \u0000 refused,
# clean fields + non-NUL escapes accepted. ASan'd (no alloc, pure scan).
test_reject_nul_field: test_reject_nul_field.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

# P2.4 [REV-15/30] last_mod read int64 (Option A): >INT32_MAX preserved vs the
# shared int32 clamp. ASan'd (pure scan).
test_last_mod_int64: test_last_mod_int64.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

# P2.5 [REV-26] poison classifier: non-empty non-object stored value => POISON
# (hard error) vs the today data[0]==123 gate that masks it as empty. ASan'd.
test_poison_value: test_poison_value.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

# P2.6 [REV-18/35] strip row_exp/schema_version at read assembly; usrloc sees
# only {contacts,aorhash}. Real lib/list.h surgery, ASan catches UAF/leak.
test_strip_private_keys: test_strip_private_keys.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

# P2.7 [REV-21/1] skew-safe write hygiene: drop a touched+expired contact, never
# an untouched merged-in one (structural). ASan'd.
test_write_hygiene_scope: test_write_hygiene_scope.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

# P2.2 [REV-8] same-subkey merge ordering: higher cseq wins (tie last_mod);
# a stale write is discarded. Engages only when both carry cseq. ASan'd.
test_cseq_merge_ordering: test_cseq_merge_ordering.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

# P3 [REV-5] value-size bound: oversize merged row rejected before CAS write.
test_oversize_row: test_oversize_row.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

# P4 [REV-3/1/26] read expiry filter: omit expired/absent contacts, keep
# permanent; real lib/list.h surgery (ASan). 
test_read_expiry_filter: test_read_expiry_filter.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

check: all
	./test_intersect_uaf
	./test_kvget_copy_pattern
	./test_json_escape
	./test_reply_size_cap
	./test_disconnected_fastfail
	./test_timeout_normalize
	./test_update_nested_dict
	./test_update_creates_doc
	./test_cas_backoff
	./test_index_stale_recovery
	./test_kv_key_encode
	./test_resync_modparams
	./test_enable_search_index
	./test_dedicated_watcher_proc
	./test_intern_wiring
	./test_intern_unit
	./test_entry_blob_combine
	./test_json_name_passthrough
	./test_entry_add_key_oom
	./test_watcher_atomic_race
	./test_watch_null_key_guard
	./test_kv_history_bounds
	./test_request_payload_guard
	./test_sink_emit_string
	./test_json_parse_guard
	./test_allops_fastfail
	./test_counter_overflow
	./test_native_key_validation
	./test_nats_request_rename
	./test_intern_scaling
	./test_revmap_delete
	./test_cas_retry_policy
	./test_pk_stack_key
	./test_resync_timer
	./test_op_stats
	./test_index_converge
	./test_query_keyset_refcount
	./test_watcher_leak_stat
	./test_map_key_encode
	./test_map_migrate
	./test_map_compose
	./test_raw_query_cols
	./test_rebuild_thread_safe
	./test_watcher_pkg_mem
	./test_json_tu_split
	./test_query_res_init
	./test_outparam_contracts
	./test_kv_key_validate
	./test_row_exp_compute
	./test_reject_nul_field
	./test_last_mod_int64
	./test_poison_value
	./test_strip_private_keys
	./test_write_hygiene_scope
	./test_cseq_merge_ordering
	./test_oversize_row
	./test_read_expiry_filter

# Run only the TSan-compatible subset.  Used by .github/workflows/nats-sanitizers.yml.
check-tsan: $(TESTS_TSAN_SAFE)
	@for t in $(TESTS_TSAN_SAFE); do echo "  ./$$t"; ./$$t || exit 1; done

clean:
	rm -f $(TESTS)
