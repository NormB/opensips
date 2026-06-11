# Unit tests for nats_consumer.
# Standalone; uses pthread shim for SHM + rw_locks.

CC      ?= cc
CFLAGS  ?= -Wall -Wextra -O2 -g -DTEST_SHIM -I. -I../../..
LDFLAGS ?= -lpthread

SHIM    := test_shim.c

REG_SRCS    := test_registry.c $(SHIM) ../nats_handle_registry.c
PARSER_SRCS := test_parser.c   $(SHIM) ../nats_handle_parse.c ../nats_handle_registry.c
RING_SRCS   := test_ring.c     $(SHIM) ../nats_ring.c
XPROC_SRCS  := test_ring_xproc_wakeup.c $(SHIM) ../nats_ring.c
ACKTOK_SRCS := test_ack_token.c
PERSIST_SRCS := test_persist.c $(SHIM) cjson_test_shim.c \
               ../nats_persist.c ../nats_handle_parse.c ../nats_handle_registry.c
SUBJECT_SRCS := test_rpc_subject.c $(SHIM) ../nats_rpc_subject.c ../nats_rpc_slot.c
IPCGEN_SRCS  := test_rpc_ipc_generation.c $(SHIM) ../nats_rpc_slot.c
INBOXAUTH_SRCS := test_rpc_inbox_auth.c $(SHIM) ../nats_rpc_subject.c ../nats_rpc_slot.c
LOOKUPREF_SRCS := test_registry_lookup_ref.c $(SHIM) ../nats_handle_registry.c
IDXRECYCLE_SRCS := test_registry_index_recycle.c $(SHIM) ../nats_handle_registry.c
MPSC_SRCS    := test_mpsc.c $(SHIM) ../nats_mpsc.c

.PHONY: all clean check check-tsan smoke smoke-tls smoke-multi-instance

# test_slurp_file_cap pins -fsanitize=address in its own rule (it is
# specifically asserting an ASan trip on a bad slurp), so it cannot
# be linked under ThreadSanitizer.  The rest of the suite is race-safe.
TESTS_TSAN_SAFE = test_registry test_parser test_ring test_ack_token \
                  test_persist test_request_route_restriction \
                  test_consumer_heartbeat test_persist_precision \
                  test_async_request_skeleton test_async_request_inflight \
                  test_header_propagation test_start_time_roundtrip \
                  test_rpc_subject test_fetch_async_timerfd \
                  test_persist_cross_process test_msg_ref_teardown \
                  test_ring_bounded_spin test_registry_ring_ref_safety \
                  test_ring_xproc_wakeup test_rpc_ipc_generation \
                  test_rpc_inbox_auth test_registry_lookup_ref \
                  test_consumer_proc_boot_retry test_rpc_subject_validation \
                  test_registry_index_recycle test_ring_push_bounded_spin \
                  test_pool_self_register test_msg_ref_orphan_reap \
                  test_retired_no_sub_reap test_sub_identity_match \
                  test_fetch_budget test_ring_wake_one \
                  test_bind_bounds test_rpc_tunables \
                  test_slot_prefix_copy test_replay_bias test_backpressure_stats test_consumer_stats_mi test_poison_term test_dead_inbox_retry test_mpsc

all: test_registry test_parser test_ring test_ack_token test_persist \
     test_slurp_file_cap test_request_route_restriction \
     test_consumer_heartbeat test_persist_precision \
     test_async_request_skeleton test_async_request_inflight \
     test_header_propagation test_start_time_roundtrip \
     test_rpc_subject test_fetch_async_timerfd test_persist_cross_process \
     test_msg_ref_teardown test_ring_bounded_spin \
     test_registry_ring_ref_safety test_ring_xproc_wakeup \
     test_rpc_ipc_generation test_rpc_inbox_auth test_registry_lookup_ref \
     test_consumer_proc_boot_retry test_rpc_subject_validation \
     test_registry_index_recycle test_ring_push_bounded_spin \
     test_pool_self_register test_msg_ref_orphan_reap \
     test_retired_no_sub_reap test_sub_identity_match \
     test_fetch_budget test_ring_wake_one \
     test_bind_bounds test_rpc_tunables \
     test_slot_prefix_copy test_replay_bias test_backpressure_stats test_consumer_stats_mi test_poison_term test_dead_inbox_retry test_mpsc

test_registry: $(REG_SRCS) test_shim.h ../nats_handle_registry.h
	$(CC) $(CFLAGS) -o $@ $(REG_SRCS) $(LDFLAGS)

test_parser: $(PARSER_SRCS) test_shim.h ../nats_handle_registry.h ../nats_handle_parse.h
	$(CC) $(CFLAGS) -o $@ $(PARSER_SRCS) $(LDFLAGS)

test_ring: $(RING_SRCS) test_shim.h ../nats_ring.h
	$(CC) $(CFLAGS) -o $@ $(RING_SRCS) $(LDFLAGS)

# Cross-process wakeup contract: the ring exposes no process-local fd
# (the eventfd that was written/closed by foreign processes is gone) and
# a waiter is woken across threads via the SHM futex.  Threaded, race-safe.
test_ring_xproc_wakeup: $(XPROC_SRCS) test_shim.h ../nats_ring.h
	$(CC) $(CFLAGS) -o $@ $(XPROC_SRCS) $(LDFLAGS)

test_ack_token: $(ACKTOK_SRCS) ../nats_ack.h
	$(CC) $(CFLAGS) -o $@ $(ACKTOK_SRCS) $(LDFLAGS)

# test_persist pulls in a minimal cJSON stand-in (cjson_test_shim.c)
# instead of lib/cJSON.c, which depends on opensips core mem/.
test_persist: $(PERSIST_SRCS) test_shim.h ../nats_persist.h \
              ../nats_handle_registry.h ../nats_handle_parse.h
	$(CC) $(CFLAGS) -o $@ $(PERSIST_SRCS) $(LDFLAGS)

# Standalone test for slurp_file size cap -- self-contained, ASan-built,
# does not link against test_shim or production .c files (uses inline
# copies of the buggy and fixed slurp_file logic plus a source-pattern
# assertion against ../nats_persist.c).
test_slurp_file_cap: test_slurp_file_cap.c
	$(CC) -g -O0 -fsanitize=address -Wall -o $@ $<

# Source-pattern test for nats_request route-flag restriction
test_request_route_restriction: test_request_route_restriction.c
	$(CC) -g -O0 -Wall -o $@ $<

# Source-pattern skeleton test for async nats_request dual
# registration (sync entry + acmd entry in nats_consumer.c).
test_async_request_skeleton: test_async_request_skeleton.c
	$(CC) -g -O0 -Wall -o $@ $<

# In-flight state-machine test.  Links nats_rpc_async.c under
# -DTEST_SHIM so the libnats glue is excluded and only the pure C
# state machine is exercised.
ASYNC_SRCS := test_async_request_inflight.c $(SHIM) ../nats_rpc_async.c
test_async_request_inflight: $(ASYNC_SRCS) test_shim.h ../nats_rpc_async.h
	$(CC) $(CFLAGS) -o $@ $(ASYNC_SRCS) $(LDFLAGS)

# Generation guard for the consumer-routed async reply correlation.
# Links the pure subject grammar + the SHM slot allocator under the shim.
test_rpc_subject: $(SUBJECT_SRCS) test_shim.h ../nats_rpc_subject.h ../nats_rpc_slot.h
	$(CC) $(CFLAGS) -o $@ $(SUBJECT_SRCS) $(LDFLAGS)

# Generation guard on the worker->consumer IPC publish path: a stale IPC
# entry from a freed+re-claimed slot must not double-publish the new
# claim's request.  Built with a 1-slot pool to force the reuse.
test_rpc_ipc_generation: $(IPCGEN_SRCS) test_shim.h ../nats_rpc_slot.h ../nats_rpc_ipc.h
	$(CC) $(CFLAGS) -DNATS_RPC_SLOT_COUNT=1 -o $@ $(IPCGEN_SRCS) $(LDFLAGS)

# Reply-inbox authentication: a forged reply that guesses slot+gen but
# not the per-call corr_id must be rejected by on_inbox_reply's check.
test_rpc_inbox_auth: $(INBOXAUTH_SRCS) test_shim.h ../nats_rpc_subject.h ../nats_rpc_slot.h
	$(CC) $(CFLAGS) -o $@ $(INBOXAUTH_SRCS) $(LDFLAGS)

# Registry lookup TOCTOU: a borrowed handle taken via lookup_ref survives
# a concurrent retire+reap until its pending_ops reference is released.
test_registry_lookup_ref: $(LOOKUPREF_SRCS) test_shim.h ../nats_handle_registry.h
	$(CC) $(CFLAGS) -o $@ $(LOOKUPREF_SRCS) $(LDFLAGS)

# Per-handle index is allocated after the duplicate check and recycled on
# reap, so duplicate/failed binds can't exhaust the index space.
test_registry_index_recycle: $(IDXRECYCLE_SRCS) test_shim.h ../nats_handle_registry.h
	$(CC) $(CFLAGS) -o $@ $(IDXRECYCLE_SRCS) $(LDFLAGS)

# Retired handle that never got a subscription is marked sub_torn_down via
# foreach_retired so the reaper frees it (its ring no longer leaks).
RETIREDNOSUB_SRCS := test_retired_no_sub_reap.c $(SHIM) ../nats_handle_registry.c
test_retired_no_sub_reap: $(RETIREDNOSUB_SRCS) test_shim.h ../nats_handle_registry.h
	$(CC) $(CFLAGS) -o $@ $(RETIREDNOSUB_SRCS) $(LDFLAGS)

# Source-pattern: proc-sub state is matched by handle identity (index /
# h_ref), not id string, so unbind+rebind of one id can't wedge delivery.
test_sub_identity_match: test_sub_identity_match.c
	$(CC) -g -O0 -Wall -o $@ $<

# Behavioural + source-pattern: the fetch sweep is budgeted by handle count
# so it can't block acks/RPCs for N*fetch_timeout (head-of-line blocking).
test_fetch_budget: test_fetch_budget.c
	$(CC) -g -O0 -Wall -o $@ $<

# Source-pattern test: the consumer process retries instead of exiting
# (an instance-fatal bail) when the broker is down at boot.
test_consumer_proc_boot_retry: test_consumer_proc_boot_retry.c
	$(CC) -g -O0 -Wall -o $@ $<

# Source-pattern: the RPC request/reply paths validate the subject
# (CR/LF/whitespace/wildcard) before it reaches the NATS wire.
test_rpc_subject_validation: test_rpc_subject_validation.c
	$(CC) -g -O0 -Wall -o $@ $<

# Source-pattern: nats_consumer registers its own pool (works standalone).
test_pool_self_register: test_pool_self_register.c
	$(CC) -g -O0 -Wall -o $@ $<

# Source-pattern: ring_capacity has an upper cap and async fetch rejects a
# non-positive timeout.
test_bind_bounds: test_bind_bounds.c
	$(CC) -g -O0 -Wall -o $@ $<

# Behavioural clamps + source-pattern: async-RPC slot count and poll
# interval are tunable modparams.
test_rpc_tunables: test_rpc_tunables.c
	$(CC) -g -O0 -Wall -o $@ $<

# Behavioural (ASan) + source-pattern: the slot prefix-copy helper copies
# only used bytes (clamping oversized lengths) and the fetch path uses it.
SLOTCOPY_SRCS := test_slot_prefix_copy.c $(SHIM) ../nats_ring.c
test_slot_prefix_copy: $(SLOTCOPY_SRCS) ../nats_ring.h
	$(CC) $(CFLAGS) -o $@ $(SLOTCOPY_SRCS) $(LDFLAGS)

# Behavioural + source-pattern: a recreated deliver_all durable biases to
# resume past the last delivered stream_seq instead of replaying the stream.
test_replay_bias: test_replay_bias.c
	$(CC) -g -O0 -Wall -o $@ $<

# Source-pattern + model: the consumer splits the mislabeled
# total_dropped_backpressure into distinct SHM per-handle counters
# (fetch_skips_full / backpressure_drops / fetch_errors) so a pre-fetch
# skip is no longer reported as data loss.
test_backpressure_stats: test_backpressure_stats.c
	$(CC) -g -O0 -Wall -o $@ $<

# Source-pattern + model: the nats_consumer_stats MI command aggregates
# per-handle SHM counters + global IPC/slot getters into one object.
test_consumer_stats_mi: test_consumer_stats_mi.c
	$(CC) -g -O0 -Wall -o $@ $<

# Source-pattern + model: a message whose NumDelivered exceeds the
# poison_max_deliver cap is Termed consumer-side (dead-letter backstop).
test_poison_term: test_poison_term.c
	$(CC) -g -O0 -Wall -o $@ $<

# Source-pattern + model: the async-RPC reply inbox subscribe is retried
# in the main loop, and the publish path abandons slots while it is down.
test_dead_inbox_retry: test_dead_inbox_retry.c
	$(CC) -g -O0 -Wall -o $@ $<

# Concurrency: the lock-free bounded MPSC queue (nats_mpsc) that replaces
# the per-queue gen_lock_t.  Message-conservation stress test (4 producer
# threads + 1 consumer); race-safe, so it runs under check-tsan too.
test_mpsc: $(MPSC_SRCS) test_shim.h ../nats_mpsc.h
	$(CC) $(CFLAGS) -pthread -o $@ $(MPSC_SRCS) $(LDFLAGS)

# Behavioural (ASan): the consumer reaps msg-ref slots orphaned by a
# worker that died before acking (no leak; table doesn't wedge).
test_msg_ref_orphan_reap: test_msg_ref_orphan_reap.c
	$(CC) -g -O0 -fsanitize=address -Wall -o $@ $<

# Async-fetch wake mechanism: behavioural timerfd-fires check + source
# assertions that the async paths use a worker-private timerfd, not the
# fork-inherited ring eventfd.  Self-contained; reads ../nats_fetch.c.
test_fetch_async_timerfd: test_fetch_async_timerfd.c
	$(CC) -g -O0 -Wall -o $@ $<

# Persistence dirty-flag cross-process visibility (fork+mmap behavioural
# check) + source assertions that the dirty flag is SHM-allocated.
# Self-contained; reads ../nats_persist.c.
test_persist_cross_process: test_persist_cross_process.c
	$(CC) -g -O0 -Wall -o $@ $<

# msg-ref leak in tear_down_retired_subs: behavioural re-implementation of
# the msg-ref row lifecycle proving the teardown destroys outstanding
# natsMsgs + frees the slots buffer, plus source assertions that the real
# tear_down_retired_subs walks g_msg_refs.  Self-contained;
# reads ../nats_consumer_proc.c.
test_msg_ref_teardown: test_msg_ref_teardown.c
	$(CC) -g -O0 -Wall -o $@ $<

# Bounded-spin bail-out in nats_ring_pop: #includes ../nats_ring.c so it
# can forge a stalled-producer state (head>tail, slot unpublished) and a
# SIGALRM watchdog proves pop returns instead of spinning forever.
# Links test_shim.c for the SHM allocator.
RINGSPIN_SRCS := test_ring_bounded_spin.c $(SHIM)
test_ring_bounded_spin: $(RINGSPIN_SRCS) test_shim.h ../nats_ring.c ../nats_ring.h
	$(CC) $(CFLAGS) -o $@ $(RINGSPIN_SRCS) $(LDFLAGS)

# Producer-side analogue: #includes ../nats_ring.c to forge a
# stalled-consumer state and a SIGALRM watchdog proves push bails (-1)
# instead of spinning the consumer process forever.
WAKEONE_SRCS := test_ring_wake_one.c $(SHIM) ../nats_ring.c
test_ring_wake_one: $(WAKEONE_SRCS) test_shim.h ../nats_ring.h
	$(CC) $(CFLAGS) -o $@ $(WAKEONE_SRCS) $(LDFLAGS)
PUSHSPIN_SRCS := test_ring_push_bounded_spin.c $(SHIM)
test_ring_push_bounded_spin: $(PUSHSPIN_SRCS) test_shim.h ../nats_ring.c ../nats_ring.h
	$(CC) $(CFLAGS) -o $@ $(PUSHSPIN_SRCS) $(LDFLAGS)

# Guards the removal of the unused, ref-unsafe registry ring helpers
# (nats_registry_ring_get / nats_registry_set_ring_capacity).  Source
# assertion; self-contained, reads ../nats_handle_registry.{c,h}.
test_registry_ring_ref_safety: test_registry_ring_ref_safety.c
	$(CC) -g -O0 -Wall -o $@ $<

check: all
	./test_registry
	./test_parser
	./test_ring
	./test_ack_token
	./test_persist
	./test_slurp_file_cap
	./test_request_route_restriction
	./test_consumer_heartbeat
	./test_persist_precision
	./test_async_request_skeleton
	./test_async_request_inflight
	./test_header_propagation
	./test_start_time_roundtrip
	./test_rpc_subject
	./test_fetch_async_timerfd
	./test_persist_cross_process
	./test_msg_ref_teardown
	./test_ring_bounded_spin
	./test_registry_ring_ref_safety
	./test_ring_xproc_wakeup
	./test_rpc_ipc_generation
	./test_rpc_inbox_auth
	./test_registry_lookup_ref
	./test_consumer_proc_boot_retry
	./test_rpc_subject_validation
	./test_registry_index_recycle
	./test_ring_push_bounded_spin
	./test_pool_self_register
	./test_msg_ref_orphan_reap
	./test_retired_no_sub_reap
	./test_sub_identity_match test_fetch_budget \
	      test_ring_wake_one test_bind_bounds \
	      test_rpc_tunables test_slot_prefix_copy
	./test_fetch_budget
	./test_ring_wake_one
	./test_bind_bounds
	./test_rpc_tunables
	./test_slot_prefix_copy
	./test_replay_bias
	./test_backpressure_stats
	./test_consumer_stats_mi
	./test_poison_term
	./test_dead_inbox_retry
	./test_mpsc

# Run only the TSan-compatible subset.  Used by .github/workflows/nats-sanitizers.yml.
check-tsan: $(TESTS_TSAN_SAFE)
	@for t in $(TESTS_TSAN_SAFE); do echo "  ./$$t"; ./$$t || exit 1; done

clean:
	rm -f test_registry test_parser test_ring test_ack_token test_persist \
	      test_slurp_file_cap test_request_route_restriction \
	      test_consumer_heartbeat test_persist_precision \
	      test_async_request_skeleton test_async_request_inflight \
	      test_header_propagation test_start_time_roundtrip \
	      test_rpc_subject test_fetch_async_timerfd test_persist_cross_process \
	      test_msg_ref_teardown test_ring_bounded_spin \
	      test_registry_ring_ref_safety test_ring_xproc_wakeup \
	      test_rpc_ipc_generation test_rpc_inbox_auth \
	      test_registry_lookup_ref test_consumer_proc_boot_retry \
	      test_rpc_subject_validation test_registry_index_recycle \
	      test_ring_push_bounded_spin test_pool_self_register \
	      test_msg_ref_orphan_reap test_retired_no_sub_reap \
	      test_sub_identity_match

# Heartbeat + persist-precision tests (self-contained)
test_consumer_heartbeat: test_consumer_heartbeat.c
	$(CC) -g -O0 -Wall -pthread -o $@ $<

test_persist_precision: test_persist_precision.c
	$(CC) -g -O0 -Wall -o $@ $<

# Source-pattern + wire-format round-trip for the async nats_request
# header propagation.  Self-contained; runs from the tests/ directory
# (reads ../nats_rpc_async.c + ../nats_rpc_consumer.c).
test_header_propagation: test_header_propagation.c
	$(CC) -g -O0 -Wall -o $@ $<

# Round-trip test for the start_time_ns -> RFC3339 -> ns conversion
# on persistence rehydrate.  Self-contained; runs from the tests/
# directory (reads ../nats_persist.c).
test_start_time_roundtrip: test_start_time_roundtrip.c
	$(CC) -g -O0 -Wall -o $@ $<

# Live shell smokes (require a real nats-server + opensips binary in
# the tree).  Skip with exit 77 if prerequisites are missing.  Not
# part of `make check` because the unit suite is supposed to run
# without external services; CI calls these explicitly when the
# environment is provisioned.
smoke: smoke-tls smoke-multi-instance

smoke-tls: ./test_tls_mgm_consumer_smoke.sh
	./test_tls_mgm_consumer_smoke.sh

smoke-multi-instance: ./test_multi_instance_durable.sh
	./test_multi_instance_durable.sh
