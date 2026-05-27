# Unit tests for nats_consumer.
# Standalone; uses pthread shim for SHM + rw_locks.

CC      ?= cc
CFLAGS  ?= -Wall -Wextra -O2 -g -DTEST_SHIM -I. -I../../..
LDFLAGS ?= -lpthread

SHIM    := test_shim.c

REG_SRCS    := test_registry.c $(SHIM) ../nats_handle_registry.c
PARSER_SRCS := test_parser.c   $(SHIM) ../nats_handle_parse.c ../nats_handle_registry.c
RING_SRCS   := test_ring.c     $(SHIM) ../nats_ring.c
ACKTOK_SRCS := test_ack_token.c
PERSIST_SRCS := test_persist.c $(SHIM) cjson_test_shim.c \
               ../nats_persist.c ../nats_handle_parse.c ../nats_handle_registry.c
SUBJECT_SRCS := test_rpc_subject.c $(SHIM) ../nats_rpc_subject.c ../nats_rpc_slot.c

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
                  test_persist_cross_process

all: test_registry test_parser test_ring test_ack_token test_persist \
     test_slurp_file_cap test_request_route_restriction \
     test_consumer_heartbeat test_persist_precision \
     test_async_request_skeleton test_async_request_inflight \
     test_header_propagation test_start_time_roundtrip \
     test_rpc_subject test_fetch_async_timerfd test_persist_cross_process

test_registry: $(REG_SRCS) test_shim.h ../nats_handle_registry.h
	$(CC) $(CFLAGS) -o $@ $(REG_SRCS) $(LDFLAGS)

test_parser: $(PARSER_SRCS) test_shim.h ../nats_handle_registry.h ../nats_handle_parse.h
	$(CC) $(CFLAGS) -o $@ $(PARSER_SRCS) $(LDFLAGS)

test_ring: $(RING_SRCS) test_shim.h ../nats_ring.h
	$(CC) $(CFLAGS) -o $@ $(RING_SRCS) $(LDFLAGS)

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

# Run only the TSan-compatible subset.  Used by .github/workflows/nats-sanitizers.yml.
check-tsan: $(TESTS_TSAN_SAFE)
	@for t in $(TESTS_TSAN_SAFE); do echo "  ./$$t"; ./$$t || exit 1; done

clean:
	rm -f test_registry test_parser test_ring test_ack_token test_persist \
	      test_slurp_file_cap test_request_route_restriction \
	      test_consumer_heartbeat test_persist_precision \
	      test_async_request_skeleton test_async_request_inflight \
	      test_header_propagation test_start_time_roundtrip \
	      test_rpc_subject test_fetch_async_timerfd test_persist_cross_process

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
