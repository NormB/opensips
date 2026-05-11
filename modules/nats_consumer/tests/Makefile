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

.PHONY: all clean check check-tsan

# test_slurp_file_cap pins -fsanitize=address in its own rule (it is
# specifically asserting an ASan trip on a bad slurp), so it cannot
# be linked under ThreadSanitizer.  The rest of the suite is race-safe.
TESTS_TSAN_SAFE = test_registry test_parser test_ring test_ack_token \
                  test_persist test_request_route_restriction \
                  test_consumer_heartbeat test_persist_precision \
                  test_async_request_skeleton test_async_request_inflight

all: test_registry test_parser test_ring test_ack_token test_persist \
     test_slurp_file_cap test_request_route_restriction \
     test_consumer_heartbeat test_persist_precision \
     test_async_request_skeleton test_async_request_inflight

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

# Phase 1 skeleton test for async nats_request dual registration
test_async_request_skeleton: test_async_request_skeleton.c
	$(CC) -g -O0 -Wall -o $@ $<

# Phase 2 in-flight state-machine test.  Links nats_rpc_async.c
# under -DTEST_SHIM so the libnats glue is excluded and only the
# pure C state machine is exercised.
ASYNC_SRCS := test_async_request_inflight.c $(SHIM) ../nats_rpc_async.c
test_async_request_inflight: $(ASYNC_SRCS) test_shim.h ../nats_rpc_async.h
	$(CC) $(CFLAGS) -o $@ $(ASYNC_SRCS) $(LDFLAGS)

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

# Run only the TSan-compatible subset.  Used by .github/workflows/nats-sanitizers.yml.
check-tsan: $(TESTS_TSAN_SAFE)
	@for t in $(TESTS_TSAN_SAFE); do echo "  ./$$t"; ./$$t || exit 1; done

clean:
	rm -f test_registry test_parser test_ring test_ack_token test_persist \
	      test_slurp_file_cap test_request_route_restriction \
	      test_consumer_heartbeat test_persist_precision \
	      test_async_request_skeleton test_async_request_inflight

# Heartbeat + persist-precision tests (self-contained)
test_consumer_heartbeat: test_consumer_heartbeat.c
	$(CC) -g -O0 -Wall -pthread -o $@ $<

test_persist_precision: test_persist_precision.c
	$(CC) -g -O0 -Wall -o $@ $<
