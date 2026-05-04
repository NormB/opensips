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

.PHONY: all clean check

all: test_registry test_parser test_ring test_ack_token test_persist \
     test_slurp_file_cap test_request_route_restriction

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

check: all
	./test_registry
	./test_parser
	./test_ring
	./test_ack_token
	./test_persist
	./test_slurp_file_cap
	./test_request_route_restriction

clean:
	rm -f test_registry test_parser test_ring test_ack_token test_persist \
	      test_slurp_file_cap test_request_route_restriction
