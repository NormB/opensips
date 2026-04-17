# Unit tests for nats_consumer Phase 1.
# Standalone; uses pthread shim for SHM + rw_locks.

CC      ?= cc
CFLAGS  ?= -Wall -Wextra -O0 -g -DTEST_SHIM -I. -I../../..
LDFLAGS ?= -lpthread

SHIM    := test_shim.c

REG_SRCS    := test_registry.c $(SHIM) ../nats_handle_registry.c
PARSER_SRCS := test_parser.c   $(SHIM) ../nats_handle_parse.c ../nats_handle_registry.c

.PHONY: all clean check

all: test_registry test_parser

test_registry: $(REG_SRCS) test_shim.h ../nats_handle_registry.h
	$(CC) $(CFLAGS) -o $@ $(REG_SRCS) $(LDFLAGS)

test_parser: $(PARSER_SRCS) test_shim.h ../nats_handle_registry.h ../nats_handle_parse.h
	$(CC) $(CFLAGS) -o $@ $(PARSER_SRCS) $(LDFLAGS)

check: all
	./test_registry
	./test_parser

clean:
	rm -f test_registry test_parser
