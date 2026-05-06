# Unit tests for event_nats.
# Each test_*.c is self-contained with its own main(); the test_nats_module.sh
# script is an end-to-end integration harness invoked separately.

CC      ?= cc
CFLAGS  ?= -g -O0 -Wall
ASAN    := -fsanitize=address

.PHONY: all check clean

TESTS = test_partial_alloc test_seq_cast_guard test_tls_default \
        test_atomic_stats test_subscription_rebuild

all: $(TESTS)

test_partial_alloc: test_partial_alloc.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

test_seq_cast_guard: test_seq_cast_guard.c
	$(CC) $(CFLAGS) -o $@ $<

test_tls_default: test_tls_default.c
	$(CC) $(CFLAGS) -o $@ $<

test_atomic_stats: test_atomic_stats.c
	$(CC) $(CFLAGS) -pthread -o $@ $<

test_subscription_rebuild: test_subscription_rebuild.c
	$(CC) $(CFLAGS) -o $@ $<

check: all
	./test_partial_alloc
	./test_seq_cast_guard
	./test_tls_default
	./test_atomic_stats
	./test_subscription_rebuild

clean:
	rm -f $(TESTS)
