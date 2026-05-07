# Unit tests for event_nats.
# Each test_*.c is self-contained with its own main(); the test_nats_module.sh
# script is an end-to-end integration harness invoked separately.

CC      ?= cc
CFLAGS  ?= -g -O0 -Wall
ASAN    := -fsanitize=address

.PHONY: all check check-tsan clean

TESTS = test_partial_alloc test_seq_cast_guard test_tls_default \
        test_atomic_stats test_subscription_rebuild

# Tests safe to run under ThreadSanitizer.
# test_atomic_stats deliberately demonstrates that `volatile` is not
# atomic by racing two writers on a non-atomic counter, so TSan
# (correctly) flags it as a data race -- that is the whole point of
# the test, not a regression.
TESTS_TSAN_SAFE = test_partial_alloc test_seq_cast_guard test_tls_default \
                  test_subscription_rebuild

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

# Run only the TSan-compatible subset.  Used by .github/workflows/nats-sanitizers.yml.
check-tsan: $(TESTS_TSAN_SAFE)
	@for t in $(TESTS_TSAN_SAFE); do echo "  ./$$t"; ./$$t || exit 1; done

clean:
	rm -f $(TESTS)
