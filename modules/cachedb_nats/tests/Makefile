# Unit tests for cachedb_nats.
# Each test_*.c is self-contained with its own main().

CC      ?= cc
CFLAGS  ?= -g -O0 -Wall
ASAN    := -fsanitize=address

.PHONY: all check check-tsan clean

TESTS = test_intersect_uaf test_kvget_copy_pattern test_json_escape \
        test_reply_size_cap test_disconnected_fastfail test_timeout_normalize \
        test_update_nested_dict test_update_creates_doc test_cas_backoff

# test_intersect_uaf and test_kvget_copy_pattern both deliberately
# exercise a use-after-free on their "buggy" arm and assert that
# AddressSanitizer trips.  TSan has no UAF detection, so the buggy
# arm completes silently and the assertion fails.  Skip both under
# TSan -- the regression they catch is an ASan-only contract.
TESTS_TSAN_SAFE = test_json_escape test_reply_size_cap \
                  test_disconnected_fastfail test_timeout_normalize \
                  test_cas_backoff

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

# Run only the TSan-compatible subset.  Used by .github/workflows/nats-sanitizers.yml.
check-tsan: $(TESTS_TSAN_SAFE)
	@for t in $(TESTS_TSAN_SAFE); do echo "  ./$$t"; ./$$t || exit 1; done

clean:
	rm -f $(TESTS)
