# Unit tests for cachedb_nats.
# Each test_*.c is self-contained with its own main().

CC      ?= cc
CFLAGS  ?= -g -O0 -Wall
ASAN    := -fsanitize=address

.PHONY: all check clean

TESTS = test_intersect_uaf test_kvget_copy_pattern test_json_escape \
        test_reply_size_cap test_disconnected_fastfail test_timeout_normalize

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

check: all
	./test_intersect_uaf
	./test_kvget_copy_pattern
	./test_json_escape
	./test_reply_size_cap
	./test_disconnected_fastfail
	./test_timeout_normalize

clean:
	rm -f $(TESTS)
