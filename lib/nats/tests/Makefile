# Unit tests for lib/nats helpers.
# Self-contained programs; each test has its own main().

CC      ?= cc
CFLAGS  ?= -g -O0 -Wall
ASAN    := -fsanitize=address

.PHONY: all check check-tsan clean

TESTS = test_redact_url test_tls_downgrade_policy test_validate_publish_subject \
        test_validate_subject_cache

# All lib/nats unit tests are TSan-safe (no race exercises).
TESTS_TSAN_SAFE = $(TESTS)

all: $(TESTS)

# nats_redact_url() lives in nats_redact.c — link the .o (built by
# the parent Makefile) to avoid duplicating its source here.
test_redact_url: test_redact_url.c ../nats_redact.o
	$(CC) $(CFLAGS) $(ASAN) -I.. -o $@ test_redact_url.c ../nats_redact.o

test_tls_downgrade_policy: test_tls_downgrade_policy.c
	$(CC) $(CFLAGS) -o $@ $<

# nats_validate_publish_subject() lives in nats_validate.c.
test_validate_publish_subject: test_validate_publish_subject.c ../nats_validate.o
	$(CC) $(CFLAGS) $(ASAN) -I.. -o $@ test_validate_publish_subject.c ../nats_validate.o

test_validate_subject_cache: test_validate_subject_cache.c ../nats_validate.o
	$(CC) $(CFLAGS) $(ASAN) -I.. -o $@ test_validate_subject_cache.c ../nats_validate.o

check: all
	./test_redact_url
	./test_tls_downgrade_policy
	./test_validate_publish_subject
	./test_validate_subject_cache

# Run only the TSan-compatible subset.  Used by .github/workflows/nats-sanitizers.yml.
check-tsan: $(TESTS_TSAN_SAFE)
	@for t in $(TESTS_TSAN_SAFE); do echo "  ./$$t"; ./$$t || exit 1; done

clean:
	rm -f $(TESTS)
