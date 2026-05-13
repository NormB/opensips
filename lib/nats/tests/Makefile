# Unit tests for lib/nats helpers.
# Self-contained programs; each test has its own main().

CC      ?= cc
CFLAGS  ?= -g -O0 -Wall
ASAN    := -fsanitize=address

.PHONY: all check check-tsan clean

TESTS = test_redact_url test_validate_publish_subject \
        test_validate_subject_cache test_nats_dl test_nats_ca_dir

# All lib/nats unit tests are TSan-safe (no race exercises).
TESTS_TSAN_SAFE = $(TESTS)

all: $(TESTS)

# nats_redact_url() lives in nats_redact.c — link the .o (built by
# the parent Makefile) to avoid duplicating its source here.
test_redact_url: test_redact_url.c ../nats_redact.o
	$(CC) $(CFLAGS) $(ASAN) -I.. -o $@ test_redact_url.c ../nats_redact.o


# nats_validate_publish_subject() lives in nats_validate.c.
test_validate_publish_subject: test_validate_publish_subject.c ../nats_validate.o
	$(CC) $(CFLAGS) $(ASAN) -I.. -o $@ test_validate_publish_subject.c ../nats_validate.o

test_validate_subject_cache: test_validate_subject_cache.c ../nats_validate.o
	$(CC) $(CFLAGS) $(ASAN) -I.. -o $@ test_validate_subject_cache.c ../nats_validate.o

# nats_dl: dlopen + dlsym function-pointer table for libnats.
# Built with -DNO_LOG -DNO_DEBUG so the in-source LM_INFO/LM_ERR macros
# expand to no-ops; otherwise the test would need to link OpenSIPS's
# dprint.o (which is a binary-only dependency, not available here).
# The compile flags do NOT propagate to the production build of
# nats_dl.c — lib/nats/Makefile compiles it normally.
# Cannot run under ASan: ASan and dlopen of libnats together produce
# false-positive "leak" reports for libnats's internal allocator state.
test_nats_dl: test_nats_dl.c ../nats_dl.c
	$(CC) $(CFLAGS) -DNO_LOG -DNO_DEBUG -I.. -I/usr/local/include \
		-o $@ test_nats_dl.c ../nats_dl.c -ldl

# nats_load_ca_directory: libc-only directory walker; no OpenSIPS
# runtime needed.  ASan-clean.
test_nats_ca_dir: test_nats_ca_dir.c ../nats_ca_dir.c
	$(CC) $(CFLAGS) $(ASAN) -I.. -o $@ test_nats_ca_dir.c ../nats_ca_dir.c

# LD_LIBRARY_PATH covers the case where libnats was installed to
# /usr/local/lib (the upstream `cmake --install` default), which
# isn't on the default ld.so search path on most distros.  Production
# OpenSIPS startup is unaffected: operators normally either install
# libnats from a distro package (which lands in /usr/lib) or run
# ldconfig after the upstream install.  This is purely a test-host
# convenience.
NATS_TEST_ENV = LD_LIBRARY_PATH=/usr/local/lib:$$LD_LIBRARY_PATH

check: all
	./test_redact_url
	./test_validate_publish_subject
	./test_validate_subject_cache
	$(NATS_TEST_ENV) ./test_nats_dl
	./test_nats_ca_dir

# Run only the TSan-compatible subset.  Used by .github/workflows/nats-sanitizers.yml.
check-tsan: $(TESTS_TSAN_SAFE)
	@for t in $(TESTS_TSAN_SAFE); do echo "  ./$$t"; ./$$t || exit 1; done

clean:
	rm -f $(TESTS)
