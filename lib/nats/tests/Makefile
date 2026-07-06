# Unit tests for lib/nats helpers.
# Self-contained programs; each test has its own main().

CC      ?= cc
CFLAGS  ?= -g -O0 -Wall
ASAN    := -fsanitize=address

.PHONY: all check check-tsan clean

TESTS = test_redact_url test_validate_publish_subject test_validate_modes test_pool_merge \
        test_validate_subject_cache test_nats_dl test_nats_ca_dir \
        test_nats_pool_fixes test_unsafe_log_clamp test_server_info_redact \
        test_js_pending_cap test_pool_refcount \
        test_kv_op_timeout test_reconnect_jitter \
        test_ping_liveness test_async_first_connect test_kv_ttl_probe_matrix \
        test_epoch_wrapper test_blocking_budget \
        test_nats_rank test_rl test_doc_truth

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

test_validate_modes: test_validate_modes.c ../nats_validate.o
	$(CC) $(CFLAGS) $(ASAN) -I.. -o $@ test_validate_modes.c ../nats_validate.o

test_pool_merge: test_pool_merge.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ test_pool_merge.c

# nats_pool_should_init() rank matrix — links only ../nats_rank.o so the
# binary does not need the full pool / core symbol graph.
test_nats_rank: test_nats_rank.c ../nats_rank.o
	$(CC) $(CFLAGS) $(ASAN) -I../../.. -o $@ test_nats_rank.c ../nats_rank.o

# [P3.7] header-only one-per-interval log gate (outage logging policy).
test_rl: test_rl.c ../nats_rl.h
	$(CC) $(CFLAGS) $(ASAN) -I.. -o $@ test_rl.c

# [P4.1/P4.3/P4.7] README + pool-doctrine truth-lock (source patterns).
test_doc_truth: test_doc_truth.c ../README.md ../nats_pool.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ test_doc_truth.c

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

# Source-structure regression guards for the nats_ca_dir bounded-read +
# nats_pool kvStore-cache-full + GetConnectedUrl-init fixes.  Reads the
# production sources; self-contained.
test_nats_pool_fixes: test_nats_pool_fixes.c
	$(CC) $(CFLAGS) -o $@ test_nats_pool_fixes.c

# Behavioural (ASan): the cnats-thread loggers clamp the snprintf return
# to the stack buffer before write(), so a long broker string cannot
# over-read the buffer.
test_unsafe_log_clamp: test_unsafe_log_clamp.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ test_unsafe_log_clamp.c

# Source-pattern: nats_pool_get_server_info() redacts the URL before
# returning it (it is exposed to MI clients).
test_server_info_redact: test_server_info_redact.c
	$(CC) $(CFLAGS) -o $@ test_server_info_redact.c

# Source-pattern: nats_pool_get_js() caps PublishAsync.MaxPending so a
# slow-acking JetStream cannot grow per-worker memory without bound.
test_js_pending_cap: test_js_pending_cap.c
	$(CC) $(CFLAGS) -o $@ test_js_pending_cap.c

# Behavioural refcount model + source-pattern: the pool is torn down only
# on the last unregister, waits for async publishes before jsCtx_Destroy,
# and event_nats frees stats after the pool.
test_pool_refcount: test_pool_refcount.c
	$(CC) $(CFLAGS) -o $@ test_pool_refcount.c

# Source-pattern: jsOpts.Wait is set from a configurable kv_op_timeout_ms.
test_kv_op_timeout: test_kv_op_timeout.c
	$(CC) $(CFLAGS) -o $@ test_kv_op_timeout.c

# Source-pattern: reconnect jitter (cnats option + per-process retry sleep).
test_reconnect_jitter: test_reconnect_jitter.c
	$(CC) $(CFLAGS) -o $@ test_reconnect_jitter.c

# Source-pattern: a short ping interval / max-pings-out so a black-holed
# broker is detected quickly (inline publishes don't block for minutes).
test_ping_liveness: test_ping_liveness.c
	$(CC) $(CFLAGS) -o $@ test_ping_liveness.c

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
	./test_validate_modes
	./test_pool_merge
	./test_validate_subject_cache
	$(NATS_TEST_ENV) ./test_nats_dl
	./test_nats_ca_dir
	./test_nats_pool_fixes
	./test_unsafe_log_clamp
	./test_server_info_redact
	./test_js_pending_cap
	./test_pool_refcount
	./test_kv_op_timeout
	./test_reconnect_jitter
	./test_ping_liveness
	./test_async_first_connect
	./test_kv_ttl_probe_matrix
	./test_rl
	./test_doc_truth

# tls_mgm end-to-end smoke: spins up a TLS-enabled nats-server,
# generates self-signed certs, boots opensips with tls_mgm + the
# "nats" client domain + cachedb_nats configured for tls://, and
# verifies the TLS handshake completes.  Requires opensips built,
# nats-server, openssl, nc.  Skips with exit 77 if anything missing.
.PHONY: smoke
smoke: ./test_tls_mgm_smoke.sh
	./test_tls_mgm_smoke.sh

# Run only the TSan-compatible subset.  Used by .github/workflows/nats-sanitizers.yml.
check-tsan: $(TESTS_TSAN_SAFE)
	@for t in $(TESTS_TSAN_SAFE); do echo "  ./$$t"; ./$$t || exit 1; done

# Structural (boot-degraded hardening): async first connect is enabled
# and NATS_NOT_YET_CONNECTED continues degraded instead of blocking
# child_init for the whole max_reconnect budget.
test_async_first_connect: test_async_first_connect.c
	$(CC) $(CFLAGS) -o $@ $<

# [HREV-1] composed per-message-TTL probe decision matrix (carried copies).
test_kv_ttl_probe_matrix: test_kv_ttl_probe_matrix.c
	$(CC) $(CFLAGS) $(ASAN) -o $@ $<

clean:
	rm -f $(TESTS)
