LIBNAME=	nats_pool

# Exclude unit-test harness from the library build; it is compiled
# separately by the 'test-rank' target below.
exclude_files= test_nats_rank.c

include ../../lib/nats/Makefile.nats

LIBS=

include ../../Makefile.misclibs

# ---------------------------------------------------------------------
# Unit test for nats_pool_should_init().
#
# Links only nats_rank.o (the predicate's own translation unit), so the
# test binary does not need to resolve the full NATS pool / OpenSIPS
# core symbol graph.  Run with:
#   make -C lib/nats test-rank
# ---------------------------------------------------------------------
.PHONY: test-rank
test-rank: test_nats_rank
	./test_nats_rank

test_nats_rank: test_nats_rank.c nats_rank.o
	$(CC) -I../.. -o $@ $< nats_rank.o

.PHONY: clean-test-rank
clean-test-rank:
	rm -f test_nats_rank

# Hook the test binary into the standard 'clean' target so 'make clean'
# from the repo root leaves no stray artifacts.
clean: clean-test-rank
