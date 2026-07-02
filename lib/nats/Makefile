# lib/nats/Makefile — builds libnats_pool as a SHARED library.
#
# Rationale: event_nats, cachedb_nats, and nats_consumer all depend on the
# same per-process NATS connection state (pool_cfg, _nc, _js, ...).  When
# this library was a static .a, each module got its own copy of those
# globals — so nats_consumer_proc could not see a pool that event_nats had
# already registered.  Building as .so gives all three modules a single
# shared backing store, which is the design the pool was written against.
#
# Runtime: the .so is installed alongside the module .so files in
# $(modules_target).  Modules carry an $ORIGIN rpath so ld.so resolves
# -lnats_pool from the same directory regardless of install prefix.

include ../../Makefile.defs

# Makefile.conf carries the memory-allocator DEFS (DBG_MALLOC, PKG_MALLOC,
# HP_MALLOC, F_PARALLEL_MALLOC, etc.).  These change the on-disk layout of
# allocator fragment headers — if this library is compiled without them
# while the loading modules are compiled with them, shm/pkg writes from
# either side will corrupt the other's fragment headers.
ifeq (,$(wildcard ../../Makefile.conf))
$(shell cp ../../Makefile.conf.template ../../Makefile.conf)
endif
include ../../Makefile.conf

NAME     = libnats_pool.so
SONAME   = libnats_pool.so
OBJS     = nats_dl.o nats_pool.o nats_rank.o nats_redact.o nats_validate.o \
           nats_ca_dir.o

# Bring in pkg-config CFLAGS/LIBS for the external libnats C client.
include ./Makefile.nats

# Gate the build on a USABLE libnats: present AND new enough for the per-key
# KV TTL API the NATS modules require (see the NATS_HAS_KV_TTL probe in
# Makefile.nats).  A clean skip with an actionable message is far better than
# a cryptic "kvStore_CreateStringWithTTL undeclared" deep in nats_dl.c.
ifneq ($(NATS_FOUND),yes)
$(info [skip] libnats_pool.so — libnats C client not detected (install libnats-dev or set LOCALBASE))
NATS_SKIP := yes
else ifneq ($(NATS_HAS_KV_TTL),yes)
$(warning ==============================================================)
$(warning  libnats was found but is TOO OLD for the OpenSIPS NATS modules:)
$(warning  it lacks the per-key KV TTL API kvStore_CreateStringWithTTL)
$(warning  (nats.c PR 1000).  Build + install a newer nats.c (e.g. to)
$(warning  /usr/local, then run ldconfig), or point LOCALBASE at its prefix.)
$(warning  Skipping libnats_pool.so + cachedb_nats/event_nats/nats_consumer.)
$(warning ==============================================================)
NATS_SKIP := yes
endif

CFLAGS  := $(MOD_CFLAGS) -fPIC

.PHONY: all clean install test-rank clean-test-rank

ifeq ($(NATS_SKIP),yes)
all install: ; @true
else

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) -shared -Wl,-soname,$(SONAME) $(OBJS) $(LIBS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(DEFS) -MMD -MP -c $< -o $@

# Pull in the auto-generated header dependencies so that editing a header
# (e.g. nats_dl_table.def, #included by nats_dl.c/.h) rebuilds the affected
# objects.  `clean` already removes the *.d files.
-include $(OBJS:.o=.d)

# Install next to the module .so files.  Modules will find this via
# $ORIGIN rpath at load time.
install: $(NAME)
	install -d $(DESTDIR)$(modules_prefix)/$(modules_dir)
	install -m 755 $(NAME) $(DESTDIR)$(modules_prefix)/$(modules_dir)/

endif

clean: clean-test-rank
	rm -f $(OBJS) $(NAME) *.d

# ---------------------------------------------------------------------
# Unit test for nats_pool_should_init().
#
# Links only nats_rank.o so the test binary does not need to resolve the
# full NATS pool / OpenSIPS core symbol graph.  Run with:
#   make -C lib/nats test-rank
# ---------------------------------------------------------------------
test-rank: test_nats_rank
	./test_nats_rank

test_nats_rank: test_nats_rank.c nats_rank.o
	$(CC) -I../.. -o $@ $< nats_rank.o

clean-test-rank:
	rm -f test_nats_rank
