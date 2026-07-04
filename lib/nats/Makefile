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

# Gate the build on libnats being present; reaper-only expiry (P1.5)
# removed the last per-key-TTL API use, so any libnats the header probe
# accepts is usable.
ifneq ($(NATS_FOUND),yes)
$(info [skip] libnats_pool.so — libnats C client not detected (install libnats-dev or set LOCALBASE))
NATS_SKIP := yes
endif

CFLAGS  := $(MOD_CFLAGS) -fPIC

.PHONY: all clean install

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

clean:
	rm -f $(OBJS) $(NAME) *.d

