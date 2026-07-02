# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs

# External libnats dependency probe (sets NATS_FOUND if available).
include ../../lib/nats/Makefile.nats

ifeq ($(NATS_FOUND),)
$(info [skip] nats_consumer.so — libnats C client not detected (install libnats-dev or set LOCALBASE))
.PHONY: all clean install modules
all clean install modules: ; @true
else ifneq ($(NATS_HAS_KV_TTL),yes)
$(info [skip] nats_consumer.so — libnats too old: missing the per-key KV TTL API kvStore_CreateStringWithTTL (nats.c PR #1000); install a newer nats.c (e.g. to /usr/local + ldconfig) or set LOCALBASE)
.PHONY: all clean install modules
all clean install modules: ; @true
else

auto_gen=
NAME=nats_consumer.so

# Shared NATS connection pool library (compiled as libnats_pool.so).
# Installed into $(modules_dir); modules locate it via $ORIGIN rpath so
# all loaded NATS modules share one copy of pool_cfg / _nc / _js state.
LIBS    += -L../../lib/nats -lnats_pool

include ../../Makefile.modules

# Appended AFTER Makefile.modules so it survives the `LDFLAGS:=$(MOD_LDFLAGS)`
# reassignment that happens inside Makefile.modules.  LDFLAGS is deferred in
# the $(NAME) link rule, so late edits still reach the linker.
LDFLAGS += -Wl,-rpath,'$$ORIGIN' -Wl,-rpath,'$$ORIGIN/../../lib/nats'

endif
