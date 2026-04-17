# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=event_nats.so

# Shared NATS connection pool library (compiled as libnats_pool.so).
# Installed into $(modules_dir); modules locate it via $ORIGIN rpath so
# all loaded NATS modules share one copy of pool_cfg / _nc / _js state.
LIBS    += -L../../lib/nats -lnats_pool

# External libnats dependency (pkg-config or fallback)
include ../../lib/nats/Makefile.nats

include ../../Makefile.modules

# Appended AFTER Makefile.modules so it survives the `LDFLAGS:=$(MOD_LDFLAGS)`
# reassignment that happens inside Makefile.modules.  LDFLAGS is deferred in
# the $(NAME) link rule, so late edits still reach the linker.
LDFLAGS += -Wl,-rpath,'$$ORIGIN'
