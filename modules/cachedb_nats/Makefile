# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=cachedb_nats.so

# Shared NATS connection pool library (compiled as libnats_pool.so).
# Installed into $(modules_dir); modules locate it via $ORIGIN rpath so
# all loaded NATS modules share one copy of pool_cfg / _nc / _js state.
LIBS    += -L../../lib/nats -lnats_pool
LDFLAGS += -Wl,-rpath,'$$ORIGIN'

# External libnats dependency (pkg-config or fallback)
include ../../lib/nats/Makefile.nats

# EVI support for E_NATS_KV_CHANGE events (KV watcher -> OpenSIPS scripts)
DEFS += -DHAVE_EVI

# pthread for KV watcher thread
LIBS += -lpthread

include ../../Makefile.modules
