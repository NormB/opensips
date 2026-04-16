# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=event_nats.so

# Shared NATS connection pool library (compiled as static .a)
# Built automatically via all_misclibs in Makefile.rules
misclibs=../../lib/nats/libnats_pool.a

# External libnats dependency (pkg-config or fallback)
include ../../lib/nats/Makefile.nats

include ../../Makefile.modules
