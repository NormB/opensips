# nats_tls_openssl Makefile.
#
# This module deliberately does NOT link against libnats at compile
# time -- it loads libnats dynamically from mod_init via dlopen with
# RTLD_GLOBAL.  Subsequent loads of the NATS user modules (event_nats,
# cachedb_nats, nats_consumer) then resolve their DT_NEEDED libnats.so.3
# against the already-loaded copy, by SONAME match.
#
# The matching wolfSSL-flavoured wrapper module (nats_tls_wolfssl) does
# the same thing but loads a wolfSSL-built libnats from a separate
# install prefix.  Operator picks the TLS backend by loading exactly
# one of these wrapper modules in opensips.cfg, before the NATS user
# modules.
include ../../Makefile.defs
auto_gen=
NAME=nats_tls_openssl.so

# libdl for dlopen / dlsym; no other linkage.
LIBS += -ldl

include ../../Makefile.modules
