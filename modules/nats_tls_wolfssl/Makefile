# nats_tls_wolfssl Makefile.
#
# Twin of nats_tls_openssl.  This module does NOT link libnats at
# compile time; instead mod_init dlopens a wolfSSL-flavoured libnats
# from a deployment-configured path with RTLD_GLOBAL so subsequent
# NATS user modules resolve their DT_NEEDED libnats.so.3 against
# the already-loaded wolfSSL build by SONAME match.
#
# See modules/nats_tls_openssl/Makefile for the architectural
# rationale; the two modules are deliberately symmetric.  The
# default `libnats_path` modparam points at /opt/libnats-wolfssl/
# but distros / operators can override per-install.
include ../../Makefile.defs
auto_gen=
NAME=nats_tls_wolfssl.so

# libdl for dlopen / dlsym; no other linkage.
LIBS += -ldl

include ../../Makefile.modules
