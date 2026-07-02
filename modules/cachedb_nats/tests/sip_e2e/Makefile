# sip_e2e local tools.
#
# bench_register is a multi-threaded SIP REGISTER load generator that
# replaces the bash drive loop in bench_ul_register.sh; see the C file
# header for the why.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -pthread
LDLIBS  ?= -pthread

.PHONY: all clean

# kvctl needs a libnats with the PR #1000 KV TTL API (kvConfig.LimitMarkerTTL).
# Point NATS_INC/NATS_LIB at it; the defaults match this dev host's fork build
# and fall back to the system paths.
NATS_INC ?= $(firstword $(wildcard $(HOME)/nats.c/src) /usr/local/include)
NATS_LIB ?= $(firstword $(wildcard $(HOME)/nats.c/build-release/lib) /usr/local/lib)

all: bench_register kvctl

bench_register: bench_register.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

kvctl: kvctl.c
	$(CC) $(CFLAGS) -I$(NATS_INC) -L$(NATS_LIB) -Wl,-rpath,$(NATS_LIB) \
		-o $@ $< -lnats

clean:
	rm -f bench_register kvctl
