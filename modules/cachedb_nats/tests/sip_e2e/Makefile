# sip_e2e local tools.
#
# bench_register is a multi-threaded SIP REGISTER load generator that
# replaces the bash drive loop in bench_ul_register.sh; see the C file
# header for the why.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -pthread
LDLIBS  ?= -pthread

.PHONY: all clean

all: bench_register

bench_register: bench_register.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f bench_register
