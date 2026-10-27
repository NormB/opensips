#!/bin/sh
#
# nats_probe.sh URL -- exit 0 when a NATS broker answers at URL, 1 when it
# does not, 2 on bad usage.
#
# `nats server check connection` is a nagios-style check: with its default
# sub-second thresholds a slow connect on a busy host is a WARNING (exit 1)
# although the broker is up.  The thresholds are raised far above them, and
# a WARNING still counts as reachable; only CRITICAL/UNKNOWN does not.
#
# Self-test: selftest_nats_probe.sh.

if [ $# -ne 1 ] || [ -z "$1" ]; then
    echo "usage: $0 <nats-url>" >&2
    exit 2
fi
command -v nats >/dev/null 2>&1 || exit 1

nats "--server=$1" server check connection \
    --connect-warn=5s --connect-critical=10s \
    --rtt-warn=5s --rtt-critical=10s \
    --req-warn=5s --req-critical=10s
case $? in
    0|1) exit 0 ;;
    *)   exit 1 ;;
esac
