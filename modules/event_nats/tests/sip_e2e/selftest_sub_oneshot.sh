#!/bin/bash
# selftest_sub_oneshot.sh -- process-ownership contract of
# nats_sub_oneshot (lib/helpers.sh).
#
# The pid returned by nats_sub_oneshot MUST be killable: after
# `kill <pid>` (the rebind pattern in case 030) no `nats sub` process
# may survive.  The original helper backgrounded the n() shell
# FUNCTION, so $! was an intermediate subshell -- killing it orphaned
# the actual nats binary, which then blocked forever on --count=1
# (observed repeatedly as PPID-1 `nats sub test.sip.unicode` leftovers,
# one of which held the LAN CI batch flock via an inherited fd).
#
# Needs: nats-server (any version), nats CLI.  Skips (77) if missing.
# Uses a throwaway broker on a dedicated port; leaves nothing behind.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)

# nats-server is commonly installed in sbin, off a user PATH.
PATH="$PATH:/usr/sbin:/usr/local/sbin"

command -v nats-server >/dev/null || { echo "SKIP: no nats-server"; exit 77; }
command -v nats        >/dev/null || { echo "SKIP: no nats CLI";    exit 77; }

PORT=4397
SUBJECT="selftest.sub.oneshot.$$"
WORKDIR=$(mktemp -d -t sub-oneshot-selftest.XXXXXX)
BROKER_PID=""

cleanup() {
    [ -n "$BROKER_PID" ] && kill "$BROKER_PID" 2>/dev/null
    # Backstop: never leave a selftest subscriber behind, pass or fail.
    pkill -f "sub $SUBJECT" 2>/dev/null
    wait 2>/dev/null
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

nats-server -p "$PORT" > "$WORKDIR/broker.log" 2>&1 &
BROKER_PID=$!
for i in $(seq 1 20); do
    nats --server "nats://127.0.0.1:$PORT" server check connection \
        >/dev/null 2>&1 && break
    sleep 0.25
done

# Source the helpers exactly as the runner does.
NATS_URL="nats://127.0.0.1:$PORT"
WORKDIR_SAVE="$WORKDIR"
# helpers.sh references $WORKDIR for some functions; ours is fine.
. "$HERE/lib/helpers.sh"
WORKDIR="$WORKDIR_SAVE"

fails=0
check() { # label, cond-rc
    if [ "$2" -eq 0 ]; then echo "  ok: $1"
    else echo "  FAIL: $1"; fails=$((fails + 1)); fi
}

sub_out="$WORKDIR/sub.out"
sub_pid=$(nats_sub_oneshot "$SUBJECT" "$sub_out")

kill -0 "$sub_pid" 2>/dev/null
check "returned pid is alive while subscribed" $?

kill "$sub_pid" 2>/dev/null
sleep 1

# THE contract: after killing the returned pid, no subscriber process
# on our subject may survive (pgrep -f matches the nats binary's args).
pgrep -f "sub $SUBJECT" >/dev/null 2>&1
[ $? -ne 0 ]
check "kill(returned pid) leaves no orphaned nats subscriber" $?

# Normal path still works: a oneshot that RECEIVES its message exits 0
# by itself.
sub_out2="$WORKDIR/sub2.out"
sub_pid2=$(nats_sub_oneshot "$SUBJECT" "$sub_out2")
nats --server "$NATS_URL" pub "$SUBJECT" "ping" >/dev/null 2>&1
for i in $(seq 1 10); do kill -0 "$sub_pid2" 2>/dev/null || break; sleep 0.5; done
grep -q "ping" "$sub_out2"
check "oneshot still receives and exits on its own" $?

echo
if [ "$fails" -eq 0 ]; then echo "=== ALL PASS ==="; exit 0
else echo "=== FAILURES ($fails) ==="; exit 1; fi
