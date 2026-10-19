#!/bin/bash
#
# test_nak_delay_e2e.sh -- nats_nak_delay(delay_ms) redelivers the message
# after delay_ms, against a real broker.
#
# One opensips instance pulls from a private nats-server.  On the first
# delivery of the test message the script calls nats_nak_delay(3000); on
# the redelivery it acks.  The redelivery must come after the delay (the
# NAK delay is honoured) and within a few seconds of it (the delay is
# milliseconds, not some larger unit).
#
# Exit 0 pass, 1 fail, 77 missing prerequisite.

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TREE_ROOT="$(cd "${HERE}/../../.." && pwd)"
OPENSIPS_BIN="${OPENSIPS_BIN:-${TREE_ROOT}/opensips}"
OPENSIPS_LIB_NATS="${OPENSIPS_LIB_NATS:-${TREE_ROOT}/lib/nats}"
NATS_PORT="${NATS_PORT:-4228}"
SIP_PORT="${SIP_PORT:-65524}"
DELAY_MS=3000
STREAM="NAK_DELAY"
SUBJECT="nak.delay.jobs"
WORKDIR="$(mktemp -d -t test_nak_delay_e2e.XXXXXX)"
NATS_PID=""
OPENSIPS_PID=""
FAILED=0

skip() { echo "SKIP: $*"; exit 77; }
fail() { echo "FAIL: $*"; FAILED=$((FAILED+1)); }
pass() { echo "PASS: $*"; }

cleanup() {
    [ -n "$OPENSIPS_PID" ] && kill -TERM "$OPENSIPS_PID" 2>/dev/null
    [ -n "$NATS_PID" ] && kill -TERM "$NATS_PID" 2>/dev/null
    sleep 0.3
    [ -n "$OPENSIPS_PID" ] && kill -KILL "$OPENSIPS_PID" 2>/dev/null
    [ -n "$NATS_PID" ] && kill -KILL "$NATS_PID" 2>/dev/null
    wait 2>/dev/null
    if [ "$FAILED" -eq 0 ]; then
        rm -rf "$WORKDIR"
    else
        echo "Workdir preserved for inspection: $WORKDIR"
    fi
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null 2>&1 || skip "$1 not found in PATH"; }
[ -x "$OPENSIPS_BIN" ] || skip "opensips binary not found at $OPENSIPS_BIN"
[ -f "$OPENSIPS_LIB_NATS/libnats_pool.so" ] || skip "libnats_pool.so not built"
for m in nats_consumer event_nats sl signaling; do
    [ -f "$TREE_ROOT/modules/$m/$m.so" ] || skip "$m.so not built"
done
need nats-server
need nats
need nc
nc -z 127.0.0.1 "$NATS_PORT" 2>/dev/null && skip "port $NATS_PORT already in use"

echo "==== test_nak_delay_e2e ===="
ulimit -c 0
cd "$WORKDIR" || skip "cd to workdir failed"

nats-server -a 127.0.0.1 -p "$NATS_PORT" -js -sd "$WORKDIR/js" \
    > "$WORKDIR/nats-server.log" 2>&1 &
NATS_PID=$!
for _ in $(seq 1 40); do nc -z 127.0.0.1 "$NATS_PORT" 2>/dev/null && break; sleep 0.25; done
nc -z 127.0.0.1 "$NATS_PORT" 2>/dev/null || { fail "nats-server never started"; exit 1; }

export XDG_CONFIG_HOME="$WORKDIR/cli-cfg"
mkdir -p "$XDG_CONFIG_HOME"
nats context add nak-delay --server "nats://127.0.0.1:${NATS_PORT}" \
    --select >/dev/null 2>&1 || { fail "nats CLI context add"; exit 1; }
nats stream add "$STREAM" --subjects "$SUBJECT" --storage memory \
    --defaults >/dev/null 2>&1 || { fail "nats stream add"; exit 1; }

# ack_wait (30 s) is far above the delay, so only the NAK delay can
# bring the message back within the window checked below.
cat > "$WORKDIR/opensips.cfg" <<EOF
log_level=3
xlog_level=3
stderror_enabled=yes
syslog_enabled=no
udp_workers=1
socket=udp:127.0.0.1:${SIP_PORT}

loadmodule "proto_udp.so"
loadmodule "${TREE_ROOT}/modules/signaling/signaling.so"
loadmodule "${TREE_ROOT}/modules/sl/sl.so"
loadmodule "${TREE_ROOT}/modules/event_nats/event_nats.so"
modparam("event_nats", "nats_url", "nats://127.0.0.1:${NATS_PORT}")
loadmodule "${TREE_ROOT}/modules/nats_consumer/nats_consumer.so"

startup_route {
    nats_consumer_bind("id=nd;stream=${STREAM};durable=nd;filter=${SUBJECT};deliver_policy=all;ack_policy=explicit;ack_wait=30s;max_deliver=5");
}

timer_route[drain, 1] {
    if (nats_fetch("nd", 200)) {
        if (\$nats_delivered == 1) {
            xlog("L_NOTICE", "[nak-delay] first delivery, nak_delay(${DELAY_MS})\n");
            nats_nak_delay(${DELAY_MS});
        } else {
            xlog("L_NOTICE", "[nak-delay] redelivered (delivery \$nats_delivered)\n");
            nats_ack();
        }
    }
}

route {
    sl_send_reply(200, "ok");
    exit;
}
EOF

LD_LIBRARY_PATH="/usr/local/lib:${OPENSIPS_LIB_NATS}:${LD_LIBRARY_PATH:-}" \
    "$OPENSIPS_BIN" -F -f "$WORKDIR/opensips.cfg" > "$WORKDIR/opensips.log" 2>&1 &
OPENSIPS_PID=$!

for _ in $(seq 1 60); do
    grep -q "subscribed id='nd'" "$WORKDIR/opensips.log" 2>/dev/null && break
    sleep 0.25
done
grep -q "subscribed id='nd'" "$WORKDIR/opensips.log" \
    || { fail "consumer never subscribed"; tail -20 "$WORKDIR/opensips.log"; exit 1; }
pass "consumer subscribed"

nats pub "$SUBJECT" "job-1" >/dev/null 2>&1 || { fail "publish"; exit 1; }

now_ms() { date +%s%3N; }
t_nak=""; t_redeliver=""
deadline=$(( $(now_ms) + 20000 ))
while [ "$(now_ms)" -lt "$deadline" ]; do
    if [ -z "$t_nak" ] && grep -q '\[nak-delay\] first delivery' "$WORKDIR/opensips.log"; then
        t_nak=$(now_ms)
    fi
    if [ -n "$t_nak" ] && grep -q '\[nak-delay\] redelivered' "$WORKDIR/opensips.log"; then
        t_redeliver=$(now_ms)
        break
    fi
    sleep 0.05
done

[ -n "$t_nak" ] && pass "first delivery NAKed with nats_nak_delay(${DELAY_MS})" \
    || { fail "message never delivered"; tail -20 "$WORKDIR/opensips.log"; exit 1; }
if [ -z "$t_redeliver" ]; then
    fail "no redelivery within 20 s of a ${DELAY_MS} ms NAK delay"
    exit 1
fi
gap=$((t_redeliver - t_nak))
echo "INFO: redelivered ${gap} ms after the NAK"
# lower bound: the delay was honoured (a plain NAK redelivers at once);
# upper bound: the delay plus pull-cycle and drain-timer slack (about
# 2 s here) -- a delay read in the wrong unit is hours or days late
if [ "$gap" -ge $((DELAY_MS - 300)) ]; then
    pass "redelivery waited for the NAK delay (${gap} ms >= $((DELAY_MS - 300)) ms)"
else
    fail "redelivered after ${gap} ms, before the ${DELAY_MS} ms NAK delay"
fi
if [ "$gap" -le $((DELAY_MS + 7000)) ]; then
    pass "redelivery came within the delay plus pull/timer slack (${gap} ms)"
else
    fail "redelivered only after ${gap} ms for a ${DELAY_MS} ms NAK delay"
fi

echo "==== summary: $([ "$FAILED" -eq 0 ] && echo pass || echo "$FAILED failure(s)") ===="
[ "$FAILED" -eq 0 ]
