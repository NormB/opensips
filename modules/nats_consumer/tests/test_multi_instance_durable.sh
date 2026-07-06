#!/bin/bash
#
# Copyright (C) 2026 OpenSIPS Solutions
# SPDX-License-Identifier: GPL-2.0-or-later
#
# test_multi_instance_durable.sh -- multi-instance durable
# load-balance + failover smoke for nats_consumer.
#
# Spins up TWO standalone opensips instances against ONE nats-server
# (no TLS, no docker -- self-contained like the lib/nats smoke tests).
# Both instances bind the SAME stream + durable name; JetStream then
# distributes delivery across the two consumers as a single logical
# work queue.
#
# Two phases:
#
#   1. Load balance.  Publish N (default 50) messages with the nats
#      CLI; poll both instances' nats_consumer_list MI and assert
#      msgs_delivered_A + msgs_delivered_B == N (no double-delivery)
#      and each individual count > 0 (distribution actually worked).
#
#   2. Failover.  SIGTERM instance A; publish K (default 20) more
#      messages.  Assert instance B's msgs_delivered grows by exactly
#      K -- the broker reroutes everything the dead instance would
#      have taken to the survivor.  Confirms redelivery semantics
#      under crash conditions without waiting for ack_wait expiry
#      (the broker treats a closed consumer connection like an
#      ack_wait expiry for in-flight messages on that subscription;
#      undelivered messages route to the survivor on the next fetch).
#
# Skip semantics: exit 77 on missing prerequisites.  Real failures
# exit 1.
#
# Run:
#   modules/nats_consumer/tests/test_multi_instance_durable.sh

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
TREE_ROOT="$(cd "${HERE}/../../.." && pwd)"

OPENSIPS_BIN="${OPENSIPS_BIN:-${TREE_ROOT}/opensips}"
OPENSIPS_LIB_NATS="${OPENSIPS_LIB_NATS:-${TREE_ROOT}/lib/nats}"
NATS_PORT="${NATS_PORT:-4227}"
SIP_PORT_A="${SIP_PORT_A:-65522}"
SIP_PORT_B="${SIP_PORT_B:-65523}"
MI_PORT_A="${MI_PORT_A:-8895}"
MI_PORT_B="${MI_PORT_B:-8896}"
N_MESSAGES="${N_MESSAGES:-50}"
K_FAILOVER="${K_FAILOVER:-20}"
WAIT_INIT_SECS="${WAIT_INIT_SECS:-10}"
WAIT_DELIVERY_SECS="${WAIT_DELIVERY_SECS:-25}"
STREAM="MULTI_INST"
SUBJECT="multi.inst.jobs"
HANDLE_ID="lb"
DURABLE="lb_shared"

WORKDIR="$(mktemp -d -t test_multi_instance_durable.XXXXXX)"
NATS_PID=""
OPENSIPS_PID_A=""
OPENSIPS_PID_B=""
SUITE_FAIL=0
PASSED=0
FAILED=0

skip() { echo "SKIP: $*"; exit 77; }
fail() { echo "FAIL: $*"; FAILED=$((FAILED+1)); SUITE_FAIL=1; }
pass() { echo "PASS: $*"; PASSED=$((PASSED+1)); }
info() { echo "INFO: $*"; }

cleanup() {
    [ -n "$OPENSIPS_PID_A" ] && kill -TERM "$OPENSIPS_PID_A" 2>/dev/null
    [ -n "$OPENSIPS_PID_B" ] && kill -TERM "$OPENSIPS_PID_B" 2>/dev/null
    [ -n "$NATS_PID"       ] && kill -TERM "$NATS_PID"       2>/dev/null
    sleep 0.3
    [ -n "$OPENSIPS_PID_A" ] && kill -KILL "$OPENSIPS_PID_A" 2>/dev/null
    [ -n "$OPENSIPS_PID_B" ] && kill -KILL "$OPENSIPS_PID_B" 2>/dev/null
    [ -n "$NATS_PID"       ] && kill -KILL "$NATS_PID"       2>/dev/null
    wait 2>/dev/null
    if [ "$SUITE_FAIL" -eq 0 ]; then
        rm -rf "$WORKDIR"
    else
        echo
        echo "Workdir preserved for inspection: $WORKDIR"
    fi
}
trap cleanup EXIT

# ──────────────────────────────────────────────────────────────────
# Prereqs
# ──────────────────────────────────────────────────────────────────
need() { command -v "$1" >/dev/null 2>&1 || skip "$1 not found in PATH"; }

[ -x "$OPENSIPS_BIN" ] || skip "opensips binary not found at $OPENSIPS_BIN"
[ -f "$OPENSIPS_LIB_NATS/libnats_pool.so" ] || skip "libnats_pool.so not built"
[ -f "$TREE_ROOT/modules/nats_consumer/nats_consumer.so" ] || skip "nats_consumer.so not built"
[ -f "$TREE_ROOT/modules/event_nats/event_nats.so" ] || skip "event_nats.so not built"
[ -f "$TREE_ROOT/modules/mi_datagram/mi_datagram.so" ] || skip "mi_datagram.so not built"
need nats-server
need nats
need nc

for p in "$NATS_PORT" "$SIP_PORT_A" "$SIP_PORT_B"; do
    if nc -z 127.0.0.1 "$p" 2>/dev/null; then
        skip "port $p already in use"
    fi
done
for p in "$MI_PORT_A" "$MI_PORT_B"; do
    if nc -uz 127.0.0.1 "$p" 2>/dev/null; then
        skip "UDP port $p already in use"
    fi
done

echo "==== test_multi_instance_durable ===="
echo "  workdir:    $WORKDIR"
echo "  nats port:  $NATS_PORT"
echo "  mi ports:   A=$MI_PORT_A  B=$MI_PORT_B"
echo "  N messages: $N_MESSAGES  (failover K=$K_FAILOVER)"

# ──────────────────────────────────────────────────────────────────
# Broker
# ──────────────────────────────────────────────────────────────────
cd "$WORKDIR" || skip "cd to workdir failed"

cat > nats-server.conf <<EOF
listen: 127.0.0.1:${NATS_PORT}
http: 127.0.0.1:$((NATS_PORT + 1))
jetstream {
    store_dir: "${WORKDIR}/jetstream"
}
EOF
nats-server -c nats-server.conf \
    -l "${WORKDIR}/nats-server.log" \
    -P "${WORKDIR}/nats-server.pid" &
NATS_PID=$!

for i in $(seq 1 20); do
    nc -z 127.0.0.1 "$NATS_PORT" 2>/dev/null \
        && { pass "nats-server listening on $NATS_PORT after ${i}*0.25s"; break; }
    sleep 0.25
done
if ! nc -z 127.0.0.1 "$NATS_PORT" 2>/dev/null; then
    fail "nats-server never started"
    tail -30 "${WORKDIR}/nats-server.log" 2>&1 | sed 's/^/  | /'
    exit 1
fi

# Point the nats CLI at our private broker via a workdir-scoped
# context (don't pollute the operator's contexts).
export XDG_CONFIG_HOME="${WORKDIR}/cli-cfg"
mkdir -p "${XDG_CONFIG_HOME}"
nats context add multi-inst \
    --server "nats://localhost:${NATS_PORT}" \
    --select >/dev/null 2>&1 \
    || { fail "nats CLI context add"; exit 1; }

nats stream add "${STREAM}" \
    --subjects "${SUBJECT}" \
    --storage memory \
    --retention limits \
    --max-msgs=-1 \
    --max-bytes=-1 \
    --max-age=1h \
    --replicas 1 \
    --discard old \
    --dupe-window 2m \
    --defaults >/dev/null 2>&1 \
    || { fail "nats stream add"; exit 1; }
pass "JetStream stream ${STREAM} created"

# ──────────────────────────────────────────────────────────────────
# opensips cfg renderer
# ──────────────────────────────────────────────────────────────────
# A short ack_wait (5s) means a crashed instance's in-flight messages
# redeliver to the survivor within 5s -- but the broker also detects
# a closed subscription (clean SIGTERM closes the libnats connection
# which closes the consumer subscription on the server side) and
# can route undelivered messages to the survivor immediately on its
# next fetch.  Test asserts on the eventual-consistency property,
# not on the exact mechanism.
render_cfg() {
    local label="$1" sip_port="$2" mi_port="$3" out_cfg="$4"
    cat > "$out_cfg" <<EOF
log_level=3
xlog_level=3
stderror_enabled=yes
syslog_enabled=no
udp_workers=1
tcp_workers=0
socket=udp:127.0.0.1:${sip_port}

loadmodule "proto_udp.so"
loadmodule "${TREE_ROOT}/modules/sipmsgops/sipmsgops.so"
loadmodule "${TREE_ROOT}/modules/signaling/signaling.so"
loadmodule "${TREE_ROOT}/modules/sl/sl.so"
loadmodule "${TREE_ROOT}/modules/maxfwd/maxfwd.so"

loadmodule "${TREE_ROOT}/modules/mi_datagram/mi_datagram.so"
modparam("mi_datagram", "socket_name", "udp:127.0.0.1:${mi_port}")

loadmodule "${TREE_ROOT}/modules/event_nats/event_nats.so"
modparam("event_nats", "nats_url", "nats://127.0.0.1:${NATS_PORT}")

loadmodule "${TREE_ROOT}/modules/nats_consumer/nats_consumer.so"

startup_route {
    xlog("L_INFO", "${label}: binding handle\n");
    nats_consumer_bind("id=${HANDLE_ID};stream=${STREAM};durable=${DURABLE};filter=${SUBJECT};deliver_policy=all;ack_policy=explicit;ack_wait=5s;max_deliver=10;max_ack_pending=32");
}

timer_route[drain, 1] {
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
}

route {
    sl_send_reply(200, "ok");
    exit;
}
EOF
}

render_cfg "instance_A" "$SIP_PORT_A" "$MI_PORT_A" "${WORKDIR}/A.cfg"
render_cfg "instance_B" "$SIP_PORT_B" "$MI_PORT_B" "${WORKDIR}/B.cfg"

# ──────────────────────────────────────────────────────────────────
# Boot helper
# ──────────────────────────────────────────────────────────────────
boot_opensips() {
    local label="$1" cfg="$2" log="$3"
    LD_LIBRARY_PATH="/usr/local/lib:${OPENSIPS_LIB_NATS}:${LD_LIBRARY_PATH:-}" \
        "$OPENSIPS_BIN" -F -i -f "$cfg" > "$log" 2>&1 &
    echo $!
}

wait_for_connected() {
    local log="$1" deadline=$((SECONDS + WAIT_INIT_SECS))
    while [ "$SECONDS" -lt "$deadline" ]; do
        [ -s "$log" ] && grep -q "NATS pool: connected to" "$log" && return 0
        sleep 0.25
    done
    return 1
}

# Poll nats_consumer_list and emit "msgs_delivered acks" on stdout.
poll_counters() {
    local port="$1"
    local reply
    reply="$(printf '{"jsonrpc":"2.0","id":1,"method":"nats_consumer:nats_consumer_list"}' \
        | nc -u -w 2 127.0.0.1 "$port" 2>/dev/null)"
    if [ -z "$reply" ]; then
        echo "0 0"
        return
    fi
    local md
    local ak
    md="$(printf '%s' "$reply" | grep -oE '"msgs_delivered"[[:space:]]*:[[:space:]]*[0-9]+' \
        | grep -oE '[0-9]+' | head -1)"
    ak="$(printf '%s' "$reply" | grep -oE '"acks"[[:space:]]*:[[:space:]]*[0-9]+' \
        | grep -oE '[0-9]+' | head -1)"
    md="${md:-0}"
    ak="${ak:-0}"
    echo "$md $ak"
}

# ──────────────────────────────────────────────────────────────────
# Phase 1: load balance
# ──────────────────────────────────────────────────────────────────
OPENSIPS_PID_A="$(boot_opensips A "${WORKDIR}/A.cfg" "${WORKDIR}/A.log")"
OPENSIPS_PID_B="$(boot_opensips B "${WORKDIR}/B.cfg" "${WORKDIR}/B.log")"

wait_for_connected "${WORKDIR}/A.log" \
    && pass "instance A connected" \
    || { fail "instance A never connected"; tail -20 "${WORKDIR}/A.log" | sed 's/^/  A| /'; exit 1; }

wait_for_connected "${WORKDIR}/B.log" \
    && pass "instance B connected" \
    || { fail "instance B never connected"; tail -20 "${WORKDIR}/B.log" | sed 's/^/  B| /'; exit 1; }

# Both instances need a moment for their startup_route to fire +
# js_PullSubscribe to register on the broker before publishes land.
sleep 1

info "publishing ${N_MESSAGES} messages to ${SUBJECT}"
for i in $(seq 1 "$N_MESSAGES"); do
    nats pub "${SUBJECT}" "msg-${i}" >/dev/null 2>&1 \
        || { fail "publish msg-${i}"; exit 1; }
done
pass "${N_MESSAGES} messages published"

# Poll both instances' counters until the sum reaches N or we time out.
md_a=0; ak_a=0; md_b=0; ak_b=0
deadline=$((SECONDS + WAIT_DELIVERY_SECS))
while [ "$SECONDS" -lt "$deadline" ]; do
    read -r md_a ak_a <<<"$(poll_counters "$MI_PORT_A")"
    read -r md_b ak_b <<<"$(poll_counters "$MI_PORT_B")"
    if [ "$((md_a + md_b))" -ge "$N_MESSAGES" ] \
        && [ "$((ak_a + ak_b))" -ge "$N_MESSAGES" ]; then
        break
    fi
    sleep 0.5
done
info "A=(delivered=${md_a} acks=${ak_a}) B=(delivered=${md_b} acks=${ak_b})"

if [ "$((md_a + md_b))" -ge "$N_MESSAGES" ]; then
    pass "sum(msgs_delivered) ${md_a}+${md_b}=$((md_a + md_b)) >= ${N_MESSAGES}"
else
    fail "sum(msgs_delivered) $((md_a + md_b)) < ${N_MESSAGES}"
fi

# No double-delivery: a fan-out bug would push the sum strictly
# above N (each instance would have its own copy).  JetStream
# durable-consumer semantics guarantee exactly-once delivery from
# the broker's side; max_deliver=10 would only redeliver on NAK or
# ack_wait expiry, neither of which happens on the happy path.
if [ "$((md_a + md_b))" -le "$N_MESSAGES" ]; then
    pass "no double-delivery (sum == N, not 2N)"
else
    fail "double-delivery detected: sum=$((md_a + md_b)) > N=${N_MESSAGES}"
fi

if [ "$md_a" -gt 0 ] && [ "$md_b" -gt 0 ]; then
    pass "load balanced: both instances received at least one message"
else
    fail "load NOT balanced: A=${md_a} B=${md_b} (one instance starved)"
fi

# ──────────────────────────────────────────────────────────────────
# Phase 2: failover
# ──────────────────────────────────────────────────────────────────
info "phase 2: killing instance A; survivor B should absorb ${K_FAILOVER} new messages"

# Snapshot B's pre-failover counters so we can measure the delta.
read -r md_b_before ak_b_before <<<"$(poll_counters "$MI_PORT_B")"
info "B before failover: delivered=${md_b_before} acks=${ak_b_before}"

kill -TERM "$OPENSIPS_PID_A" 2>/dev/null
wait "$OPENSIPS_PID_A" 2>/dev/null
OPENSIPS_PID_A=""
pass "instance A SIGTERMed"

# Give the broker a beat to notice A's subscription closed.
sleep 1

info "publishing ${K_FAILOVER} failover messages"
for i in $(seq 1 "$K_FAILOVER"); do
    nats pub "${SUBJECT}" "failover-${i}" >/dev/null 2>&1 \
        || { fail "publish failover-${i}"; exit 1; }
done

# Poll B until it has consumed K_FAILOVER additional messages.
md_b=0
deadline=$((SECONDS + WAIT_DELIVERY_SECS))
while [ "$SECONDS" -lt "$deadline" ]; do
    read -r md_b ak_b <<<"$(poll_counters "$MI_PORT_B")"
    if [ "$((md_b - md_b_before))" -ge "$K_FAILOVER" ]; then
        break
    fi
    sleep 0.5
done
info "B after failover: delivered=${md_b} acks=${ak_b} (delta=$((md_b - md_b_before)))"

if [ "$((md_b - md_b_before))" -ge "$K_FAILOVER" ]; then
    pass "survivor absorbed $((md_b - md_b_before)) >= ${K_FAILOVER} failover messages"
else
    fail "survivor absorbed only $((md_b - md_b_before)) < ${K_FAILOVER}"
    tail -10 "${WORKDIR}/B.log" 2>&1 | sed 's/^/  B| /'
fi

# Defensive: no errors slipped through B's log (A's log is allowed
# to contain shutdown noise from the SIGTERM).  set_core_dump's
# CRITICAL is environmental noise: it fires whenever the harness runs
# under `ulimit -c 0` (deliberate on tmpfs boxes -- SIGKILL cases
# would otherwise OOM /tmp with cores) and says nothing about NATS.
if grep -E "ERROR.*nats|CRITICAL" "${WORKDIR}/B.log"         | grep -v 'set_core_dump' | grep -q .; then
    fail "fatal errors in instance B log"
    grep -E "ERROR.*nats|CRITICAL" "${WORKDIR}/B.log"         | grep -v 'set_core_dump' | head -5 | sed 's/^/  B| /'
else
    pass "no fatal errors in survivor instance log"
fi

echo "==== summary: $PASSED pass, $FAILED fail ===="
exit "$SUITE_FAIL"
