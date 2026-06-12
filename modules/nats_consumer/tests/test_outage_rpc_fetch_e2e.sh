#!/bin/bash
# test_outage_rpc_fetch_e2e.sh -- broker-lifecycle matrix for
# nats_consumer's fetch + sync-RPC surfaces, against a PRIVATE
# disposable broker.
#
#   phase 1 (broker up):        publish -> nats_fetch delivers;
#                               nats_request gets a reply from a CLI
#                               responder
#   phase 2 (broker SIGKILLed): nats_fetch fast-fails (-2, no stall);
#                               nats_request fast-fails (-3) instead of
#                               blocking the worker for the full
#                               timeout (regression: the sync path had
#                               no connectivity guard)
#   phase 3 (broker restarted): fetch resumes on the rebuilt durable
#                               subscription; nats_request succeeds
#                               again
#
# Fault classes: SIGKILL (TCP drop, no clean close) + restart with the
# same JetStream store (stream + durable consumer state persist).
#
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/../../../lib/nats/tests/nats_local_lib.sh"

require_opensips_built
require_cmd nats nc
command -v nats-server >/dev/null 2>&1 || skip "nats-server not in PATH"

PORT=4324
PRIV_URL="nats://127.0.0.1:${PORT}"
STREAM="OS_OUT_$$"
HANDLE="om$$"
SIP_PORT=5197

mkworkdir outage_rpc_fetch
JSDIR="${WORK}/jsdir"
mkdir -p "${JSDIR}"

NS_PID=""
RESP_PID=""
start_broker() {
    nats-server -p "${PORT}" -js -sd "${JSDIR}" >> "${WORK}/nats.log" 2>&1 &
    NS_PID=$!
    local i=0
    while [ $i -lt 20 ]; do
        nats --server "${PRIV_URL}" server check connection >/dev/null 2>&1 && return 0
        sleep 0.5; i=$((i+1))
    done
    fail "private broker did not come up on :${PORT}"
}
start_responder() {  # answers nats_request on rpc.echo
    nats --server "${PRIV_URL}" reply "rpc.echo" "pong" \
        >> "${WORK}/responder.log" 2>&1 &
    RESP_PID=$!
    sleep 0.5
}
stop_broker_hard() {
    [ -n "${NS_PID}" ] && kill -9 "${NS_PID}" 2>/dev/null
    wait "${NS_PID}" 2>/dev/null; NS_PID=""
    [ -n "${RESP_PID}" ] && kill "${RESP_PID}" 2>/dev/null
    wait "${RESP_PID}" 2>/dev/null; RESP_PID=""
}
cleanup_all() {
    stop_opensips
    [ -n "${RESP_PID}" ] && kill "${RESP_PID}" 2>/dev/null
    [ -n "${NS_PID}" ] && kill -9 "${NS_PID}" 2>/dev/null
    cleanup_workdir
}
trap cleanup_all EXIT

start_broker
nats --server "${PRIV_URL}" stream add "${STREAM}" \
    --subjects "om.in.>" --storage file --defaults >/dev/null 2>&1 \
    || fail "stream create failed"
start_responder

cat > "${WORK}/test.cfg" <<EOF
log_level=3
xlog_level=3
stderror_enabled=yes
syslog_facility=LOG_LOCAL0
udp_workers=1
socket=udp:127.0.0.1:${SIP_PORT}

mpath="${OPENSIPS_MPATH}"

loadmodule "signaling.so"
loadmodule "sl.so"
loadmodule "tm.so"
loadmodule "maxfwd.so"
loadmodule "sipmsgops.so"
loadmodule "proto_udp.so"

loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "${OPS_FIFO}")

loadmodule "event_nats.so"
modparam("event_nats", "nats_url", "${PRIV_URL}")

loadmodule "nats_consumer.so"
modparam("nats_consumer", "fetch_timeout_ms", 800)
# opt in to sync nats_request from the request route (test rig only)
modparam("nats_consumer", "allow_sync_anywhere", 1)

startup_route {
    nats_consumer_bind("id=${HANDLE};stream=${STREAM};filter=om.in.>;durable=${HANDLE};ack_wait=30s");
}

route {
    \$var(p) = \$rU;

    nats_fetch("${HANDLE}", 1500);
    \$var(frc) = \$retcode;
    if (\$var(frc) > 0) {
        xlog("L_NOTICE","[\$var(p)] fetch=ok data=\$nats_data\n");
        nats_ack();
    } else {
        xlog("L_NOTICE","[\$var(p)] fetch=fail rc=\$var(frc)\n");
    }

    nats_request("rpc.echo", "ping", 1500);
    \$var(rrc) = \$retcode;
    if (\$var(rrc) > 0) {
        xlog("L_NOTICE","[\$var(p)] request=ok reply=\$nats_data\n");
    } else {
        xlog("L_NOTICE","[\$var(p)] request=fail rc=\$var(rrc)\n");
    }

    xlog("L_NOTICE","[\$var(p)] phase-done\n");
    sl_send_reply(200, "done");
    exit;
}
EOF

start_opensips "${WORK}/test.cfg"
wait_for_log "subscribed id='${HANDLE}'" 10 \
    || fail "durable subscription not established; log:
$(tail -30 "${OPS_LOG}")"

send_phase() {
    printf "%b" "OPTIONS sip:$1@127.0.0.1:${SIP_PORT} SIP/2.0\r
Via: SIP/2.0/UDP 127.0.0.1:55197;branch=z9hG4bK-$1.${RANDOM}\r
From: <sip:harness@127.0.0.1>;tag=$1\r
To: <sip:$1@127.0.0.1>\r
Call-ID: $1.${RANDOM}@127.0.0.1\r
CSeq: 1 OPTIONS\r
Max-Forwards: 70\r
Content-Length: 0\r
\r
" | timeout 5 nc -u -w1 127.0.0.1 "${SIP_PORT}" >/dev/null 2>&1 || true
}

ok=0; total=0
expect() {  # $1 = marker regex, $2 = timeout, $3 = description
    total=$((total+1))
    if wait_for_log "$1" "$2"; then
        echo "  ok: $3"; ok=$((ok+1))
    else
        echo "  MISSING: $3"
    fi
}

# ---------- phase 1: up ----------
nats --server "${PRIV_URL}" pub "om.in.p1" "m-p1" >/dev/null 2>&1
sleep 1   # let the consumer proc pull it into the ring
send_phase p1
expect '\[p1\] fetch=ok data=m-p1' 8 "p1 fetch delivers the published message"
expect '\[p1\] request=ok reply=pong' 8 "p1 sync request gets the responder's reply"

# ---------- phase 2: SIGKILL ----------
stop_broker_hard
sleep 3   # let cnats notice the dead TCP

P2_T0=$(date +%s)
send_phase p2
expect '\[p2\] fetch=fail rc=-2' 10 "p2 fetch fast-fails with -2 (disconnected)"
expect '\[p2\] request=fail rc=-3' 10 "p2 sync request fast-fails with -3 (no stall)"
wait_for_log '\[p2\] phase-done' 12 || fail "phase 2 route never completed"
P2_T1=$(date +%s)
P2_ELAPSED=$((P2_T1 - P2_T0))
if [ "${P2_ELAPSED}" -gt 6 ]; then
    fail "phase 2 took ${P2_ELAPSED}s -- fetch/request stalled on the dead broker"
fi
echo "  ok: phase 2 completed in ${P2_ELAPSED}s (fast-fail)"
if log_contains 'segfault in process\|exited by a signal'; then
    fail "opensips crashed during the outage:
$(grep -E 'segfault|signal' "${OPS_LOG}" | tail -5)"
fi
echo "  ok: no crash during outage"

# ---------- phase 3: restart ----------
start_broker
start_responder
# durable consumer + stream persisted in JSDIR; publish a fresh message
recovered=0
for i in 1 2 3 4 5 6 7 8; do
    sleep 2
    nats --server "${PRIV_URL}" pub "om.in.p3" "m-p3" >/dev/null 2>&1
    send_phase p3
    if wait_for_log '\[p3\] fetch=ok' 4; then recovered=1; break; fi
done
[ "${recovered}" = "1" ] || fail "fetch did not recover within ~40s of broker restart:
$(tail -30 "${OPS_LOG}")"
expect '\[p3\] fetch=ok data=m-p3' 4 "p3 fetch resumes on the rebuilt durable"
expect '\[p3\] request=ok reply=pong' 8 "p3 sync request succeeds post-restart"

[ "${ok}" = "${total}" ] || fail "only ${ok}/${total} checks passed"
pass "fetch+RPC outage matrix green (up=ok, SIGKILL=fast-fail -2/-3, restart=recovered)"
