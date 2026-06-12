#!/bin/bash
# test_boot_degraded_e2e.sh -- broker DOWN AT BOOT, then arriving late.
#
# Distinct fault class from crash/restart-mid-traffic: the broker is
# unreachable while every OpenSIPS process runs child_init.  The
# NATS_TODO #7 hardening requires:
#
#   - event_nats: child_init logs + returns 0 (degraded), publish
#     fails cleanly while down (no crash, no abort)
#   - nats_consumer: the consumer proc loop-retries the pool instead
#     of exiting
#   - lib/nats: RetryOnFailedConnect + reconnect handling pick the
#     broker up when it finally appears, WITHOUT a restart
#
# Phases:
#   boot     broker down -> opensips must come up (degraded)
#   degraded publish fails cleanly, process alive
#   late     broker starts -> publish succeeds, consumer subscribes
#
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/nats_local_lib.sh"

require_opensips_built
require_cmd nats nc
command -v nats-server >/dev/null 2>&1 || skip "nats-server not in PATH"

PORT=4325
PRIV_URL="nats://127.0.0.1:${PORT}"
STREAM="OS_BOOT_$$"
HANDLE="bd$$"
SIP_PORT=5196

mkworkdir boot_degraded
JSDIR="${WORK}/jsdir"
mkdir -p "${JSDIR}"

NS_PID=""
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
cleanup_all() {
    stop_opensips
    [ -n "${NS_PID}" ] && kill -9 "${NS_PID}" 2>/dev/null
    cleanup_workdir
}
trap cleanup_all EXIT

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

startup_route {
    # bind while the broker is DOWN: must not crash; the consumer proc
    # keeps retrying and subscribes once the broker appears.
    nats_consumer_bind("id=${HANDLE};stream=${STREAM};filter=bd.in.>;durable=${HANDLE};ack_wait=30s");
}

route {
    \$var(p) = \$rU;
    if (nats_publish("bd.evt.\$var(p)", "hello-\$var(p)"))
        xlog("L_NOTICE","[\$var(p)] publish=ok\n");
    else
        xlog("L_NOTICE","[\$var(p)] publish=fail\n");
    xlog("L_NOTICE","[\$var(p)] phase-done\n");
    sl_send_reply(200, "done");
    exit;
}
EOF

# ---------- phase: boot with the broker DOWN ----------
start_opensips "${WORK}/test.cfg"
sleep 4

ok=0; total=0
expect() {
    total=$((total+1))
    if eval "$1"; then echo "  ok: $2"; ok=$((ok+1)); else echo "  MISSING: $2"; fi
}

expect 'kill -0 "${OPS_PID}" 2>/dev/null' \
    "opensips alive 4s after boot with broker down (degraded start)"
expect '! log_contains "segfault in process"' \
    "no segfault during degraded boot"

send_phase() {
    printf "%b" "OPTIONS sip:$1@127.0.0.1:${SIP_PORT} SIP/2.0\r
Via: SIP/2.0/UDP 127.0.0.1:55196;branch=z9hG4bK-$1.${RANDOM}\r
From: <sip:harness@127.0.0.1>;tag=$1\r
To: <sip:$1@127.0.0.1>\r
Call-ID: $1.${RANDOM}@127.0.0.1\r
CSeq: 1 OPTIONS\r
Max-Forwards: 70\r
Content-Length: 0\r
\r
" | timeout 5 nc -u -w1 127.0.0.1 "${SIP_PORT}" >/dev/null 2>&1 || true
}

# ---------- phase: degraded publish ----------
send_phase down
expect 'wait_for_log "\\[down\\] publish=fail" 8' \
    "publish fails cleanly while the broker is down"
expect 'wait_for_log "\\[down\\] phase-done" 8' \
    "route completes (no stall) while the broker is down"
expect 'kill -0 "${OPS_PID}" 2>/dev/null' \
    "opensips still alive after the failed publish"

# ---------- phase: the broker arrives LATE ----------
start_broker
nats --server "${PRIV_URL}" stream add "${STREAM}" \
    --subjects "bd.in.>" --storage file --defaults >/dev/null 2>&1 \
    || fail "stream create failed"

recovered=0
for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 2
    send_phase up
    if wait_for_log '\[up\] publish=ok' 4; then recovered=1; break; fi
done
expect '[ "${recovered}" = "1" ]' \
    "publish recovers once the broker appears (no restart needed)"

# the consumer proc, which boot-looped on the missing broker, must now
# connect and establish the durable subscription
expect 'wait_for_log "subscribed id=.${HANDLE}." 30' \
    "consumer proc subscribes after the late broker arrival"

[ "${ok}" = "${total}" ] || fail "only ${ok}/${total} checks passed; log tail:
$(tail -30 "${OPS_LOG}")"
pass "boot-degraded matrix green (boot=degraded-ok, down=clean-fail, late broker=full recovery)"
