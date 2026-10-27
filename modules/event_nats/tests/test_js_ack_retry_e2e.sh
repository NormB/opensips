#!/bin/bash
# test_js_ack_retry_e2e.sh -- a JetStream publish whose ack goes missing
# is resent, and the stream still holds exactly one copy.
#
# A private nats-server with JetStream; event_nats reaches it through
# nats_ack_drop_proxy.py, which drops the first N publish acks on their
# way back.  Each scenario boots opensips, publishes ONE message with
# nats_publish() (jetstream=1, js_ack_timeout_ms=500) and checks:
#
#  1. drop 1 ack, js_publish_retries=3: the ack wait expires, the message
#     is resent with the same Nats-Msg-Id, the server acks the resend as a
#     duplicate.  Stream: 1 message.  nats_stats: js_retried=1,
#     js_duplicate=1, js_ack_ok=1, js_ack_failed=0.
#  2. drop every ack, js_publish_retries=3: 3 resends, then the message
#     is counted as failed.  Stream: 1 message (the resends were
#     duplicates).  js_retried=3, js_ack_failed=1, js_ack_ok=0.
#  3. drop 1 ack, js_publish_retries=0: no resend, counted as failed at
#     once.  Stream: 1 message.  js_retried=0, js_ack_failed=1.
#
# Skips (exit 77) without nats-server, the nats CLI, jq, python3 or a
# built opensips.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/../../../lib/nats/tests/nats_local_lib.sh"

require_opensips_built
require_cmd nats nats-server opensips jq python3 nc

PROXY="${HERE}/../../../lib/nats/tests/nats_ack_drop_proxy.py"
mkworkdir js_ack_retry >/dev/null

PRIV_PORT=$((21000 + ($$ % 15000)))
PROXY_PORT=$((PRIV_PORT + 1))
SIP_PORT=$((PRIV_PORT + 2))
PROXY_PID=""

stop_proxy() {
    [ -n "${PROXY_PID}" ] || return 0
    kill "${PROXY_PID}" 2>/dev/null || true
    wait "${PROXY_PID}" 2>/dev/null || true
    PROXY_PID=""
}
trap 'stop_opensips; stop_proxy; stop_private_nats; cleanup_workdir' EXIT
start_private_nats "${PRIV_PORT}"

FAILS=0
check() {   # check <label> <expected> <actual>
    if [ "$2" = "$3" ]; then echo "  ok: $1"
    else echo "  FAIL: $1 (expected '$2', got '$3')"; FAILS=$((FAILS + 1)); fi
}

start_proxy() {   # start_proxy <drop_n>
    rm -f "${WORK}/proxy.ready"
    python3 -I "${PROXY}" "${PROXY_PORT}" "${PRIV_PORT}" "$1" "${WORK}/proxy.ready" \
        > "${WORK}/proxy.out" 2>&1 &
    PROXY_PID=$!
    local i
    for i in $(seq 1 50); do
        [ -f "${WORK}/proxy.ready" ] && return 0
        sleep 0.1
    done
    fail "ack-drop proxy did not start: $(cat "${WORK}/proxy.out")"
}

add_stream() {   # add_stream <name> <subject>
    nats --server "${PRIVATE_NATS_URL}" stream add "$1" \
        --subjects "$2" --storage memory --replicas 1 \
        --retention limits --discard old --max-msgs=-1 \
        --max-msgs-per-subject=-1 --max-bytes=-1 --max-age=10m \
        --max-msg-size=-1 --dupe-window=2m --no-allow-rollup \
        --no-deny-delete --no-deny-purge --defaults >/dev/null 2>&1 \
        || fail "cannot create stream $1"
}

stream_msgs() {
    nats --server "${PRIVATE_NATS_URL}" stream info "$1" --json 2>/dev/null \
        | jq -r '.state.messages'
}

stat() {   # stat <field>
    mi_call nats_stats | jq -r ".result.$1"
}

write_cfg() {   # write_cfg <subject> <retries>
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
loadmodule "proto_udp.so"
loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "${OPS_FIFO}")

loadmodule "event_nats.so"
modparam("event_nats", "nats_url", "nats://127.0.0.1:${PROXY_PORT}")
modparam("event_nats", "jetstream", 1)
modparam("event_nats", "js_ack_timeout_ms", 500)
modparam("event_nats", "js_publish_retries", $2)
modparam("event_nats", "reconnect_wait", 200)

route {
    if (nats_publish("$1", "{\"n\":1}"))
        xlog("L_NOTICE", "[e22] publish ok\n");
    else
        xlog("L_NOTICE", "[e22] publish fail\n");
    sl_send_reply(200, "ok");
    exit;
}
EOF
}

send_options() {
    printf 'OPTIONS sip:t@127.0.0.1:%s SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:9;branch=z9hG4bK-e22-%s\r\nFrom: <sip:h@127.0.0.1>;tag=1\r\nTo: <sip:t@127.0.0.1>\r\nCall-ID: e22-%s@127.0.0.1\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n' \
        "${SIP_PORT}" "${RANDOM}" "${RANDOM}" \
        | timeout 3 nc -u -w1 127.0.0.1 "${SIP_PORT}" >/dev/null 2>&1 || true
}

# Boot, publish once, wait until the message has a final ack outcome
# (js_ack_ok + js_ack_failed == 1), then check the counters and stream.
scenario() {   # scenario <label> <drop_n> <retries> <stream> <subject>
    local label=$1 drop=$2 retries=$3 stream=$4 subj=$5
    echo "--- ${label} ---"
    add_stream "${stream}" "${subj}"
    start_proxy "${drop}"
    write_cfg "${subj}" "${retries}"
    rm -f "${OPS_FIFO}"   # start_opensips waits for the FIFO to appear
    start_opensips "${WORK}/test.cfg"
    wait_for_log "NATS pool: connected to" 10 || fail "opensips did not connect; log:\n$(tail -20 "${OPS_LOG}")"
    wait_for_log "JetStream context created" 10 || fail "no JetStream context; log:\n$(tail -20 "${OPS_LOG}")"
    send_options
    wait_for_log "\\[e22\\] publish (ok|fail)" 5 || fail "route did not run"
    log_contains "\\[e22\\] publish ok" || fail "nats_publish returned failure"

    local i done=0
    for i in $(seq 1 100); do
        done=$(( $(stat js_ack_ok) + $(stat js_ack_failed) ))
        [ "${done}" -ge 1 ] && break
        sleep 0.1
    done
    sleep 1   # a resend still in flight would show up here
    S_OK=$(stat js_ack_ok); S_FAILED=$(stat js_ack_failed)
    S_RETRIED=$(stat js_retried); S_DUP=$(stat js_duplicate)
    S_MSGS=$(stream_msgs "${stream}")
    S_DROPPED=$(grep -c '^dropped ack' "${WORK}/proxy.out")
    stop_opensips
    stop_proxy
}

scenario "first ack lost, 3 retries" 1 3 E22A e22.a
check "the proxy dropped one ack" 1 "${S_DROPPED}"
check "stream holds exactly one copy" 1 "${S_MSGS}"
check "js_retried" 1 "${S_RETRIED}"
check "js_duplicate (the resend was a duplicate)" 1 "${S_DUP}"
check "js_ack_ok" 1 "${S_OK}"
check "js_ack_failed" 0 "${S_FAILED}"

scenario "every ack lost, 3 retries" 1000 3 E22B e22.b
check "the proxy dropped four acks (first publish + 3 resends)" 4 "${S_DROPPED}"
check "stream holds exactly one copy" 1 "${S_MSGS}"
check "js_retried" 3 "${S_RETRIED}"
check "js_ack_failed (retries used up)" 1 "${S_FAILED}"
check "js_ack_ok" 0 "${S_OK}"

scenario "first ack lost, js_publish_retries=0" 1 0 E22C e22.c
check "the proxy dropped one ack" 1 "${S_DROPPED}"
check "stream holds exactly one copy" 1 "${S_MSGS}"
check "js_retried" 0 "${S_RETRIED}"
check "js_ack_failed (no retry)" 1 "${S_FAILED}"

[ "${FAILS}" -eq 0 ] || fail "${FAILS} check(s) failed"
pass "a lost ack is resent with the same message id, bounded by js_publish_retries"
