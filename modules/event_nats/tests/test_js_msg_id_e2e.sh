#!/bin/bash
# test_js_msg_id_e2e.sh -- every JetStream publish of event_nats carries a
# Nats-Msg-Id, so the server stores a repeated publish once.
#
# A private nats-server with JetStream and three streams (2 minute
# duplicate window).  One opensips (jetstream=1) with the rule
#   modparam("event_nats", "msg_id", "E_E21: call, state")
# and event E_E21 subscribed to nats:e21.evt.  Each SIP OPTIONS runs one
# step, named by its Subject header:
#
#   evt-same     E_E21 call=c1 state=ringing, raised twice  -> stored once,
#                with Nats-Msg-Id "E_E21:c1:ringing"
#   evt-other    E_E21 call=c1 state=answered                -> stored
#   evt-missing  E_E21 without "state", raised twice         -> stored twice
#                (generated ids), a warning names the event
#   scr-id       nats_publish(..., "fixed-1") twice, then "fixed-2"
#                                                            -> stored twice
#   scr-gen      nats_publish() without an id, twice         -> stored twice,
#                ids "<16 hex>-<seq>", different
#   scr-bad      nats_publish(..., "a b")                    -> returns -1
#
# Skips (exit 77) without nats-server, the nats CLI, jq or a built opensips.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/../../../lib/nats/tests/nats_local_lib.sh"

require_opensips_built
require_cmd nats nats-server jq nc base64

mkworkdir js_msg_id >/dev/null
PRIV_PORT=$((21000 + ($$ % 15000)))
SIP_PORT=$((PRIV_PORT + 2))
trap 'stop_opensips; stop_private_nats; cleanup_workdir' EXIT
start_private_nats "${PRIV_PORT}"

FAILS=0
check() {   # check <label> <expected> <actual>
    if [ "$2" = "$3" ]; then echo "  ok: $1"
    else echo "  FAIL: $1 (expected '$2', got '$3')"; FAILS=$((FAILS + 1)); fi
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
# the Nats-Msg-Id header of message <seq> of stream <name>
msg_id_of() {   # msg_id_of <name> <seq>
    nats --server "${PRIVATE_NATS_URL}" stream get "$1" "$2" --json 2>/dev/null \
        | jq -r '.hdrs // empty' | base64 -d 2>/dev/null \
        | tr -d '\r' | sed -n 's/^Nats-Msg-Id: //p'
}
stat() { mi_call nats_stats | jq -r ".result.$1"; }

add_stream E21EVT e21.evt
add_stream E21SCR e21.scr
add_stream E21GEN e21.gen

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
modparam("event_nats", "nats_url", "${PRIVATE_NATS_URL}")
modparam("event_nats", "jetstream", 1)
modparam("event_nats", "msg_id", "E_E21: call, state")

startup_route {
    subscribe_event("E_E21", "nats:e21.evt");
}

route[E21] {
    \$avp(e21n) = "call";
    \$avp(e21v) = "c1";
    if (\$var(state) != "") {
        \$avp(e21n) = "state";
        \$avp(e21v) = \$var(state);
    }
    raise_event("E_E21", \$avp(e21n), \$avp(e21v));
    \$(avp(e21n)[*]) = NULL;
    \$(avp(e21v)[*]) = NULL;
}

route {
    \$var(step) = \$hdr(Subject);
    \$var(state) = "";
    if (\$var(step) == "evt-same") {
        \$var(state) = "ringing";
        route(E21);
        route(E21);
    } else if (\$var(step) == "evt-other") {
        \$var(state) = "answered";
        route(E21);
    } else if (\$var(step) == "evt-missing") {
        route(E21);
        route(E21);
    } else if (\$var(step) == "scr-id") {
        nats_publish("e21.scr", "{\"n\":1}", "fixed-1");
        nats_publish("e21.scr", "{\"n\":2}", "fixed-1");
        nats_publish("e21.scr", "{\"n\":3}", "fixed-2");
    } else if (\$var(step) == "scr-gen") {
        nats_publish("e21.gen", "{\"n\":1}");
        nats_publish("e21.gen", "{\"n\":1}");
    } else if (\$var(step) == "scr-bad") {
        if (nats_publish("e21.scr", "{\"n\":9}", "a b"))
            xlog("L_NOTICE", "[e21] scr-bad accepted\n");
        else
            xlog("L_NOTICE", "[e21] scr-bad refused\n");
    }
    xlog("L_NOTICE", "[e21] step \$var(step) done\n");
    sl_send_reply(200, "ok");
    exit;
}
EOF

start_opensips "${WORK}/test.cfg"
wait_for_log "NATS pool: connected to" 10 || fail "opensips did not connect; log:\n$(tail -20 "${OPS_LOG}")"
wait_for_log "JetStream context created" 10 || fail "no JetStream context"

step() {   # step <name>: one OPTIONS, wait for the route to finish
    printf 'OPTIONS sip:t@127.0.0.1:%s SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:9;branch=z9hG4bK-e21-%s\r\nFrom: <sip:h@127.0.0.1>;tag=1\r\nTo: <sip:t@127.0.0.1>\r\nCall-ID: e21-%s@127.0.0.1\r\nCSeq: 1 OPTIONS\r\nSubject: %s\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n' \
        "${SIP_PORT}" "$1" "$1" "$1" \
        | timeout 3 nc -u -w1 127.0.0.1 "${SIP_PORT}" >/dev/null 2>&1 || true
    wait_for_log "\\[e21\\] step $1 done" 5 || fail "step $1 did not run; log:\n$(tail -20 "${OPS_LOG}")"
}

for s in evt-same evt-other evt-missing scr-id scr-gen scr-bad; do
    step "$s"
done

# every publish above gets its ack: 2 + 1 + 2 + 3 + 2 = 10
acked=0
for i in $(seq 1 50); do
    acked=$(stat js_ack_ok)
    [ "${acked}" -ge 10 ] && break
    sleep 0.1
done

echo "--- EVI events with a msg_id rule ---"
check "E21EVT: the twice-raised event once, the other state, two without the rule parameter" \
    4 "$(stream_msgs E21EVT)"
check "Nats-Msg-Id of the first event built from call and state" \
    "E_E21:c1:ringing" "$(msg_id_of E21EVT 1)"
check "Nats-Msg-Id of the second state" "E_E21:c1:answered" "$(msg_id_of E21EVT 2)"
g1=$(msg_id_of E21EVT 3); g2=$(msg_id_of E21EVT 4)
check "an event lacking a rule parameter gets a generated id" yes \
    "$(echo "${g1}" | grep -qE '^[0-9a-f]{16}-[0-9]+$' && echo yes || echo "no (${g1})")"
check "...a different one each time" yes "$([ -n "${g1}" ] && [ "${g1}" != "${g2}" ] && echo yes || echo no)"
check "the warning names the event" yes \
    "$(log_contains 'msg_id of E_E21: the event lacks a parameter' && echo yes || echo no)"

echo "--- nats_publish() ids ---"
check "E21SCR: fixed-1 once, fixed-2 once" 2 "$(stream_msgs E21SCR)"
check "Nats-Msg-Id given by the script" "fixed-1" "$(msg_id_of E21SCR 1)"
check "E21GEN: two publishes without an id, two messages" 2 "$(stream_msgs E21GEN)"
g1=$(msg_id_of E21GEN 1); g2=$(msg_id_of E21GEN 2)
check "generated ids are <16 hex>-<seq> and differ" yes \
    "$(echo "${g1}" | grep -qE '^[0-9a-f]{16}-[0-9]+$' && [ "${g1}" != "${g2}" ] && echo yes || echo "no (${g1} ${g2})")"
check "an id with a space is refused" yes \
    "$(log_contains '\[e21\] scr-bad refused' && log_contains 'msg_id must be' && echo yes || echo no)"

echo "--- counters ---"
check "js_duplicate: the repeated event and the repeated fixed-1" 2 "$(stat js_duplicate)"
check "js_ack_ok: every publish acked (duplicates included)" 10 "$(stat js_ack_ok)"
check "js_ack_failed" 0 "$(stat js_ack_failed)"
check "js_retried" 0 "$(stat js_retried)"

assert_opensips_alive
[ "${FAILS}" -eq 0 ] || fail "${FAILS} check(s) failed; log:\n$(grep -E 'e21|msg_id|ERROR' "${OPS_LOG}" | tail -20)"
pass "JetStream publishes carry a Nats-Msg-Id; repeats are stored once"
