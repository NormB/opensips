#!/bin/bash
# test_publish_during_disconnect.sh -- what event_nats publishes while the
# NATS server restarts reaches the server after the reconnect; once the
# reconnect buffer is full, every publish it refuses is counted.
#
# A private nats-server with a file-backed JetStream stream capturing
# e12.> (it survives the restart).  A timer route publishes 5 messages a
# second with nats_publish().  The broker is stopped for 3 seconds and
# started again, then opensips is stopped (its shutdown drain flushes
# what is left) and the stream is compared with the log.  Contract:
#
#  1. core publish (jetstream=0), default reconnect_buf_size: no publish
#     fails during the outage; the stream holds every published message,
#     once; failed = reconnect_buf_dropped = 0.
#  2. the same with jetstream=1 (async publish with message ids).
#  3. reconnect_buf_size=300: the buffer takes the first messages of the
#     outage and refuses the rest; nats_publish returns -1 for each
#     refused one, and failed = reconnect_buf_dropped = the number of
#     refusals in the log; the stream holds exactly the accepted ones.
#  4. opensips never crashes.
#
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/../../../lib/nats/tests/nats_local_lib.sh"

require_opensips_built
require_cmd nats nats-server jq

mkworkdir disconnect >/dev/null

# Pick an unused private port; offset $$ into the ephemeral range to
# minimise collisions when this test runs in parallel with itself.
PRIV_PORT=$((20000 + ($$ % 20000)))
trap 'stop_opensips; stop_private_nats; cleanup_workdir' EXIT
start_private_nats "${PRIV_PORT}"

FAILS=0
check() {   # check <label> <expected> <actual>
    if [ "$2" = "$3" ]; then echo "  ok: $1"
    else echo "  FAIL: $1 (expected '$2', got '$3')"; FAILS=$((FAILS + 1)); fi
}
stat() { mi_call nats_stats | jq -r ".result.$1"; }
stream_msgs() {
    nats --server "${PRIVATE_NATS_URL}" stream info "$1" --json 2>/dev/null \
        | jq -r '.state.messages'
}
add_stream() {   # add_stream <name> <subject>: file storage, kept across restarts
    nats --server "${PRIVATE_NATS_URL}" stream add "$1" \
        --subjects "$2" --storage file --replicas 1 \
        --retention limits --discard old --max-msgs=-1 \
        --max-msgs-per-subject=-1 --max-bytes=-1 --max-age=10m \
        --max-msg-size=-1 --dupe-window=2m --no-allow-rollup \
        --no-deny-delete --no-deny-purge --defaults >/dev/null 2>&1 \
        || fail "cannot create stream $1"
}

write_cfg() {   # write_cfg <subject> <jetstream> [reconnect_buf_size]
    local bufparam=""
    [ -n "${3:-}" ] && bufparam="modparam(\"event_nats\", \"reconnect_buf_size\", $3)"
    cat > "${WORK}/test.cfg" <<EOF
log_level=3
xlog_level=3
stderror_enabled=yes
syslog_facility=LOG_LOCAL0
udp_workers=1
socket=udp:127.0.0.1:$((PRIV_PORT + 3))

mpath="${OPENSIPS_MPATH}"

loadmodule "signaling.so"
loadmodule "sl.so"
loadmodule "proto_udp.so"
loadmodule "cfgutils.so"   # \$shv
loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "${OPS_FIFO}")

loadmodule "event_nats.so"
modparam("event_nats", "nats_url", "${PRIVATE_NATS_URL}")
modparam("event_nats", "jetstream", $2)
# Aggressive reconnect so the test finishes promptly.
modparam("event_nats", "reconnect_wait", 200)
modparam("event_nats", "max_reconnect", 600)
${bufparam}

# 5 messages a second, ~100 bytes each, numbered.
timer_route[BEAT, 1] {
    \$var(i) = 0;
    while (\$var(i) < 5) {
        \$var(seq) = \$shv(seq) + 1;
        \$shv(seq) = \$var(seq);
        \$var(payload) = "{\"seq\":" + \$var(seq) + ",\"pad\":\"0123456789012345678901234567890123456789012345678901234567890123456789\"}";
        if (nats_publish("$1", "\$var(payload)"))
            xlog("L_NOTICE","[e12] beat seq=\$var(seq) ok\n");
        else
            xlog("L_NOTICE","[e12] beat seq=\$var(seq) fail\n");
        \$var(i) = \$var(i) + 1;
    }
}

route {
    sl_send_reply(200, "ok");
    exit;
}
EOF
}

# Boot, 2 s of publishing, a 3 s outage, 3 s after the restart, then
# read the counters, stop opensips and count the stream.
run_phase() {   # run_phase <label> <stream> <subject> <jetstream> [bufsize]
    echo "--- $1 ---"
    add_stream "$2" "$3"
    write_cfg "$3" "$4" "${5:-}"
    rm -f "${OPS_FIFO}"
    start_opensips "${WORK}/test.cfg"
    wait_for_log "NATS pool: connected to" 10 || fail "opensips did not connect; log:\n$(tail -20 "${OPS_LOG}")"
    sleep 2
    grep -q '\[e12\] beat seq=.* ok' "${OPS_LOG}" || fail "no successful beats in warm-up; log:\n$(tail -40 "${OPS_LOG}")"

    local from to
    stop_private_nats
    from=$(wc -l < "${OPS_LOG}")
    sleep 3
    assert_opensips_alive
    to=$(wc -l < "${OPS_LOG}")
    # what the route logged while the broker was down
    P_OUTAGE_OK=$(sed -n "$((from + 1)),${to}p" "${OPS_LOG}" | grep -c '\[e12\] beat seq=.* ok')
    P_OUTAGE_FAIL=$(sed -n "$((from + 1)),${to}p" "${OPS_LOG}" | grep -c '\[e12\] beat seq=.* fail')

    start_private_nats "${PRIV_PORT}"
    wait_for_log "NATS pool: reconnected to" 10 || fail "no reconnect; log:\n$(tail -20 "${OPS_LOG}")"
    sleep 3
    assert_opensips_alive
    P_FAILED=$(stat failed)
    P_DROPPED=$(stat reconnect_buf_dropped)
    stop_opensips
    P_OK=$(grep -c '\[e12\] beat seq=.* ok' "${OPS_LOG}")
    P_FAIL=$(grep -c '\[e12\] beat seq=.* fail' "${OPS_LOG}")
    sleep 0.5
    P_STREAM=$(stream_msgs "$2")
    echo "    published ok=${P_OK} refused=${P_FAIL} (during the outage: ok=${P_OUTAGE_OK} refused=${P_OUTAGE_FAIL}) stream=${P_STREAM}"
}

run_phase "core publish, default buffer" E12CORE e12.core 0
check "publishes during the outage succeed (buffered)" yes \
    "$([ "${P_OUTAGE_OK}" -ge 5 ] && echo yes || echo "no (${P_OUTAGE_OK})")"
check "no publish refused" 0 "${P_FAIL}"
check "failed" 0 "${P_FAILED}"
check "reconnect_buf_dropped" 0 "${P_DROPPED}"
check "the stream holds every published message, once" "${P_OK}" "${P_STREAM}"

run_phase "JetStream publish, default buffer" E12JS e12.js 1
check "publishes during the outage succeed (buffered)" yes \
    "$([ "${P_OUTAGE_OK}" -ge 5 ] && echo yes || echo "no (${P_OUTAGE_OK})")"
check "no publish refused" 0 "${P_FAIL}"
check "failed" 0 "${P_FAILED}"
check "reconnect_buf_dropped" 0 "${P_DROPPED}"
check "the stream holds every published message, once" "${P_OK}" "${P_STREAM}"

run_phase "core publish, reconnect_buf_size=300" E12BUF e12.buf 0 300
# How many fit is timing-dependent: libnats also moves what was written
# before it noticed the disconnect into the buffer.  The counts below are
# exact.
check "the buffer took publishes of the outage" yes \
    "$([ "${P_OUTAGE_OK}" -ge 1 ] && echo yes || echo "no (${P_OUTAGE_OK})")"
check "the full buffer refused the rest" yes \
    "$([ "${P_OUTAGE_FAIL}" -ge 1 ] && echo yes || echo "no (${P_OUTAGE_FAIL})")"
check "every refusal is counted in failed" "${P_FAIL}" "${P_FAILED}"
check "every refusal is counted in reconnect_buf_dropped" "${P_FAIL}" "${P_DROPPED}"
check "the stream holds exactly the accepted messages" "${P_OK}" "${P_STREAM}"

[ "${FAILS}" -eq 0 ] || fail "${FAILS} check(s) failed"
pass "publishes during a broker restart reach the server; refusals of a full buffer are counted"
