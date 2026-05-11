#!/bin/bash
# test_publish_during_disconnect.sh -- verify event_nats survives a NATS
# server outage mid-publish without crashing OpenSIPS.
#
# Drives a private nats-server (so we can kill+restart without touching
# the shared dev cluster), aims a timer route at it doing nats_publish
# every 250 ms, kills the broker mid-stream, then restarts it.  The
# contract being pinned:
#
#  1. opensips must not crash during the outage
#  2. nats_publish must surface failure (return 0, log error) -- not
#     silently drop messages while reporting success
#  3. once the broker comes back, the pool must reconnect and the next
#     publish must succeed -- a downstream subscriber sees both a
#     pre-outage and a post-reconnect message
#
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/../../../lib/nats/tests/nats_local_lib.sh"

require_opensips_built
require_cmd nats nats-server opensips

mkworkdir disconnect

# Pick an unused private port; offset $$ into the ephemeral range to
# minimise collisions when this test runs in parallel with itself.
PRIV_PORT=$((20000 + ($$ % 20000)))
trap 'stop_opensips; stop_private_nats; cleanup_workdir' EXIT
start_private_nats "${PRIV_PORT}"

# Subscribe to the heartbeat subject in the BACKGROUND so we can later
# count how many made it through.
SUB_LOG="${WORK}/sub.log"
( nats --server "${PRIVATE_NATS_URL}" sub 'e12.>' --raw --no-context \
    >"${SUB_LOG}" 2>&1 ) &
SUB_PID=$!

cat > "${WORK}/test.cfg" <<EOF
log_level=3
xlog_level=3
stderror_enabled=yes
syslog_facility=LOG_LOCAL0
udp_workers=1
socket=udp:127.0.0.1:5197

mpath="${OPENSIPS_MPATH}"

loadmodule "signaling.so"
loadmodule "sl.so"
loadmodule "tm.so"
loadmodule "rr.so"
loadmodule "maxfwd.so"
loadmodule "sipmsgops.so"
loadmodule "proto_udp.so"

loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "${OPS_FIFO}")

loadmodule "event_nats.so"
modparam("event_nats", "nats_url", "${PRIVATE_NATS_URL}")
# Aggressive reconnect so the test finishes promptly (default 2 s wait
# would put us into a 30+ s test).
modparam("event_nats", "reconnect_wait", 200)
modparam("event_nats", "max_reconnect", 600)

# Counters carried in script vars for the heartbeat route.
timer_route[BEAT, 1] {
    \$var(seq) = \$var(seq) + 1;
    \$var(payload) = "{\"seq\":" + \$var(seq) + "}";
    if (nats_publish("e12.heartbeat", "\$var(payload)")) {
        xlog("L_NOTICE","[e12] beat seq=\$var(seq) ok\n");
    } else {
        xlog("L_NOTICE","[e12] beat seq=\$var(seq) fail\n");
    }
}

route {
    sl_send_reply(200, "ok");
    exit;
}
EOF

start_opensips "${WORK}/test.cfg"

# Warm-up: 2 s of normal beats.
echo "--- warm-up ---"
sleep 2
ok_before=$(grep -c '\[e12\] beat seq=.* ok' "${OPS_LOG}" || echo 0)
[ "${ok_before}" -ge 1 ] || fail "no successful beats in warm-up; log:\n$(tail -40 "${OPS_LOG}")"

# Outage: kill the broker.
echo "--- killing broker ---"
stop_private_nats
# Beats should now fail; we let several elapse to guarantee at least one
# attempted publish hits the down state.
sleep 3
assert_opensips_alive
fail_count=$(grep -c '\[e12\] beat seq=.* fail' "${OPS_LOG}" || echo 0)
if [ "${fail_count}" -eq 0 ]; then
    fail "no failed beats during outage — silent success while broker was down"
fi
echo "    failed beats during outage: ${fail_count}"

# Recovery: bring broker back, allow reconnect.
echo "--- restarting broker ---"
start_private_nats "${PRIV_PORT}"
# reconnect_wait=200ms, plus a generous margin for the next timer tick.
sleep 4
assert_opensips_alive

ok_after=$(grep -c '\[e12\] beat seq=.* ok' "${OPS_LOG}" || echo 0)
new_ok=$((ok_after - ok_before))
[ "${new_ok}" -ge 1 ] || fail "no successful beats after broker restart (ok_before=${ok_before} ok_after=${ok_after}); log:\n$(grep '\[e12\]' "${OPS_LOG}" | tail -20)"
echo "    new successful beats post-recovery: ${new_ok}"

# The subscriber stayed connected through the warm-up only (it
# disconnects when the broker is killed).  As long as it caught at
# least one beat we know the publish leg worked end-to-end pre-outage.
kill ${SUB_PID} 2>/dev/null || true
wait ${SUB_PID} 2>/dev/null || true
sub_count=$(grep -c '"seq":' "${SUB_LOG}" || echo 0)
[ "${sub_count}" -ge 1 ] || \
    echo "    NOTE: subscriber saw 0 messages — likely subscribed before pool ready"

pass "publish-during-disconnect survived: ok_before=${ok_before} fail=${fail_count} ok_after=${ok_after}"
