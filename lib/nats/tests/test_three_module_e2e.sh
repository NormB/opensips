#!/bin/bash
# test_three_module_e2e.sh -- end-to-end test that all three NATS
# modules cooperate inside a single opensips, sharing the lib/nats
# connection pool.
#
# Owned by lib/nats/tests because the property under test is "the
# shared pool delivers one logical NATS connection to N modules".
# This is the regression that motivated turning lib/nats from a static
# .a into libnats_pool.so in the first place — three modules each with
# their own copy of the pool state was the original bug.
#
# Verifies:
#   1. cachedb_nats, event_nats, and nats_consumer all load + register
#      against the same pool (first registrant wins, others piggy-back).
#   2. From a single SIP-driven request_route we exercise
#        cachedb_nats: nats_kv_put + nats_kv_get round-trip
#        event_nats : nats_publish to a fan-out subject
#      And in parallel, the nats_consumer worker picks up a JetStream
#      message that was published from outside.
#   3. An external NATS subscriber receives the event_nats publish.
#
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/nats_local_lib.sh"

require_nats_reachable
require_opensips_built
require_cmd nats opensips

STREAM="X8_INBOX_$$"
BUCKET="X8_KV_$$"
mkworkdir three_mod

cleanup_resources() {
    nats --server "${NATS_URL}" kv del "${BUCKET}" --force >/dev/null 2>&1 || true
    nats --server "${NATS_URL}" stream rm "${STREAM}" --force >/dev/null 2>&1 || true
}
trap 'stop_opensips; cleanup_resources; cleanup_workdir' EXIT
cleanup_resources  # belt+braces

# Pre-create the JetStream stream that nats_consumer will bind against.
nats --server "${NATS_URL}" stream add "${STREAM}" \
    --subjects "x8.in.>" --storage memory --replicas 1 \
    --retention limits --discard old --max-msgs=-1 \
    --max-msgs-per-subject=-1 --max-bytes=-1 --max-age=10m \
    --max-msg-size=-1 --dupe-window=2m --no-allow-rollup \
    --no-deny-delete --no-deny-purge --defaults >/dev/null 2>&1 \
    || fail "failed to create test stream ${STREAM}"

# Subscribe to the event_nats fan-out subject from outside opensips.
SUB_LOG="${WORK}/sub.log"
( nats --server "${NATS_URL}" sub 'x8.event.>' --raw --no-context \
    >"${SUB_LOG}" 2>&1 ) &
SUB_PID=$!

cat > "${WORK}/test.cfg" <<EOF
log_level=3
xlog_level=3
stderror_enabled=yes
syslog_facility=LOG_LOCAL0
udp_workers=1
socket=udp:127.0.0.1:5195

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
modparam("event_nats", "nats_url", "${NATS_URL}")

loadmodule "cachedb_nats.so"
modparam("cachedb_nats", "nats_url", "${NATS_URL}")
modparam("cachedb_nats", "kv_bucket", "${BUCKET}")
modparam("cachedb_nats", "kv_replicas", 1)

loadmodule "nats_consumer.so"
modparam("nats_consumer", "persist_handles", 0)

# Background fetch loop: poll the consumer ring for any pending
# message every 500 ms and log what we got.
timer_route[X8_PUMP, 1] {
    if (nats_fetch("ib", 200)) {
        xlog("L_NOTICE","[x8] consume subj=\$nats_subject data=\$nats_data\n");
        nats_ack();
    }
}

route {
    \$var(v) = "";
    \$var(rev) = 0;

    # cachedb_nats round-trip
    if (nats_kv_put("${BUCKET}", "x8.k", "x8.v")) {
        xlog("L_NOTICE","[x8] cdb.put=ok\n");
    } else {
        xlog("L_ERR","[x8] cdb.put=fail\n");
    }
    if (nats_kv_get("${BUCKET}", "x8.k", \$var(v), \$var(rev))) {
        if (\$var(v) == "x8.v") {
            xlog("L_NOTICE","[x8] cdb.get=ok rev=\$var(rev)\n");
        } else {
            xlog("L_ERR","[x8] cdb.get=mismatch v=\$var(v)\n");
        }
    } else {
        xlog("L_ERR","[x8] cdb.get=fail\n");
    }

    # event_nats fan-out
    if (nats_publish("x8.event.from-route", "{\"hi\":\"three-mods\"}")) {
        xlog("L_NOTICE","[x8] evt.publish=ok\n");
    } else {
        xlog("L_ERR","[x8] evt.publish=fail\n");
    }

    sl_send_reply(200, "x8-done");
    exit;
}
EOF

start_opensips "${WORK}/test.cfg"

# Wait for ALL THREE modules to register against the shared pool.
# Whichever module loads first is the registrant; the other two log
# "NATS pool: connected" with the original registrant's URL/TLS.
wait_for_log "nats_pool_register: NATS pool: registered by"           5  || fail "pool not registered"
wait_for_log "NATS pool: KV bucket '${BUCKET}' created"               8  || fail "cachedb_nats not ready"
wait_for_log "nats_consumer_proc: pool ready"                          5  || fail "nats_consumer not ready"
wait_for_log "evi_publish_event: Registered event <E_NATS_KV_CHANGE"   3  || fail "event registration not seen"
sleep 0.5

# Bind the consumer handle.
mi_resp=$(mi_call nats_consumer_bind \
    "{\"config\":\"id=ib;stream=${STREAM};durable=ibd;filter=x8.in.test;ack_wait=30s\"}")
echo "    bind reply: ${mi_resp}"
echo "${mi_resp}" | grep -q '"result":"OK"' \
    || fail "consumer_bind did not return OK; reply was: ${mi_resp}"

# Inject a JetStream message that the consumer should pick up.
nats --server "${NATS_URL}" pub "x8.in.test" '{"src":"external"}' >/dev/null 2>&1 \
    || fail "could not publish to ${STREAM}"

# Drive a SIP OPTIONS to trigger the request_route.
SIP_REQ="OPTIONS sip:test@127.0.0.1:5195 SIP/2.0\r
Via: SIP/2.0/UDP 127.0.0.1:55195;branch=z9hG4bK-x8\r
From: <sip:harness@127.0.0.1>;tag=h1\r
To: <sip:test@127.0.0.1>\r
Call-ID: x8.${RANDOM}@127.0.0.1\r
CSeq: 1 OPTIONS\r
Max-Forwards: 70\r
Content-Length: 0\r
\r
"
printf "%b" "${SIP_REQ}" | timeout 3 nc -u -w1 127.0.0.1 5195 >/dev/null 2>&1 || true

# All three modules' markers should appear within 6 s.
ok=0
for m in 'cdb\.put=ok' 'cdb\.get=ok' 'evt\.publish=ok' 'consume subj=x8\.in\.test'; do
    if wait_for_log "\\[x8\\] ${m}" 8; then
        echo "  ok: ${m}"
        ok=$((ok+1))
    else
        echo "  MISSING: ${m}"
    fi
done

# Stop the external subscriber and check it caught the fan-out publish.
kill ${SUB_PID} 2>/dev/null || true
wait ${SUB_PID} 2>/dev/null || true
sub_count=$(grep -c "three-mods" "${SUB_LOG}" || echo 0)
[ "${sub_count}" -ge 1 ] || fail "external subscriber missed event_nats publish"
echo "    external subscriber caught: ${sub_count} message(s)"

# Confirm the shared pool: only ONE registrant line in the log.
reg_count=$(grep -c "nats_pool_register: NATS pool: registered by" "${OPS_LOG}" || echo 0)
[ "${reg_count}" = "1" ] || fail "expected exactly 1 pool registrant, saw ${reg_count}"

# P0.3 single-owner MI: with all three modules co-loaded, the JS
# observability commands must be registered exactly once (cachedb_nats
# owns them) and must respond over MI; the log must show no duplicate
# MI registration.
mi_resp=$(mi_call nats_stream_list)
echo "${mi_resp}" | grep -q '"jsonrpc"'     || fail "nats_stream_list MI did not respond; reply: ${mi_resp}"
echo "${mi_resp}" | grep -qi '"error"'     && fail "nats_stream_list MI errored; reply: ${mi_resp}"
echo "  ok: MI nats_stream_list responds (single owner)"

mi_resp=$(mi_call nats_stream_info "{\"stream\":\"${STREAM}\"}")
echo "${mi_resp}" | grep -q "${STREAM}"     || fail "nats_stream_info did not return stream ${STREAM}; reply: ${mi_resp}"
echo "  ok: MI nats_stream_info responds (single owner)"

if grep -qiE "already registered|command .* registered twice" "${OPS_LOG}"; then
    fail "duplicate MI registration found in log:
$(grep -iE 'already registered|registered twice' "${OPS_LOG}")"
fi
echo "  ok: no duplicate-MI-registration errors in log"

[ "${ok}" = "4" ] || fail "only ${ok}/4 module markers passed; relevant log:
$(grep -E '\[x8\]|nats_pool|nats_consumer|cachedb_nats:' "${OPS_LOG}" | tail -40)"

pass "three-module e2e (cachedb+event+consumer) green; shared pool single-registrant; MI single-owner; external sub saw publish"
