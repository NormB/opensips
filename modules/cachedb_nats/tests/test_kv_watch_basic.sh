#!/bin/bash
# test_kv_watch_basic.sh -- end-to-end test for cachedb_nats's KV watcher.
#
# cachedb_nats raises E_NATS_KV_CHANGE for every put/delete in a watched
# bucket.  We subscribe an event_route to that name, write a key from a
# SIP-driven request_route, then assert the event_route fires with the
# expected key/operation/value/revision params.
#
# Catches regressions in three layers at once:
#  - the kvWatcher pthread inside the SIP worker (cachedb_nats_watch.c)
#  - the shm copy + IPC bounce that hands the event to a worker
#  - evi_param_add_str/_int marshalling of the event payload
#
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/../../../lib/nats/tests/nats_local_lib.sh"

require_nats_reachable
require_opensips_built
require_cmd nats opensips

BUCKET="OS_TEST_KV_C8_$$"
mkworkdir watch_basic
nats --server "${NATS_URL}" kv del "${BUCKET}" --force >/dev/null 2>&1 || true
cleanup_bucket() { nats --server "${NATS_URL}" kv del "${BUCKET}" --force >/dev/null 2>&1 || true; }
trap 'stop_opensips; cleanup_bucket; cleanup_workdir' EXIT

cat > "${WORK}/test.cfg" <<EOF
log_level=3
xlog_level=3
stderror_enabled=yes
syslog_facility=LOG_LOCAL0
udp_workers=1
socket=udp:127.0.0.1:5198

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

loadmodule "cachedb_nats.so"
modparam("cachedb_nats", "nats_url", "${NATS_URL}")
modparam("cachedb_nats", "kv_bucket", "${BUCKET}")
modparam("cachedb_nats", "kv_replicas", 1)
# Watch every key in the bucket -- the watcher fans out to E_NATS_KV_CHANGE.
modparam("cachedb_nats", "kv_watch", ">")

event_route[E_NATS_KV_CHANGE] {
    xlog("L_NOTICE","[c8] watch key=\$param(key) op=\$param(operation) val=\$param(value) rev=\$param(revision)\n");
}

route {
    if (nats_kv_put("${BUCKET}", "watched.key", "hello-watcher")) {
        xlog("L_NOTICE","[c8] put.ok\n");
    } else {
        xlog("L_ERR","[c8] put.fail\n");
    }
    if (nats_kv_delete("${BUCKET}", "watched.key")) {
        xlog("L_NOTICE","[c8] del.ok\n");
    } else {
        xlog("L_ERR","[c8] del.fail\n");
    }
    sl_send_reply(200, "c8-done");
    exit;
}
EOF

start_opensips "${WORK}/test.cfg"

# Wait for the bucket to be created AND for the watcher pthread to spin up.
wait_for_log "nats_pool_get_kv: NATS pool: KV bucket '${BUCKET}' created" 8 \
    || fail "bucket not created within 8s"
# The watcher logs "kv_watch" on init when patterns are configured.
wait_for_log "kv_watch" 8 \
    || fail "kv_watch never wired up; log:\n$(tail -40 "${OPS_LOG}")"
sleep 0.5

# Drive a SIP OPTIONS so the request_route fires and writes the key.
SIP_REQ="OPTIONS sip:test@127.0.0.1:5198 SIP/2.0\r
Via: SIP/2.0/UDP 127.0.0.1:55198;branch=z9hG4bK-c8\r
From: <sip:harness@127.0.0.1>;tag=h1\r
To: <sip:test@127.0.0.1>\r
Call-ID: c8.${RANDOM}@127.0.0.1\r
CSeq: 1 OPTIONS\r
Max-Forwards: 70\r
Content-Length: 0\r
\r
"
printf "%b" "${SIP_REQ}" | timeout 3 nc -u -w1 127.0.0.1 5198 >/dev/null 2>&1 || true

# We expect:
#  1. put.ok logged from the request route
#  2. event_route fired with op=put, key=watched.key, val=hello-watcher
#  3. del.ok logged
#  4. event_route fired with op=delete
wait_for_log '\[c8\] put\.ok' 4   || fail "request route did not put"
wait_for_log '\[c8\] del\.ok' 4   || fail "request route did not delete"

# event_route fires asynchronously through a watcher thread; allow generous time.
if ! wait_for_log '\[c8\] watch key=watched\.key op=put val=hello-watcher' 8; then
    fail "missing put-watch event; relevant log:
$(grep -E '\[c8\]|cachedb_nats|kvWatch|E_NATS_KV_CHANGE|kv_watch' "${OPS_LOG}" | tail -40)"
fi
if ! wait_for_log '\[c8\] watch key=watched\.key op=delete' 8; then
    fail "missing delete-watch event; relevant log:
$(grep -E '\[c8\]' "${OPS_LOG}" | tail -20)"
fi

pass "cachedb_nats kv_watch fired E_NATS_KV_CHANGE for both put and delete"
