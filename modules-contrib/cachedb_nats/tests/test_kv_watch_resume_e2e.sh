#!/bin/bash
# test_kv_watch_resume_e2e.sh -- the KV watcher resumes where it stopped.
#
# Changes made while the watcher is disconnected must still raise
# E_NATS_KV_CHANGE once it reconnects, and changes it already delivered
# must not be delivered again.
#
# Against a PRIVATE disposable broker: the broker is SIGKILLed and
# restarted, and keys are written right after the restart, while
# OpenSIPS is still waiting out reconnect_wait (4 s) -- i.e. before the
# watcher can possibly have re-subscribed.  A watcher that re-subscribes
# for "new changes only" never sees them.
#
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/../../nats/tests/nats_local_lib.sh"

require_opensips_built
require_cmd nats
command -v nats-server >/dev/null 2>&1 || skip "nats-server not in PATH (apt: nats-server; often /usr/sbin)"

PORT=4324
PRIV_URL="nats://127.0.0.1:${PORT}"
BUCKET="OS_TEST_RESUME_$$"

mkworkdir watch_resume
JSDIR="${WORK}/jsdir"
mkdir -p "${JSDIR}"

NS_PID=""
start_broker() {
    nats-server -a 127.0.0.1 -p "${PORT}" -js -sd "${JSDIR}" >> "${WORK}/nats.log" 2>&1 &
    NS_PID=$!
    local i
    for i in $(seq 1 100); do
        nats --server "${PRIV_URL}" rtt --timeout 200ms >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    fail "private broker did not come up on :${PORT}"
}
stop_broker_hard() {  # SIGKILL: TCP drop, no clean NATS close
    [ -n "${NS_PID}" ] && kill -9 "${NS_PID}" 2>/dev/null
    wait "${NS_PID}" 2>/dev/null
    NS_PID=""
}
cleanup_all() {
    stop_opensips
    [ -n "${NS_PID}" ] && kill -9 "${NS_PID}" 2>/dev/null
    cleanup_workdir
}
trap cleanup_all EXIT

kv_put() {
    nats --server "${PRIV_URL}" kv put "${BUCKET}" "$1" "$2" >/dev/null 2>&1 \
        || fail "external kv put $1 failed"
}
events_for() { grep -cE "\[watch\] op=[a-z]+ key=$1\$" "${OPS_LOG}"; }

start_broker

cat > "${WORK}/test.cfg" <<EOF
log_level=3
xlog_level=3
stderror_enabled=yes
udp_workers=1
socket=udp:127.0.0.1:5199

mpath="${OPENSIPS_MPATH}"

loadmodule "proto_udp.so"
loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "${OPS_FIFO}")

loadmodule "nats.so"
loadmodule "cachedb_nats.so"
modparam("cachedb_nats", "nats_url", "${PRIV_URL}")
modparam("cachedb_nats", "kv_bucket", "${BUCKET}")
modparam("cachedb_nats", "kv_replicas", 1)
modparam("cachedb_nats", "kv_watch", ">")
modparam("cachedb_nats", "reconnect_wait", 4000)

event_route[E_NATS_KV_CHANGE] {
    xlog("L_NOTICE","[watch] op=\$param(operation) key=\$param(key)\n");
    xlog("L_NOTICE","[watch-value] key=\$param(key) value=\$param(value) rev=\$param(revision)\n");
}

route {
    exit;
}
EOF

start_opensips "${WORK}/test.cfg"
wait_for_log "watcher: watching KV" 15 \
    || fail "watcher did not start; log:
$(tail -30 "${OPS_LOG}")"

checks=0
ok() { echo "  ok: $*"; checks=$((checks+1)); }

# ---------- a change while connected ----------
kv_put before v1
wait_for_log '\[watch\] op=[a-z]+ key=before$' 10 \
    || fail "no E_NATS_KV_CHANGE for a write while connected; log:
$(grep -E 'watch|KV|ERROR' "${OPS_LOG}" | tail -15)"
ok "change while connected raised E_NATS_KV_CHANGE"

# ---------- broker SIGKILLed and restarted ----------
stop_broker_hard
wait_for_log "watcher: disconnect detected|watcher: reconnect detected" 15 \
    || fail "watcher never noticed the broker going away"
start_broker
# OpenSIPS is still inside reconnect_wait: these land before any
# re-subscribe
for k in gap1 gap2 gap3; do kv_put "$k" "v-$k"; done
kv_put gap2 v-gap2-updated
nats --server "${PRIV_URL}" kv del -f "${BUCKET}" gap3 >/dev/null 2>&1 \
    || fail "external kv del gap3 failed"
if log_contains "watcher: watching KV \(.*epoch: [1-9]"; then
    fail "the watcher re-subscribed before the gap writes; the test proves nothing"
fi

wait_for_log "watcher: watching KV \(.*epoch: [1-9]" 30 \
    || fail "watcher did not re-subscribe after the restart; log:
$(grep -E 'watcher|NATS' "${OPS_LOG}" | tail -15)"

for k in gap1 gap2 gap3; do
    wait_for_log "\[watch\] op=[a-z]+ key=${k}\$" 10 \
        || fail "change to ${k} made while disconnected was lost (no E_NATS_KV_CHANGE); log:
$(grep -E 'watch' "${OPS_LOG}" | tail -15)"
done
ok "changes made while disconnected raised E_NATS_KV_CHANGE after the reconnect"
# kv_history=1: the bucket keeps only the newest value of a key, so of
# the two writes to gap2 only the second still exists to be delivered
grep -qE '\[watch-value\] key=gap2 value=v-gap2-updated rev=' "${OPS_LOG}" \
    || fail "gap2 was not delivered with its latest value:
$(grep -E 'key=gap2' "${OPS_LOG}")"
ok "a key changed twice while disconnected is delivered with its latest value"
grep -qE '\[watch\] op=(delete|del|purge)[a-z]* key=gap3$' "${OPS_LOG}" \
    || fail "the delete of gap3 made while disconnected was not delivered:
$(grep -E 'key=gap3' "${OPS_LOG}")"
ok "a delete made while disconnected is delivered"

[ "$(events_for before)" = "1" ] \
    || fail "a change delivered before the outage was delivered again ($(events_for before) events):
$(grep -E "watch" "${OPS_LOG}")"
ok "nothing delivered twice"

# ---------- live again ----------
kv_put after v1
wait_for_log '\[watch\] op=[a-z]+ key=after$' 10 \
    || fail "no E_NATS_KV_CHANGE for a write after the reconnect"
ok "changes after the reconnect raise E_NATS_KV_CHANGE"

assert_opensips_alive
pass "KV watcher resume: ${checks} checks green"
