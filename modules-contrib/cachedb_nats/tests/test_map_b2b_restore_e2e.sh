#!/bin/bash
# test_map_b2b_restore_e2e.sh -- b2b_entities / b2b_logic keep their state
# in cachedb_nats (the CacheDB map API) and restore it after a restart.
#
# A call goes through b2b_logic "top hiding" (SIPp UAC -> OpenSIPS -> SIPp
# UAS) with both b2b modules persisting to a private broker.  Mid-call,
# OpenSIPS is restarted: at startup b2b reloads every entity and tuple
# with map_get(NULL).  The UAC's BYE then has to be matched against the
# restored state and relayed to the UAS, so the call completes cleanly
# only if the restore worked.  Afterwards the call's maps must be gone
# from the bucket.
#
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/../../nats/tests/nats_local_lib.sh"

require_opensips_built
require_cmd nats sipp nc
command -v nats-server >/dev/null 2>&1 || skip "nats-server not in PATH (apt: nats-server; often /usr/sbin)"
require_modules_built b2b_entities b2b_logic tm sl signaling sipmsgops mi_fifo

PORT=4329
PRIV_URL="nats://127.0.0.1:${PORT}"
BUCKET="OS_TEST_B2B_$$"
SIP_PORT=5370
UAS_PORT=5380
UAC_PORT=5390

mkworkdir map_b2b_restore
NS_PID=""; UAS_PID=""; UAC_PID=""
cleanup_all() {
    [ -n "${UAC_PID}" ] && kill "${UAC_PID}" 2>/dev/null
    [ -n "${UAS_PID}" ] && kill "${UAS_PID}" 2>/dev/null
    stop_opensips
    [ -n "${NS_PID}" ] && kill "${NS_PID}" 2>/dev/null
    wait 2>/dev/null
    cleanup_workdir
}
trap cleanup_all EXIT

nats-server -a 127.0.0.1 -p "${PORT}" -js -sd "${WORK}/js" > "${WORK}/nats.log" 2>&1 &
NS_PID=$!
for _ in $(seq 1 50); do
    nats --server "${PRIV_URL}" rtt --timeout 200ms >/dev/null 2>&1 && break
    sleep 0.1
done

cat > "${WORK}/test.cfg" <<EOF
log_level=3
stderror_enabled=yes
udp_workers=2
socket=udp:127.0.0.1:${SIP_PORT}

mpath="${OPENSIPS_MPATH}"
loadmodule "proto_udp.so"
loadmodule "signaling.so"
loadmodule "sl.so"
loadmodule "sipmsgops.so"
loadmodule "tm.so"
loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "${OPS_FIFO}")

loadmodule "nats.so"
loadmodule "cachedb_nats.so"
modparam("cachedb_nats", "nats_url", "${PRIV_URL}")
modparam("cachedb_nats", "cachedb_url", "nats:b2b://127.0.0.1:${PORT}/")
modparam("cachedb_nats", "kv_bucket", "${BUCKET}")
modparam("cachedb_nats", "kv_replicas", 1)

loadmodule "b2b_entities.so"
modparam("b2b_entities", "cachedb_url", "nats:b2b://127.0.0.1:${PORT}/")
modparam("b2b_entities", "db_mode", 1)
loadmodule "b2b_logic.so"
modparam("b2b_logic", "cachedb_url", "nats:b2b://127.0.0.1:${PORT}/")
modparam("b2b_logic", "db_mode", 1)

route {
    if (is_method("INVITE") && !has_totag()) {
        \$ru = "sip:uas@127.0.0.1:${UAS_PORT}";
        b2b_init_request("top hiding");
        exit;
    }
    sl_send_reply(404, "Not here");
}
EOF

start_opensips "${WORK}/test.cfg"
sleep 1
assert_opensips_alive

sipp -sn uas -i 127.0.0.1 -p "${UAS_PORT}" -m 1 -bg -trace_err \
    -error_file "${WORK}/uas_err.log" > "${WORK}/uas.out" 2>&1 &
UAS_PID=$!
sleep 0.5
# one call, 12 s long: OpenSIPS is restarted while it is up
sipp -sn uac 127.0.0.1:${SIP_PORT} -i 127.0.0.1 -p "${UAC_PORT}" -m 1 \
    -d 12000 -trace_err -error_file "${WORK}/uac_err.log" -nostdin \
    > "${WORK}/uac.out" 2>&1 &
UAC_PID=$!

checks=0
ok() { echo "  ok: $*"; checks=$((checks+1)); }

map_keys() {  # live map entries in the bucket
    nats --server "${PRIV_URL}" kv ls "${BUCKET}" 2>/dev/null | grep -c '^_map\.' || true
}
b2be_count() {
    mi_call b2b_entities:list 2>/dev/null | grep -o '"callid"' | wc -l
}

for _ in $(seq 1 40); do [ "$(b2be_count)" -ge 2 ] && break; sleep 0.25; done
[ "$(b2be_count)" -ge 2 ] || fail "the call did not create two b2b entities; MI:
$(mi_call b2b_entities:list 2>&1 | head -c 600)
uac: $(tail -3 "${WORK}/uac_err.log" 2>/dev/null) $(tail -3 "${WORK}/uac.out")
log:
$(grep -E 'ERROR|WARN|b2b' "${OPS_LOG}" | tail -15)"
ok "call up: two b2b entities"
[ "$(map_keys)" -gt 0 ] || fail "nothing stored in the bucket by b2b"
ok "b2b state stored in NATS ($(map_keys) map entries)"

# ---------- restart mid-call ----------
stop_opensips
start_opensips "${WORK}/test.cfg"
sleep 1
assert_opensips_alive
if grep -qE "Failed to retrieve map keys|Failed to restore" "${OPS_LOG}"; then
    fail "restore failed:
$(grep -E 'map|restore|b2b' "${OPS_LOG}" | tail -10)"
fi
[ "$(b2be_count)" -ge 2 ] || fail "b2b entities not restored after the restart (got $(b2be_count)); log:
$(grep -E 'b2b|map|cachedb' "${OPS_LOG}" | tail -15)"
ok "after the restart both b2b entities are back"

# ---------- the BYE goes through the restored state ----------
wait "${UAC_PID}"; rc=$?
UAC_PID=""
[ "$rc" = "0" ] || fail "the call did not complete after the restart (uac rc=$rc):
$(tail -5 "${WORK}/uac_err.log" 2>/dev/null)"
ok "BYE relayed through the restored b2b state; call completed"

for _ in $(seq 1 40); do [ "$(map_keys)" = "0" ] && break; sleep 0.25; done
[ "$(map_keys)" = "0" ] || fail "map entries left in the bucket after the call: $(map_keys)"
ok "the call's maps are removed from the bucket"

assert_opensips_alive
pass "b2b restore over cachedb_nats maps: ${checks} checks green"
