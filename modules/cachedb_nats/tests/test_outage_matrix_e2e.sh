#!/bin/bash
# test_outage_matrix_e2e.sh -- broker-lifecycle matrix for cachedb_nats.
#
# Three phases against a PRIVATE disposable broker (so the operator's
# suite broker is never disturbed):
#
#   phase 1 (broker up):       every script-reachable op succeeds
#   phase 2 (broker SIGKILLed) every op fails CLEANLY and FAST --
#                              opensips alive, no segfault, no
#                              full-JetStream-timeout stall
#   phase 3 (broker restarted) every op succeeds again, and the KV
#                              watcher resumes (E_NATS_KV_CHANGE fires
#                              for a post-restart external write)
#
# Ops covered: nats_kv_put / get / update(CAS) / delete / revision,
# plus the core cachedb surface (cache_store / cache_fetch /
# cache_add / cache_counter_fetch) which drives the module's
# set/get/add/get_counter out-param contract paths.
#
# Distinct fault classes exercised:
#   - SIGKILL (TCP drop, no clean close) vs the suite's docker pause
#   - restart-with-persistent-store (bucket survives, handles must
#     refresh, watcher must re-watch)
#
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/../../../lib/nats/tests/nats_local_lib.sh"

require_opensips_built
require_cmd nats nc
command -v nats-server >/dev/null 2>&1 || skip "nats-server not in PATH (apt: nats-server; often /usr/sbin)"

PORT=4323
PRIV_URL="nats://127.0.0.1:${PORT}"
BUCKET="OS_TEST_OUTAGE_$$"
SIP_PORT=5198

mkworkdir outage_matrix
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

start_broker

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
loadmodule "rr.so"
loadmodule "maxfwd.so"
loadmodule "sipmsgops.so"
loadmodule "proto_udp.so"

loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "${OPS_FIFO}")

loadmodule "cachedb_nats.so"
modparam("cachedb_nats", "nats_url", "${PRIV_URL}")
modparam("cachedb_nats", "cachedb_url", "nats:loc://127.0.0.1:${PORT}/")
modparam("cachedb_nats", "kv_bucket", "${BUCKET}")
modparam("cachedb_nats", "kv_replicas", 1)
modparam("cachedb_nats", "enable_search_index", 1)
modparam("cachedb_nats", "kv_watch", ">")
# keep op timeouts small so even a non-fast-fail path can't stall long
modparam("cachedb_nats", "kv_op_timeout_ms", 800)

event_route[E_NATS_KV_CHANGE] {
    xlog("L_NOTICE","[watch] op=\$param(op) key=\$param(key)\n");
}

route {
    \$var(p) = \$rU;     # phase tag from the request URI user
    \$var(v) = "";
    \$var(rev) = 0;
    \$var(cnt) = 0;

    # --- nats_kv_* family -------------------------------------------
    if (nats_kv_put("${BUCKET}", "mk", "v-\$var(p)"))
        xlog("L_NOTICE","[\$var(p)] put=ok\n");
    else
        xlog("L_NOTICE","[\$var(p)] put=fail\n");

    if (nats_kv_get("${BUCKET}", "mk", \$var(v), \$var(rev)))
        xlog("L_NOTICE","[\$var(p)] get=ok value=\$var(v)\n");
    else
        xlog("L_NOTICE","[\$var(p)] get=fail\n");

    if (nats_kv_update("${BUCKET}", "mk", "v2-\$var(p)", \$var(rev)))
        xlog("L_NOTICE","[\$var(p)] cas=ok\n");
    else
        xlog("L_NOTICE","[\$var(p)] cas=fail\n");

    if (nats_kv_revision("${BUCKET}", "mk", \$var(rev)))
        xlog("L_NOTICE","[\$var(p)] rev=ok\n");
    else
        xlog("L_NOTICE","[\$var(p)] rev=fail\n");

    if (nats_kv_delete("${BUCKET}", "mk"))
        xlog("L_NOTICE","[\$var(p)] del=ok\n");
    else
        xlog("L_NOTICE","[\$var(p)] del=fail\n");

    # --- core cachedb surface (set/get/add/get_counter paths) -------
    if (cache_store("nats:loc", "ck_\$var(p)", "cv-\$var(p)"))
        xlog("L_NOTICE","[\$var(p)] store=ok\n");
    else
        xlog("L_NOTICE","[\$var(p)] store=fail\n");

    if (cache_fetch("nats:loc", "ck_\$var(p)", \$var(v)))
        xlog("L_NOTICE","[\$var(p)] fetch=ok value=\$var(v)\n");
    else
        xlog("L_NOTICE","[\$var(p)] fetch=fail\n");

    if (cache_add("nats:loc", "ctr_\$var(p)", 1, 0, \$var(cnt)))
        xlog("L_NOTICE","[\$var(p)] add=ok cnt=\$var(cnt)\n");
    else
        xlog("L_NOTICE","[\$var(p)] add=fail\n");

    if (cache_counter_fetch("nats:loc", "ctr_\$var(p)", \$var(cnt)))
        xlog("L_NOTICE","[\$var(p)] cfetch=ok cnt=\$var(cnt)\n");
    else
        xlog("L_NOTICE","[\$var(p)] cfetch=fail\n");

    xlog("L_NOTICE","[\$var(p)] phase-done\n");
    sl_send_reply(200, "done");
    exit;
}
EOF

start_opensips "${WORK}/test.cfg"
wait_for_log "KV bucket '${BUCKET}' created" 8 \
    || fail "bucket not created within 8s; log:
$(tail -30 "${OPS_LOG}")"
sleep 0.5

send_phase() {  # $1 = phase tag
    printf "%b" "OPTIONS sip:$1@127.0.0.1:${SIP_PORT} SIP/2.0\r
Via: SIP/2.0/UDP 127.0.0.1:55198;branch=z9hG4bK-$1.${RANDOM}\r
From: <sip:harness@127.0.0.1>;tag=$1\r
To: <sip:$1@127.0.0.1>\r
Call-ID: $1.${RANDOM}@127.0.0.1\r
CSeq: 1 OPTIONS\r
Max-Forwards: 70\r
Content-Length: 0\r
\r
" | timeout 3 nc -u -w1 127.0.0.1 "${SIP_PORT}" >/dev/null 2>&1 || true
}

OPS="put get cas rev del store fetch add cfetch"
ok=0; total=0

check_phase() {  # $1 = phase tag, $2 = expected (ok|fail)
    local p="$1" want="$2" m
    for m in ${OPS}; do
        total=$((total+1))
        if wait_for_log "\\[${p}\\] ${m}=${want}" 8; then
            echo "  ok: [${p}] ${m}=${want}"
            ok=$((ok+1))
        else
            echo "  MISSING: [${p}] ${m}=${want}   (got: $(grep -o "\[${p}\] ${m}=[a-z]*" "${OPS_LOG}" | tail -1))"
        fi
    done
}

# ---------- phase 1: broker up, everything succeeds ----------
send_phase p1
check_phase p1 ok

# ---------- phase 2: SIGKILL the broker (TCP drop) ----------
stop_broker_hard
# give cnats a moment to notice the dead TCP (ping/eof)
sleep 3

P2_T0=$(date +%s)
send_phase p2
check_phase p2 fail
wait_for_log "\\[p2\\] phase-done" 15 || fail "phase 2 route never completed -- worker stalled or crashed:
$(tail -20 "${OPS_LOG}")"
P2_T1=$(date +%s)
P2_ELAPSED=$((P2_T1 - P2_T0))

# the whole 9-op phase must fail FAST (fast-fail, not 9 x JS timeout)
if [ "${P2_ELAPSED}" -gt 12 ]; then
    fail "phase 2 took ${P2_ELAPSED}s -- ops are stalling on the dead broker instead of fast-failing"
fi
echo "  ok: phase 2 completed in ${P2_ELAPSED}s (fast-fail)"

# the process must have survived the whole outage phase
if log_contains 'segfault in process\|exited by a signal'; then
    fail "opensips crashed during the outage phase:
$(grep -E 'segfault|signal' "${OPS_LOG}" | tail -5)"
fi
echo "  ok: no crash during outage"

# ---------- phase 3: restart the broker (same store) ----------
start_broker
# wait for the pool to reconnect + KV handles to refresh (retry loop:
# the reconnect is cnats-timed, so poll by resending the phase probe)
recovered=0
for i in 1 2 3 4 5 6; do
    sleep 2
    send_phase p3
    if wait_for_log "\\[p3\\] put=ok" 4; then recovered=1; break; fi
done
[ "${recovered}" = "1" ] || fail "ops did not recover within ~30s of broker restart:
$(tail -30 "${OPS_LOG}")"
check_phase p3 ok

# ---------- watcher resumed after the restart? ----------
nats --server "${PRIV_URL}" kv put "${BUCKET}" wkey wval >/dev/null 2>&1 \
    || fail "external post-restart kv put failed"
if wait_for_log '\[watch\] op=.* key=wkey' 10; then
    echo "  ok: watcher resumed post-restart (E_NATS_KV_CHANGE fired)"
    ok=$((ok+1))
else
    fail "KV watcher did NOT resume after broker restart (no E_NATS_KV_CHANGE for post-restart write):
$(grep -E 'watcher|watch' "${OPS_LOG}" | tail -15)"
fi
total=$((total+1))

[ "${ok}" = "${total}" ] || fail "only ${ok}/${total} matrix checks passed"

pass "outage matrix: ${total} checks green (up=ok, SIGKILL=clean+fast fail, restart=recovered, watcher resumed)"
