#!/bin/bash
# test_boot_degraded_cdb_e2e.sh -- cachedb_nats without a NATS server at
# startup: the broker is down, or the only server URL is unusable.
#
# cachedb_nats must start DEGRADED with a warning instead of keeping
# OpenSIPS from starting:
#   - child_init, the cachedb connections and the reaper / watcher procs
#     come up without a KV handle; cache operations fail cleanly
#   - once the broker appears, operations get the KV handle themselves
#     (no restart)
#   - require_usrloc_safe_bucket=1 (strict) still refuses: the bucket
#     cannot be checked
#
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
NATS_PROBE="${HERE}/nats_probe.sh"
. "${HERE}/nats_local_lib.sh"

require_opensips_built
require_cmd nats nc
command -v nats-server >/dev/null 2>&1 || skip "nats-server not in PATH"

PORT=4326
PRIV_URL="nats://127.0.0.1:${PORT}"
BUCKET="bdcdb$$"
SIP_PORT=5197

mkworkdir boot_degraded_cdb
JSDIR="${WORK}/jsdir"
mkdir -p "${JSDIR}"

NS_PID=""
start_broker() {
    nats-server -p "${PORT}" -js -sd "${JSDIR}" >> "${WORK}/nats.log" 2>&1 &
    NS_PID=$!
    local i=0
    while [ $i -lt 20 ]; do
        "${NATS_PROBE}" "${PRIV_URL}" >/dev/null 2>&1 && return 0
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

# $1 nats_url, $2 extra modparam lines
write_cfg() {
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

loadmodule "cachedb_nats.so"
modparam("cachedb_nats", "cachedb_url", "nats://127.0.0.1:${PORT}/")
modparam("cachedb_nats", "nats_url", "$1")
modparam("cachedb_nats", "kv_bucket", "${BUCKET}")
modparam("cachedb_nats", "kv_replicas", 1)
modparam("cachedb_nats", "kv_watch", ">")
$2

route {
    \$var(p) = \$rU;
    \$var(want) = "v_" + \$var(p);
    \$var(v) = "";
    if (cache_store("nats", "k_\$var(p)", "v_\$var(p)"))
        cache_fetch("nats", "k_\$var(p)", \$var(v));
    if (\$var(v) == \$var(want))
        xlog("L_NOTICE","[\$var(p)] cache=ok\n");
    else
        xlog("L_NOTICE","[\$var(p)] cache=fail\n");
    xlog("L_NOTICE","[\$var(p)] phase-done\n");
    sl_send_reply(200, "done");
    exit;
}
EOF
}

ok=0; total=0
expect() {
    total=$((total+1))
    if eval "$1"; then echo "  ok: $2"; ok=$((ok+1)); else echo "  MISSING: $2"; fi
}

send_phase() {
    printf "%b" "OPTIONS sip:$1@127.0.0.1:${SIP_PORT} SIP/2.0\r
Via: SIP/2.0/UDP 127.0.0.1:55197;branch=z9hG4bK-$1.${RANDOM}\r
From: <sip:harness@127.0.0.1>;tag=$1\r
To: <sip:$1@127.0.0.1>\r
Call-ID: $1.${RANDOM}@127.0.0.1\r
CSeq: 1 OPTIONS\r
Max-Forwards: 70\r
Content-Length: 0\r
\r
" | timeout 5 nc -u -w1 127.0.0.1 "${SIP_PORT}" >/dev/null 2>&1 || true
}

procs_alive() { pgrep -f -- "${WORK}/test.cfg" | wc -l; }

# ---------- 1: broker DOWN at boot, arriving late ----------
echo "broker down at boot:"
write_cfg "${PRIV_URL}" ""
start_opensips "${WORK}/test.cfg"
sleep 5
expect 'kill -0 "${OPS_PID}" 2>/dev/null' \
    "opensips alive 5s after boot with the broker down (degraded start)"
expect 'log_contains "cachedb_nats: NATS is unavailable at startup; starting degraded"' \
    "cachedb_nats warns that it starts degraded"
expect '! log_contains "reaper proc: NATS connection unavailable, exiting|watcher proc: NATS connection unavailable, exiting"' \
    "reaper and watcher procs stay up"
send_phase down
expect 'wait_for_log "\\[down\\] cache=fail" 8' \
    "cache operation fails cleanly while the broker is down"
expect 'wait_for_log "\\[down\\] phase-done" 8' \
    "route completes (no stall) while the broker is down"

start_broker
recovered=0
for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 2
    send_phase "up$i"
    if wait_for_log "\\[up$i\\] cache=ok" 4; then recovered=1; break; fi
done
expect '[ "${recovered}" = "1" ]' \
    "cache operations work once the broker appears (no restart needed)"
expect 'nats --server "${PRIV_URL}" kv ls "${BUCKET}" 2>/dev/null | grep -q "k_up"' \
    "the value is in the KV bucket"
expect '! log_contains "segfault in process"' "no segfault"
stop_opensips
nats --server "${PRIV_URL}" kv del -f "${BUCKET}" >/dev/null 2>&1 || true

# ---------- 2: the only server URL is unusable ----------
LIBNATS="${NATS_DL_LIBNATS_PATH:-$(ldconfig -p 2>/dev/null | awk '/libnats\.so /{print $NF; exit}')}"
if [ -n "${LIBNATS}" ] && nm -D "${LIBNATS}" 2>/dev/null | grep -q " T nats_SupportsSRV"; then
    echo "only an unusable SRV URL:"
    : > "${OPS_LOG}"
    write_cfg "nats+srv://exa%41mple.test" ""
    start_opensips "${WORK}/test.cfg"
    sleep 5
    expect 'kill -0 "${OPS_PID}" 2>/dev/null' \
        "opensips alive with no usable NATS server (degraded start)"
    expect 'log_contains "has no usable domain name"' \
        "warning for the unusable SRV URL"
    expect 'log_contains "starting degraded"' \
        "cachedb_nats warns that it starts degraded"
    expect 'log_contains "reaper proc: NATS connection unavailable, running degraded" && log_contains "watcher proc: NATS connection unavailable, running degraded"' \
        "reaper and watcher procs warn and keep running"
    expect '! log_contains "proc: NATS connection unavailable, exiting"' \
        "no dedicated proc exits"
    send_phase nosrv
    expect 'wait_for_log "\\[nosrv\\] cache=fail" 8' \
        "cache operation fails cleanly without a server"
    stop_opensips
else
    echo "  (skipped: the loaded libnats has no SRV support)"
fi

# ---------- 3: strict mode still refuses ----------
echo "require_usrloc_safe_bucket=1, broker down:"
kill -9 "${NS_PID}" 2>/dev/null; NS_PID=""
: > "${OPS_LOG}"
write_cfg "${PRIV_URL}" 'modparam("cachedb_nats", "require_usrloc_safe_bucket", 1)'
# expected to exit: no waiting for the MI FIFO
"${OPENSIPS_BIN}" -F -f "${WORK}/test.cfg" >"${OPS_LOG}" 2>&1 &
OPS_PID=$!
sleep 6
expect '! kill -0 "${OPS_PID}" 2>/dev/null' \
    "strict mode refuses to start without the bucket"
expect 'log_contains "require_usrloc_safe_bucket=1"' \
    "the refusal names require_usrloc_safe_bucket"

[ "${ok}" = "${total}" ] || fail "only ${ok}/${total} checks passed; log tail:
$(tail -30 "${OPS_LOG}")"
pass "cachedb_nats boot-degraded green (broker down, unusable URL, strict refusal)"
