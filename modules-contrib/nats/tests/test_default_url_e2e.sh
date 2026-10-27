#!/bin/bash
# test_default_url_e2e.sh -- a NATS module without nats_url does not add
# its default server to the servers another module configured.
#
# event_nats defaults to nats://127.0.0.1:4222.  Loaded with a module that
# configures its servers (here cachedb_nats), the shared connection must
# use those servers only, whatever the module load order: otherwise, with
# no_randomize=1, every process connects to the localhost default -- and
# with DNS SRV URLs, a failed lookup leaves the default as the only server.
# Loaded alone, event_nats still uses its default.
#
# Needs port 4222 free: a stand-in broker listens there, as the server the
# default would wrongly point to.
#
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/nats_local_lib.sh"

require_opensips_built
require_cmd nats curl jq
command -v nats-server >/dev/null 2>&1 || skip "nats-server not in PATH"
if ss -ltn 'sport = :4222' 2>/dev/null | grep -q LISTEN; then
    skip "port 4222 is in use"
fi

DEF_PORT=4222        # the default URL of event_nats
DEF_MON=8322
CFG_PORT=4328        # the servers configured in cachedb_nats
CFG_MON=8328
BUCKET="dfurl$$"
SIP_PORT=5198

mkworkdir default_url

DEF_PID=""; CFG_PID=""
start_brokers() {
    mkdir -p "${WORK}/js-def" "${WORK}/js-cfg"
    nats-server -a 127.0.0.1 -p "${DEF_PORT}" -m "${DEF_MON}" -js -sd "${WORK}/js-def" \
        >> "${WORK}/nats-def.log" 2>&1 &
    DEF_PID=$!
    nats-server -a 127.0.0.1 -p "${CFG_PORT}" -m "${CFG_MON}" -js -sd "${WORK}/js-cfg" \
        >> "${WORK}/nats-cfg.log" 2>&1 &
    CFG_PID=$!
    local i=0
    while [ $i -lt 40 ]; do
        nats --server "nats://127.0.0.1:${DEF_PORT}" rtt --timeout 200ms >/dev/null 2>&1 &&
        nats --server "nats://127.0.0.1:${CFG_PORT}" rtt --timeout 200ms >/dev/null 2>&1 &&
            return 0
        sleep 0.25; i=$((i+1))
    done
    fail "brokers did not come up"
}
cleanup_all() {
    stop_opensips
    [ -n "${DEF_PID}" ] && kill -9 "${DEF_PID}" 2>/dev/null
    [ -n "${CFG_PID}" ] && kill -9 "${CFG_PID}" 2>/dev/null
    cleanup_workdir
}
trap cleanup_all EXIT

# client connections a broker has, from its monitoring port
conns() { curl -s "http://127.0.0.1:$1/connz" | jq -r '.num_connections // -1'; }

EVENT_NATS='loadmodule "event_nats.so"'
CACHEDB_NATS="loadmodule \"cachedb_nats.so\"
modparam(\"cachedb_nats\", \"cachedb_url\", \"nats://127.0.0.1:${CFG_PORT}/\")
modparam(\"cachedb_nats\", \"nats_url\", \"nats://127.0.0.1:${CFG_PORT}\")
modparam(\"cachedb_nats\", \"kv_bucket\", \"${BUCKET}\")
modparam(\"cachedb_nats\", \"kv_replicas\", 1)
modparam(\"cachedb_nats\", \"no_randomize\", 1)"

# $1, $2: the module blocks, in load order
write_cfg() {
cat > "${WORK}/test.cfg" <<EOF
log_level=3
stderror_enabled=yes
syslog_facility=LOG_LOCAL0
udp_workers=2
socket=udp:127.0.0.1:${SIP_PORT}

mpath="${OPENSIPS_MPATH}"

loadmodule "signaling.so"
loadmodule "sl.so"
loadmodule "tm.so"
loadmodule "proto_udp.so"

loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "${OPS_FIFO}")

loadmodule "nats.so"
$1
$2

route {
    sl_send_reply(200, "ok");
    exit;
}
EOF
}

ok=0; total=0
expect() {
    total=$((total+1))
    if eval "$1"; then echo "  ok: $2"; ok=$((ok+1)); else echo "  MISSING: $2"; fi
}

# $1 label, $2 first module, $3 second module: boots, then lets the
# processes connect
boot() {
    echo "$1:"
    : > "${OPS_LOG}"
    write_cfg "$2" "$3"
    start_opensips "${WORK}/test.cfg"
    sleep 4
}

start_brokers

boot "event_nats (no nats_url) loaded before cachedb_nats" "${EVENT_NATS}" "${CACHEDB_NATS}"
expect 'kill -0 "${OPS_PID}" 2>/dev/null' "opensips is up"
expect '[ "$(conns ${CFG_MON})" -gt 0 ]' "the processes connect to the configured server"
expect '[ "$(conns ${DEF_MON})" = "0" ]' "no process connects to the event_nats default"
stop_opensips

boot "cachedb_nats loaded before event_nats (no nats_url)" "${CACHEDB_NATS}" "${EVENT_NATS}"
expect 'kill -0 "${OPS_PID}" 2>/dev/null' "opensips is up"
expect '[ "$(conns ${CFG_MON})" -gt 0 ]' "the processes connect to the configured server"
expect '[ "$(conns ${DEF_MON})" = "0" ]' "no process connects to the event_nats default"
stop_opensips

boot "event_nats alone, no nats_url" "${EVENT_NATS}" ""
expect 'kill -0 "${OPS_PID}" 2>/dev/null' "opensips is up"
expect '[ "$(conns ${DEF_MON})" -gt 0 ]' "the processes connect to the default"
stop_opensips

expect '! grep -q "segfault in process" "${OPS_LOG}"' "no segfault"
nats --server "nats://127.0.0.1:${CFG_PORT}" kv del -f "${BUCKET}" >/dev/null 2>&1 || true

[ "${ok}" = "${total}" ] || fail "only ${ok}/${total} checks passed; log tail:
$(tail -30 "${OPS_LOG}")"
pass "a module default URL never joins configured servers"
