#!/bin/bash
# test_no_randomize_e2e.sh -- no_randomize=1 makes every OpenSIPS process
# connect to the first configured server.
#
# Two private nats-servers, A and B, with monitoring.  opensips with
# event_nats, 4 UDP workers (each process opens its own connection):
#
#   nats_url "A,B", no_randomize=1  -> every connection on A, none on B
#   nats_url "B,A", no_randomize=1  -> every connection on B, none on A
#
# The second case is the control: the order, not the servers, decides.
# (no_randomize=0 shuffles per process, so it is not asserted.)
#
# Skips (exit 77) without nats-server, curl, jq or a built opensips.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/nats_local_lib.sh"

require_opensips_built
require_cmd nats-server curl jq

mkworkdir no_randomize >/dev/null
PA=$((23000 + ($$ % 15000)))
PB=$((PA + 10))
PIDS=()
trap 'stop_opensips; for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; cleanup_workdir' EXIT

for p in "${PA}" "${PB}"; do
    nats-server -a 127.0.0.1 -p "${p}" -m $((p + 1)) -l "${WORK}/srv${p}.log" &
    PIDS+=($!)
done
for p in "${PA}" "${PB}"; do
    for i in $(seq 1 50); do
        curl -sf "http://127.0.0.1:$((p + 1))/varz" >/dev/null 2>&1 && break
        sleep 0.1
    done
done

conns() { curl -sf "http://127.0.0.1:$(($1 + 1))/connz" | jq -r '.num_connections'; }

FAILS=0
run_case() {   # run_case <label> <first port> <second port>
    local first=$2 second=$3
    stop_opensips
    cat > "${WORK}/test.cfg" <<EOF
log_level=3
stderror_enabled=yes
syslog_facility=LOG_LOCAL0
udp_workers=4
socket=udp:127.0.0.1:$((PA + 2))
mpath="${OPENSIPS_MPATH}"
loadmodule "signaling.so"
loadmodule "sl.so"
loadmodule "proto_udp.so"
loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "${OPS_FIFO}")
loadmodule "nats.so"
loadmodule "event_nats.so"
modparam("event_nats", "nats_url", "nats://127.0.0.1:${first},nats://127.0.0.1:${second}")
modparam("event_nats", "no_randomize", 1)
route { sl_send_reply(200, "ok"); exit; }
EOF
    rm -f "${OPS_FIFO}"
    start_opensips "${WORK}/test.cfg"
    # every process that connects logs it once
    local want
    for i in $(seq 1 100); do
        want=$(grep -c "NATS pool: connected to" "${OPS_LOG}")
        [ "${want}" -ge 5 ] && break
        sleep 0.1
    done
    sleep 0.5
    want=$(grep -c "NATS pool: connected to" "${OPS_LOG}")
    local on_first on_second
    on_first=$(conns "${first}"); on_second=$(conns "${second}")
    echo "    ${want} process connections; first server ${on_first}, second ${on_second}"
    if [ "${want}" -ge 5 ] && [ "${on_first}" = "${want}" ] && [ "${on_second}" = 0 ]; then
        echo "  ok: $1"
    else
        echo "  FAIL: $1"
        FAILS=$((FAILS + 1))
    fi
}

run_case "order A,B: every process on A" "${PA}" "${PB}"
run_case "order B,A: every process on B" "${PB}" "${PA}"

[ "${FAILS}" -eq 0 ] || fail "${FAILS} case(s) failed"
pass "no_randomize=1 keeps the configured server order in every process"
