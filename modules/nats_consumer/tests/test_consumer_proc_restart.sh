#!/bin/bash
# test_consumer_proc_restart.sh -- pin the contract for what happens
# when the [NATS consumer] worker dies unexpectedly.
#
# Today's contract (signals.c:handle_sigs SIGCHLD branch): a registered
# child that exits without OSS_PROC_SELFEXIT triggers shutdown_opensips()
# for the whole instance.  Auto-respawn is NOT implemented.
#
# This test pins that contract: if anyone later flips a respawn flag or
# changes the proc registration to OSS_PROC_SELFEXIT, this fails and
# forces the change to come with documentation + an N15-respawn test.
#
# What we actually verify:
#   1. After SIGKILL on the [NATS consumer] worker, the parent opensips
#      process exits within a bounded timeout
#   2. The log contains the standard core message identifying the
#      signaled child and the SIGCHLD-driven shutdown
#
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/../../../lib/nats/tests/nats_local_lib.sh"

require_nats_reachable
require_opensips_built
require_cmd nats opensips

mkworkdir consumer_kill
trap 'stop_opensips; cleanup_workdir' EXIT

cat > "${WORK}/test.cfg" <<EOF
log_level=3
xlog_level=3
stderror_enabled=yes
syslog_facility=LOG_LOCAL0
udp_workers=1
socket=udp:127.0.0.1:5196

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

loadmodule "nats_consumer.so"
modparam("nats_consumer", "persist_handles", 0)

route {
    sl_send_reply(200, "ok");
    exit;
}
EOF

start_opensips "${WORK}/test.cfg"

# Give the consumer process up to 5 s to register itself in the proc
# table and log its starting line.
wait_for_log "nats_consumer_proc: starting" 5 \
    || fail "nats_consumer_proc never started; log:\n$(tail -40 "${OPS_LOG}")"

# The [NATS consumer] worker logs its own pid:
#    nats_consumer_proc_main: nats_consumer_proc: starting (pid=NNNN rank=0)
# OpenSIPS uses set_proc_attrs() to name the worker but doesn't write
# that name to /proc/comm (which is capped at 16 chars and held at
# "opensips" by the exec), so log-parsing is the most reliable path.
CONS_PID=$(grep -oE "nats_consumer_proc: starting \(pid=[0-9]+" "${OPS_LOG}" \
          | head -1 | grep -oE "[0-9]+" )
[ -n "${CONS_PID}" ] && kill -0 "${CONS_PID}" 2>/dev/null \
    || fail "could not locate [NATS consumer] worker pid from log; tail:
$(tail -30 "${OPS_LOG}")"

echo "    [NATS consumer] pid=${CONS_PID}, parent opensips pid=${OPS_PID}"

# SIGKILL the consumer worker.
kill -9 "${CONS_PID}" 2>/dev/null || fail "kill -9 ${CONS_PID} failed"

# Wait up to 8 s for the parent to notice and exit.
deadline=$(( $(date +%s) + 8 ))
while [ "$(date +%s)" -lt "${deadline}" ]; do
    if ! kill -0 "${OPS_PID}" 2>/dev/null; then
        OPS_PID=""
        break
    fi
    sleep 0.2
done

if [ -n "${OPS_PID:-}" ] && kill -0 "${OPS_PID}" 2>/dev/null; then
    fail "parent opensips did NOT exit within 8 s of consumer SIGKILL — \
contract changed: silent respawn or hung supervisor.  log tail:
$(tail -30 "${OPS_LOG}")"
fi

# Assert the documented log message appeared.
log_contains "child process ${CONS_PID} exited by a signal" \
    || fail "missing expected SIGCHLD log line for pid ${CONS_PID}; tail:
$(tail -30 "${OPS_LOG}")"
log_contains "terminating due to SIGCHLD" \
    || fail "missing expected 'terminating due to SIGCHLD' line; tail:
$(tail -30 "${OPS_LOG}")"

pass "consumer SIGKILL → parent opensips terminated cleanly (contract pinned)"
