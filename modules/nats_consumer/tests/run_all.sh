#!/bin/bash
# run_all.sh -- the nats_consumer integration batch, end to end.
#
# Runs every test_*.sh case against the docker-compose stack, PLUS the
# host-side cases (which spin their own opensips against a local
# broker).  Exists so the whole batch has ONE entry point with the
# prerequisites arranged -- before this runner the host-side cases
# silently skipped in every batch (no broker on 127.0.0.1:4222, no
# nats-server in PATH) and two genuinely failing cases rotted for
# weeks as a "known environment baseline".  Silence is not success:
# this runner arranges the prerequisites it can and prints WHY for
# anything it still skips.
#
#   - compose stack: built from the CURRENT tree, so local changes are
#     what gets tested; torn down afterwards.
#   - host-side cases: a DISPOSABLE local nats-server (JetStream, own
#     port, own store dir under /tmp) is started when 127.0.0.1:4222
#     has no broker, and /usr/sbin joins PATH when nats-server lives
#     there (Debian).  Both are cleaned up on exit.
#   - cores are disabled (ulimit -c 0): several cases SIGKILL opensips
#     on purpose, and core dumps on a tmpfs /tmp can OOM the box.
#
# Exit: 0 iff no case failed (skips with a printed reason are OK).
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "${HERE}"

ulimit -c 0

# nats-server lives in /usr/sbin and the installed opensips in
# /usr/local/sbin -- both commonly missing from non-login PATHs.  The
# outage case spins its own private broker with the former; the
# host-side cases' require_cmd probes want the latter resolvable (they
# still RUN the tree binary via OPENSIPS_BIN).
if ! command -v nats-server >/dev/null 2>&1 && [ -x /usr/sbin/nats-server ]; then
    export PATH="/usr/sbin:${PATH}"
fi
if ! command -v opensips >/dev/null 2>&1 && [ -x /usr/local/sbin/opensips ]; then
    export PATH="/usr/local/sbin:${PATH}"
fi

# Host-side cases target ${NATS_URL:-nats://127.0.0.1:4222}.  If nothing
# listens there, start a disposable JetStream broker on that port; never
# touch a broker we did not start.
LOCAL_NATS_PID=""
LOCAL_NATS_DIR=""
if ! nats --server "${NATS_URL:-nats://127.0.0.1:4222}" rtt \
        --timeout 2s >/dev/null 2>&1; then
    if command -v nats-server >/dev/null 2>&1; then
        LOCAL_NATS_DIR="$(mktemp -d /tmp/nc_batch_js.XXXXXX)"
        nats-server -a 127.0.0.1 -p 4222 -js -sd "${LOCAL_NATS_DIR}" \
            > "${LOCAL_NATS_DIR}/nats.log" 2>&1 &
        LOCAL_NATS_PID=$!
        for _ in $(seq 1 20); do
            nats --server nats://127.0.0.1:4222 rtt --timeout 1s \
                >/dev/null 2>&1 && break
            sleep 0.5
        done
        echo "== disposable local nats-server up (pid ${LOCAL_NATS_PID})"
    else
        echo "== no nats-server binary; host-side cases will skip"
    fi
fi

cleanup() {
    ${COMPOSE:-docker compose -f docker-compose.yaml} down -v \
        >/dev/null 2>&1 || true
    if [ -n "${LOCAL_NATS_PID}" ]; then
        kill "${LOCAL_NATS_PID}" >/dev/null 2>&1 || true
        wait "${LOCAL_NATS_PID}" 2>/dev/null || true
    fi
    [ -n "${LOCAL_NATS_DIR}" ] && rm -rf "${LOCAL_NATS_DIR}"
}
trap cleanup EXIT

COMPOSE="docker compose -f docker-compose.yaml"

echo "== compose build =="
${COMPOSE} build --quiet || { echo "BUILD FAILED"; exit 1; }
echo "== compose up =="
${COMPOSE} up -d || { echo "UP FAILED"; exit 1; }
sleep 5

pass=0; fail=0; skip=0
for t in test_*.sh; do
    echo "== CASE: $t =="
    if bash "$t"; then
        pass=$((pass+1))
    else
        rc=$?
        if [ "$rc" = 77 ]; then
            skip=$((skip+1)); echo "  (skipped)"
        else
            fail=$((fail+1)); echo "  CASE FAILED: $t (rc=$rc)"
        fi
    fi
done

echo "=========================================="
echo "e2e summary: pass=$pass fail=$fail skip=$skip"
echo "=========================================="
[ "$fail" = 0 ]
