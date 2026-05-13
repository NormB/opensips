#!/bin/bash
# End-to-end test runner for the bidirectional SIP <-> NATS suite.
#
# Boots opensips ONCE, sources lib/helpers.sh, then iterates over
# every cases/*.sh file in lexical order.  Each case file is sourced
# (not exec'd); each calls case_begin <name> + check <label> ok|fail.
# The runner aggregates results and exits non-zero unless every check
# in every case passes.
#
# Required tools: opensips (built), sipp, nats CLI, docker (only if
# no broker is reachable on $NATS_URL).  Skips with autotools-style
# exit 77 on missing prerequisites.
#
# Environment overrides:
#   OPENSIPS_BIN          path to opensips (default: ../../../../opensips)
#   OPENSIPS_LIB_NATS     dir with libnats_pool.so (default: ../../../../lib/nats)
#   OPENSIPS_MODULES      dir with flat-symlinked .so files
#                         (default: ../../../../_modules)
#   NATS_URL              broker URL (default: nats://127.0.0.1:4322)
#   ONLY                  glob to filter which cases run (default: '*.sh')

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
TREE_ROOT="$(cd "${HERE}/../../../.." && pwd)"

OPENSIPS_BIN="${OPENSIPS_BIN:-${TREE_ROOT}/opensips}"
OPENSIPS_LIB_NATS="${OPENSIPS_LIB_NATS:-${TREE_ROOT}/lib/nats}"
OPENSIPS_MODULES="${OPENSIPS_MODULES:-${TREE_ROOT}/_modules}"
NATS_URL="${NATS_URL:-nats://127.0.0.1:4322}"
ONLY="${ONLY:-*.sh}"

WORKDIR="$(mktemp -d -t sip-nats-e2e.XXXXXX)"

OPENSIPS_PID=""
DOCKER_NATS=""

cleanup() {
    [ -n "$OPENSIPS_PID" ] && kill "$OPENSIPS_PID" 2>/dev/null
    [ -n "$DOCKER_NATS" ] && docker rm -f "$DOCKER_NATS" >/dev/null 2>&1
    wait 2>/dev/null
    # leave WORKDIR around if anything failed; remove on success
    if [ "${SUITE_FAIL:-0}" -eq 0 ]; then
        rm -rf "$WORKDIR"
    else
        echo
        echo "Workdir preserved for inspection: $WORKDIR"
    fi
}
trap cleanup EXIT

# ─── prerequisite checks ─────────────────────────────────────────
need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing required tool: $1"
        exit 77
    }
}
need sipp; need nats; need nc

if [ ! -x "$OPENSIPS_BIN" ]; then
    echo "opensips binary not found at $OPENSIPS_BIN"
    exit 77
fi
if [ ! -d "$OPENSIPS_MODULES" ]; then
    echo "module directory not found at $OPENSIPS_MODULES"
    exit 77
fi

# ─── ensure broker reachable ────────────────────────────────────
if ! nats --server "$NATS_URL" server check connection \
        > "$WORKDIR/conn.out" 2>&1; then
    need docker
    NATS_PORT="${NATS_URL##*:}"; NATS_PORT="${NATS_PORT%%/*}"
    DOCKER_NATS="sip-nats-e2e-natstest"
    docker rm -f "$DOCKER_NATS" >/dev/null 2>&1 || true
    docker run -d --rm --name "$DOCKER_NATS" \
        -p "${NATS_PORT}:4222" nats:2.10-alpine -js >/dev/null
    for i in $(seq 1 10); do
        nats --server "$NATS_URL" server check connection \
            >/dev/null 2>&1 && break
        sleep 1
    done
fi

# Buckets / streams the suite expects up front.
nats --server "$NATS_URL" kv add TESTKV --history=5 --replicas=1 \
    >/dev/null 2>&1 || true
nats --server "$NATS_URL" stream add TEST --subjects 'test.>' \
    --storage memory --defaults >/dev/null 2>&1 || true

# ─── render cfg + boot opensips ─────────────────────────────────
sed -e "s|@@MODULES@@|${OPENSIPS_MODULES}|g" \
    -e "s|@@NATS_URL@@|${NATS_URL}|g" \
    "${HERE}/opensips.cfg.in" > "$WORKDIR/opensips.cfg"

# /usr/local/lib is where the upstream `cmake --install` for libnats
# lands by default; on hosts that also ship a stale libnats from a
# system package (libnats3.7 in /lib/<arch>-linux-gnu on Debian-family)
# the upstream-installed version wins via this path order.  Without
# this, nats_dl_load picks the system libnats whose older minor
# version is missing kvStore_WatchMulti, kvStore_WatchAll, and other
# symbols added in 3.10+ and event_nats mod_init aborts before the
# MI socket comes up.
LD_LIBRARY_PATH="${OPENSIPS_LIB_NATS}:/usr/local/lib:${LD_LIBRARY_PATH:-}" \
    "$OPENSIPS_BIN" -F -f "$WORKDIR/opensips.cfg" -m 64 -M 4 \
    > "$WORKDIR/opensips.log" 2>&1 &
OPENSIPS_PID=$!
sleep 3

if ! kill -0 "$OPENSIPS_PID" 2>/dev/null; then
    echo "FATAL: opensips died on startup"
    tail -30 "$WORKDIR/opensips.log"
    exit 1
fi

# Wait for mi_datagram + UDP socket to be live.
for i in $(seq 1 20); do
    ss -lnu 2>/dev/null | grep -q '127.0.0.1:8889' && \
    ss -lnu 2>/dev/null | grep -q '127.0.0.1:5072' && break
    sleep 0.5
done

# ─── source helpers + iterate cases ─────────────────────────────
. "${HERE}/lib/helpers.sh"

echo
echo "=========================================="
echo "  bidirectional SIP <-> NATS e2e suite"
echo "  workdir: $WORKDIR"
echo "  cases:   ${HERE}/cases/${ONLY}"
echo "=========================================="

shopt -s nullglob
cases=( "${HERE}/cases/"${ONLY} )
shopt -u nullglob

if [ ${#cases[@]} -eq 0 ]; then
    echo "no cases matched"
    exit 1
fi

for c in "${cases[@]}"; do
    [ -f "$c" ] || continue
    echo
    # shellcheck source=/dev/null
    . "$c"
done

# ─── summary ────────────────────────────────────────────────────
echo
echo "=========================================="
echo "  summary: pass=${SUITE_PASS} fail=${SUITE_FAIL}"
if [ "${SUITE_FAIL}" -gt 0 ]; then
    echo
    echo "  failing checks:"
    for f in "${FAILED_CASES[@]}"; do
        echo "    - $f"
    done
fi
echo "=========================================="

exit "${SUITE_FAIL}"
