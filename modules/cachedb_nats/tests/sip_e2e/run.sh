#!/bin/bash
# End-to-end test runner for cachedb_nats <-> usrloc full-sharing-cachedb.
#
# Boots ONE opensips instance against the user-supplied NATS broker,
# sources lib/helpers.sh, and iterates cases/*.sh in lexical order.
# Cases that need a second instance start it on demand via helpers and
# tear it down before returning.
#
# Required tools: opensips (built), nats CLI, sipsak, nc.
# Skips with autotools-style exit 77 on missing prerequisites.
#
# Environment overrides:
#   OPENSIPS_BIN           path to opensips binary
#                          (default: ../../../../opensips)
#   OPENSIPS_LIB_NATS      dir with libnats_pool.so
#                          (default: ../../../../lib/nats)
#   OPENSIPS_MODULES       dir with flat-symlinked .so files
#                          (default: ../../../../_modules)
#   NATS_URL               broker URL (default: nats://127.0.0.1:4222)
#   KV_BUCKET              bucket name (default: ULNATS_E2E)
#   ONLY                   glob to filter cases (default: '*.sh')

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
TREE_ROOT="$(cd "${HERE}/../../../.." && pwd)"

OPENSIPS_BIN="${OPENSIPS_BIN:-${TREE_ROOT}/opensips}"
OPENSIPS_LIB_NATS="${OPENSIPS_LIB_NATS:-${TREE_ROOT}/lib/nats}"
OPENSIPS_MODULES="${OPENSIPS_MODULES:-${TREE_ROOT}/_modules}"
NATS_URL="${NATS_URL:-nats://127.0.0.1:4222}"
# A run-unique bucket avoids tombstone bleed between runs (`nats kv del`
# leaves tombstones that still appear in `nats kv ls`, and the operator's
# user-bucket purge requires a TTY for the destructive-action warning).
KV_BUCKET="${KV_BUCKET:-ULNATS_E2E_$$_$(date +%s)}"
ONLY="${ONLY:-*.sh}"

WORKDIR="$(mktemp -d -t cachedb-nats-e2e.XXXXXX)"

OPENSIPS_PID=""
OPENSIPS_PID_B=""

cleanup() {
    [ -n "$OPENSIPS_PID" ]   && kill "$OPENSIPS_PID"   2>/dev/null
    [ -n "$OPENSIPS_PID_B" ] && kill "$OPENSIPS_PID_B" 2>/dev/null
    [ -n "${BOUNCE_NATS_PID:-}" ] && kill "$BOUNCE_NATS_PID" 2>/dev/null
    wait 2>/dev/null
    [ -n "${KVCTL:-}" ] && "$KVCTL" rm "$NATS_URL" "$KV_BUCKET" >/dev/null 2>&1 || \
        nats --server "$NATS_URL" kv del "$KV_BUCKET" -f >/dev/null 2>&1 || true
    if [ "${SUITE_FAIL:-0}" -eq 0 ]; then
        rm -rf "$WORKDIR"
    else
        echo
        echo "Workdir preserved for inspection: $WORKDIR"
        echo "Test bucket left for inspection:  $KV_BUCKET"
    fi
}
trap cleanup EXIT

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing required tool: $1"
        exit 77
    }
}
need nats; need sipsak; need nc

# kvctl creates buckets the way the module does (AllowMsgTTL via
# kvConfig.LimitMarkerTTL) -- the nats CLI on this host is too old for
# per-message TTL and would create buckets that latch native TTL off.
if ! make -C "$HERE" kvctl >/dev/null 2>&1 || [ ! -x "$HERE/kvctl" ]; then
    echo "kvctl build failed (needs a libnats with the PR #1000 KV TTL API)"
    exit 77
fi
KVCTL="$HERE/kvctl"

if [ ! -x "$OPENSIPS_BIN" ]; then
    echo "opensips binary not found at $OPENSIPS_BIN"
    exit 77
fi
if [ ! -d "$OPENSIPS_MODULES" ]; then
    echo "module directory not found at $OPENSIPS_MODULES"
    exit 77
fi

if ! nats --server "$NATS_URL" server check connection \
        > "$WORKDIR/conn.out" 2>&1; then
    echo "NATS broker not reachable at $NATS_URL"
    cat "$WORKDIR/conn.out"
    exit 77
fi

# Fresh bucket for this run -- history=1 [HREV-1] + marker TTL, exactly the
# shape nats_pool_get_kv creates, so native per-key TTL is exercised.
"$KVCTL" mk "$NATS_URL" "$KV_BUCKET" "${KV_HISTORY:-1}" 30 >/dev/null 2>&1 || true

# Derive the cachedb_url form (nats:<group>://host:port/) from NATS_URL.
NATS_HOSTPORT="${NATS_URL#nats://}"
NATS_HOSTPORT="${NATS_HOSTPORT#tls://}"
NATS_HOSTPORT="${NATS_HOSTPORT%/}"
CACHEDB_URL="nats:loc://${NATS_HOSTPORT}/"

# ── render cfg + boot opensips A ────────────────────────────────
SIP_PORT_A="${SIP_PORT_A:-5072}"
MI_PORT_A="${MI_PORT_A:-8889}"
CLUSTER_PORT_A="${CLUSTER_PORT_A:-5666}"
NODE_ID_A="${NODE_ID_A:-1}"
SIP_PORT_B="${SIP_PORT_B:-5074}"
MI_PORT_B="${MI_PORT_B:-8890}"
CLUSTER_PORT_B="${CLUSTER_PORT_B:-5667}"
NODE_ID_B="${NODE_ID_B:-2}"

render_cfg() {
    # render_cfg <out> <instance> <sip-port> <mi-port> <cluster-port> <node-id>
    local out=$1 inst=$2 sip=$3 mi=$4 cport=$5 nid=$6
    # The cfg template gained `enable_search_index` and `index_buckets`
    # placeholders for bench_ul_register.sh; integration cases default
    # both to legacy values (index on, 4096 buckets) unless the case
    # overrides via env.
    sed -e "s|@@MODULES@@|${OPENSIPS_MODULES}|g" \
        -e "s|@@NATS_URL@@|${NATS_URL}|g" \
        -e "s|@@CACHEDB_URL@@|${CACHEDB_URL}|g" \
        -e "s|@@SIP_PORT@@|${sip}|g" \
        -e "s|@@MI_PORT@@|${mi}|g" \
        -e "s|@@CLUSTER_PORT@@|${cport}|g" \
        -e "s|@@NODE_ID@@|${nid}|g" \
        -e "s|@@KV_BUCKET@@|${KV_BUCKET}|g" \
        -e "s|@@INSTANCE@@|${inst}|g" \
        -e "s|@@ENABLE_INDEX@@|${ENABLE_INDEX:-1}|g" \
        -e "s|@@INDEX_BUCKETS@@|${INDEX_BUCKETS:-4096}|g" \
        -e "s|@@EXPIRED_LINGER@@|${EXPIRED_LINGER:-0}|g" \
        -e "s|@@REAP_INTERVAL@@|${REAP_INTERVAL:-30}|g" \
        "${HERE}/opensips.cfg.in" > "$out"
}

start_opensips() {
    # start_opensips <instance> <sip-port> <mi-port> <cluster-port> <node-id> <cfg-out> <log-out>
    local inst=$1 sip=$2 mi=$3 cport=$4 nid=$5 cfg=$6 log=$7
    render_cfg "$cfg" "$inst" "$sip" "$mi" "$cport" "$nid"
    # /usr/local/lib is where the upstream `cmake --install` for libnats
    # lands by default; on hosts that also ship a stale libnats from a
    # system package (libnats3.7 in /lib/<arch>-linux-gnu on Debian-family)
    # the upstream-installed version wins via this path order.  Without
    # this, nats_dl_load picks the system libnats whose older minor
    # version is missing kvStore_WatchMulti, kvStore_WatchAll, and other
    # symbols added in 3.10+ and cachedb_nats mod_init aborts before the
    # MI socket comes up.
    LD_LIBRARY_PATH="${OPENSIPS_LIB_NATS}:/usr/local/lib:${LD_LIBRARY_PATH:-}" \
        "$OPENSIPS_BIN" -F -f "$cfg" -m 64 -M 4 > "$log" 2>&1 &
    local pid=$!
    sleep 2
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "FATAL: opensips $inst died on startup" >&2
        tail -30 "$log" >&2
        return 1
    fi
    for i in $(seq 1 20); do
        ss -lnu 2>/dev/null | grep -q "127.0.0.1:${mi}" && \
        ss -lnu 2>/dev/null | grep -q "127.0.0.1:${sip}" && break
        sleep 0.5
    done
    echo "$pid"
}

start_opensips_a() {
    OPENSIPS_PID=$(start_opensips A "$SIP_PORT_A" "$MI_PORT_A" \
        "$CLUSTER_PORT_A" "$NODE_ID_A" \
        "$WORKDIR/opensips_A.cfg" "$WORKDIR/opensips.log") || exit 1
}

start_opensips_b() {
    OPENSIPS_PID_B=$(start_opensips B "$SIP_PORT_B" "$MI_PORT_B" \
        "$CLUSTER_PORT_B" "$NODE_ID_B" \
        "$WORKDIR/opensips_B.cfg" "$WORKDIR/opensips_B.log") || return 1
}

# kill PID + wait PID reaps the attendant only.  OpenSIPS worker
# processes (MI Datagram, SIP receivers, timer) are children of the
# attendant but the SIGTERM-driven shutdown can leave them alive for
# tens of milliseconds after the attendant exits, still holding the
# MI port.  The next start_opensips then fails on bind ("Address
# already in use") and case 020_cold_start_hydration aborts the
# whole suite.  Wait for the actual MI port to free before returning.
_wait_port_free() {
    local port=$1
    local deadline=$(( $(date +%s) + 5 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        ss -lnu 2>/dev/null | grep -q "127.0.0.1:${port}\b" || return 0
        sleep 0.05
    done
    return 1
}

# Recursively collect every PID under attendant_pid via /proc, then
# kill them all.  OpenSIPS's SIGTERM handler propagates to children
# in normal operation, but under load (or just under GitHub-runner
# scheduler latency) the MI Datagram worker can outlive the
# attendant by tens to hundreds of milliseconds, holding the MI
# UDP port.  Hard-kill the whole tree in one shot so the next
# start_opensips never races bind on the MI port.
_kill_tree() {
    local root=$1
    [ -z "$root" ] && return 0
    # children-of-PID via /proc/*/stat (pos 4 = ppid).  Recurse first.
    local pid
    for pid in $(ps --no-headers -o pid --ppid "$root" 2>/dev/null); do
        _kill_tree "$pid"
    done
    kill -9 "$root" 2>/dev/null
}

stop_opensips_a() {
    if [ -n "$OPENSIPS_PID" ]; then
        kill "$OPENSIPS_PID" 2>/dev/null
        # Brief grace period for the orderly shutdown path.
        local deadline=$(( $(date +%s) + 2 ))
        while [ "$(date +%s)" -lt "$deadline" ]; do
            kill -0 "$OPENSIPS_PID" 2>/dev/null || break
            sleep 0.05
        done
        # Whether the attendant exited or not, hard-kill any straggling
        # workers under it.  After this, no opensips child can hold the
        # MI port.
        _kill_tree "$OPENSIPS_PID"
        wait "$OPENSIPS_PID" 2>/dev/null
    fi
    _wait_port_free "$MI_PORT_A" || \
        echo "WARN: MI port $MI_PORT_A still held after stop_opensips_a" >&2
    OPENSIPS_PID=""
}

stop_opensips_b() {
    if [ -n "$OPENSIPS_PID_B" ]; then
        kill "$OPENSIPS_PID_B" 2>/dev/null
        local deadline=$(( $(date +%s) + 2 ))
        while [ "$(date +%s)" -lt "$deadline" ]; do
            kill -0 "$OPENSIPS_PID_B" 2>/dev/null || break
            sleep 0.05
        done
        _kill_tree "$OPENSIPS_PID_B"
        wait "$OPENSIPS_PID_B" 2>/dev/null
    fi
    _wait_port_free "$MI_PORT_B" || \
        echo "WARN: MI port $MI_PORT_B still held after stop_opensips_b" >&2
    OPENSIPS_PID_B=""
}

start_opensips_a

# ── source helpers + iterate cases ──────────────────────────────
. "${HERE}/lib/helpers.sh"

echo
echo "=========================================="
echo "  cachedb_nats <-> usrloc e2e suite"
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
