#!/bin/bash
# Bench harness for the cachedb_nats <-> usrloc full-sharing-cachedb
# write path.  Drives N concurrent REGISTERs at a configurable RPS,
# captures end-to-end latency percentiles, the CAS-retry / CAS-
# exhausted deltas reported via the nats_cdb_stats MI, and the NATS
# stream growth.  Intended for topology decisions:
#   - single-instance baseline
#   - two-instance (run with INSTANCES=2)
#   - cross-DC RTT (set NATS_URL to a remote broker; tc qdisc on the
#     loopback if simulating in-host)
#
# Required tools: opensips, nats CLI, sipsak, awk, gnu-time, ts (moreutils).
# Skips with exit 77 when prereqs absent.
#
# Environment overrides:
#   N=1000                    total REGISTERs
#   RPS=200                   target rate (sustained, simple fork-batched)
#   AOR_SPACE=200             distinct AoRs (mod-cycled; smaller -> more
#                             contention)
#   INSTANCES=1               1 or 2 — 2 splits load across A and B
#   NATS_URL                  NATS broker URL
#   KV_BUCKET                 bucket (default ULNATS_E2E_BENCH_<pid>_<ts>)
#   OUT                       output directory (default $WORKDIR)

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
TREE_ROOT="$(cd "${HERE}/../../../.." && pwd)"

OPENSIPS_BIN="${OPENSIPS_BIN:-${TREE_ROOT}/opensips}"
OPENSIPS_LIB_NATS="${OPENSIPS_LIB_NATS:-${TREE_ROOT}/lib/nats}"
OPENSIPS_MODULES="${OPENSIPS_MODULES:-${TREE_ROOT}/_modules}"
NATS_URL="${NATS_URL:-nats://127.0.0.1:4222}"
KV_BUCKET="${KV_BUCKET:-ULNATS_E2E_BENCH_$$_$(date +%s)}"

N="${N:-1000}"
RPS="${RPS:-200}"
AOR_SPACE="${AOR_SPACE:-200}"
INSTANCES="${INSTANCES:-1}"

# Scale-tuning knobs.  ENABLE_INDEX=0 disables the
# in-memory JSON-FTS index entirely; reads/writes use the PK fast
# path.  This is the recommended setting for usrloc-as-store
# deployments and the canonical bench mode for measuring the
# index-disable win versus the legacy index-on baseline.
ENABLE_INDEX="${ENABLE_INDEX:-1}"
INDEX_BUCKETS="${INDEX_BUCKETS:-4096}"
# Dedicated KV-watcher process.  When 1 (and the index is on)
# OpenSIPS forks one extra child that owns the watcher loop and frees
# rank 1 from the watcher pthread.  Default 0 keeps the legacy
# rank-1 pthread topology.
DEDICATED_WATCHER="${DEDICATED_WATCHER:-0}"

WORKDIR="$(mktemp -d -t cachedb-nats-bench.XXXXXX)"
OUT="${OUT:-$WORKDIR}"
mkdir -p "$OUT"

OPENSIPS_PID=""
OPENSIPS_PID_B=""

cleanup() {
    [ -n "$OPENSIPS_PID" ]   && kill "$OPENSIPS_PID"   2>/dev/null
    [ -n "$OPENSIPS_PID_B" ] && kill "$OPENSIPS_PID_B" 2>/dev/null
    wait 2>/dev/null
    nats --server "$NATS_URL" kv del "$KV_BUCKET" -f >/dev/null 2>&1 || true
}
trap cleanup EXIT

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing: $1"; exit 77;
    }
}
need nats; need sipsak; need awk

[ -x "$OPENSIPS_BIN" ] || { echo "no opensips: $OPENSIPS_BIN"; exit 77; }
[ -d "$OPENSIPS_MODULES" ] || { echo "no modules: $OPENSIPS_MODULES"; exit 77; }
nats --server "$NATS_URL" server check connection >/dev/null 2>&1 || {
    echo "NATS unreachable: $NATS_URL"; exit 77;
}

NATS_HOSTPORT="${NATS_URL#nats://}"; NATS_HOSTPORT="${NATS_HOSTPORT%/}"
CACHEDB_URL="nats:loc://${NATS_HOSTPORT}/"

nats --server "$NATS_URL" kv add "$KV_BUCKET" --history=3 --replicas=1 \
    >/dev/null 2>&1 || true

render_cfg() {
    local out=$1 inst=$2 sip=$3 mi=$4 cport=$5 nid=$6
    sed -e "s|@@MODULES@@|${OPENSIPS_MODULES}|g" \
        -e "s|@@NATS_URL@@|${NATS_URL}|g" \
        -e "s|@@CACHEDB_URL@@|${CACHEDB_URL}|g" \
        -e "s|@@SIP_PORT@@|${sip}|g" -e "s|@@MI_PORT@@|${mi}|g" \
        -e "s|@@CLUSTER_PORT@@|${cport}|g" -e "s|@@NODE_ID@@|${nid}|g" \
        -e "s|@@KV_BUCKET@@|${KV_BUCKET}|g" -e "s|@@INSTANCE@@|${inst}|g" \
        -e "s|@@ENABLE_INDEX@@|${ENABLE_INDEX}|g" \
        -e "s|@@INDEX_BUCKETS@@|${INDEX_BUCKETS}|g" \
        -e "s|@@DEDICATED_WATCHER@@|${DEDICATED_WATCHER}|g" \
        "${HERE}/opensips.cfg.in" > "$out"
}

start_instance() {
    local inst=$1 sip=$2 mi=$3 cport=$4 nid=$5
    local cfg="$WORKDIR/o_${inst}.cfg"
    local log="$OUT/opensips_${inst}.log"
    render_cfg "$cfg" "$inst" "$sip" "$mi" "$cport" "$nid"
    LD_LIBRARY_PATH="${OPENSIPS_LIB_NATS}:/usr/local/lib:${LD_LIBRARY_PATH:-}" \
        "$OPENSIPS_BIN" -F -f "$cfg" -s HP_MALLOC -m 256 -M 8 > "$log" 2>&1 &
    local pid=$!
    sleep 2
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "FATAL: opensips $inst died" >&2
        tail -20 "$log" >&2
        exit 1
    fi
    echo "$pid"
}

mi_at() {
    local port=$1 method=$2
    printf '{"jsonrpc":"2.0","id":1,"method":"%s"}' "$method" \
        | timeout 3 nc -u -w 2 127.0.0.1 "$port"
}
mi_cdb_stats_at() {
    mi_at "$1" nats_cdb_stats
}

OPENSIPS_PID=$(start_instance A 5072 8889 5666 1)
if [ "$INSTANCES" = 2 ]; then
    OPENSIPS_PID_B=$(start_instance B 5074 8890 5667 2)
fi

# Capture the pre-run baseline for both instances
A_STATS_BEFORE=$(mi_cdb_stats_at 8889)
[ "$INSTANCES" = 2 ] && B_STATS_BEFORE=$(mi_cdb_stats_at 8890)

echo
echo "=========================================="
echo "  cachedb_nats <-> usrloc bench"
echo "  instances:  $INSTANCES"
echo "  N:          $N"
echo "  target RPS: $RPS"
echo "  AoR space:  $AOR_SPACE"
echo "  bucket:     $KV_BUCKET"
echo "  out:        $OUT"
echo "=========================================="

# Drive REGISTERs.
#
# Two drivers are supported:
#   - bench_register (compiled C, multi-threaded; preferred for >150 RPS)
#   - bash + sipsak per-call (legacy fallback; 7 ms/iter floor caps
#     effective rate at ~140 RPS regardless of OpenSIPS)
#
# The C driver is auto-built once if its source is present and a
# binary doesn't already exist.  Operators can force the legacy bash
# driver with BENCH_DRIVER=bash; useful for cross-checking but not
# recommended for real numbers.
LATENCIES="$OUT/latencies_us.txt"
: > "$LATENCIES"

BENCH_DRIVER="${BENCH_DRIVER:-auto}"
DRIVER_BIN="${HERE}/bench_register"

if [ "$BENCH_DRIVER" = "auto" ] && [ ! -x "$DRIVER_BIN" ] && \
        [ -f "${HERE}/bench_register.c" ]; then
    ( cd "$HERE" && make bench_register >/dev/null 2>&1 ) || true
fi

if [ "$BENCH_DRIVER" != "bash" ] && [ -x "$DRIVER_BIN" ]; then
    DRIVER_NAME="bench_register (compiled)"
else
    DRIVER_NAME="bash + sipsak (legacy)"
fi
echo "  driver:     $DRIVER_NAME"

start=$(date +%s.%N)

if [ "$BENCH_DRIVER" != "bash" ] && [ -x "$DRIVER_BIN" ]; then
    # Compiled driver: one process, W worker threads, token-bucket
    # pacing, persistent UDP sockets.  Latencies written directly to
    # $LATENCIES; stats line emitted on stdout.
    WORKERS="${BENCH_WORKERS:-8}"
    TIMEOUT_MS="${BENCH_TIMEOUT_MS:-1000}"
    "$DRIVER_BIN" \
        --target "127.0.0.1:5072" \
        --n "$N" \
        --rps "$RPS" \
        --aor-space "$AOR_SPACE" \
        --workers "$WORKERS" \
        --timeout-ms "$TIMEOUT_MS" \
        --user-prefix "bench" \
        --out "$LATENCIES" \
        > "$OUT/driver_stats.txt" 2>&1
    # The driver computes its own elapsed but we re-derive it from
    # wallclock for parity with the legacy path.
    if [ "$INSTANCES" = 2 ]; then
        echo "  note: INSTANCES=2 not yet wired into bench_register; " \
             "compiled driver targets instance A only" >&2
    fi
else
    # Legacy bash drive loop.
    i=0
    while [ "$i" -lt "$N" ]; do
        user="bench$((i % AOR_SPACE))"
        if [ "$INSTANCES" = 2 ] && [ $((i & 1)) = 1 ]; then
            port=5074
        else
            port=5072
        fi
        {
            t0=$(date +%s%N)
            sipsak -U -C "sip:${user}@127.0.0.1:${port}" \
                -s "sip:${user}@127.0.0.1:${port}" \
                -e 60 -t 1 -O 1 >/dev/null 2>&1
            t1=$(date +%s%N)
            echo $(( (t1 - t0) / 1000 )) >> "$LATENCIES"
        } &

        i=$((i + 1))
        # Crude pacing: sleep based on RPS budget.
        if [ "$RPS" -gt 0 ]; then
            usleep_us=$(( 1000000 / RPS ))
            sleep "$(awk -v u=$usleep_us 'BEGIN{printf "%.6f", u/1000000}')"
        fi
    done
    wait
fi

end=$(date +%s.%N)
elapsed=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.3f", e - s}')

# Stats deltas
A_STATS_AFTER=$(mi_cdb_stats_at 8889)
[ "$INSTANCES" = 2 ] && B_STATS_AFTER=$(mi_cdb_stats_at 8890)

extract() {
    local v=$(printf '%s' "$1" | sed -n 's/.*"'"$2"'":\([0-9]*\).*/\1/p')
    echo "${v:-0}"
}
delta() {
    local f=$1 b=$2 a=$3
    local va=$(extract "$a" "$f")
    local vb=$(extract "$b" "$f")
    echo $(( ${va:-0} - ${vb:-0} ))
}

# Latency percentiles via sort + awk.
if [ -s "$LATENCIES" ]; then
    sort -n "$LATENCIES" -o "$LATENCIES"
    P50=$(awk 'NR==int(0.50*ct)' ct="$(wc -l < "$LATENCIES")" "$LATENCIES")
    P95=$(awk 'NR==int(0.95*ct)' ct="$(wc -l < "$LATENCIES")" "$LATENCIES")
    P99=$(awk 'NR==int(0.99*ct)' ct="$(wc -l < "$LATENCIES")" "$LATENCIES")
    PMAX=$(tail -1 "$LATENCIES")
fi

# Stream depth (KV bucket size, message count)
STREAM_INFO=$(nats --server "$NATS_URL" stream info "KV_${KV_BUCKET}" 2>/dev/null)
MSGS=$(printf '%s' "$STREAM_INFO" | sed -n 's/.*Messages:[[:space:]]*\([0-9,]*\).*/\1/p' \
    | tr -d ',' | head -1)

# Aggregate RSS (KB) across the opensips A worker tree.  When the
# index is enabled this captures the SHM-backed bucket array +
# entries; when ENABLE_INDEX=0 the same workload runs without that
# allocation and the delta is the index footprint.
A_RSS_KB=0
if [ -n "$OPENSIPS_PID" ] && kill -0 "$OPENSIPS_PID" 2>/dev/null; then
    A_RSS_KB=$(ps -o rss= -p "$OPENSIPS_PID" \
        $(pgrep -P "$OPENSIPS_PID" 2>/dev/null) 2>/dev/null \
        | awk '{s+=$1} END{print s+0}')
fi

echo
echo "=========================================="
echo "  results"
echo "  elapsed:               ${elapsed} s"
echo "  effective RPS:         $(awk -v n=$N -v e=$elapsed 'BEGIN{printf "%.1f", n/e}')"
echo "  latency p50/p95/p99/max: ${P50:-?}/${P95:-?}/${P99:-?}/${PMAX:-?} us"
echo "  CAS retry delta A:     $(delta cas_retry "$A_STATS_BEFORE" "$A_STATS_AFTER")"
echo "  CAS exhausted delta A: $(delta cas_exhausted "$A_STATS_BEFORE" "$A_STATS_AFTER")"
echo "  create_doc delta A:    $(delta create_doc "$A_STATS_BEFORE" "$A_STATS_AFTER")"
if [ "$INSTANCES" = 2 ]; then
    echo "  CAS retry delta B:     $(delta cas_retry "$B_STATS_BEFORE" "$B_STATS_AFTER")"
    echo "  CAS exhausted delta B: $(delta cas_exhausted "$B_STATS_BEFORE" "$B_STATS_AFTER")"
    echo "  create_doc delta B:    $(delta create_doc "$B_STATS_BEFORE" "$B_STATS_AFTER")"
fi
echo "  KV stream messages:    ${MSGS:-?}"
echo "  opensips A RSS (KB):   ${A_RSS_KB}"
echo "  ENABLE_INDEX:          ${ENABLE_INDEX}"
echo "  index_buckets:         ${INDEX_BUCKETS}"
echo "  DEDICATED_WATCHER:     ${DEDICATED_WATCHER}"
echo "=========================================="
