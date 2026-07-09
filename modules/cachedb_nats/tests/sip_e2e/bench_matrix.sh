#!/bin/bash
# bench_matrix.sh -- multi-mode, multi-scale, multi-trial bench driver.
#
# Wraps bench_ul_register.sh.  Drives the same harness across every
# (mode, scale, trial) cell, captures the stats line per run into a
# CSV, then aggregates median + min/max per cell.
#
# Why this script exists:
# An earlier attempt to run a 3-mode matrix as an inline shell loop
# composed `eval | tail | grep` pipelines in the loop body.  When
# grep didn't match anything (harness emitting a slightly different
# format, an extra cleanup-trap line, etc.), the pipeline returned
# 1; the tool wrapper surfaced that as the script's exit status and
# truncated subsequent iterations from the visible output.
#
# Two lessons baked in here:
#
#   1. Each bench run is its own top-level command and writes its
#      raw stdout to a per-run log file.  Parsing happens in a
#      separate stage, after all runs complete -- so a parse failure
#      can't terminate the matrix mid-flight.
#
#   2. set -o pipefail is on inside parse stages but NOT around the
#      bench invocations themselves.  We want to keep going even
#      when one trial misbehaves; the aggregation reports trial
#      counts so anomalies are visible.
#
# The script always exits 0 unless invoked with bad arguments.
# Run-level failures are reported in the final table and via the
# cell trial counts.
#
# Usage:
#   ./bench_matrix.sh [--out DIR] [--trials N] [--scales 'AOR1 AOR2 ...'] \
#                     [--modes  'idx off']                          \
#                     [--rps RPS]      [--workers W]      [--timeout-ms MS]
#
# Defaults: 3 trials, scales "10000 30000", modes "idx off",
#           RPS 1000, 16 workers, 1 s timeout.
#
# Reaper: bench_ul_register.sh defaults REAP_INTERVAL to run-length
# + 60 s, so the reaper's O(bucket) pass stays OUT of every measured
# cell (the 2026-07-07 investigation traced the 30k-scale p99/max tail
# blowups to that collision).  `REAP_INTERVAL=30 ./bench_matrix.sh ...`
# restores the collision when the sweep phase is what you are measuring.
#
# Each mode is mapped to a knob preset:
#   idx -> ENABLE_INDEX=1 (watcher in its dedicated process, the only mode)
#   off -> ENABLE_INDEX=0 (no index, no watcher)
#
# Output:
#   $OUT/runs.csv   -- one row per run: scale,mode,trial,elapsed_s,rps,
#                      p50_us,p95_us,p99_us,max_us,rss_kb,err
#   $OUT/summary.txt -- pretty aggregated table (printed to stdout too).

set -u  # strict on undefined variables; pipefail is set per-stage.

HERE="$(cd "$(dirname "$0")" && pwd)"
TREE_ROOT="$(cd "${HERE}/../../../.." && pwd)"

# --- argument parsing ---------------------------------------------

OUT="${OUT:-/tmp/bench-matrix-$(date +%Y%m%d-%H%M%S)}"
TRIALS=3
SCALES="10000 30000"
MODES="idx off"
RPS=1000
WORKERS=16
TIMEOUT_MS=1000
INDEX_BUCKETS_DEFAULT=4096
# Scale-specific bucket count overrides for the index path.  Per
# SCALING.md: 4096 ≤ 20k AoRs, 16384 at 100k.  At 30k we still use
# 16384 because the chain-walk hypothesis was empirically rejected
# (no measurable improvement from 4k → 16k buckets at 30k); we set
# it for parity with the 100k mode anyway.
INDEX_BUCKETS_30000=16384
INDEX_BUCKETS_100000=16384

while [ $# -gt 0 ]; do
    case "$1" in
        --out)         OUT="$2"; shift 2 ;;
        --trials)      TRIALS="$2"; shift 2 ;;
        --scales)      SCALES="$2"; shift 2 ;;
        --modes)       MODES="$2"; shift 2 ;;
        --rps)         RPS="$2"; shift 2 ;;
        --workers)     WORKERS="$2"; shift 2 ;;
        --timeout-ms)  TIMEOUT_MS="$2"; shift 2 ;;
        -h|--help)
            sed -n '/^# Usage:/,/^# Output:/p' "$0" | sed 's/^# //'
            exit 0 ;;
        *)
            echo "bench_matrix: unknown arg: $1" >&2
            echo "  use --help for usage" >&2
            exit 2 ;;
    esac
done

mkdir -p "$OUT"
RUNS_CSV="$OUT/runs.csv"
SUMMARY="$OUT/summary.txt"

echo "scale,mode,trial,elapsed_s,rps,p50_us,p95_us,p99_us,max_us,rss_kb,err" \
    > "$RUNS_CSV"

# --- mode → knob preset --------------------------------------------

mode_env() {
    case "$1" in
        idx) echo "ENABLE_INDEX=1" ;;
        off) echo "ENABLE_INDEX=0" ;;
        *) echo "bench_matrix: unknown mode: $1" >&2; exit 2 ;;
    esac
}

scale_buckets() {
    case "$1" in
        100000) echo "$INDEX_BUCKETS_100000" ;;
        30000)  echo "$INDEX_BUCKETS_30000"  ;;
        *)      echo "$INDEX_BUCKETS_DEFAULT" ;;
    esac
}

# --- one bench run -------------------------------------------------
#
# Stage 1: drive the bench, capture raw stdout.  Returns 0 always
#          (we never want a single bad trial to abort the matrix).
# Stage 2: parse the captured stdout.  Errors here append a row with
#          err=1; the cell aggregator then ignores those rows.

run_one() {
    local scale=$1 mode=$2 trial=$3
    local label="${scale}_${mode}_t${trial}"
    local raw="$OUT/raw_${label}.log"
    local cellout="$OUT/cell_${label}"
    rm -rf "$cellout"

    local env_str
    env_str=$(mode_env "$mode")
    local buckets
    buckets=$(scale_buckets "$scale")

    # Pre-flight: kill any lingering opensips from a prior trial.
    # We keep the test bucket per trial unique so old data doesn't
    # leak; the fresh-bucket invariant is delegated to the harness.
    pkill -9 -f "opensips -F.*cachedb-nats-bench" 2>/dev/null || true
    sleep 1

    # Run.  We construct the eval string explicitly because the env
    # preset comes from mode_env above.  set +e is the default in this
    # shell so a non-zero from the harness doesn't terminate us.
    local rc=0
    bash -c "
        ${env_str} \
        N=${scale} \
        RPS=${RPS} \
        AOR_SPACE=${scale} \
        INDEX_BUCKETS=${buckets} \
        BENCH_WORKERS=${WORKERS} \
        BENCH_TIMEOUT_MS=${TIMEOUT_MS} \
        OUT=${cellout} \
        bash '${HERE}/bench_ul_register.sh'
    " > "$raw" 2>&1
    rc=$?

    # Stage 2: parse the harness's results block.  Each extractor
    # uses a single sed capture so we don't depend on field-counting
    # awk -F splits, which broke at first attempt because the literal
    # 'p50/p95/p99/max:' header in the source line was being treated
    # as four numeric-adjacent tokens.  Run each in a subshell with
    # pipefail set: a parse miss returns empty, never a non-zero
    # exit that could leak out of run_one.
    local elapsed rps p50 p95 p99 mx rss err=0
    elapsed=$(sed -n 's/^[[:space:]]*elapsed:[[:space:]]\+\([0-9.]\+\).*/\1/p'  "$raw" | tail -1)
    rps=$(    sed -n 's/^[[:space:]]*effective RPS:[[:space:]]\+\([0-9.]\+\).*/\1/p' "$raw" | tail -1)
    # Single-pass capture of all four latency values.
    read -r p50 p95 p99 mx <<<"$(
        sed -n 's|^[[:space:]]*latency p50/p95/p99/max:[[:space:]]\+\([0-9]\+\)/\([0-9]\+\)/\([0-9]\+\)/\([0-9]\+\).*|\1 \2 \3 \4|p' "$raw" | tail -1
    )"
    rss=$(sed -n 's/^[[:space:]]*opensips A RSS (KB):[[:space:]]\+\([0-9]\+\).*/\1/p' "$raw" | tail -1)

    # Anything blank means parse failure: mark the row as errored so
    # aggregation can skip it.  The raw log stays on disk for audit.
    if [ -z "${elapsed:-}" ] || [ -z "${rps:-}" ] || [ -z "${p50:-}" ] || \
       [ -z "${p95:-}" ] || [ -z "${p99:-}" ] || [ -z "${rss:-}" ]; then
        err=1
        elapsed=${elapsed:-NA}
        rps=${rps:-NA}; p50=${p50:-NA}; p95=${p95:-NA}; p99=${p99:-NA}
        mx=${mx:-NA};   rss=${rss:-NA}
    fi

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$scale" "$mode" "$trial" "$elapsed" "$rps" \
        "$p50" "$p95" "$p99" "$mx" "$rss" "$err" \
        >> "$RUNS_CSV"

    # One-line status to stdout so the caller can watch progress.
    if [ "$err" = 0 ]; then
        printf '  [%-6s][%-5s][t%d] elapsed=%ss rps=%s p50=%sus p95=%sus p99=%sus rss=%sKB\n' \
            "$scale" "$mode" "$trial" "$elapsed" "$rps" \
            "$p50" "$p95" "$p99" "$rss"
    else
        printf '  [%-6s][%-5s][t%d] PARSE ERROR (raw: %s, harness rc=%d)\n' \
            "$scale" "$mode" "$trial" "$raw" "$rc"
    fi

    # Always 0 -- never break the matrix on a single trial failure.
    return 0
}

# --- aggregation ---------------------------------------------------
#
# Per (scale, mode), compute median + min/max across trials of:
#   p50, p95, p99, rps, rss
# Tab-separated table written to $SUMMARY and stdout.

aggregate() {
    {
        echo
        echo "==================== bench_matrix summary ===================="
        echo "trials per cell: $TRIALS"
        echo "scales:          $SCALES"
        echo "modes:           $MODES"
        echo "rps target:      $RPS"
        echo "workers:         $WORKERS"
        echo "out:             $OUT"
        echo "==============================================================="
        echo
        printf '%-7s %-5s %-6s | %s | %s | %s | %s | %s\n' \
            scale mode trials \
            "p50_us(med min..max)" "p95_us(med min..max)" \
            "p99_us(med min..max)" "rps(med)" "rss_KB(med)"
        printf '%.0s-' {1..130}; echo
    } | tee "$SUMMARY"

    local scale mode
    for scale in $SCALES; do
        for mode in $MODES; do
            python3 - "$scale" "$mode" "$RUNS_CSV" <<'PY' | tee -a "$SUMMARY"
import csv, sys, statistics

scale, mode, runs_csv = sys.argv[1], sys.argv[2], sys.argv[3]

rows = []
with open(runs_csv) as f:
    r = csv.DictReader(f)
    for row in r:
        if row['scale'] == scale and row['mode'] == mode and row['err'] == '0':
            try:
                rows.append({
                    'p50': int(row['p50_us']),
                    'p95': int(row['p95_us']),
                    'p99': int(row['p99_us']),
                    'rps': float(row['rps']),
                    'rss': int(row['rss_kb']),
                })
            except (ValueError, KeyError):
                pass

n = len(rows)
def fmt(values, fmt_spec):
    if not values:
        return f'{"NA":>20}'
    med = statistics.median(values)
    lo, hi = min(values), max(values)
    return f'{med:>6{fmt_spec}} ({lo:>6{fmt_spec}} ..{hi:>6{fmt_spec}})'

if n == 0:
    print(f'{scale:>7} {mode:<5} {n:>6} | (no successful trials)')
else:
    p50 = fmt([r['p50'] for r in rows], 'd')
    p95 = fmt([r['p95'] for r in rows], 'd')
    p99 = fmt([r['p99'] for r in rows], 'd')
    rps_med = statistics.median(r['rps'] for r in rows)
    rss_med = statistics.median(r['rss'] for r in rows)
    print(f'{scale:>7} {mode:<5} {n:>6} | {p50} | {p95} | {p99} | '
          f'{rps_med:>7.1f} | {rss_med:>10.0f}')
PY
        done
    done

    echo "" | tee -a "$SUMMARY"
    echo "raw rows:    $RUNS_CSV"     | tee -a "$SUMMARY"
    echo "raw logs:    $OUT/raw_*.log" | tee -a "$SUMMARY"
}

# --- main ----------------------------------------------------------

trap 'pkill -9 -f "opensips -F.*cachedb-nats-bench" 2>/dev/null || true' EXIT

echo "bench_matrix: scales='$SCALES' modes='$MODES' trials=$TRIALS rps=$RPS"
echo "out: $OUT"
echo

total_runs=$(( $(echo "$SCALES" | wc -w) * $(echo "$MODES" | wc -w) * TRIALS ))
done_runs=0
for scale in $SCALES; do
    for mode in $MODES; do
        for trial in $(seq 1 "$TRIALS"); do
            done_runs=$(( done_runs + 1 ))
            echo "[$done_runs/$total_runs] scale=$scale mode=$mode trial=$trial"
            run_one "$scale" "$mode" "$trial"
        done
    done
done

aggregate

# --- STRICT release-gate arm ----------------------------------------
# Developer default: always exit 0 (the table/CSV is the product and a
# failed cell is visible there).  STRICT=1: any (scale,mode) cell with
# ZERO successful trials fails the run -- a missing dependency or a
# collapsed benchmark must not read as a green pipeline.
if [ "${STRICT:-0}" = "1" ]; then
    if ! awk -F, 'NR>1 { tot[$1","$2]++; if ($11==0) ok[$1","$2]++ }
        END { n=0
              for (c in tot) if (!(c in ok)) { print "  " c; n++ }
              exit(n ? 1 : 0) }' "$RUNS_CSV" > "$OUT/strict_bad_cells.txt"
    then
        echo "STRICT=1: benchmark cells with no successful trial:"
        cat "$OUT/strict_bad_cells.txt"
        exit 1
    fi
fi
exit 0
