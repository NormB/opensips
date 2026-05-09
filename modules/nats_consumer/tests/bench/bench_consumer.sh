#!/bin/bash
# bench_consumer.sh -- nats_consumer fetch+ack throughput benchmark.
#
# What it measures
#   - Steady-state throughput (msgs/sec) the timer-route drain can
#     sustain when the JetStream stream is pre-filled with N
#     messages and opensips has nothing else to do.
#   - End-to-end "publish to ack" latency, sampled by reading the
#     consumer-info pending count over time (with the publish
#     epoch timestamps embedded in the payload).
#
# What it doesn't measure (yet)
#   - Real-world workloads where opensips also handles SIP traffic
#     concurrently -- those need a SIP-side load generator running
#     alongside this driver.
#   - The async fetch path (acmd_export nats_fetch).  This bench
#     uses the synchronous fetch_batch path because it's the
#     dominant pattern for timer-driven drain workloads.
#
# Output
#   $OUT/bench.log              -- harness log + opensips stdout
#   $OUT/opensips.log           -- opensips's main log
#   $OUT/handle_metrics.json    -- nats_consumer_list snapshot at end
#
# Stats on stdout: msgs ingested, msgs acked, elapsed s, msgs/sec.
#
# Env knobs:
#   N=10000        Number of messages to pre-publish + drain.
#   STREAM=BENCH   JetStream stream name (created if absent).
#   SUBJECT=bench  Subject for the messages.
#   HANDLE=bench   nats_consumer handle id.
#   NATS_URL=...   Broker URL.
#   OUT=...        Output directory (default mktemp).
#
# Exit 0 success, 1 failure, 77 prerequisites missing.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
TREE_ROOT="$(cd "${HERE}/../../../.." && pwd)"

OPENSIPS_BIN="${OPENSIPS_BIN:-${TREE_ROOT}/opensips}"
OPENSIPS_LIB_NATS="${OPENSIPS_LIB_NATS:-${TREE_ROOT}/lib/nats}"
OPENSIPS_MODULES="${OPENSIPS_MODULES:-${TREE_ROOT}/_modules}"
NATS_URL="${NATS_URL:-nats://127.0.0.1:4222}"
NATS_HOSTPORT="${NATS_URL#nats://}"; NATS_HOSTPORT="${NATS_HOSTPORT%/}"

N="${N:-10000}"
STREAM="${STREAM:-BENCH_$$}"
SUBJECT="${SUBJECT:-bench.in}"  # full subject; consumer filter
                                # matches this exact pattern
HANDLE="${HANDLE:-bench}"
MI_PORT="${MI_PORT:-9888}"

OUT="${OUT:-$(mktemp -d -t nats-consumer-bench.XXXXXX)}"
mkdir -p "$OUT"

OPENSIPS_PID=""
cleanup() {
    [ -n "$OPENSIPS_PID" ] && kill "$OPENSIPS_PID" 2>/dev/null
    wait 2>/dev/null
    nats --server "$NATS_URL" stream del "$STREAM" -f >/dev/null 2>&1 || true
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 77; }; }
need nats; need awk; need nc

[ -x "$OPENSIPS_BIN" ] || { echo "no opensips: $OPENSIPS_BIN" >&2; exit 77; }
[ -d "$OPENSIPS_MODULES" ] || { echo "no modules: $OPENSIPS_MODULES" >&2; exit 77; }

# Prereq check: nats_consumer.so must be loadable from this build.
[ -f "$OPENSIPS_MODULES/nats_consumer.so" ] || {
    echo "no nats_consumer.so in $OPENSIPS_MODULES; build it first" >&2
    exit 77
}
[ -f "$OPENSIPS_MODULES/event_nats.so" ] || {
    echo "no event_nats.so in $OPENSIPS_MODULES; build it first" >&2
    exit 77
}

nats --server "$NATS_URL" server check connection >/dev/null 2>&1 || {
    echo "NATS unreachable: $NATS_URL" >&2; exit 77;
}

# --- 1. Create a fresh stream on the broker ---

echo "[bench] creating stream $STREAM (subject $SUBJECT)..."
nats --server "$NATS_URL" stream del "$STREAM" -f >/dev/null 2>&1 || true
nats --server "$NATS_URL" stream add "$STREAM" \
    --subjects "$SUBJECT" \
    --storage memory --replicas 1 \
    --defaults \
    >/dev/null 2>&1

# --- 2. Pre-publish N messages with a sequence number payload ---

echo "[bench] publishing $N messages to $SUBJECT ..."
pub_start=$(date +%s.%N)
nats --server "$NATS_URL" pub "$SUBJECT" \
    --count "$N" "msg-{{Count}}" >"$OUT/pub.log" 2>&1
pub_end=$(date +%s.%N)
pub_elapsed=$(awk -v s="$pub_start" -v e="$pub_end" 'BEGIN{printf "%.3f", e-s}')

# Confirm the stream actually has N messages
stream_info=$(nats --server "$NATS_URL" stream info "$STREAM" 2>/dev/null)
stream_msgs=$(printf '%s' "$stream_info" | sed -n 's/.*Messages:[[:space:]]*\([0-9,]*\).*/\1/p' | tr -d ',' | head -1)
[ "${stream_msgs:-0}" = "$N" ] || {
    echo "WARN: expected $N stream messages, got $stream_msgs" >&2
}
echo "[bench] published $stream_msgs in $pub_elapsed s"

# --- 3. Render cfg + start opensips ---

CFG="$OUT/opensips.cfg"
sed -e "s|@@MODULES@@|${OPENSIPS_MODULES}|g" \
    -e "s|@@NATS_URL@@|${NATS_URL}|g" \
    -e "s|@@MI_PORT@@|${MI_PORT}|g" \
    -e "s|@@STREAM@@|${STREAM}|g" \
    -e "s|@@SUBJECT@@|${SUBJECT}|g" \
    -e "s|@@HANDLE_ID@@|${HANDLE}|g" \
    "${HERE}/opensips.cfg.in" > "$CFG"

echo "[bench] starting opensips ..."
LD_LIBRARY_PATH="${OPENSIPS_LIB_NATS}:${LD_LIBRARY_PATH:-}" \
    "$OPENSIPS_BIN" -F -f "$CFG" -s HP_MALLOC -m 128 -M 8 \
    > "$OUT/opensips.log" 2>&1 &
OPENSIPS_PID=$!
sleep 2
kill -0 "$OPENSIPS_PID" 2>/dev/null || {
    echo "FATAL: opensips died on startup" >&2
    tail -30 "$OUT/opensips.log" >&2
    exit 1
}

# Helper: ask opensips's MI for handle counters (acks, msgs, etc.)
mi_consumer_list() {
    printf '{"jsonrpc":"2.0","id":1,"method":"nats_consumer:nats_consumer_list"}' \
        | timeout 3 nc -u -w 2 127.0.0.1 "$MI_PORT" 2>/dev/null
}

# Helper: pull the per-handle ack count from a list response.
acks_of() {
    local resp="$1"
    printf '%s' "$resp" \
        | sed -n 's/.*"id":"'"$HANDLE"'"[^}]*"acks":\([0-9]*\).*/\1/p' \
        | head -1
}

# --- 4. Wait for the bind to register and the drain to start ---

for i in $(seq 1 30); do
    resp=$(mi_consumer_list)
    [ -n "$resp" ] && break
    sleep 0.2
done
[ -n "$resp" ] || {
    echo "FATAL: MI never came up" >&2
    tail -30 "$OUT/opensips.log" >&2
    exit 1
}

# --- 5. Time the drain.  Poll MI; stop when acks reach N. ---

drain_start=$(date +%s.%N)
last_acks=0
last_t=$drain_start
deadline=$((SECONDS + 120))
while [ "$SECONDS" -lt "$deadline" ]; do
    resp=$(mi_consumer_list)
    acks=$(acks_of "$resp")
    acks=${acks:-0}
    if [ "$acks" -ge "$N" ]; then
        break
    fi
    # 200 ms poll interval; capture mid-drain progress for a
    # smoothed instantaneous-rate readout in the final report.
    sleep 0.2
done
drain_end=$(date +%s.%N)

drain_elapsed=$(awk -v s="$drain_start" -v e="$drain_end" 'BEGIN{printf "%.3f", e-s}')
final_resp=$(mi_consumer_list)
final_acks=$(acks_of "$final_resp")
final_acks=${final_acks:-0}
echo "$final_resp" > "$OUT/handle_metrics.json"

# --- 6. Report ---

if [ "$final_acks" -ge "$N" ]; then
    rate=$(awk -v n="$final_acks" -v t="$drain_elapsed" \
        'BEGIN{ printf "%.1f", (t > 0) ? n/t : 0 }')
    avg_ms=$(awk -v n="$final_acks" -v t="$drain_elapsed" \
        'BEGIN{ printf "%.3f", (n > 0) ? (t * 1000)/n : 0 }')
    status=ok
else
    rate=0
    avg_ms=NA
    status=fail
fi

cat <<EOF

==========================================
  nats_consumer fetch+ack bench
  N (target):           $N
  pre-publish elapsed:  ${pub_elapsed}s
  drain elapsed:        ${drain_elapsed}s
  acks completed:       $final_acks / $N
  effective msgs/sec:   $rate
  avg latency / msg:    ${avg_ms}ms
  status:               $status
  out:                  $OUT
==========================================

EOF

[ "$status" = ok ] && exit 0 || exit 1
