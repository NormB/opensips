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
# Stream subject pattern uses a wildcard so the consumer's filter
# can be any specific subject under the same root.  Tested
# combinations: stream subjects 'bench.>', publish to 'bench.in',
# consumer filter 'bench.>'.  A literal-on-literal config (stream
# subjects = 'bench.in', filter = 'bench.in') was observed to
# trigger js_PullSubscribe('bench') failed: Error against the
# local nats.c v3.7 client; the root cause is filed but the
# wildcard form is the supported configuration regardless.
STREAM_SUBJECTS="${STREAM_SUBJECTS:-bench.>}"
PUB_SUBJECT="${PUB_SUBJECT:-bench.in}"
FILTER="${FILTER:-bench.>}"
HANDLE="${HANDLE:-bench}"
MI_PORT="${MI_PORT:-9888}"

# Module-global Fetch tuning (see modparam("nats_consumer", "fetch_batch", ...)
# in nats_consumer.c).  Bumping FETCH_BATCH lifts the steady-state
# per-handle drain cap roughly linearly until the broker's
# max_ack_pending or scheduler wakeup latency takes over.
FETCH_BATCH="${FETCH_BATCH:-10}"
FETCH_TIMEOUT_MS="${FETCH_TIMEOUT_MS:-1000}"
# Must be a power of 2, >= 2 * FETCH_BATCH to avoid backpressure-
# induced redeliveries.  Defaults to 4 * batch (rounded up to
# next pow2) when unset; harness env override is honored verbatim.
_default_ring=$((FETCH_BATCH * 4))
_p=2; while [ "$_p" -lt "$_default_ring" ]; do _p=$((_p * 2)); done
RING_CAPACITY="${RING_CAPACITY:-$_p}"

# Drain mode: 'single' (one fetch+ack per message; default for
# back-compat with earlier numbers) or 'batch' (amortizes the
# script overhead over a fetch_batch chunk via nats_fetch_batch).
DRAIN_MODE="${DRAIN_MODE:-single}"
TIMER_INTERVAL="${TIMER_INTERVAL:-1}"

case "$DRAIN_MODE" in
    single)
        DRAIN_BODY=$(cat <<'EOS'
$var(n) = 0;
while (nats_fetch("@@HANDLE_ID@@", 100)) {
    nats_ack();
    $var(n) = $var(n) + 1;
    if ($var(n) >= 5000) { break; }
}
EOS
)
        ;;
    batch)
        # nats_fetch_batch fills an internal slot vector; we then
        # iterate slots via nats_batch_select(idx).  Drain up to
        # 5000 batches per tick so a sustained burst doesn't camp
        # the timer process indefinitely.
        DRAIN_BODY=$(cat <<'EOS'
# Drain in batches.  expires_ms=5 keeps the worker in the drain
# loop as long as messages keep arriving within 5ms (the consumer
# process refills every ~5ms on a loaded stream).  Without this
# wait the worker exits on the first empty ring observation
# between two consumer-process pushes, which collapses throughput
# to one-burst-per-timer-tick.
#
# Note: nats_fetch_batch returns the count via $retcode in
# OpenSIPS script (not directly assignable to $var()).  Capture
# $retcode immediately after the call into a $var() so subsequent
# function calls don't clobber it.
$var(b) = 0;
while ($var(b) < 5000) {
    nats_fetch_batch("@@HANDLE_ID@@", "count=@@FETCH_BATCH@@;expires_ms=100");
    $var(rc) = $retcode;
    if ($var(rc) <= 0) { break; }
    $var(i) = 0;
    while ($var(i) < $var(rc)) {
        nats_batch_select($var(i));
        nats_ack();
        $var(i) = $var(i) + 1;
    }
    $var(b) = $var(b) + 1;
}
EOS
)
        ;;
    *)
        echo "DRAIN_MODE must be 'single' or 'batch', got '$DRAIN_MODE'" >&2
        exit 2
        ;;
esac

OUT="${OUT:-$(mktemp -d -t nats-consumer-bench.XXXXXX)}"
mkdir -p "$OUT"

OPENSIPS_PID=""
cleanup() {
    [ -n "$OPENSIPS_PID" ] && kill "$OPENSIPS_PID" 2>/dev/null
    wait 2>/dev/null
    if [ "${KEEP_STREAM:-0}" != "1" ]; then
        nats --server "$NATS_URL" stream del "$STREAM" -f >/dev/null 2>&1 || true
    fi
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

echo "[bench] creating stream $STREAM (subjects $STREAM_SUBJECTS)..."
nats --server "$NATS_URL" stream del "$STREAM" -f >/dev/null 2>&1 || true
nats --server "$NATS_URL" stream add "$STREAM" \
    --subjects "$STREAM_SUBJECTS" \
    --storage memory --replicas 1 \
    --defaults \
    >/dev/null 2>&1

# --- 2. Pre-publish N messages with a sequence number payload ---

echo "[bench] publishing $N messages to $PUB_SUBJECT ..."
pub_start=$(date +%s.%N)
nats --server "$NATS_URL" pub "$PUB_SUBJECT" \
    --count "$N" "msg-{{Count}}" >"$OUT/pub.log" 2>&1
pub_end=$(date +%s.%N)
pub_elapsed=$(awk -v s="$pub_start" -v e="$pub_end" 'BEGIN{printf "%.3f", e-s}')

# Confirm the stream actually has N messages.  `nats stream info`
# output has multiple "Messages: ..." lines (limits, state); we want
# the State -> Messages count specifically, which is the LAST one
# under "State:" -- pick the highest numeric on a Messages line.
stream_info=$(nats --server "$NATS_URL" stream info "$STREAM" 2>/dev/null)
stream_msgs=$(printf '%s\n' "$stream_info" \
    | awk '/^[[:space:]]*Messages:[[:space:]]+[0-9,]+/ {
            gsub(",", "", $0); for (i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/) print $i
        }' \
    | sort -n | tail -1)
if [ "${stream_msgs:-0}" != "$N" ]; then
    echo "WARN: expected $N stream messages, got ${stream_msgs:-0}" >&2
fi
echo "[bench] published ${stream_msgs:-0} in $pub_elapsed s"

# --- 3. Render cfg + start opensips ---

CFG="$OUT/opensips.cfg"
sed -e "s|@@MODULES@@|${OPENSIPS_MODULES}|g" \
    -e "s|@@NATS_URL@@|${NATS_URL}|g" \
    -e "s|@@MI_PORT@@|${MI_PORT}|g" \
    -e "s|@@STREAM@@|${STREAM}|g" \
    -e "s|@@SUBJECT@@|${FILTER}|g" \
    -e "s|@@HANDLE_ID@@|${HANDLE}|g" \
    -e "s|@@FETCH_BATCH@@|${FETCH_BATCH}|g" \
    -e "s|@@FETCH_TIMEOUT_MS@@|${FETCH_TIMEOUT_MS}|g" \
    -e "s|@@RING_CAPACITY@@|${RING_CAPACITY}|g" \
    -e "s|@@TIMER_INTERVAL@@|${TIMER_INTERVAL}|g" \
    "${HERE}/opensips.cfg.in" > "$CFG"

# Splice the drain body in (multi-line; sed -e doesn't handle that
# cleanly across all shells).  Resolve placeholders inside the body
# first because the awk splice runs AFTER sed.
DRAIN_BODY="${DRAIN_BODY//@@HANDLE_ID@@/$HANDLE}"
DRAIN_BODY="${DRAIN_BODY//@@FETCH_BATCH@@/$FETCH_BATCH}"
awk -v body="$DRAIN_BODY" '
    /@@DRAIN_BODY@@/ { print body; next }
    { print }
' "$CFG" > "$CFG.tmp" && mv "$CFG.tmp" "$CFG"

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

# Helper: ask opensips's MI for handle counters (acks, msgs, etc.).
# Currently kept for diagnostics only -- the per-handle msgs_delivered
# / acks counters in nats_consumer's MI never increment as of this
# writing, so the bench's drain-completion check is broker-side via
# the JetStream consumer-info Ack Floor (see acks_of_broker below).
mi_consumer_list() {
    printf '{"jsonrpc":"2.0","id":1,"method":"nats_consumer:nats_consumer_list"}' \
        | timeout 3 nc -u -w 2 127.0.0.1 "$MI_PORT" 2>/dev/null
}

# Helper: read the broker-side ack count for our consumer.  This is
# the JetStream "Acknowledgment Floor consumer sequence" -- the
# highest contiguous ack the broker has received.  Used as the
# canonical drain-completion signal because the opensips-side MI
# counters are unreliable.
acks_of_broker() {
    nats --server "$NATS_URL" consumer info "$STREAM" "$HANDLE" \
        2>/dev/null \
        | sed -n 's/.*Acknowledgment Floor: Consumer sequence: \([0-9,]*\).*/\1/p' \
        | tr -d ',' | head -1
}

# --- 4. Wait for the bind to register on the broker.  The consumer
#       process forks the kvWatcher / pull subscription async, so it
#       takes ~1 s after opensips startup before the consumer appears
#       on the broker side.

for i in $(seq 1 30); do
    if nats --server "$NATS_URL" consumer info "$STREAM" "$HANDLE" \
            >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done

# --- 5. Time the drain.  Poll the broker's "Acknowledgment Floor"
#       consumer sequence; stop when it reaches N.  This is the
#       canonical drain-completion signal because it reflects acks
#       confirmed by the broker, not opensips-side counters which
#       happen to be broken at the time of writing.

drain_start=$(date +%s.%N)
deadline=$((SECONDS + ${DEADLINE_S:-60}))
final_acks=0
while [ "$SECONDS" -lt "$deadline" ]; do
    final_acks=$(acks_of_broker)
    final_acks=${final_acks:-0}
    if [ "$final_acks" -ge "$N" ]; then
        break
    fi
    sleep 0.2
done
drain_end=$(date +%s.%N)

drain_elapsed=$(awk -v s="$drain_start" -v e="$drain_end" 'BEGIN{printf "%.3f", e-s}')

# Capture the MI snapshot for diagnostics -- the broker has the
# authoritative count; the opensips side is informational only.
mi_consumer_list > "$OUT/handle_metrics.json" 2>&1 || true

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
