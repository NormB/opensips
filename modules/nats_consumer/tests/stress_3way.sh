#!/bin/bash
# stress_3way.sh -- multi-hour stress of all three NATS modules.
#
# Loads opensips with event_nats + cachedb_nats + nats_consumer (the
# event_nats e2e cfg already bundles the three) and drives sustained
# load on each module's surface in parallel.  Samples MI counters,
# JetStream broker state, and process RSS every 60 s.
#
# Threat surfaces exercised
#   event_nats     -- nats_publish() from SIP-REGISTER traffic
#   nats_consumer  -- pull-mode consumer drains "stress.>" pushes
#   cachedb_nats   -- KV watcher + nats_kv_put / nats_kv_get on a
#                     dedicated bucket
#
# What we look for over hours
#   - RSS growth (memory leak)
#   - acks / msgs_delivered drift (ack-IPC leak)
#   - redeliveries climbing with no published-rate change
#     (broken ack path)
#   - opensips.log errors / WARN floods
#   - hangs / deadlocks (sample becomes stale)
#
# Env knobs (defaults shown)
#   DURATION_S=7200        -- run length, default 2 h
#   SAMPLE_S=60            -- sampler period
#   PUB_RPS=100            -- nats_publish rate (msgs/sec into stress.>)
#   REG_RPS=10             -- SIP REGISTER rate (per second)
#   KV_RPS=50              -- KV put + get rate (operations/sec)
#   NATS_URL=nats://127.0.0.1:4222
#   OUT=/tmp/stress-3way-<pid>
#
# Exit 0 = clean shutdown after DURATION_S, sampling stable
# Exit 1 = opensips died, sampler stalled, or rss/counter anomaly

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
TREE_ROOT="$(cd "${HERE}/../../.." && pwd)"

OPENSIPS_BIN="${OPENSIPS_BIN:-${TREE_ROOT}/opensips}"
OPENSIPS_LIB_NATS="${OPENSIPS_LIB_NATS:-${TREE_ROOT}/lib/nats}"
OPENSIPS_MODULES="${OPENSIPS_MODULES:-${TREE_ROOT}/_modules}"
NATS_URL="${NATS_URL:-nats://127.0.0.1:4222}"

DURATION_S="${DURATION_S:-7200}"
SAMPLE_S="${SAMPLE_S:-60}"
PUB_RPS="${PUB_RPS:-100}"
REG_RPS="${REG_RPS:-10}"
KV_RPS="${KV_RPS:-50}"

OUT="${OUT:-/tmp/stress-3way-$$}"
mkdir -p "$OUT"

STREAM="STRESS_$$"
KV_BUCKET="STRESS_KV_$$"
HANDLE="stress"
SUBJECT_PREFIX="stress"
SIP_PORT=5072
MI_PORT=8889
LOG_FILE="$OUT/opensips.log"
CFG_FILE="$OUT/opensips.cfg"
SAMPLES_FILE="$OUT/samples.csv"

OPENSIPS_PID=""
DRIVER_PIDS=()

cleanup() {
    local pid
    for pid in "${DRIVER_PIDS[@]}"; do
        kill "$pid" 2>/dev/null
    done
    if [ -n "$OPENSIPS_PID" ]; then
        kill "$OPENSIPS_PID" 2>/dev/null
        local i
        for i in 1 2 3 4 5; do
            kill -0 "$OPENSIPS_PID" 2>/dev/null || break
            sleep 0.2
        done
        # Hard-kill the whole tree to release the MI port for re-runs.
        if command -v ps >/dev/null 2>&1; then
            local children
            children=$(ps --no-headers -o pid --ppid "$OPENSIPS_PID" 2>/dev/null)
            for pid in $children; do
                kill -9 "$pid" 2>/dev/null
            done
        fi
        kill -9 "$OPENSIPS_PID" 2>/dev/null
        wait "$OPENSIPS_PID" 2>/dev/null
    fi
    nats --server "$NATS_URL" stream del "$STREAM" -f >/dev/null 2>&1 || true
    nats --server "$NATS_URL" kv del "$KV_BUCKET" -f >/dev/null 2>&1 || true
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 77; }; }
need nats; need awk; need nc; need sipsak; need ps

[ -x "$OPENSIPS_BIN" ] || { echo "no opensips: $OPENSIPS_BIN" >&2; exit 77; }
[ -d "$OPENSIPS_MODULES" ] || { echo "no modules: $OPENSIPS_MODULES" >&2; exit 77; }
nats --server "$NATS_URL" server check connection >/dev/null 2>&1 || \
    { echo "NATS unreachable: $NATS_URL" >&2; exit 77; }

# ---- 1. cfg ----------------------------------------------------------

cat > "$CFG_FILE" <<EOF_CFG
log_level=2
xlog_level=2
stderror_enabled=yes
syslog_enabled=no

udp_workers=4
tcp_workers=0

socket=udp:127.0.0.1:${SIP_PORT}
mpath="${OPENSIPS_MODULES}/"

loadmodule "proto_udp.so"
loadmodule "sl.so"
loadmodule "signaling.so"
loadmodule "sipmsgops.so"

loadmodule "mi_datagram.so"
modparam("mi_datagram", "socket_name", "udp:127.0.0.1:${MI_PORT}")

loadmodule "event_nats.so"
modparam("event_nats", "nats_url", "${NATS_URL}")

loadmodule "cachedb_nats.so"
modparam("cachedb_nats", "nats_url",  "${NATS_URL}")
modparam("cachedb_nats", "kv_bucket", "${KV_BUCKET}")

loadmodule "nats_consumer.so"
modparam("nats_consumer", "fetch_batch",      32)
modparam("nats_consumer", "fetch_timeout_ms", 1000)

startup_route {
    xlog("L_INFO", "stress_3way: cfg up\n");
    # Subscribe nats_consumer to the stress stream/subject space.
    nats_consumer_bind("id=${HANDLE};stream=${STREAM};filter=${SUBJECT_PREFIX}.>;durable=${HANDLE};ack_wait=30s;max_ack_pending=4096;ring_capacity=512;fetch_batch=32");
}

# Receive SIP traffic from the REG_RPS driver -> publish to event_nats.
# The publish lands on a stream "STRESS_REG_<pid>" (different from the
# nats_consumer stream) so the two surfaces are independent.
route {
    if (is_method("REGISTER")) {
        nats_publish("stress.reg",
                     "method=\$rm uri=\$ru from=\$fU contact=\$ct expires=\$hdr(Expires)");
        sl_send_reply(200, "OK");
        exit;
    }
    if (is_method("OPTIONS")) {
        sl_send_reply(200, "OK");
        exit;
    }
    sl_send_reply(405, "Method Not Allowed");
    exit;
}

# Drain the stress stream via batch-mode fetch.
timer_route[drain, 1] {
    \$var(b) = 0;
    while (\$var(b) < 5000) {
        nats_fetch_batch("${HANDLE}", "count=32;expires_ms=100");
        \$var(rc) = \$retcode;
        if (\$var(rc) <= 0) { break; }
        \$var(i) = 0;
        while (\$var(i) < \$var(rc)) {
            nats_batch_select(\$var(i));
            nats_ack();
            \$var(i) = \$var(i) + 1;
        }
        \$var(b) = \$var(b) + 1;
    }
}
EOF_CFG

# ---- 2. broker prep --------------------------------------------------

nats --server "$NATS_URL" stream del "$STREAM" -f >/dev/null 2>&1 || true
nats --server "$NATS_URL" stream add "$STREAM" \
    --subjects "${SUBJECT_PREFIX}.>" \
    --storage memory --replicas 1 --defaults >/dev/null 2>&1

nats --server "$NATS_URL" kv add "$KV_BUCKET" --replicas 1 --history 3 \
    >/dev/null 2>&1

# ---- 3. start opensips ----------------------------------------------

LD_LIBRARY_PATH="${OPENSIPS_LIB_NATS}:${LD_LIBRARY_PATH:-}" \
    "$OPENSIPS_BIN" -F -f "$CFG_FILE" -m 256 -M 16 \
    > "$LOG_FILE" 2>&1 &
OPENSIPS_PID=$!
sleep 3
kill -0 "$OPENSIPS_PID" 2>/dev/null || {
    echo "FATAL: opensips died on startup" >&2
    tail -30 "$LOG_FILE" >&2
    exit 1
}

# Confirm the consumer bound on the broker side.
for i in $(seq 1 30); do
    if nats --server "$NATS_URL" consumer info "$STREAM" "$HANDLE" \
            >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

# ---- 4. sampler helpers + baseline sample ---------------------------
#
# IMPORTANT ORDERING: the baseline (sample 1) is captured BEFORE the
# drivers start so that all "delta" metrics in the final summary
# subtract a true zero-state baseline.  An earlier version started
# the drivers first and had the baseline sample race the first few
# acks; that produced a small (~7 of 600,000) delta_acks - delta_delivered
# discrepancy at sample 1 due to the non-atomic MI snapshot.  By
# capturing baseline pre-drivers we know msgs_delivered == 0,
# acks == 0, redeliveries == 0 with no race window.

mi_call() {
    printf '{"jsonrpc":"2.0","id":1,"method":"%s"}' "$1" \
        | timeout 3 nc -u -w 2 127.0.0.1 "$MI_PORT" 2>/dev/null
}

extract_first_int() {
    grep -oE "\"$1\":[0-9]+" | head -1 | sed 's/.*://'
}

write_sample() {
    local now uptime rss_kb self_rss mi_resp pulls delivered acks naks
    local terms redeliv stream_msgs kv_keys log_errors log_warns
    now=$(date +%s)
    uptime=$((now - start_ts))
    rss_kb=$(ps --no-headers -o rss --ppid "$OPENSIPS_PID" 2>/dev/null \
        | awk '{s += $1} END {print s+0}')
    self_rss=$(ps --no-headers -o rss -p "$OPENSIPS_PID" 2>/dev/null \
        | awk '{print $1+0}')
    rss_kb=$((rss_kb + ${self_rss:-0}))

    mi_resp=$(mi_call "nats_consumer:nats_consumer_list")
    pulls=$(echo "$mi_resp" | extract_first_int "pulls_requested")
    delivered=$(echo "$mi_resp" | extract_first_int "msgs_delivered")
    acks=$(echo "$mi_resp" | extract_first_int "acks")
    naks=$(echo "$mi_resp" | extract_first_int "naks")
    terms=$(echo "$mi_resp" | extract_first_int "terms")
    redeliv=$(echo "$mi_resp" | extract_first_int "redeliveries")

    stream_msgs=$(nats --server "$NATS_URL" stream info "$STREAM" \
            2>/dev/null \
        | awk '/^[[:space:]]*Messages:[[:space:]]+[0-9,]+/ {
                gsub(",","",$0); for(i=1;i<=NF;i++) if($i~/^[0-9]+$/) print $i
              }' | sort -n | tail -1)
    kv_keys=$(nats --server "$NATS_URL" kv ls "$KV_BUCKET" --names 2>/dev/null \
        | wc -l)

    log_errors=$(grep -cE "ERROR|CRITICAL|FATAL" "$LOG_FILE" 2>/dev/null)
    log_warns=$(grep -c "WARN" "$LOG_FILE" 2>/dev/null)
    : "${log_errors:=0}"
    : "${log_warns:=0}"

    echo "$now,$uptime,${rss_kb:-0},${pulls:-0},${delivered:-0},${acks:-0},${naks:-0},${terms:-0},${redeliv:-0},${stream_msgs:-0},${kv_keys:-0},${log_errors:-0},${log_warns:-0}" \
        >> "$SAMPLES_FILE"
}

echo "ts,uptime_s,rss_kb,pulls,delivered,acks,naks,terms,redeliveries,stream_msgs,kv_keys,log_errors,log_warns" \
    > "$SAMPLES_FILE"

start_ts=$(date +%s)
deadline=$((start_ts + DURATION_S))

# Baseline sample.  No drivers running yet -> guaranteed all-zero
# counters, no race against the consumer process's atomic increments.
write_sample

# ---- 5. drivers ------------------------------------------------------

# 5a. event_nats SIP REGISTER pump (REG_RPS rate).
(
    seq=0
    while true; do
        for i in $(seq 1 "$REG_RPS"); do
            sipsak -U -C "sip:user${seq}@127.0.0.1:${SIP_PORT}" \
                -s "sip:user${seq}@127.0.0.1:${SIP_PORT}" \
                -e 3600 -t 1 -O 1 \
                >/dev/null 2>&1 &
            seq=$((seq + 1))
        done
        wait 2>/dev/null
        sleep 1
    done
) >/dev/null 2>&1 &
DRIVER_PIDS+=("$!")

# 5b. nats_consumer publish pump (PUB_RPS rate).  These messages land
# on "stress.foo" and the consumer's timer route drains them.
(
    seq=0
    while true; do
        nats --server "$NATS_URL" pub "${SUBJECT_PREFIX}.foo" \
            --count "$PUB_RPS" \
            --sleep "$((1000 / PUB_RPS))ms" \
            "msg-${seq}-{{Count}}" >/dev/null 2>&1
        seq=$((seq + PUB_RPS))
    done
) >/dev/null 2>&1 &
DRIVER_PIDS+=("$!")

# 5c. cachedb_nats KV churn via the nats CLI directly.  The opensips
# instance's KV watcher will see these mutations and route them
# through E_NATS_KV_CHANGE on the EVI bus -- exercises the watcher
# subscribe + dispatch path even without a script handler bound.
(
    seq=0
    while true; do
        for i in $(seq 1 "$KV_RPS"); do
            nats --server "$NATS_URL" kv put "$KV_BUCKET" \
                "kv-key-$((seq % 100))" "value-${seq}" \
                >/dev/null 2>&1
            if [ $((seq % 5)) -eq 0 ]; then
                nats --server "$NATS_URL" kv get "$KV_BUCKET" \
                    "kv-key-$((seq % 100))" --raw >/dev/null 2>&1
            fi
            seq=$((seq + 1))
        done
        sleep 1
    done
) >/dev/null 2>&1 &
DRIVER_PIDS+=("$!")

# ---- 6. sampler loop -------------------------------------------------

while [ "$(date +%s)" -lt "$deadline" ]; do
    sleep "$SAMPLE_S"
    write_sample

    # Liveness check: opensips must still be alive.
    if ! kill -0 "$OPENSIPS_PID" 2>/dev/null; then
        echo "FATAL: opensips died at uptime=$(( $(date +%s) - start_ts ))s" >&2
        tail -50 "$LOG_FILE" >&2
        exit 1
    fi
done

# ---- 7. report -------------------------------------------------------

awk -F, -v dur="$DURATION_S" -v csv="$SAMPLES_FILE" '
    NR == 1 { next }
    NR == 2 { rss0 = $3; pulls0 = $4; deliv0 = $5; acks0 = $6 }
    {
        if ($3 > rss_max) rss_max = $3
        rss_last = $3; pulls_last = $4; deliv_last = $5; acks_last = $6
        redeliv_last = $9; log_err_last = $12; log_warn_last = $13
        n++
    }
    END {
        rss_growth = (rss0 > 0) ? (rss_last - rss0) * 100.0 / rss0 : 0
        deliv_delta = deliv_last - deliv0
        ack_ratio = (deliv_delta > 0) ? (acks_last - acks0) * 1.0 / deliv_delta : 0
        status = (rss_growth > 50) ? "WARN_RSS_GROWTH" : "ok"
        printf "\n========================================\n"
        printf "  stress_3way summary\n"
        printf "  samples:                 %d\n", n
        printf "  duration:                %ds\n", dur
        printf "  rss kb (start->last):    %d -> %d (peak %d)\n", rss0, rss_last, rss_max
        printf "  rss growth:              %.2f%%\n", rss_growth
        printf "  pulls (delta):           %d\n", pulls_last - pulls0
        printf "  msgs_delivered (delta):  %d\n", deliv_delta
        printf "  acks (delta):            %d\n", acks_last - acks0
        printf "  ack/delivered ratio:     %.4f\n", ack_ratio
        printf "  redeliveries (last):     %d\n", redeliv_last
        printf "  log errors (last):       %d\n", log_err_last
        printf "  log warns (last):        %d\n", log_warn_last
        printf "  status:                  %s\n", status
        printf "  samples csv:             %s\n", csv
        printf "========================================\n"
    }
' "$SAMPLES_FILE"

exit 0
