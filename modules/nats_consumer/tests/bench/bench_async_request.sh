#!/bin/bash
# bench_async_request.sh -- throughput / latency bench for
# `async(nats_request(...), rt)` from a SIP-driven route.
#
# What it measures
#   - End-to-end OPTIONS round-trip latency: SIP UA -> opensips
#     -> NATS broker -> responder -> NATS broker -> opensips ->
#     SIP UA.  All under a single OpenSIPS worker so the bench
#     directly exercises the per-worker in-flight scaling that
#     the async path enables.
#
#   - Concurrency: with sync nats_request, one worker can hold
#     exactly one in-flight RPC at a time -- throughput is
#     1 / RTT.  With async, a worker yields on each call and
#     services other SIP requests while replies are in flight,
#     so the practical ceiling is the smaller of (broker
#     throughput, responder concurrency, NATS_RPC_ASYNC_MAX_INFLIGHT).
#
# What it doesn't measure
#   - The sync path's actual blocking behaviour from
#     request_route -- the default route mask refuses it, and we
#     would have to set `allow_sync_anywhere=1` and explicitly
#     stall the worker.  Skipped here on purpose; the async path
#     is the one operators are meant to use.
#
# Topology
#
#   sipp -i 127.0.0.1 (driver, configurable rate / call count)
#       |
#       v UDP 5070
#   opensips (this cfg, udp_workers=1 by default)
#       |
#       v NATS request on @@RPC_SUBJECT@@
#   NATS broker
#       |
#       v subscriber
#   responder (`nats reply` CLI with a configurable delay)
#       ^
#       | reply
#   ... reply path symmetric ...
#
# Output
#   $OUT/opensips.log         OpenSIPS stdout/stderr
#   $OUT/responder.log        nats reply stdout
#   $OUT/sipp_stats.csv       sipp -trace_stat stats
#   $OUT/bench.summary        one-line summary printed to stdout too
#
# Env knobs
#   N=1000                Number of OPTIONS to send.
#   CPS=100               Calls per second (sipp -r).
#   RESPONDER_DELAY_MS=0  Sleep duration on the responder before
#                         replying (controls how many in-flight
#                         calls a worker has to manage).  Higher
#                         values = more concurrency required.
#   RPC_TIMEOUT_MS=500    Per-call timeout passed to nats_request.
#   UDP_WORKERS=1         How many UDP workers opensips runs with.
#                         1 isolates the per-worker scaling test;
#                         bump for sustained-RPS tests.
#   SIP_PORT=5070         OpenSIPS UDP port.
#   MI_PORT=8880          OpenSIPS MI datagram port.
#   RPC_SUBJECT=rpc.bench Subject the responder is subscribed to.
#   NATS_URL=...          Broker URL.
#   OUT=...               Output directory (default mktemp).
#
# Exit 0 = success, 1 = bench reported failures, 77 = prereqs
# missing.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
TREE_ROOT="$(cd "${HERE}/../../../.." && pwd)"

OPENSIPS_BIN="${OPENSIPS_BIN:-${TREE_ROOT}/opensips}"
OPENSIPS_LIB_NATS="${OPENSIPS_LIB_NATS:-${TREE_ROOT}/lib/nats}"
OPENSIPS_MODULES="${OPENSIPS_MODULES:-${TREE_ROOT}/_modules}"

NATS_URL="${NATS_URL:-nats://127.0.0.1:4222}"

N="${N:-1000}"
CPS="${CPS:-100}"
RESPONDER_DELAY_MS="${RESPONDER_DELAY_MS:-0}"
RPC_TIMEOUT_MS="${RPC_TIMEOUT_MS:-500}"
UDP_WORKERS="${UDP_WORKERS:-1}"
SIP_PORT="${SIP_PORT:-5070}"
MI_PORT="${MI_PORT:-8880}"
RPC_SUBJECT="${RPC_SUBJECT:-rpc.bench}"

OUT="${OUT:-$(mktemp -d -t nats-async-request-bench.XXXXXX)}"
mkdir -p "$OUT"

OPENSIPS_PID=""
RESPONDER_PID=""

cleanup() {
    [ -n "$OPENSIPS_PID" ]  && kill "$OPENSIPS_PID"  2>/dev/null
    [ -n "$RESPONDER_PID" ] && kill "$RESPONDER_PID" 2>/dev/null
    wait 2>/dev/null
}
trap cleanup EXIT

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing prerequisite: $1"; exit 77;
    }
}
need nats
need sipp

[ -x "$OPENSIPS_BIN" ]     || { echo "no opensips binary: $OPENSIPS_BIN"; exit 77; }
[ -d "$OPENSIPS_MODULES" ] || { echo "no modules dir:    $OPENSIPS_MODULES"; exit 77; }
[ -e "$OPENSIPS_MODULES/nats_consumer.so" ] || {
    echo "no nats_consumer.so in $OPENSIPS_MODULES"; exit 77;
}

nats --server "$NATS_URL" server check connection >/dev/null 2>&1 || {
    echo "NATS broker unreachable: $NATS_URL"; exit 77;
}

####### render opensips cfg #####################################

CFG="$OUT/opensips.cfg"
sed -e "s|@@MODULES@@|${OPENSIPS_MODULES}|g" \
    -e "s|@@SIP_PORT@@|${SIP_PORT}|g" \
    -e "s|@@MI_PORT@@|${MI_PORT}|g" \
    -e "s|@@RPC_SUBJECT@@|${RPC_SUBJECT}|g" \
    -e "s|@@RPC_TIMEOUT@@|${RPC_TIMEOUT_MS}|g" \
    -e "s|@@UDP_WORKERS@@|${UDP_WORKERS}|g" \
    -e "s|@@NATS_URL@@|${NATS_URL}|g" \
    "${HERE}/opensips_async_request.cfg.in" > "$CFG"

####### start responder #########################################
#
# `nats reply` echoes the request body back with an optional sleep
# in between.  --command runs a shell snippet per request, so we
# can sleep RESPONDER_DELAY_MS to simulate a slow upstream.

RESPONDER_LOG="$OUT/responder.log"
{
    if [ "$RESPONDER_DELAY_MS" -gt 0 ]; then
        nats --server "$NATS_URL" reply "$RPC_SUBJECT" \
            --command "bash -c 'sleep $(awk -v m=$RESPONDER_DELAY_MS 'BEGIN{printf \"%.3f\", m/1000}'); echo pong'" \
            >> "$RESPONDER_LOG" 2>&1
    else
        nats --server "$NATS_URL" reply "$RPC_SUBJECT" "pong" \
            >> "$RESPONDER_LOG" 2>&1
    fi
} &
RESPONDER_PID=$!
# give it a moment to subscribe
sleep 1

####### boot opensips ###########################################

OPENSIPS_LOG="$OUT/opensips.log"
LD_LIBRARY_PATH="${OPENSIPS_LIB_NATS}:/usr/local/lib:${LD_LIBRARY_PATH:-}" \
    "$OPENSIPS_BIN" -F -f "$CFG" -s HP_MALLOC -m 256 -M 8 > "$OPENSIPS_LOG" 2>&1 &
OPENSIPS_PID=$!
sleep 2
if ! kill -0 "$OPENSIPS_PID" 2>/dev/null; then
    echo "FATAL: opensips failed to boot"; tail -30 "$OPENSIPS_LOG" >&2
    exit 1
fi

####### drive with sipp #########################################
#
# sipp has no built-in OPTIONS scenario, so we render a minimal
# XML one inline: send OPTIONS, wait for any response 200-5xx,
# done.  No ACK / BYE traffic so the timing is purely the
# end-to-end async RPC latency.
#
# Previous revisions of this scenario marked EVERY <recv> as
# optional="true".  That left sipp with no mandatory state to
# block on, so every call stayed in CurrentCall forever; sipp
# hit its internal open-call ceiling (~150) and stopped placing
# new calls long before reaching -m N.  Fix: the 200 recv is
# mandatory (happy path); 503/504 are handled via next-branch
# labels so a server-side failure response still terminates the
# call cleanly and is counted as Failed by sipp.

SIPP_SCENARIO="$OUT/options_uac.xml"
cat > "$SIPP_SCENARIO" <<'XML'
<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="options-uac">
  <!-- start_rtd="1" starts response-time-duration counter 1 on
       the outbound send; the matching rtd="1" on the recv
       records the elapsed time into ResponseTime1.  Without the
       start_rtd, rtd on recv has nothing to subtract from and
       sipp records 0. -->
  <send start_rtd="1">
    <![CDATA[
      OPTIONS sip:bench@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/UDP [local_ip]:[local_port];branch=[branch]
      From: sipp <sip:sipp@[local_ip]>;tag=[call_number]
      To: bench <sip:bench@[remote_ip]:[remote_port]>
      Call-ID: [call_id]
      CSeq: 1 OPTIONS
      Contact: sip:sipp@[local_ip]:[local_port]
      Max-Forwards: 70
      Content-Length: 0

    ]]>
  </send>

  <!-- Failure branches first.  Each is optional so it doesn't
       block the happy path; if any of them matches the inbound
       response, sipp counts the call as Failed and the scenario
       ends. -->
  <recv response="504" optional="true" rtd="1" next="failed" />
  <recv response="503" optional="true" rtd="1" next="failed" />
  <recv response="500" optional="true" rtd="1" next="failed" />
  <recv response="405" optional="true" rtd="1" next="failed" />

  <!-- Happy path: mandatory 200 OK.  This is what gives sipp a
       state to block on so the call actually terminates instead
       of sitting in CurrentCall forever. -->
  <recv response="200" rtd="1" />

  <label id="failed" />
</scenario>
XML

SIPP_STATS_BASE="$OUT/sipp"
echo
echo "================================================================"
echo "  nats_consumer async-request bench"
echo "    N             $N"
echo "    CPS           $CPS"
echo "    responder dly ${RESPONDER_DELAY_MS} ms"
echo "    rpc tmo       ${RPC_TIMEOUT_MS} ms"
echo "    udp_workers   $UDP_WORKERS"
echo "    rpc subject   $RPC_SUBJECT"
echo "    out           $OUT"
echo "================================================================"

sipp -i 127.0.0.1 -p 0 \
     -sf "$SIPP_SCENARIO" \
     -m "$N" -r "$CPS" -rp 1000 \
     -trace_stat -stf "${SIPP_STATS_BASE}_stats.csv" \
     -fd 1 \
     -trace_screen -screen_file "${SIPP_STATS_BASE}_screen.log" \
     "127.0.0.1:${SIP_PORT}" > "${SIPP_STATS_BASE}_run.log" 2>&1
SIPP_RC=$?

####### parse + report ##########################################

# sipp's stats CSV columns use "(P)" and "(C)" suffixes for the
# periodic and cumulative variants of each counter.  We always
# want the cumulative final-row value.
#
# RTT: sipp exports only a single ResponseTime1(C) column -- a
# rolling average -- not min/avg/max.  -trace_rtt has a buffer-
# overflow bug in the bundled sipp build, so we don't use it.
# The summary reports the rolling-average alone, which is enough
# to characterise the workload.  Format is HH:MM:SS:microseconds;
# we normalise to "Xs Yms" for readability.

normalise_rtd() {
    # input "HH:MM:SS:uuuuuu" -> "<milliseconds>ms"
    local raw="$1"
    [ -z "$raw" ] && { echo "n/a"; return; }
    echo "$raw" | awk -F: '{
        if (NF != 4) { print "n/a"; exit }
        ms = $1*3600000 + $2*60000 + $3*1000 + $4/1000;
        if (ms < 10) printf "%.3fms\n", ms;
        else         printf "%.1fms\n", ms;
    }'
}

STATS_CSV="${SIPP_STATS_BASE}_stats.csv"
SUCCEED="n/a"; FAILED="n/a"; UNEXPECTED="n/a"; RT_AVG="n/a"
if [ -s "$STATS_CSV" ]; then
    HEADER=$(head -1 "$STATS_CSV")
    LAST=$(tail -1 "$STATS_CSV")
    col() {
        local name="$1"
        echo "$HEADER" | awk -F';' -v n="$name" '{
            for (i=1; i<=NF; i++) if ($i == n) { print i; exit } }'
    }
    PICK() {
        local i; i=$(col "$1")
        [ -n "$i" ] || { echo ""; return; }
        echo "$LAST" | awk -F';' -v i="$i" '{ print $i }'
    }

    SUCCEED=$(PICK "SuccessfulCall(C)")
    FAILED=$(PICK "FailedCall(C)")
    UNEXPECTED=$(PICK "FailedUnexpectedMessage(C)")
    RT_AVG=$(normalise_rtd "$(PICK "ResponseTime1(C)")")
fi

# OpenSIPS-side counters: errors / timeouts surface as non-2xx
# return paths in our cfg.  Count occurrences in the log.  grep -c
# emits its own "0" on no match and exits 1, so the "|| echo 0"
# fallback used to double-print -- pipe through head -1 to keep
# the value single-line.
TIMEOUTS=$(grep -c "504 Gateway Timeout"     "$OPENSIPS_LOG" 2>/dev/null | head -1)
BROKER_DN=$(grep -c "503 Broker Unavailable" "$OPENSIPS_LOG" 2>/dev/null | head -1)
INTERNAL=$(grep -c  "500 Internal Server"    "$OPENSIPS_LOG" 2>/dev/null | head -1)
TIMEOUTS=${TIMEOUTS:-0}
BROKER_DN=${BROKER_DN:-0}
INTERNAL=${INTERNAL:-0}

cat > "$OUT/bench.summary" <<EOF
N=${N} CPS=${CPS} responder_delay_ms=${RESPONDER_DELAY_MS}
RPC_TIMEOUT=${RPC_TIMEOUT_MS}ms UDP_WORKERS=${UDP_WORKERS}
sipp_rc=${SIPP_RC} succeed=${SUCCEED} failed=${FAILED} unexpected=${UNEXPECTED}
sip_rtt_avg=${RT_AVG}
opensips_timeouts=${TIMEOUTS} broker_dn=${BROKER_DN} internal=${INTERNAL}
EOF
cat "$OUT/bench.summary"

# Bench is successful if sipp itself didn't fail.  Counter-style
# concurrency / latency interpretation is left to the operator
# (or a downstream parser of sipp_stats.csv).
[ "$SIPP_RC" = 0 ] && exit 0
exit 1
