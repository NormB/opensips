#!/bin/bash
#
# selftest_harness.sh -- hermetic self-tests for the nats_consumer
# integration harness itself (lib.sh + the stress helpers).  No docker,
# broker or opensips needed: docker is replaced by a stub on PATH and the
# stress report is driven from fixture files.
#
# Pins:
#   1. ensure_stack SKIPS (77) promptly when the compose stack is down.
#      `docker compose ps --format json` exits 0 with no output when
#      nothing runs, so a check built on its exit status can never fire;
#      the stack must be detected from the running opensips container.
#   2. ensure_stack returns 0 when the stack is up and the MI FIFO exists.
#   3. stress_3way's RSS verdict ignores the start-up warm-up: a jump in
#      the first minute that then stays flat is "ok"; steady growth after
#      warm-up is still WARN_RSS_GROWTH; a run too short to have a
#      post-warm-up sample falls back to the first sample.
#   4. stress_3way's log-error count ignores the harness's own
#      "core limits increased only to 0" notice (it sets ulimit -c 0) but
#      still counts real ERROR/CRITICAL/FATAL lines.
#   5. stress_multi_worker rides out one failed MI poll (a docker exec
#      that fails on a loaded host) instead of dying silently under
#      set -e, and on a real failure says why and dumps the handle.
#   6. stop_driver (stress_helpers.sh) stops a load-driver loop together
#      with the command it is running: killing only the loop orphaned its
#      in-flight `nats pub`, which outlived the nightly batch.
#
# Exit 0 iff every check passes.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d -t nc_selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
FAILS=0

check() {  # check <description> <expected> <actual>
    if [ "$2" = "$3" ]; then
        echo "  ok: $1"
    else
        echo "  FAIL: $1 (expected '$2', got '$3')"
        FAILS=$((FAILS + 1))
    fi
}

# ---- docker stub --------------------------------------------------------
# FAKE_STACK=down : compose ps prints nothing (exit 0), exec fails
# FAKE_STACK=up   : compose ps -q prints a container id, exec succeeds
mkdir -p "$WORK/bin"
cat > "$WORK/bin/docker" <<'STUB'
#!/bin/sh
[ "$1" = info ] && exit 0
if [ "$1" = compose ]; then
    for a in "$@"; do
        case "$a" in
        ps)   [ "${FAKE_STACK:-down}" = up ] && echo "0123456789ab"; exit 0 ;;
        exec) [ "${FAKE_STACK:-down}" = up ] && exit 0; exit 1 ;;
        esac
    done
fi
exit 0
STUB
chmod +x "$WORK/bin/docker"

run_ensure_stack() {  # run_ensure_stack <down|up> -> prints rc
    (
        export PATH="$WORK/bin:$PATH" FAKE_STACK="$1"
        timeout 10 bash -c ". '$HERE/lib.sh'; ensure_stack" >/dev/null 2>&1
        echo $?
    )
}

echo "== ensure_stack"
check "stack down -> skip (77), without waiting out the readiness deadline" \
    77 "$(run_ensure_stack down)"
check "stack up + MI FIFO present -> ready (0)" \
    0 "$(run_ensure_stack up)"

# ---- stress report --------------------------------------------------------
echo "== stress_3way report"
HDR="ts,uptime_s,rss_kb,pulls,delivered,acks,naks,terms,redeliveries,stream_msgs,kv_keys,log_errors,log_warns"

status_of() {  # status_of <csv> [warmup_s] -> the report's status field
    if [ ! -f "$HERE/stress_summary.awk" ]; then
        echo "<stress_summary.awk missing>"
        return
    fi
    awk -F, -v dur=900 -v csv="$1" -v warmup="${2:-120}" \
        -f "$HERE/stress_summary.awk" "$1" \
        | awk '/status:/ {print $2}'
}

# warm-up jump in minute 1, then flat for 14 minutes (the 2026-09-24 run)
{ echo "$HDR"
  echo "0,0,84708,0,0,0,0,0,0,0,1,1,3"
  t=62; rss=133812
  while [ $t -le 931 ]; do
      echo "$t,$t,$rss,0,$((t*100)),$((t*100)),0,0,0,0,100,1,7"
      t=$((t + 62)); rss=$((rss + 2))
  done
} > "$WORK/warmup_flat.csv"
check "warm-up jump then flat -> ok" ok "$(status_of "$WORK/warmup_flat.csv")"

# steady growth after warm-up: +50% every ~5 minutes is a leak
{ echo "$HDR"
  echo "0,0,80000,0,0,0,0,0,0,0,1,0,0"
  echo "120,120,100000,0,0,0,0,0,0,0,1,0,0"
  echo "420,420,150000,0,0,0,0,0,0,0,1,0,0"
  echo "720,720,200000,0,0,0,0,0,0,0,1,0,0"
} > "$WORK/leak.csv"
check "steady growth after warm-up -> WARN_RSS_GROWTH" \
    WARN_RSS_GROWTH "$(status_of "$WORK/leak.csv")"

# run shorter than the warm-up: falls back to the first sample
{ echo "$HDR"
  echo "0,0,80000,0,0,0,0,0,0,0,1,0,0"
  echo "60,60,130000,0,0,0,0,0,0,0,1,0,0"
} > "$WORK/short.csv"
check "no post-warm-up sample -> first-sample baseline (growth warns)" \
    WARN_RSS_GROWTH "$(status_of "$WORK/short.csv" 120)"

echo "== stress log counters"
cat > "$WORK/opensips.log" <<'LOG'
Sep 24 00:36:51 [1] CRITICAL:core:set_core_dump: core limits increased only to 0
Sep 24 00:36:51 [1] NOTICE:core:main: version: opensips 4.1.0-dev
Sep 24 00:36:52 [2] WARNING:core:timer_ticker: timer task <timer_route> already scheduled
Sep 24 00:36:53 [3] ERROR:nats_consumer:bind: something real went wrong
Sep 24 00:36:54 [4] CRITICAL:core:receive_msg: something really bad
LOG
if [ -f "$HERE/stress_helpers.sh" ]; then
    got=$( . "$HERE/stress_helpers.sh"; count_log_errors "$WORK/opensips.log" )
else
    got="<stress_helpers.sh missing>"
fi
check "core-limit notice not counted; real ERROR + CRITICAL counted" 2 "$got"
got=$( [ -f "$HERE/stress_helpers.sh" ] && . "$HERE/stress_helpers.sh" && count_log_errors "$WORK/absent.log" )
check "missing log -> 0 errors" 0 "${got:-<error>}"

echo "== stress_multi_worker against a stubbed stack"
# The stack stub answers just what stress_multi_worker asks: the MI FIFO
# exists, the broker lists consumer "mw", binds succeed, and
# nats_consumer_list reports 0 deliveries on the first poll and
# $MW_DELIVERED afterwards -- except poll number $MW_FAIL_AT, whose docker
# exec fails outright.
mkdir -p "$WORK/mwbin"
cat > "$WORK/mwbin/docker" <<'STUB'
#!/bin/sh
[ "$1" = info ] && exit 0
args=" $* "
case "$args" in
*" ps -q "*)        echo 0123456789ab; exit 0 ;;
*" restart "*)      exit 0 ;;
*" test -p "*)      exit 0 ;;
*" consumer ls "*)  echo mw; exit 0 ;;
esac
body=""
for a in "$@"; do case "$a" in BODY=*) body="${a#BODY=}" ;; esac; done
case "$body" in
*nats_consumer_list*)
    n=$(( $(cat "$MW_STATE" 2>/dev/null || echo 0) + 1 ))
    echo "$n" > "$MW_STATE"
    [ "$n" = "${MW_FAIL_AT:-0}" ] && exit 1
    d=0; [ "$n" -gt 1 ] && d="$MW_DELIVERED"
    printf '{"jsonrpc":"2.0","result":{"handles":[{"id":"mw","msgs_delivered":%s,"redeliveries":%s}]},"id":1}' \
        "$d" "$( [ "$n" -gt 1 ] && echo "${MW_REDELIVERED:-0}" || echo 0 )"
    ;;
*nats_consumer_bind*|*nats_consumer_unbind*)
    printf '{"jsonrpc":"2.0","result":"OK","id":1}' ;;
esac
exit 0
STUB
chmod +x "$WORK/mwbin/docker"

run_mw() {  # run_mw <fail_at> <redelivered> -> prints "<rc> <last line>"
    local out rc
    out=$(PATH="$WORK/mwbin:$PATH" MW_STATE="$WORK/mw.state.$1.$2" \
        MW_FAIL_AT="$1" MW_REDELIVERED="$2" MW_DELIVERED=200 \
        N_MESSAGES=200 timeout 60 "$HERE/stress_multi_worker.sh" 2>&1)
    rc=$?
    printf '%s\n' "$out" > "$WORK/mw.out.$1.$2"
    printf '%s %s' "$rc" "$(printf '%s\n' "$out" | tail -1)"
}
r=$(run_mw 0 0)
check "clean run passes" 0 "${r%% *}"
r=$(run_mw 2 0)
check "one failed MI poll mid-run is ridden out" 0 "${r%% *}"
r=$(run_mw 0 3)
check "redeliveries fail the run" 1 "${r%% *}"
check "a redelivery failure dumps the handle" yes \
    "$(grep -q '"redeliveries":3' "$WORK/mw.out.0.3" && echo yes || echo no)"

echo "== stop_driver"
# A driver like stress_3way's: a loop that keeps a child running.  The
# child's argv carries a unique marker so it can be found after the loop
# is gone (an orphan is reparented to init).
mark="drv-marker-$$-$RANDOM"
child() { python3 -c 'import time; time.sleep(300)' "$mark"; }
( while true; do child; done ) >/dev/null 2>&1 &
drv=$!
( while true; do child; sleep 0.1; done ) >/dev/null 2>&1 &
drv2=$!
sleep 0.5
before=$(pgrep -f -- "$mark" | wc -l)
if [ -f "$HERE/stress_helpers.sh" ] && ( . "$HERE/stress_helpers.sh"; type stop_driver ) >/dev/null 2>&1; then
    ( . "$HERE/stress_helpers.sh"; stop_driver "$drv"; stop_driver "$drv2" )
else
    kill "$drv" "$drv2" 2>/dev/null   # the old cleanup
fi
sleep 0.5
check "drivers were running their children" yes "$( [ "$before" -ge 1 ] && echo yes || echo no)"
check "the driver loops are gone" no \
    "$(kill -0 "$drv" 2>/dev/null || kill -0 "$drv2" 2>/dev/null && echo yes || echo no)"
left=$(pgrep -f -- "$mark" | wc -l)
check "no child left behind" 0 "$left"
pkill -9 -f -- "$mark" 2>/dev/null
check "stop_driver on a pid that is gone is a no-op" 0 \
    "$( [ -f "$HERE/stress_helpers.sh" ] && . "$HERE/stress_helpers.sh" && type stop_driver >/dev/null 2>&1 && { stop_driver 999999999; echo $?; } || echo missing)"

echo "== docker build context"
# The compose image rebuilds opensips from source inside the container, so
# host build output must stay out of the context: stale objects carry the
# host's revision stamp, and .d depfiles name HOST header paths that make
# then demands inside the container ("No rule to make target
# /home/.../nats.h") whenever they do not exist there.
DI="$HERE/../../../.dockerignore"
for pat in '**/*.o' '**/*.so' '**/*.a' '**/*.d'; do
    if grep -qxF -- "$pat" "$DI" 2>/dev/null; then r=excluded; else r=missing; fi
    check ".dockerignore excludes $pat" excluded "$r"
done

echo
if [ "$FAILS" -eq 0 ]; then
    echo "selftest_harness: OK"
    exit 0
fi
echo "selftest_harness: $FAILS check(s) FAILED"
exit 1
