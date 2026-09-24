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
