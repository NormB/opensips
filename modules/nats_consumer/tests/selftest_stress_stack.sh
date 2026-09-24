#!/bin/bash
#
# selftest_stress_stack.sh -- live checks of the stress scripts' own
# plumbing against the compose stack (bring it up first:
# `docker compose up -d`; skips with 77 when it is down).
#
# Pins:
#   1. stress_churn runs cleanly right after stress_multi_worker.  Both use
#      the handle id "mw" and the stack is meant to survive between runs,
#      so churn must start from a clean handle registry instead of failing
#      its bind with 409 "duplicate id".
#   2. stress_churn's RSS figure covers every opensips process in the
#      container, not just PID 1 (the attendant, which does no consumer
#      work), so its leak bound can actually see a worker leak.
#
# Short runs (N_MESSAGES=200, DURATION=20) keep this under two minutes.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/lib.sh"
ensure_stack || exit 1

FAILS=0
check() {  # check <description> <expected> <actual>
    if [ "$2" = "$3" ]; then echo "  ok: $1"
    else echo "  FAIL: $1 (expected '$2', got '$3')"; FAILS=$((FAILS + 1)); fi
}

# Independent measure: VmRSS of every process whose comm is "opensips".
total_rss_proc() {
    ${COMPOSE} exec -T opensips sh -c '
        t=0
        for s in /proc/[0-9]*/status; do
            [ "$(sed -n "s/^Name:[[:space:]]*//p" "$s" 2>/dev/null)" = opensips ] || continue
            r=$(sed -n "s/^VmRSS:[[:space:]]*\([0-9]*\).*/\1/p" "$s" 2>/dev/null)
            t=$((t + ${r:-0}))
        done
        echo "$t"'
}

echo "== stress_multi_worker (short) leaves its handle behind"
N_MESSAGES=200 "${HERE}/stress_multi_worker.sh" > /tmp/nc_selftest_mw.log 2>&1
check "stress_multi_worker (N_MESSAGES=200) passes" 0 "$?"

echo "== stress_churn right after it"
DURATION=20 "${HERE}/stress_churn.sh" > /tmp/nc_selftest_churn.log 2>&1
rc=$?
# same processes as churn's final sample (churn restarts opensips at start,
# so compare against its END figure, taken moments before this one)
after=$(total_rss_proc)
check "stress_churn (DURATION=20) passes after stress_multi_worker" 0 "$rc"
[ "$rc" -ne 0 ] && sed 's/^/    | /' /tmp/nc_selftest_churn.log | tail -5

end_rss=$(sed -n 's/^end_rss=\([0-9]*\) kB.*/\1/p' /tmp/nc_selftest_churn.log)
echo "  (churn end_rss=${end_rss:-?} kB, all-opensips VmRSS right after=${after} kB)"
covers=no
if [ -n "${end_rss}" ] && [ "${after}" -gt 0 ] && \
   [ $(( end_rss * 10 )) -ge $(( after * 8 )) ]; then
    covers=yes
fi
check "churn RSS covers all opensips processes (>= 80% of /proc total)" yes "$covers"

rm -f /tmp/nc_selftest_mw.log /tmp/nc_selftest_churn.log
echo
if [ "$FAILS" -eq 0 ]; then echo "selftest_stress_stack: OK"; exit 0; fi
echo "selftest_stress_stack: $FAILS check(s) FAILED"; exit 1
