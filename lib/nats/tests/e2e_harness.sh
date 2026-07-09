# e2e_harness.sh -- shared core for the NATS sip_e2e suites.  [P5.5]
#
# Sourced by modules/*/tests/sip_e2e/lib/helpers.sh (which keep their
# module-specific helpers).  Hoisted here because the two copies had
# already drifted in comments and would eventually drift in behavior:
# one definition of the result aggregation and the bounded pollers.
#
# Requires: $WORKDIR set by the calling run.sh (opensips.log location).
# Bash (not POSIX sh): arrays and `local`, like the suites themselves.

# ── result aggregation ──────────────────────────────────────────
SUITE_PASS=0
SUITE_FAIL=0
declare -a FAILED_CASES

case_name=""
case_begin() {
    case_name="$1"
    echo "[$(date +%H:%M:%S)] CASE: $case_name"
}

check() {
    local label=$1
    local ok=$2
    local detail=${3:-}
    if [ "$ok" = ok ]; then
        echo "  PASS: $label"
        SUITE_PASS=$((SUITE_PASS + 1))
    else
        echo "  FAIL: $label"
        [ -n "$detail" ] && echo "        $detail"
        SUITE_FAIL=$((SUITE_FAIL + 1))
        FAILED_CASES+=("${case_name}::${label}")
    fi
}

# ── bounded pollers ─────────────────────────────────────────────
# The deflake rule: a bare `sleep N` is only for wall-clock semantics
# (TTL expiry under test, absence-proof windows).  Anything waiting for
# an OBSERVABLE condition polls, bounded, through one of these.

# log_contains <pattern> -> 0 if found in the opensips log, 1 otherwise
log_contains() {
    grep -q -- "$1" "$WORKDIR/opensips.log"
}

# wait_for_log <timeout-sec> <pattern> -> 0 on hit, 1 on timeout
wait_for_log() {
    local timeout=$1
    local pattern=$2
    local end=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$end" ]; do
        log_contains "$pattern" && return 0
        sleep 0.2
    done
    return 1
}

# wait_for <timeout-sec> <cmd...> -> 0 as soon as <cmd...> succeeds,
# 1 on timeout.  <cmd...> runs in the caller's shell, so case-local
# functions work as conditions.
wait_for() {
    local timeout=$1; shift
    local end=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$end" ]; do
        "$@" && return 0
        sleep 0.2
    done
    return 1
}
