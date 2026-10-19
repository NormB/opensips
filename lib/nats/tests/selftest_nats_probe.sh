#!/bin/bash
#
# selftest_nats_probe.sh -- hermetic self-test for nats_probe.sh, the "is a
# NATS broker answering at this URL?" check the e2e scripts share.  The
# nats CLI is stubbed on PATH, so this runs anywhere.
#
# Pins:
#   1. A nagios WARNING (exit 1: a connect or round trip slower than the
#      CLI's sub-second defaults, as on a busy CI host) is REACHABLE -- the
#      nightly skipped the whole suite on one, which STRICT=1 made a failure.
#   2. CRITICAL (2) / UNKNOWN (3) and a missing nats CLI are unreachable.
#   3. The thresholds are raised far above the CLI defaults.
#   4. The URL reaches the CLI as one argument, byte-exact.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d -t nats_probe_selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
FAILS=0
check() {
    if [ "$2" = "$3" ]; then echo "  ok: $1"
    else echo "  FAIL: $1 (expected '$2', got '$3')"; FAILS=$((FAILS + 1)); fi
}

mkdir -p "$WORK/bin"
# nats stub: records its argv (one per line) and exits with $STUB_RC
cat > "$WORK/bin/nats" <<'STUB'
#!/bin/sh
for a in "$@"; do printf '%s\n' "$a"; done > "$STUB_ARGS"
[ "${STUB_RC:-0}" = 1 ] && echo "WARNING: connect_time=0.906s"
exit "${STUB_RC:-0}"
STUB
chmod +x "$WORK/bin/nats"
export STUB_ARGS="$WORK/args"

probe() {  # probe <rc> <url> -> the probe's exit status
    STUB_RC="$1" PATH="$WORK/bin:/usr/bin:/bin" "$HERE/nats_probe.sh" "$2" \
        >/dev/null 2>&1
    echo $?
}

echo "== CLI exit status -> reachable?"
check "OK (0) is reachable"             0 "$(probe 0 nats://127.0.0.1:4222)"
check "WARNING (1) is reachable"        0 "$(probe 1 nats://127.0.0.1:4222)"
check "CRITICAL (2) is unreachable"     1 "$(probe 2 nats://127.0.0.1:4222)"
check "UNKNOWN (3) is unreachable"      1 "$(probe 3 nats://127.0.0.1:4222)"

echo "== arguments"
probe 0 nats://10.0.0.31:4222 >/dev/null
check "URL passed to --server"   "--server=nats://10.0.0.31:4222" "$(grep -- '^--server=' "$WORK/args")"
check "connect threshold raised" "--connect-critical=10s" "$(grep -- '^--connect-critical=' "$WORK/args")"
check "rtt threshold raised"     "--rtt-critical=10s" "$(grep -- '^--rtt-critical=' "$WORK/args")"
check "request threshold raised" "--req-critical=10s" "$(grep -- '^--req-critical=' "$WORK/args")"
for odd in 'nats://u:p\w@h:1' 'nats://h:1 nats://h:2' 'tls://h:1/?a=$b;c"d'; do
    probe 0 "$odd" >/dev/null
    check "URL kept byte-exact: $odd" "--server=$odd" "$(grep -- '^--server=' "$WORK/args")"
done

echo "== bad usage"
check "no URL is an error"       2 "$(STUB_RC=0 PATH="$WORK/bin:/usr/bin:/bin" "$HERE/nats_probe.sh" >/dev/null 2>&1; echo $?)"
check "empty URL is an error"    2 "$(probe 0 '')"
check "missing nats CLI is unreachable" 1 \
    "$(PATH="/usr/bin:/bin" bash -c 'command -v nats >/dev/null && echo skip || { "$0" nats://h:1 >/dev/null 2>&1; echo $?; }' "$HERE/nats_probe.sh")"

echo
[ "$FAILS" -eq 0 ] && echo "selftest_nats_probe: all checks passed" \
    || echo "selftest_nats_probe: $FAILS check(s) FAILED"
[ "$FAILS" -eq 0 ]
