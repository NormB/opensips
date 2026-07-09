#!/bin/sh
# selftest_strict.sh -- the release-gate contract of run.sh/bench_matrix.sh.
#
# Developer default: a missing prerequisite SKIPS (autotools exit 77) so
# local exploration works anywhere.  Release-gate mode (STRICT=1) must
# turn every such skip into a hard FAILURE: a missing dependency, or a
# benchmark cell with zero successful trials, must not read as a green
# pipeline.  (IMPROVEMENT Tier-2 / spec P5.2.)
#
# Cheap and broker-free: prerequisites are checked before any network
# use, so pointing OPENSIPS_BIN at a nonexistent file exercises the
# skip-vs-fail decision immediately.
#
# Run from anywhere; exit 0 = contract holds, 1 = violations.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
fails=0

check() { # label, want_rc, got_rc
    if [ "$3" -eq "$2" ]; then
        echo "  ok: $1 (rc=$3)"
    else
        echo "  FAIL: $1 (want rc=$2, got rc=$3)"
        fails=$((fails + 1))
    fi
}

# 1. developer default: missing prerequisite -> skip (77)
OPENSIPS_BIN=/nonexistent/opensips "$HERE/run.sh" >/dev/null 2>&1
check "missing prerequisite skips by default" 77 $?

# 2. release gate: same condition -> hard failure (1)
STRICT=1 OPENSIPS_BIN=/nonexistent/opensips "$HERE/run.sh" >/dev/null 2>&1
check "STRICT=1 turns the skip into a failure" 1 $?

# 3. bench_matrix must carry the STRICT arm (errored cells -> nonzero)
if grep -q 'STRICT' "$HERE/bench_matrix.sh"; then
    echo "  ok: bench_matrix.sh carries a STRICT arm"
else
    echo "  FAIL: bench_matrix.sh has no STRICT handling"
    fails=$((fails + 1))
fi

if [ "$fails" -eq 0 ]; then echo "selftest_strict: OK"; exit 0; fi
echo "selftest_strict: FAIL ($fails)"
exit 1
