#!/bin/sh
# lint_private_refs.sh -- forbid references to private planning material in
# the NATS code, tests, docs and CI.
#
# Work-item labels ([P3.2], P2.3, P3-63, bare P9), review ids ([REV-15], [HREV-1], [TREV-2]),
# citations of design documents that are not in this repository
# (SPEC section refs, *-SPEC.md, NATS_TODO.md, the maintainability spec,
# the capacity runbook / design package / design repo and its PERF_NOTES.md
# and SCALING.md) and "owner decision" notes mean
# nothing to a reader of this tree.  Say what the code does and why,
# in place; do not point at documents the reader cannot open.
#
# Run from anywhere.  Exit 0 = clean, 1 = violations listed on stdout.
#
# Wired into: the repo pre-commit hook and the NATS CI workflow.
set -eu
root=$(cd "$(dirname "$0")/../../.." && pwd)
self="lib/nats/tests/lint_private_refs.sh"

pattern='\[P[0-9]+(\.[0-9]+)?[a-z]?[^]]*\]|(^|[^A-Za-z0-9_.])P[0-9]\.[0-9]+[a-z]?([^0-9]|$)|(^|[^A-Za-z0-9_])P[0-9] \[|\[[TH]?REV-[0-9]+|(^|[^A-Za-z])[TH]?REV-[0-9]+|§[0-9]|SPEC §|[A-Z][A-Z-]*-SPEC(\.md)?|MAINTAINABILITY|IMPLEMENTATION-PLAN|IMPROVEMENT|NATS_TODO|(^|[^A-Za-z0-9_.])P[0-9]+[a-z]([^A-Za-z0-9]|$)|\[P[0-9]+ |\[(OBS|KVOBS|FMT|D-OBS|TTL-BELOW-MARKER|DOCX|PREV)([^]A-Za-z][^]]*)?\]|\[[DR][0-9]+[^]]*\]|\(F[0-9]+[ )]|(^|[^A-Za-z])PREV-[0-9]+|(^|[^A-Za-z0-9_$.-])P[0-9]+-[0-9]+|(^|[^A-Za-z0-9_$.{-])P([0-9]|1[0-9])\+?([^0-9A-Za-z_.=]|$)|[Oo]wner decision|CAPACITY-RUNBOOK|design package|[Dd]esign[ -]repo|PERF_NOTES|SCALING\.md|opensips-usrloc-nats|modules-readme'

# work-item labels in file names (test_p45_foo.c)
name_pattern='(^|/)[^/]*[_-][Pp][0-9]+[a-z]?[_.-][^/]*$'

cd "$root"
files=$(git ls-files -- \
        lib/nats modules/cachedb_nats modules/cachedb_nats_fts \
        modules/event_nats modules/nats_consumer \
        '.github/workflows/nats-*.yml' 'docs/nats-*.md' \
        scripts/git-hooks scripts/build/install_libnats.sh \
        scripts/build/cppcheck-nats.supp 2>/dev/null \
      | grep -vxF "$self" || true)
out=$(printf '%s\n' "$files" | xargs -r grep -nIE "$pattern" 2>/dev/null || true)
names=$(printf '%s\n' "$files" | grep -E "$name_pattern" | sed 's/$/: file name carries a work-item label/' || true)
out=$(printf '%s\n%s' "$out" "$names" | sed '/^$/d')

if [ -n "$out" ]; then
	printf '%s\n' "$out"
	echo "lint_private_refs: $(printf '%s\n' "$out" | wc -l) reference(s) to private planning material (see header)"
	exit 1
fi
echo "lint_private_refs: OK"
