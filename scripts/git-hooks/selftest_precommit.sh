#!/bin/sh
# selftest_precommit.sh -- contract of scripts/git-hooks/pre-commit.
#
# The hook must reject:
#   1. private development files (CLAUDE.md / .claude/) -- long-standing,
#   2. staged ELF binaries -- the class of the committed-test-binary
#      accident cleaned up in the P1 repo-hygiene pass (test_* binaries
#      have no extension, so name filters cannot catch them; the hook
#      checks the staged BLOB's magic bytes).                 [P5.6]
# and must pass a normal text file.
#
# Self-contained: builds a scratch repo under mktemp, installs the hook,
# exercises all three cases.  Exit 0 = contract holds.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
fails=0

check() { # label, want_rc, got_rc
    if [ "$3" -eq "$2" ]; then echo "  ok: $1"; else
        echo "  FAIL: $1 (want rc=$2, got rc=$3)"; fails=$((fails+1)); fi
}

cd "$TMP"
git init -q .
git config user.email t@t; git config user.name t
mkdir -p .git/hooks
cp "$HERE/pre-commit" .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# 1. normal text file commits fine
echo "hello" > notes.txt
git add notes.txt
git commit -qm ok >/dev/null 2>&1
check "text file commits" 0 $?

# 2. an ELF binary is rejected (magic bytes, no extension)
printf '\177ELF\002\001\001\000padpadpad' > test_sneaky
git add test_sneaky
git commit -qm elf >/dev/null 2>&1
check "staged ELF binary is rejected" 1 $?
git reset -q test_sneaky

# 3. CLAUDE.md stays rejected (existing guard)
echo "private" > CLAUDE.md
git add -f CLAUDE.md
git commit -qm claude >/dev/null 2>&1
check "CLAUDE.md stays rejected" 1 $?

if [ "$fails" -eq 0 ]; then echo "selftest_precommit: OK"; exit 0; fi
echo "selftest_precommit: FAIL ($fails)"
exit 1
