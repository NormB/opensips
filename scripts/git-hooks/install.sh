#!/bin/sh
# Install the in-tree git hooks for this clone.
#
# Run from the repo root:    sh scripts/git-hooks/install.sh
#
# Sets core.hooksPath to scripts/git-hooks so every hook in this
# directory takes effect for every commit / push from this clone.
# Versioned hooks have to be opted into per-clone because Git does
# not auto-trust executables that arrive over the network.
set -e

if [ ! -d ".git" ] && [ ! -f ".git" ]; then
	echo "install.sh: run from the repo root (no .git here)" >&2
	exit 1
fi

# .git can be a directory (normal clones) or a file (worktrees).
git config core.hooksPath scripts/git-hooks
chmod +x scripts/git-hooks/pre-commit

echo "git-hooks installed (core.hooksPath=scripts/git-hooks)."
echo "Test it:    touch CLAUDE.md && git add -f CLAUDE.md && git commit -m test"
echo "Expected:   pre-commit refuses, exit 1."
