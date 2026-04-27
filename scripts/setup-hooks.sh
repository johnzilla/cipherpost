#!/usr/bin/env bash
# Wire the tracked .githooks/ directory as this clone's git-hooks path.
# Run once per fresh clone:  bash scripts/setup-hooks.sh
#
# Why a script and not a hard requirement: git's `core.hooksPath` is
# per-clone configuration (not committed). Each contributor opts in.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

if [ ! -d .githooks ]; then
    echo "✗ .githooks/ directory not found at $REPO_ROOT/.githooks" >&2
    echo "  Are you running this from inside the cipherpost repo?" >&2
    exit 1
fi

# Make every hook executable (chmod is not always preserved across clones)
chmod +x .githooks/*

git config core.hooksPath .githooks

CURRENT="$(git config --get core.hooksPath)"
if [ "$CURRENT" = ".githooks" ]; then
    echo "✓ git hooks now run from .githooks/"
    echo ""
    echo "  Active hooks:"
    for h in .githooks/*; do
        [ -f "$h" ] && [ -x "$h" ] && printf "    • %s\n" "$(basename "$h")"
    done
    echo ""
    echo "  Recommended (optional but nice for the audit/deny gates):"
    echo "    cargo install cargo-nextest cargo-audit cargo-deny lychee"
    echo ""
    echo "  Escape hatch (use sparingly):  git push --no-verify"
else
    echo "✗ failed to set core.hooksPath (got: '$CURRENT')" >&2
    exit 1
fi
