#!/bin/sh
# tree.sh: prints the hash git would give the working tree, untracked files
# included and ignored ones not, leaving the index as it is.
set -eu
index=$(mktemp)
trap 'rm -f "$index"' EXIT
cp "$(git rev-parse --git-path index)" "$index" 2>/dev/null || rm -f "$index"
# Files git is told to take as unchanged count as they are.
git ls-files -z | GIT_INDEX_FILE=$index git update-index -z --no-assume-unchanged --no-skip-worktree --stdin
GIT_INDEX_FILE=$index git add -A
GIT_INDEX_FILE=$index git write-tree
