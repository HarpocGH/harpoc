#!/usr/bin/env bash
# Fixture git repositories for the E2E harness. Generated, never committed
# (see .gitignore). Bare repos served by the git-http container over smart-HTTP
# and by the sshd container over git-over-ssh.
#
#   clean.git      one commit, one file. The happy-path clone target.
#   submodule.git  carries a hostile .gitmodules. The H6b arm attempts
#                  --recurse-submodules and the vault denies the arg before any
#                  spawn — the submodule URL is never contacted, so it can point
#                  anywhere; it exists only to make the recursion request real.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$DIR/out"

if [ -d "$OUT/clean.git" ]; then
  echo "repos: already generated at $OUT"
  exit 0
fi

mkdir -p "$OUT"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Deterministic identity so a regenerate is byte-stable modulo commit time.
export GIT_AUTHOR_NAME="Harpoc E2E" GIT_AUTHOR_EMAIL="e2e@harpoc.test"
export GIT_COMMITTER_NAME="Harpoc E2E" GIT_COMMITTER_EMAIL="e2e@harpoc.test"

git init -q -b main "$WORK/clean"
echo "harpoc e2e clean repo" >"$WORK/clean/README.md"
git -C "$WORK/clean" add -A
git -C "$WORK/clean" commit -q -m "initial"
git clone -q --bare "$WORK/clean" "$OUT/clean.git"
git -C "$OUT/clean.git" update-server-info

git init -q -b main "$WORK/sub"
echo "harpoc e2e submodule repo" >"$WORK/sub/README.md"
# A tab-indented .gitmodules, git's own format. The URL is deliberately off-box.
printf '[submodule "evil"]\n\tpath = evil\n\turl = https://attacker.example/evil.git\n' \
  >"$WORK/sub/.gitmodules"
git -C "$WORK/sub" add -A
git -C "$WORK/sub" commit -q -m "initial with hostile submodule"
git clone -q --bare "$WORK/sub" "$OUT/submodule.git"
git -C "$OUT/submodule.git" update-server-info

echo "repos: generated bare git repositories in $OUT"
