#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$DIR/out"

required=(
  hostkey_ed25519 hostkey_ed25519.pub
  agent_ed25519 agent_ed25519.pub
  password
)
complete=1
for f in "${required[@]}"; do
  [ -f "$OUT/$f" ] || complete=0
done
if [ "$complete" = 1 ]; then
  echo "sshd-bootstrap: already generated at $OUT"
  exit 0
fi
if [ -d "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then
  echo "sshd-bootstrap: incomplete artifact set at $OUT — regenerating" >&2
  rm -rf "$OUT"
fi

mkdir -p "$OUT"

gen() {
  local name="$1"
  ssh-keygen -t ed25519 -f "$OUT/$name" -N "" -C "harpoc-e2e-$name" -q
  chmod 600 "$OUT/$name"
  chmod 644 "$OUT/$name.pub"
}

gen hostkey_ed25519
gen agent_ed25519

(umask 077 && printf '%s' "$(head -c 18 /dev/urandom | base64 | tr '+/' '-_')" >"$OUT/password")
chmod 600 "$OUT/password"

echo "sshd-bootstrap: generated the host key, the agent's key and the password in $OUT"
