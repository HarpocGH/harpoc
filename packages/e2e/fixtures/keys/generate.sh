#!/usr/bin/env bash
# Fixture SSH key material for the E2E harness. Generated, never committed
# (see .gitignore). OpenSSH keypairs, not X.509 — the PKI generator issues
# certificates and cannot produce these.
#
#   client_ed25519          the client identity. The PRIVATE half is stored
#                           verbatim as the ssh / git-over-ssh secret; the
#                           PUBLIC half is the sshd containers' authorized_keys.
#   hostkey_pinned_ed25519  sshd-pinned's host key. Its public line becomes the
#                           known_hosts pin the happy path materializes.
#   hostkey_rogue_ed25519   sshd-rogue's host key — DIFFERENT, so a connection
#                           pinned to the pinned key but answered by rogue fails
#                           host-key verification (no TOFU, D4).
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$DIR/out"

# The sentinel checks EVERY artifact, not just the first one generated: a run
# killed mid-generation must not read as complete (docker would bind-mount the
# missing host-key path as a directory and the sshd container crash-loops with
# nothing pointing here). A partial set is wiped and regenerated.
required=(
  client_ed25519 client_ed25519.pub
  hostkey_pinned_ed25519 hostkey_pinned_ed25519.pub
  hostkey_rogue_ed25519 hostkey_rogue_ed25519.pub
  authorized_keys
)
complete=1
for f in "${required[@]}"; do
  [ -f "$OUT/$f" ] || complete=0
done
if [ "$complete" = 1 ]; then
  echo "keys: already generated at $OUT"
  exit 0
fi
if [ -d "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then
  echo "keys: incomplete artifact set at $OUT — regenerating" >&2
  rm -rf "$OUT"
fi

mkdir -p "$OUT"

gen() {
  local name="$1"
  # ed25519, no passphrase (cipher none) so the vault's key-loader accepts the
  # stored private key without a decrypt step; -q suppresses the fingerprint art.
  ssh-keygen -t ed25519 -f "$OUT/$name" -N "" -C "harpoc-e2e-$name" -q
  chmod 600 "$OUT/$name"
  chmod 644 "$OUT/$name.pub"
}

gen client_ed25519
gen hostkey_pinned_ed25519
gen hostkey_rogue_ed25519

# The sshd containers authorize exactly the client identity, nothing else.
cp "$OUT/client_ed25519.pub" "$OUT/authorized_keys"
chmod 644 "$OUT/authorized_keys"

echo "keys: generated client + host keypairs in $OUT"
