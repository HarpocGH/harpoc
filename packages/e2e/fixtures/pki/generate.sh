#!/usr/bin/env bash
# Fixture PKI for the E2E harness. Generated, never committed (see .gitignore).
#
# Server certificates carry DNS SANs ONLY. The happy path connects to
# "localhost" (in the SAN, verifies) and the M3 arm connects to the IP literal
# 127.0.0.1, which no SAN covers and which therefore has no name to verify
# against. That reproduces the documented defect without touching /etc/hosts.
set -euo pipefail

# Inert on Linux (the harness target). On an MSYS development host the shell
# rewrites "/CN=..." into a filesystem path before openssl sees it; excluding
# exactly that prefix keeps the subject intact while -keyout/-out are still
# converted to native paths (MSYS_NO_PATHCONV=1 would break those instead).
export MSYS2_ARG_CONV_EXCL='/CN='

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$DIR/out"

# The sentinel checks EVERY artifact, not just the CA: a run killed mid-issuance
# — or an out/ dir produced by an earlier revision that issued fewer certificates
# — must not read as complete, or a service silently starts on a missing or
# stale certificate. A partial set is wiped and regenerated.
required=(
  ca.crt ca.key
  postgres-tls.crt postgres-tls.key
  mysql-tls.crt mysql-tls.key
  echo-https.crt echo-https.key
)
complete=1
for f in "${required[@]}"; do
  [ -f "$OUT/$f" ] || complete=0
done
if [ "$complete" = 1 ]; then
  echo "pki: already generated at $OUT"
  exit 0
fi
if [ -d "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then
  echo "pki: incomplete artifact set at $OUT — regenerating" >&2
  # A NEW CA invalidates the certificates the running services installed at
  # their own startup: `docker compose up` leaves an unchanged service running,
  # so the fleet would keep serving the previous CA's certificates while the
  # harness verifies against this one. Every TLS arm then fails — loudly, but
  # for a reason that reads like a vault defect.
  echo "pki: services holding old certificates must be recreated:" >&2
  echo "     pnpm --filter @harpoc/e2e fleet:recreate" >&2
  rm -rf "$OUT"
fi

mkdir -p "$OUT"

openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout "$OUT/ca.key" -out "$OUT/ca.crt" \
  -subj "/CN=Harpoc E2E Test CA" 2>/dev/null
chmod 644 "$OUT/ca.crt"
chmod 600 "$OUT/ca.key"

issue() {
  local name="$1"
  local extra_san="${2:-}"
  local ext="$OUT/$name.ext"
  local san="DNS:$name,DNS:localhost"
  [ -n "$extra_san" ] && san="$san,$extra_san"

  # A real file, not a process substitution: /dev/fd paths are not readable by
  # a native openssl running under MSYS on a development host.
  printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\n' "$san" > "$ext"

  openssl req -newkey rsa:2048 -nodes \
    -keyout "$OUT/$name.key" -out "$OUT/$name.csr" \
    -subj "/CN=$name" 2>/dev/null
  openssl x509 -req -in "$OUT/$name.csr" \
    -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
    -out "$OUT/$name.crt" -days 3650 -sha256 \
    -extfile "$ext" 2>/dev/null

  rm -f "$OUT/$name.csr" "$ext"
  chmod 644 "$OUT/$name.crt"
  chmod 600 "$OUT/$name.key"
}

issue postgres-tls
issue mysql-tls
# echo-https carries an IP SAN as well: the http context pins the pre-flight
# resolved address, and the demonstration cell must stay reachable whether it
# addresses the service as localhost or as the literal the container is bound to.
issue echo-https "IP:127.0.0.1"

echo "pki: generated CA and server certificates in $OUT"
