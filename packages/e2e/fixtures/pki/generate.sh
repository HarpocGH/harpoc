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

if [ -f "$OUT/ca.crt" ]; then
  echo "pki: already generated at $OUT"
  exit 0
fi

mkdir -p "$OUT"

openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout "$OUT/ca.key" -out "$OUT/ca.crt" \
  -subj "/CN=Harpoc E2E Test CA" 2>/dev/null
chmod 644 "$OUT/ca.crt"
chmod 600 "$OUT/ca.key"

issue() {
  local name="$1"
  local ext="$OUT/$name.ext"

  # A real file, not a process substitution: /dev/fd paths are not readable by
  # a native openssl running under MSYS on a development host.
  printf 'subjectAltName=DNS:%s,DNS:localhost\nbasicConstraints=CA:FALSE\n' "$name" > "$ext"

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

echo "pki: generated CA and server certificates in $OUT"
