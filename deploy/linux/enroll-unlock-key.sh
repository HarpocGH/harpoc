#!/usr/bin/env bash
set -eu

PROG="enroll-unlock-key.sh"
CRED_NAME="harpoc-unlock"
CRED_DIR="/etc/credstore.encrypted"
CRED_PATH="$CRED_DIR/$CRED_NAME.cred"
KEY_BYTES=32

usage() {
  cat <<USAGE
Usage: $PROG <key-file> [auto|tpm2|host+tpm2|host]

Seals a Harpoc unlock key with systemd-creds for the unit deploy/systemd/harpoc.service.
<key-file> is the file 'harpoc unlock-key enroll --out <key-file>' wrote: a regular
file of exactly $KEY_BYTES bytes that only its owner can read.

  auto        the default, systemd-creds' own: the TPM2 and the host key where a TPM2
              is usable (and not in a container), else the host key alone
  tpm2        the TPM2 alone: the credential decrypts on this machine only
  host+tpm2   both the TPM2 and the host key
  host        the host key alone, /var/lib/systemd/credential.secret, which root
              can read: weaker, never the default

Writes $CRED_PATH (0600 root:root; the credential
name $CRED_NAME embedded), checks that it decrypts to the key, then removes
<key-file> with shred -u, best effort: a journaling, copy-on-write or flash
file system may keep a copy. Run it once per key file; a second run finds no key
file. To seal a new key, enrol it ('harpoc unlock-key enroll' replaces the slot)
and run this script on it. No PCR policy is set, so a modified boot still unseals.
Run as root; needs systemd-creds (systemd 250 or later). No byte of the key is
printed.

Exit status: 0 done, 1 not root or a command failed, 2 usage error.
USAGE
}

die() {
  printf '%s: %s\n' "$PROG" "$1" >&2
  exit "$2"
}

case "${1:-}" in
  -h | --help)
    usage
    exit 0
    ;;
esac

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  usage >&2
  die "expected <key-file> [mode]" 2
fi
key_file="$1"
mode="${2:-auto}"
case "$key_file" in
  "" | -*) die "the key file must be a path (give one that starts with a dash as ./-name)" 2 ;;
esac
case "$mode" in
  auto | tpm2 | host+tpm2 | host) ;;
  *) die "unknown mode: $mode (auto, tpm2, host+tpm2 or host)" 2 ;;
esac

[ "$(id -u)" -eq 0 ] || die "must run as root" 1
command -v systemd-creds >/dev/null 2>&1 || die "systemd-creds not found (systemd 250 or later)" 1

if [ ! -f "$key_file" ] || [ -L "$key_file" ]; then
  die "not a regular file: $key_file" 2
fi
[ "$(stat -c %s -- "$key_file")" -eq "$KEY_BYTES" ] ||
  die "not a $KEY_BYTES-byte unlock key: $key_file" 2
key_mode="$(stat -c %a -- "$key_file")"
case "$key_mode" in
  400 | 600) ;;
  *)
    die "$key_file has mode $key_mode, not 0400 or 0600: revoke the key and enrol a new one" 2
    ;;
esac

tpm2="$(
  (systemd-analyze has-tpm2 2>/dev/null || systemd-creds has-tpm2 2>/dev/null || true) | head -n 1
)"
printf 'systemd reports TPM2: %s; sealing with --with-key=%s\n' "${tpm2:-unknown}" "$mode"

umask 077
install -d -m 0700 -o root -g root -- "$CRED_DIR"
tmp="$CRED_PATH.new"
rm -f -- "$tmp"
trap 'rm -f -- "$tmp"' EXIT
systemd-creds encrypt --name="$CRED_NAME" --with-key="$mode" -- "$key_file" "$tmp"
chmod 0600 -- "$tmp"
systemd-creds decrypt --name="$CRED_NAME" -- "$tmp" - | cmp -s -- - "$key_file" ||
  die "the credential does not decrypt to the key: $CRED_PATH unchanged, $key_file kept" 1
mv -f -- "$tmp" "$CRED_PATH"
trap - EXIT
shred -u -- "$key_file"
printf '%s written (credential %s)\n' "$CRED_PATH" "$CRED_NAME"
printf '%s removed\n' "$key_file"
printf 'the unit reads it as LoadCredentialEncrypted=%s:%s\n' "$CRED_NAME" "$CRED_PATH"
