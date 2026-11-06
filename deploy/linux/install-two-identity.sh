#!/usr/bin/env bash
set -eu

PROG="install-two-identity.sh"
VAULT_USER="harpoc"
CLIENTS_GROUP="harpoc-clients"
STATE_DIR="/var/lib/harpoc"
RUNTIME_DIR="/run/harpoc"
TMPFILES_CONF="/etc/tmpfiles.d/harpoc.conf"

usage() {
  cat <<USAGE
Usage: $PROG [agent-user ...]

Creates the two-identity layout of Harpoc deployment model B. Idempotent: a second
run with the same arguments changes nothing.

  group $CLIENTS_GROUP            system group; every agent user becomes a member
  user  $VAULT_USER                    system user, primary group $VAULT_USER, no login shell
  $STATE_DIR            0700 $VAULT_USER:$VAULT_USER (the vault directory)
  $RUNTIME_DIR                0750 $VAULT_USER:$CLIENTS_GROUP
  $RUNTIME_DIR/<agent-user>   2750 $VAULT_USER:<the agent user's primary group>

An agent user's name is its consumer name: lowercase letters, digits, '_' and '-',
not dash-led; its primary group must be its own. Where /etc/tmpfiles.d exists
(systemd), the runtime directories are written to $TMPFILES_CONF and
recreated at every boot; elsewhere /run is lost at reboot: re-run this script at boot.
Run as root. No secret is read, written or printed.

Exit status: 0 done, 1 not root or a command failed, 2 usage error.
USAGE
}

die() {
  printf '%s: %s\n' "$PROG" "$1" >&2
  exit "$2"
}

ensure_dir() {
  mkdir -p -- "$1"
  chown -- "$3:$4" "$1"
  chmod -- "$2" "$1"
  printf '%s %s %s:%s\n' "$1" "$2" "$3" "$4"
}

write_tmpfiles() {
  {
    printf 'd %s 0750 %s %s -\n' "$RUNTIME_DIR" "$VAULT_USER" "$CLIENTS_GROUP"
    for dir in "$RUNTIME_DIR"/*/; do
      [ -d "$dir" ] || continue
      dir="${dir%/}"
      printf 'd %s 2750 %s %s -\n' "$dir" "$VAULT_USER" "$(stat -c %G -- "$dir")"
    done
  } >"$TMPFILES_CONF"
  printf '%s written\n' "$TMPFILES_CONF"
  if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create "$TMPFILES_CONF"
  fi
}

for arg in "$@"; do
  case "$arg" in
    -h | --help)
      usage
      exit 0
      ;;
    -*)
      usage >&2
      die "unknown option: $arg" 2
      ;;
  esac
done

for agent in "$@"; do
  [[ "$agent" =~ ^[a-z0-9_][a-z0-9_-]*$ ]] ||
    die "not a consumer name (lowercase letters, digits, '_', '-'; not dash-led): $agent" 2
  [ "$agent" != "$VAULT_USER" ] || die "the vault user cannot be an agent user" 2
  id -u "$agent" >/dev/null 2>&1 || die "no such user: $agent" 2
  [ "$(id -u "$agent")" -ne 0 ] || die "root cannot be an agent user: $agent" 2
  case "$(id -gn "$agent")" in
    "$CLIENTS_GROUP" | "$VAULT_USER")
      die "$agent's primary group must be its own, not $(id -gn "$agent")" 2
      ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "must run as root" 1

getent group "$CLIENTS_GROUP" >/dev/null || groupadd --system "$CLIENTS_GROUP"
if ! getent passwd "$VAULT_USER" >/dev/null; then
  if getent group "$VAULT_USER" >/dev/null; then
    useradd --system --gid "$VAULT_USER" --home-dir "$STATE_DIR" --no-create-home \
      --shell /usr/sbin/nologin "$VAULT_USER"
  else
    useradd --system --user-group --home-dir "$STATE_DIR" --no-create-home \
      --shell /usr/sbin/nologin "$VAULT_USER"
  fi
fi

ensure_dir "$STATE_DIR" 00700 "$VAULT_USER" "$(id -gn "$VAULT_USER")"
ensure_dir "$RUNTIME_DIR" 00750 "$VAULT_USER" "$CLIENTS_GROUP"
for agent in "$@"; do
  usermod --append --groups "$CLIENTS_GROUP" "$agent"
  ensure_dir "$RUNTIME_DIR/$agent" 02750 "$VAULT_USER" "$(id -gn "$agent")"
done

if [ -d /etc/tmpfiles.d ]; then
  write_tmpfiles
else
  printf '%s: no /etc/tmpfiles.d: %s does not survive a reboot; re-run this script at boot\n' \
    "$PROG" "$RUNTIME_DIR" >&2
fi
