#!/usr/bin/env bash
set -eu

usage() {
  cat <<USAGE
Usage: deploy/dev-container/run.sh [test | shell | e2e-b]

Builds the harpoc-dev image (node 24, Debian bookworm; the vault user harpoc and the
agent user agent from deploy/linux/install-two-identity.sh), copies the working tree
into the harpoc-dev-work volume (node_modules, dist and the git directory excluded),
then installs and builds and either runs the whole suite (test, the default) as a
local Linux leg, opens a shell there (shell), or runs the deployment model B e2e suite
(e2e-b: the fixture PKI and SSH keys, then src/model-b.e2e.test.ts; no Docker inside
the container, so its docker row skips). Needs Docker; on Windows run it from Git Bash.

  HARPOC_DEV_TIERS   the tiers the run requires (default for test and shell:
                     secret-service,keyring,isolation,fs-isolation,ssh-live,two-uid;
                     for e2e-b: two-uid)
  HARPOC_DEV_MIN_AVAILABLE_MB
                     the host's available memory in MB below which run.sh refuses
                     (default 8192; 0 skips the check)
USAGE
}

mode="${1:-test}"
case "$mode" in
  test | shell | e2e-b) ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
case "$mode" in
  e2e-b) default_tiers=two-uid ;;
  *) default_tiers=secret-service,keyring,isolation,fs-isolation,ssh-live,two-uid ;;
esac
tiers="${HARPOC_DEV_TIERS:-$default_tiers}"
min_available_mb="${HARPOC_DEV_MIN_AVAILABLE_MB:-8192}"
case "$min_available_mb" in
  *[!0-9]*)
    echo "run.sh: HARPOC_DEV_MIN_AVAILABLE_MB must be a whole number of MB (0 skips the check)" >&2
    exit 2
    ;;
esac

host_path() {
  case "$(uname -s)" in
    MINGW* | MSYS*) cygpath -w "$1" ;;
    *) printf '%s' "$1" ;;
  esac
}

case "$(uname -s)" in
  MINGW* | MSYS*) export MSYS_NO_PATHCONV=1 ;;
esac

if ! [ "$min_available_mb" -eq 0 ]; then
  case "$(uname -s)" in
    MINGW* | MSYS*)
      available_mb="$(powershell.exe -NoProfile -Command "[int]((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory/1024)")"
      available_mb=${available_mb%$'\r'}
      ;;
    Linux) available_mb="$(awk '/^MemAvailable:/ { print int($2 / 1024) }' /proc/meminfo)" ;;
    *) available_mb= ;;
  esac
  if [ -n "$available_mb" ] && ! [ "$available_mb" -ge "$min_available_mb" ]; then
    echo "run.sh: the host has $available_mb MB of memory available, under HARPOC_DEV_MIN_AVAILABLE_MB=$min_available_mb (0 skips the check)" >&2
    exit 75
  fi
fi

docker build -t harpoc-dev -f "$(host_path "$here/Dockerfile")" "$(host_path "$repo/deploy")"

prepare='set -eu
rsync -a --chmod=go-w --delete --exclude node_modules --exclude dist --exclude .turbo --exclude coverage \
  --exclude /.git/ --exclude /.superpowers/ --exclude /.claude/ --exclude /NUL \
  --exclude "/%SystemDrive%/" /src/ /work/
cd /work
pnpm install --frozen-lockfile --store-dir /pnpm-store
pnpm build'

suite='dbus-run-session -- sh -c '"'"'echo harpoc-ci | gnome-keyring-daemon --unlock; keyctl link @u @s || true; pnpm test --force --concurrency=1'"'"

# The copied fixtures carry the bind mount's mode (0755 after --chmod=go-w, still world-readable): regenerated, the client key is 0600 (dev).
e2e_b='rm -rf packages/e2e/fixtures/pki/out packages/e2e/fixtures/keys/out
pnpm --filter @harpoc/e2e pki
pnpm --filter @harpoc/e2e keys
pnpm --filter @harpoc/e2e test:e2e src/model-b.e2e.test.ts'

run_args=(
  --rm --init
  --security-opt seccomp=unconfined
  --security-opt apparmor=unconfined
  --mount "type=bind,source=$(host_path "$repo"),target=/src,readonly"
  --mount type=volume,source=harpoc-dev-work,target=/work
  --mount type=volume,source=harpoc-dev-store,target=/pnpm-store
  --env "HARPOC_REQUIRE_PLATFORM_TESTS=$tiers"
  --env HARPOC_TWO_UID_VAULT_USER=harpoc
  --env HARPOC_TWO_UID_AGENT_USER=agent
)

running="$(docker ps -q --filter volume=harpoc-dev-work)"
if [ -n "$running" ]; then
  echo "run.sh: another run.sh is using the harpoc-dev-work volume" >&2
  exit 75
fi

if [ "$mode" = shell ]; then
  docker run -it "${run_args[@]}" harpoc-dev bash -c "$prepare
exec dbus-run-session -- bash -c 'echo harpoc-ci | gnome-keyring-daemon --unlock; keyctl link @u @s || true; exec bash -l'"
elif [ "$mode" = e2e-b ]; then
  docker run "${run_args[@]}" harpoc-dev bash -c "$prepare
$e2e_b"
else
  docker run "${run_args[@]}" harpoc-dev bash -c "$prepare
$suite"
fi
