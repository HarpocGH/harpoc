import { execFileSync } from "node:child_process";
import { COMPOSE_DIR, DOCKER } from "./backends.js";
import type { FleetService } from "./backends.js";

/**
 * The target of the `sftp` `render` rows: `sshd-pinned`'s own `sftp-server`, reached at the
 * container's address on the compose network — an entry's host may not be loopback, and the
 * fleet publishes on loopback alone.
 */
export const RENDER_TARGET = {
  service: "sshd-pinned",
  port: 2222,
  user: "harpoc",
  dir: "/home/harpoc/render",
} as const satisfies { service: FleetService; port: number; user: string; dir: string };

/** What `plant("file", …)` writes. */
export const PLANTED = "untouched\n";

export interface RemoteEntry {
  kind: "file" | "link" | "directory" | "none";
  mode: string;
  owner: string;
  size: number;
  sha256: string | null;
}

const FLEET_UP = "run: pnpm --filter @harpoc/e2e fleet:up";

const OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
const IPV4 = new RegExp(`^${OCTET}(?:\\.${OCTET}){3}$`);

const KINDS = new Map<string, RemoteEntry["kind"]>([
  ["regular file", "file"],
  ["regular empty file", "file"],
  ["symbolic link", "link"],
  ["directory", "directory"],
]);

const RESET_SCRIPT = 'rm -rf -- "$1" && install -d -o "$2" -g "$2" -m 700 -- "$1"';

const REMOVE_SCRIPT = 'rm -rf -- "$1"';

const PLANT_SCRIPT = [
  'p="$2/$3"',
  'case "$1" in',
  `file) printf '${PLANTED.replace("\n", "\\n")}' >"$p" && chown "$4:$4" "$p" && chmod 644 "$p" ;;`,
  'link) ln -s -- "$5" "$p" && chown -h "$4:$4" "$p" ;;',
  'directory) install -d -o "$4" -g "$4" -m 755 -- "$p" ;;',
  "*) exit 2 ;;",
  "esac",
].join("\n");

const ENTRY_SCRIPT = [
  'p="$1/$2"',
  'if [ -e "$p" ] || [ -L "$p" ]; then stat -c %F:%a:%U:%s -- "$p"; else echo -; fi',
  'if [ -f "$p" ] && [ ! -L "$p" ]; then sha256sum <"$p" | cut -d " " -f 1; else echo -; fi',
].join("\n");

const NAMES_SCRIPT = 'ls -A -- "$1"';

function docker(argv: string[]): string {
  return execFileSync(DOCKER, argv, { cwd: COMPOSE_DIR, encoding: "utf8" });
}

function inTarget(script: string, args: string[]): string {
  return docker([
    "compose",
    "exec",
    "-T",
    RENDER_TARGET.service,
    "sh",
    "-c",
    script,
    "sh",
    ...args,
  ]);
}

/** The first plain dotted IPv4 of `docker inspect`'s address line. */
export function parseRenderAddress(text: string): string {
  const address = text.split(/\s+/).find((word) => IPV4.test(word));
  if (address === undefined) {
    throw new Error(
      `backend "${RENDER_TARGET.service}" has no IPv4 address on a compose network — ${FLEET_UP}`,
    );
  }
  return address;
}

/** `sshd-pinned`'s address on the compose network, which the render's entry names as its host. */
export function renderAddress(): string {
  let id: string;
  let line: string;
  try {
    id = docker(["compose", "ps", "-q", RENDER_TARGET.service]).trim();
    line =
      id === ""
        ? ""
        : docker([
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
            id,
          ]);
  } catch (cause) {
    throw new Error(`cannot read the address of "${RENDER_TARGET.service}" — ${FLEET_UP}`, {
      cause,
    });
  }
  return parseRenderAddress(line);
}

/** As root: the render directory removed and made again, empty, `harpoc`'s, mode 0700. */
export function resetRenderDir(): void {
  inTarget(RESET_SCRIPT, [RENDER_TARGET.dir, RENDER_TARGET.user]);
}

/** As root: the render directory removed with everything in it, so that the rows leave nothing on the service. */
export function removeRenderDir(): void {
  inTarget(REMOVE_SCRIPT, [RENDER_TARGET.dir]);
}

/** A file holding `PLANTED`, mode 0644; a link to `target`; or a directory, mode 0755 — each `harpoc`'s. */
export function plant(kind: "file" | "link" | "directory", name: string, target?: string): void {
  if (kind === "link" && target === undefined) throw new Error("plant: a link needs its target");
  inTarget(PLANT_SCRIPT, [kind, RENDER_TARGET.dir, name, RENDER_TARGET.user, target ?? ""]);
}

export function parseRemoteEntry(text: string): RemoteEntry {
  const bad = (): Error => new Error(`unexpected remote entry: ${JSON.stringify(text)}`);
  const lines = text.split(/\r?\n/);
  if (lines.at(-1) === "") lines.pop();
  const [stat, sum] = lines;
  if (lines.length !== 2 || stat === undefined || sum === undefined) throw bad();
  if (stat === "-") {
    if (sum !== "-") throw bad();
    return { kind: "none", mode: "", owner: "", size: 0, sha256: null };
  }
  const fields = stat.split(":");
  const [type, mode, owner, size] = fields;
  const kind = type === undefined ? undefined : KINDS.get(type);
  if (
    fields.length !== 4 ||
    kind === undefined ||
    mode === undefined ||
    !/^[0-7]{3,4}$/.test(mode) ||
    owner === undefined ||
    owner === "" ||
    size === undefined ||
    !/^[0-9]+$/.test(size)
  ) {
    throw bad();
  }
  if (kind === "file" ? !/^[0-9a-f]{64}$/.test(sum) : sum !== "-") throw bad();
  return { kind, mode, owner, size: Number(size), sha256: kind === "file" ? sum : null };
}

/** The entry at `name` in the render directory, by `stat` (not following a link) and, for a regular file, `sha256sum`. */
export function remoteEntry(name: string): RemoteEntry {
  return parseRemoteEntry(inTarget(ENTRY_SCRIPT, [RENDER_TARGET.dir, name]));
}

/** `ls -A` of the render directory, or of a directory `sub` in it. */
export function renderDirNames(sub?: string): string[] {
  const dir = sub === undefined ? RENDER_TARGET.dir : `${RENDER_TARGET.dir}/${sub}`;
  return inTarget(NAMES_SCRIPT, [dir])
    .split(/\r?\n/)
    .filter((name) => name !== "");
}
