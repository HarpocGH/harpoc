import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BOOTSTRAP_REMOTE_COMMAND } from "../ssh-injector-bootstrap-script.js";

const SUDO: readonly string[] = [
  "#!/bin/sh",
  "d=${0%/bin/sudo}",
  'mode=$(cat "$d/sudo.mode")',
  'case "$#:$1:$2:$3:$4:$5" in "6:-S:-p::/bin/sh:-c") ;; *) echo "sudo bad-arguments" >>"$d/log"; exit 2 ;; esac',
  "line=",
  "case $mode in",
  '  password|outside-after) IFS= read -r line; echo "sudo read=${#line}" >>"$d/log" ;;',
  '  *) echo "sudo read=none" >>"$d/log" ;;',
  "esac",
  "case $mode in",
  "  outside-after|outside-before) exit 1 ;;",
  '  password) case $line in "$(cat "$d/sudo.password")") ;; *) exit 1 ;; esac ;;',
  "esac",
  'SUDO_UID=$(cat "$d/sudo.uid")',
  "export SUDO_UID",
  'exec "$4" "$5" "$6"',
];

const VISUDO: readonly string[] = [
  "#!/bin/sh",
  "d=${0%/bin/visudo}",
  "n=$(cat | wc -c)",
  'echo "visudo $* stdin=$(echo $n)" >>"$d/log"',
  'case "$#:$1:$2" in "3:-c:-f")',
  '  case $3 in "$d/sudoers") exit "$(cat "$d/visudo.whole")" ;; *) exit "$(cat "$d/visudo.file")" ;; esac ;;',
  "esac",
  "exit 2",
];

const ID: readonly string[] = [
  "#!/bin/sh",
  "d=${0%/bin/id}",
  "n=$(cat | wc -c)",
  'echo "id $* stdin=$(echo $n)" >>"$d/log"',
  'cat "$d/id.uid"',
];

const STAND_IN_DIR = /^[A-Za-z0-9._/-]+$/;
const SCRIPT_DEADLINE_MS = 20_000;

/**
 * The constant with three of its texts replaced — the `PATH`, the drop-in directory and the main
 * sudoers file's path —, so that it runs against the stand-ins in `dir`:
 * each text must occur as often as the constant has it, and nothing under `/etc/` may be left.
 */
export function standInCommand(command: string, dir: string): string {
  if (!STAND_IN_DIR.test(dir)) {
    throw new Error("stand-ins: the directory holds a character outside A-Z a-z 0-9 . _ / -");
  }
  const replacements: readonly [string, number, string][] = [
    ["PATH=/usr/sbin:/usr/bin:/sbin:/bin;", 2, `PATH=${dir}/bin:/usr/sbin:/usr/bin:/sbin:/bin;`],
    ["D=/etc/sudoers.d;", 1, `D=${dir}/sudoers.d;`],
    ["visudo -c -f /etc/sudoers ||", 1, `visudo -c -f ${dir}/sudoers ||`],
  ];
  for (const [text, count] of replacements) {
    const found = command.split(text).length - 1;
    if (found !== count) {
      throw new Error(`stand-ins: "${text}" occurs ${String(found)} times, not ${String(count)}`);
    }
  }
  let result = command;
  for (const [text, , replacement] of replacements) result = result.split(text).join(replacement);
  if (result.includes("/etc/")) throw new Error("stand-ins: the command still names /etc/");
  return result;
}

export interface BootstrapStandIns {
  dir: string;
  home: string;
  sudoersDir: string;
  command: string;
  password: string;
  uid: string;
  set(
    name: "sudo.mode" | "sudo.uid" | "sudo.password" | "id.uid" | "visudo.file" | "visudo.whole",
    value: string,
  ): void;
  log(): string[];
  dispose(): void;
}

/** A directory of its own with the stand-in `sudo`, `visudo` and `id`, a home and a drop-in directory. */
export function makeBootstrapStandIns(): BootstrapStandIns {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-bootstrap-")));
  const home = join(dir, "home");
  const sudoersDir = join(dir, "sudoers.d");
  const bin = join(dir, "bin");
  for (const sub of [home, sudoersDir, bin]) mkdirSync(sub);
  for (const [name, lines] of [
    ["sudo", SUDO],
    ["visudo", VISUDO],
    ["id", ID],
  ] as const) {
    const file = join(bin, name);
    writeFileSync(file, `${lines.join("\n")}\n`, { mode: 0o755 });
    chmodSync(file, 0o755);
  }
  const password = randomBytes(18).toString("base64url");
  const uid = "1000";
  const set: BootstrapStandIns["set"] = (name, value) => {
    writeFileSync(join(dir, name), value);
  };
  set("sudo.mode", "password");
  set("sudo.uid", uid);
  set("sudo.password", password);
  set("id.uid", uid);
  set("visudo.file", "0");
  set("visudo.whole", "0");
  return {
    dir,
    home,
    sudoersDir,
    command: standInCommand(BOOTSTRAP_REMOTE_COMMAND, dir),
    password,
    uid,
    set,
    log: () => {
      const file = join(dir, "log");
      if (!existsSync(file)) return [];
      const text = readFileSync(file, "utf8");
      return text === "" ? [] : text.replace(/\n$/, "").split("\n");
    },
    dispose: () => {
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    },
  };
}

/** The command run as sshd would hand it to `/bin/sh`, in an environment of `HOME` and the `PATH` `/nonexistent` alone. */
export function runBootstrapScript(
  command: string,
  home: string,
  stdin: Buffer,
  startup?: string,
): Promise<{ stdout: string; stderr: string; code: number | null }> {
  return new Promise((resolve, reject) => {
    const child = spawn("/bin/sh", ["-c", (startup ?? "") + command], {
      env: { HOME: home, PATH: "/nonexistent" },
      stdio: "pipe",
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let late = false;
    const deadline = setTimeout(() => {
      late = true;
      child.kill("SIGKILL");
    }, SCRIPT_DEADLINE_MS);
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", (err) => {
      clearTimeout(deadline);
      reject(err);
    });
    child.on("close", (code) => {
      clearTimeout(deadline);
      if (late) {
        reject(new Error(`the bootstrap script ran past ${String(SCRIPT_DEADLINE_MS)} ms`));
        return;
      }
      resolve({
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        code,
      });
    });
    child.stdin.on("error", () => {});
    child.stdin.end(stdin);
  });
}
