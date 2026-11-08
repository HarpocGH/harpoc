import { posix } from "node:path";
import type { ChildRun } from "../harness/child.js";
import { scan } from "./scan.js";

/** One process as the sweep read it: its environment and its argument vector. */
export interface ProcEntry {
  pid: number;
  environ: string[];
  cmdline: string[];
}

/**
 * Runs `argv` as the user whose processes are swept. The kernel lets a process
 * read `/proc/<pid>/environ` only under `ptrace_may_access` in read mode: the
 * same uid as a dumpable target, or CAP_SYS_PTRACE (Yama's `ptrace_scope`
 * governs attach, not read). The runner is a third user, so the sweep reads as
 * the swept user — through `sudo -n -u` on the two-UID deployment, directly
 * for the same-UID negative control.
 */
export type ProcReader = (argv: string[]) => Promise<ChildRun>;

export interface SweepJudgement {
  credentialSeen: boolean;
  placeholderSeen: boolean;
  leakingPids: number[];
  placeholderPids: number[];
  /** Each swept process's `argv[0]` basename, in sweep order. */
  commands: string[];
}

/** The variables a model-B row is about; any other is kept only where it carries a credential or a placeholder. */
export const SWEEP_RECORD_VARIABLE = /^(?:HARPOC_[A-Z0-9_]+|SSH_AUTH_SOCK|CREDENTIALS_DIRECTORY)=/;

/** A `/proc/<pid>/environ` or `/cmdline` body: NUL-terminated strings, the last terminator dropped. */
export function parseNulList(text: string): string[] {
  const parts = text.split("\0");
  if (parts.at(-1) === "") parts.pop();
  return parts;
}

/**
 * One process's environ and cmdline through `read`; `undefined` when it
 * exited between the listing and the read. Any other failure throws — a
 * process the sweep cannot read is never swept past.
 */
export async function readProcEntry(pid: number, read: ProcReader): Promise<ProcEntry | undefined> {
  const environ = await read(["cat", `/proc/${String(pid)}/environ`]);
  const cmdline = await read(["cat", `/proc/${String(pid)}/cmdline`]);
  if (environ.code === 0 && cmdline.code === 0) {
    return { pid, environ: parseNulList(environ.stdout), cmdline: parseNulList(cmdline.stdout) };
  }
  if (/No such file or directory|No such process/.test(`${environ.stderr}${cmdline.stderr}`)) {
    return undefined;
  }
  throw new Error(
    `proc sweep: pid ${String(pid)} could not be read (cat exited ${String(environ.code)} / ${String(cmdline.code)})`,
  );
}

/** Every process `user` owns, listed and read as `user` (`pgrep` excludes itself). */
export async function sweepUserProcesses(user: string, read: ProcReader): Promise<ProcEntry[]> {
  const listed = await read(["pgrep", "-u", user]);
  if (listed.code !== 0 && listed.code !== 1) {
    throw new Error(`proc sweep: pgrep -u ${user} exited ${String(listed.code)}`);
  }
  const entries: ProcEntry[] = [];
  for (const line of listed.stdout.split("\n")) {
    if (line.trim() === "") continue;
    const entry = await readProcEntry(Number(line.trim()), read);
    if (entry !== undefined) entries.push(entry);
  }
  return entries;
}

/**
 * The sweep's verdict inputs: the credential in any encoding `scan` knows,
 * anywhere in any swept environ or cmdline, and the placeholders as written.
 * A sweep that sees no placeholder caught none of the agent's tools — the
 * anti-vacuity half a HANDLE_ONLY verdict requires beside the absent credential.
 */
export function judgeSweep(
  entries: ProcEntry[],
  opts: { credentials: string[]; placeholders: string[] },
): SweepJudgement {
  const leaking = entries.filter((entry) =>
    opts.credentials.some(
      (credential) =>
        scan(credential, { environ: entry.environ, cmdline: entry.cmdline }).length > 0,
    ),
  );
  const carrying = entries.filter((entry) =>
    opts.placeholders.some((placeholder) =>
      [...entry.environ, ...entry.cmdline].some((text) => text.includes(placeholder)),
    ),
  );
  return {
    credentialSeen: leaking.length > 0,
    placeholderSeen: carrying.length > 0,
    leakingPids: leaking.map((entry) => entry.pid),
    placeholderPids: carrying.map((entry) => entry.pid),
    commands: entries.map((entry) => posix.basename(entry.cmdline[0] ?? "")),
  };
}

/**
 * The text a record carries for one swept process: its command line and the
 * variables the row is about — `SWEEP_RECORD_VARIABLE`'s, and any that carries
 * a credential or a placeholder whatever its name, so a leak is never filtered
 * out of the record. The host's own variables (`PATH`, `HOME`, `USER`, the
 * `SUDO_*` set without a placeholder) say nothing about the row and stay out.
 */
export function sweepRecordText(
  entry: ProcEntry,
  opts: { credentials: string[]; placeholders: string[] },
): string {
  const kept = entry.environ.filter(
    (line) =>
      SWEEP_RECORD_VARIABLE.test(line) ||
      opts.placeholders.some((placeholder) => line.includes(placeholder)) ||
      opts.credentials.some((credential) => scan(credential, line).length > 0),
  );
  return [
    `pid ${String(entry.pid)}: ${entry.cmdline.join(" ")}`,
    ...kept.map((l) => `  ${l}`),
  ].join("\n");
}
