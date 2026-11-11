import { scan } from "./scan.js";
import type { ChildRun } from "../harness/child.js";
import { systemPaths } from "../harness/runas-windows.js";

/** In the argument of every command the suite starts as the agent account, so the teardown can name them. */
export const B7_MARKER = "harpoc-b7";

/** One process as `Get-CimInstance Win32_Process` lists it; `commandLine` is `null` where the caller may not read it. */
export interface InventoryEntry {
  pid: number;
  name: string;
  commandLine: string | null;
}

/** Runs `argv` as the account whose view of the process list is taken. */
export type InventoryReader = (argv: string[]) => Promise<ChildRun>;

export interface InventoryJudgement {
  credentialSeen: boolean;
  placeholderSeen: boolean;
  leakingPids: number[];
  placeholderPids: number[];
  /** The marked processes (`B7_MARKER` in the command line): the account's own, command lines readable. */
  markedPids: number[];
  /** The `foreignPids` the listing holds, and of those the ones whose command line it carries. */
  foreignListed: number[];
  foreignReadable: number[];
  /** Each marked process's image name, lower-cased, in listing order. */
  commands: string[];
}

export interface InventoryJudged {
  credentials: string[];
  placeholders: string[];
  foreignPids: number[];
}

/**
 * The inventory command: the standard cmdlet, no P/Invoke, no handle opened by
 * this code. `Win32_Process.CommandLine` is filled for processes the caller may
 * query and `null` for the others (measured against `lsass.exe` and
 * `winlogon.exe` from a standard token; `research-evidence.md` § E2) — the
 * row's claim is what the listing shows, not an access the harness exercises.
 * `-InputObject @(...)` keeps one process an array. Every non-ASCII character
 * leaves as a `\uXXXX` escape, so the bytes on the pipe are ASCII whatever the
 * console's code page (Windows PowerShell writes in the OEM one).
 */
export const INVENTORY_COMMAND =
  "$ProgressPreference = 'SilentlyContinue'; " +
  "[regex]::Replace((ConvertTo-Json -InputObject @(Get-CimInstance Win32_Process | " +
  "Select-Object ProcessId, Name, CommandLine) -Compress), " +
  "'[^\\x00-\\x7f]', { param($m) '\\u{0:x4}' -f [int][char]$m.Value })";

export function inventoryArgv(systemRoot?: string): string[] {
  return [
    systemPaths(systemRoot).powershell,
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-OutputFormat",
    "Text",
    "-Command",
    INVENTORY_COMMAND,
  ];
}

export function parseInventory(stdout: string): InventoryEntry[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new SyntaxError(
      `process inventory: the listing (${String(stdout.length)} characters) is not valid JSON`,
    );
  }
  if (!Array.isArray(parsed)) throw new Error("process inventory: the listing is not an array");
  return parsed.map((row, index) => {
    const r = row as { ProcessId?: unknown; Name?: unknown; CommandLine?: unknown };
    if (
      typeof r.ProcessId !== "number" ||
      typeof r.Name !== "string" ||
      (r.CommandLine !== null && typeof r.CommandLine !== "string")
    ) {
      throw new Error(`process inventory: malformed entry at index ${String(index)}`);
    }
    return { pid: r.ProcessId, name: r.Name, commandLine: r.CommandLine };
  });
}

/** The process list as the account `read` runs for sees it; a listing that fails is never read past. */
export async function listAccountProcesses(
  read: InventoryReader,
  systemRoot?: string,
): Promise<InventoryEntry[]> {
  const run = await read(inventoryArgv(systemRoot));
  if (run.code !== 0) {
    throw new Error(`process inventory: the listing exited ${String(run.code)}`);
  }
  return parseInventory(run.stdout);
}

/**
 * The verdict inputs: the credential in any encoding `scan` knows anywhere in
 * any command line, the placeholders as written, the marked processes (the
 * account's own tools — the anti-vacuity half: the listing caught them), and
 * for each foreign pid whether the listing holds it and whether its command
 * line is carried.
 */
export function judgeInventory(
  entries: InventoryEntry[],
  opts: InventoryJudged,
): InventoryJudgement {
  const lines = (entry: InventoryEntry): string[] =>
    entry.commandLine === null ? [] : [entry.commandLine];
  const leaking = entries.filter((entry) =>
    opts.credentials.some((credential) => scan(credential, lines(entry)).length > 0),
  );
  const carrying = entries.filter((entry) =>
    opts.placeholders.some((placeholder) =>
      lines(entry).some((text) => text.includes(placeholder)),
    ),
  );
  const marked = entries.filter((entry) => lines(entry).some((text) => text.includes(B7_MARKER)));
  const foreign = entries.filter((entry) => opts.foreignPids.includes(entry.pid));
  return {
    credentialSeen: leaking.length > 0,
    placeholderSeen: carrying.length > 0,
    leakingPids: leaking.map((entry) => entry.pid),
    placeholderPids: carrying.map((entry) => entry.pid),
    markedPids: marked.map((entry) => entry.pid),
    foreignListed: foreign.map((entry) => entry.pid),
    foreignReadable: foreign
      .filter((entry) => entry.commandLine !== null)
      .map((entry) => entry.pid),
    commands: marked.map((entry) => entry.name.toLowerCase()),
  };
}

/**
 * The text a record carries for one entry: the image name and the command line
 * — or, for a line the listing does not carry, the stated absence — for the
 * marked processes, the placeholder carriers and the foreign pids; every other
 * process of the host says nothing about the row and stays out.
 */
export function inventoryRecordText(
  entry: InventoryEntry,
  opts: InventoryJudged,
): string | undefined {
  const text = entry.commandLine;
  const relevant =
    opts.foreignPids.includes(entry.pid) ||
    (text !== null &&
      (text.includes(B7_MARKER) ||
        opts.placeholders.some((placeholder) => text.includes(placeholder)) ||
        opts.credentials.some((credential) => scan(credential, text).length > 0)));
  if (!relevant) return undefined;
  return `pid ${String(entry.pid)}: ${entry.name} ${text ?? "[command line not carried]"}`;
}
