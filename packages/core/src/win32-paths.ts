import { join } from "node:path";

/**
 * Absolute path of an OS-shipped binary under `%SystemRoot%\System32` — the
 * one place the vault builds such a path, so every helper it spawns (taskkill,
 * icacls, the Windows PowerShell host) is pinned the same way. `SystemRoot` is
 * set by the OS on every Windows session; the fallback only serves an
 * environment that scrubbed it.
 */
export function system32Path(...segments: string[]): string {
  return join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", ...segments);
}
