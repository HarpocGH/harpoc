import { spawnSync } from "node:child_process";
import { expect } from "vitest";

/** `icacls.exe` on a directory a test created, through no shell, under a deadline. */
export function icacls(path: string, ...args: string[]): void {
  const res = spawnSync(
    `${process.env.SystemRoot as string}\\System32\\icacls.exe`,
    [path, ...args],
    {
      shell: false,
      windowsHide: true,
      timeout: 15_000,
      encoding: "utf8",
    },
  );
  if (res.status !== 0) {
    expect.fail(
      `icacls ${[path, ...args].join(" ")} exited ${String(res.status)}${res.error === undefined ? "" : ` (${res.error.message})`}: ${res.stderr}`,
    );
  }
}
