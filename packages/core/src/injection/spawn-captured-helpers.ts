import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface HelperFilesSpec {
  prefix: string;
  script: string;
  launcher: { posix: string; win32: string };
  source: string;
  nullStdin?: true;
}

export interface HelperFiles {
  dir: string;
  launcher: string;
  dispose: () => void;
}

function singleQuoted(text: string): string {
  return `'${text.replaceAll("'", `'\\''`)}'`;
}

export function writeHelperFiles(
  spec: HelperFilesSpec,
  failure: (err: unknown) => unknown,
): HelperFiles {
  let dir: string;
  try {
    dir = mkdtempSync(join(tmpdir(), spec.prefix));
  } catch (err) {
    throw failure(err);
  }
  const script = join(dir, spec.script);
  const node = process.execPath;
  let launcher: string;
  try {
    writeFileSync(script, spec.source, { mode: 0o700 });
    if (process.platform === "win32") {
      launcher = join(dir, spec.launcher.win32);
      const nul = spec.nullStdin ? " <NUL" : "";
      writeFileSync(launcher, `@"${node}" "${script}" %*${nul}\r\n`, { mode: 0o700 });
    } else {
      launcher = join(dir, spec.launcher.posix);
      const devNull = spec.nullStdin ? " </dev/null" : "";
      writeFileSync(
        launcher,
        `#!/bin/sh\nexec ${singleQuoted(node)} ${singleQuoted(script)} "$@"${devNull}\n`,
        { mode: 0o700 },
      );
    }
  } catch (err) {
    rmSync(dir, { recursive: true, force: true });
    throw failure(err);
  }
  return {
    dir,
    launcher,
    dispose: () => {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        /* best effort */
      }
    },
  };
}
