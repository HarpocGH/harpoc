// Runs fixtures/<name>/generate.sh through a bash that can actually open a
// Windows script path. A bare `bash` in the package.json script resolved to the
// System32 WSL launcher on a Windows dev host, which cannot exec the generator
// (`execvpe(/bin/bash) failed`, live-hit 2026-08-12) — so this wrapper resolves
// Git-for-Windows' own bash, exactly like the harness' resolveBash()
// (src/harness/fixtures.ts, its typed twin: provisioning must stay dist-free,
// so the resolution is duplicated here rather than imported). `bin\bash.exe` —
// the launcher that bootstraps the MSYS PATH — deliberately precedes
// `usr\bin\bash.exe`, which runs with the ambient Windows PATH and dies on the
// first coreutil.
import { execFileSync } from "node:child_process";
import { statSync } from "node:fs";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const isWin = process.platform === "win32";

function isFile(p) {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

function pathDirs() {
  return (process.env.PATH ?? process.env.Path ?? "").split(delimiter).filter(Boolean);
}

function fromPath(name) {
  const exts = isWin ? [".exe", ""] : [""];
  for (const dir of pathDirs()) {
    for (const ext of exts) {
      const candidate = join(dir, name + ext);
      if (isFile(candidate)) return candidate;
    }
  }
  return null;
}

function resolveBash() {
  if (!isWin) {
    const p = fromPath("bash");
    if (p) return p;
    console.error("generate-fixtures: no bash found on PATH — install bash");
    process.exit(1);
  }
  const candidates = [];
  const git = fromPath("git");
  if (git) {
    for (const root of [dirname(dirname(git)), dirname(dirname(dirname(git)))]) {
      candidates.push(join(root, "bin", "bash.exe"), join(root, "usr", "bin", "bash.exe"));
    }
  }
  candidates.push(
    "C:\\Program Files\\Git\\bin\\bash.exe",
    "C:\\Program Files\\Git\\usr\\bin\\bash.exe",
  );
  for (const c of candidates) {
    if (isFile(c)) return c;
  }
  const onPath = fromPath("bash");
  if (onPath && !/\\windows\\system32\\/i.test(onPath)) return onPath;
  console.error(
    "generate-fixtures: no usable bash found — the WSL launcher cannot run the fixture " +
      "generators; install Git for Windows (looked in:\n" +
      candidates.map((c) => `  ${c}`).join("\n") +
      ")",
  );
  process.exit(1);
}

const name = process.argv[2];
if (!["pki", "keys", "repos"].includes(name ?? "")) {
  console.error(`generate-fixtures: unknown fixture set "${name}" (pki | keys | repos)`);
  process.exit(1);
}
const script = fileURLToPath(new URL(`../fixtures/${name}/generate.sh`, import.meta.url)).replace(
  /\\/g,
  "/",
);
execFileSync(resolveBash(), [script], { stdio: "inherit" });
