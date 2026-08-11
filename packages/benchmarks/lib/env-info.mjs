// Environment capture — every committed result must be traceable to a host + repo commit.

import { execSync } from "node:child_process";
import os from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

/** Absolute path of the code repository (sibling of this docs repo). */
// lib → benchmarks → packages → the repository root.
export const REPO_DIR = join(HERE, "..", "..", "..");

export function captureEnv() {
  let repoCommit = "unknown";
  try {
    repoCommit = execSync("git rev-parse --short HEAD", { cwd: REPO_DIR, encoding: "utf8" }).trim();
  } catch {
    // git unavailable — keep "unknown"; the result is still usable, just less traceable
  }
  const cpus = os.cpus();
  return {
    timestamp: new Date().toISOString(),
    hostname: os.hostname(),
    platform: process.platform,
    os_release: os.release(),
    arch: process.arch,
    cpu: cpus[0]?.model?.trim() ?? "unknown",
    cores: cpus.length,
    memory_gib: Math.round((os.totalmem() / 2 ** 30) * 10) / 10,
    node: process.version,
    repo_commit: repoCommit,
  };
}
