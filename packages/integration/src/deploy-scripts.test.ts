import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { resolve, sep } from "node:path";
import { describe, expect, it } from "vitest";
import { getPkgRoot } from "@harpoc/test-utils";

const deployRoot = resolve(getPkgRoot(import.meta.url), "..", "..", "deploy");

/** Every shell script under deploy/, relative to it with `/` separators, sorted. */
const SCRIPTS = readdirSync(deployRoot, { recursive: true, encoding: "utf8" })
  .filter((p) => p.endsWith(".sh"))
  .map((p) => p.split(sep).join("/"))
  .sort();

describe("deploy scripts (deployment model B)", () => {
  it("finds exactly the scripts the deployment ships", () => {
    expect(SCRIPTS).toEqual(["dev-container/run.sh", "linux/install-two-identity.sh"]);
  });

  it.each(SCRIPTS)("%s starts with the bash shebang and set -eu", (script) => {
    const lines = readFileSync(resolve(deployRoot, script), "utf8").split("\n");
    expect(lines.slice(0, 2)).toEqual(["#!/usr/bin/env bash", "set -eu"]);
  });
});

describe.skipIf(process.platform === "win32")(
  "deploy scripts on POSIX (the recipes target Linux; on win32 `bash` may resolve to Git Bash or the WSL launcher, and git there tracks no mode)",
  () => {
    it.each(SCRIPTS)("%s parses under bash -n", (script) => {
      const run = spawnSync("bash", ["-n", resolve(deployRoot, script)], {
        encoding: "utf8",
        timeout: 10_000,
      });
      expect(run.error).toBeUndefined();
      expect(run.stderr).toBe("");
      expect(run.status).toBe(0);
    });

    it.each(SCRIPTS)("%s is executable (the index mode git checks out)", (script) => {
      expect(statSync(resolve(deployRoot, script)).mode & 0o111).toBe(0o111);
    });
  },
);
