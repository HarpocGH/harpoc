import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { HARPOC_VERSION } from "@harpoc/shared";
import { runCli } from "./helpers/spawn-cli.js";

// Through the real binary: commander answers --version before any subcommand
// runs, so no vault exists in the directory and none is created.
describe("harpoc --version (spawned CLI)", () => {
  let vaultDir: string;

  beforeAll(() => {
    vaultDir = mkdtempSync(join(tmpdir(), "harpoc-version-"));
  });

  afterAll(() => {
    rmSync(vaultDir, { recursive: true, force: true });
  });

  it("prints the product version and exits 0", async () => {
    const out = await runCli(["--version"], { vaultDir });
    expect(out.code).toBe(0);
    expect(out.stdout.trim()).toBe(HARPOC_VERSION);
    expect(out.stderr).toBe("");
  });
});
