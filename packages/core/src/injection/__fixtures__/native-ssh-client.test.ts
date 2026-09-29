import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resolveNativeSshClient } from "./native-ssh-client.js";

describe.runIf(process.platform === "win32")("resolveNativeSshClient", () => {
  let dir: string;
  let ssh: string;
  let savedPath: string | undefined;

  beforeEach(() => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-native-ssh-")));
    ssh = join(dir, "ssh.exe");
    writeFileSync(ssh, "");
    savedPath = process.env.PATH;
    process.env.PATH = dir;
  });

  afterEach(() => {
    if (savedPath === undefined) delete process.env.PATH;
    else process.env.PATH = savedPath;
    rmSync(dir, { recursive: true, force: true });
  });

  it("returns the resolved path of a client with no runtime DLL beside it", () => {
    expect(resolveNativeSshClient("ssh")).toBe(realpathSync(ssh));
  });

  it("reads an MSYS build as absent", () => {
    writeFileSync(join(dir, "msys-2.0.dll"), "");
    expect(resolveNativeSshClient("ssh")).toBeNull();
  });
});
