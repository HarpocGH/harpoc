import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { assertNativeWin32SshClient } from "./ssh-common.js";
import { expectVaultError } from "@harpoc/test-utils";

let dir: string;
let ssh: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "harpoc-ssh-check-"));
  ssh = join(dir, "ssh.exe");
  writeFileSync(ssh, "");
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe.runIf(process.platform === "win32")("assertNativeWin32SshClient (win32)", () => {
  it("passes a client with neither runtime DLL beside it", () => {
    expect(() => assertNativeWin32SshClient(ssh)).not.toThrow();
  });

  it.each(["msys-2.0.dll", "cygwin1.dll"])(
    "refuses a client with %s beside it, naming the directory only",
    async (dll) => {
      writeFileSync(join(dir, dll), "");
      const err = await expectVaultError(
        () => assertNativeWin32SshClient(ssh),
        ErrorCode.SSH_CLIENT_UNSUPPORTED,
      );
      expect(err.statusCode).toBe(501);
      expect(err.message).toContain(dir);
      expect(err.message).not.toContain(ssh);
      expect(err.message).toContain("C:\\Windows\\System32\\OpenSSH\\ssh.exe");
    },
  );

  it("ignores a DLL that is a directory, not a file", () => {
    mkdirSync(join(dir, "msys-2.0.dll"));
    expect(() => assertNativeWin32SshClient(ssh)).not.toThrow();
  });
});

describe.runIf(process.platform !== "win32")("assertNativeWin32SshClient (POSIX)", () => {
  it("is a no-op off win32, even with the DLL beside the client", () => {
    writeFileSync(join(dir, "msys-2.0.dll"), "");
    expect(() => assertNativeWin32SshClient(ssh)).not.toThrow();
  });
});
