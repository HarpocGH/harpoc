import { spawn } from "node:child_process";
import { existsSync, lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import type { Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { prepareUnixSocketPath } from "./unix-socket.js";
import { expectVaultError } from "@harpoc/test-utils";

const LABEL = "test socket";
const CHILD_DEADLINE_MS = 10_000;

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "harpoc-unix-socket-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("prepareUnixSocketPath", () => {
  it("refuses a path over 107 bytes, naming its length, before touching the filesystem", async () => {
    const path = join(dir, "x".repeat(108 - dir.length - 1));
    expect(Buffer.byteLength(path)).toBe(108);

    const err = await expectVaultError(
      () => prepareUnixSocketPath(path, LABEL),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(
      `test socket: path is 108 bytes, over the 107 a Unix socket address holds: ${path}`,
    );
    expect(existsSync(path)).toBe(false);
  });

  it("passes a 107-byte path that does not exist and creates nothing", async () => {
    const path = join(dir, "x".repeat(107 - dir.length - 1));
    expect(Buffer.byteLength(path)).toBe(107);

    await expect(prepareUnixSocketPath(path, LABEL)).resolves.toBeUndefined();
    expect(existsSync(path)).toBe(false);
  });

  it("refuses a path that exists and is not a socket, and leaves it untouched", async () => {
    const path = join(dir, "ssh-agent.sock");
    writeFileSync(path, "not a socket");

    const err = await expectVaultError(
      () => prepareUnixSocketPath(path, LABEL),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(`test socket: ${path} exists and is not a socket`);
    expect(readFileSync(path, "utf8")).toBe("not a socket");
  });

  // A Unix socket file exists on POSIX only (a Windows `listen(path)` is a named pipe).
  describe.skipIf(process.platform === "win32")("an existing socket (POSIX)", () => {
    it("refuses a socket another listener accepts on and leaves it bound", async () => {
      const path = join(dir, "ssh-agent.sock");
      const other: Server = createServer();
      await new Promise<void>((resolve) => other.listen(path, resolve));
      try {
        const err = await expectVaultError(
          () => prepareUnixSocketPath(path, LABEL),
          ErrorCode.INVALID_INPUT,
        );
        expect(err.message).toBe(`test socket: another process is listening on ${path}`);
        expect(lstatSync(path).isSocket()).toBe(true);
      } finally {
        await new Promise<void>((resolve) => other.close(() => resolve()));
      }
    });

    it("unlinks a stale socket nothing accepts on", async () => {
      const path = join(dir, "ssh-agent.sock");
      // A listener SIGKILLed after its bind leaves its socket file behind.
      const child = spawn(
        process.execPath,
        [
          "-e",
          `require("net").createServer().listen(${JSON.stringify(path)}, () => process.kill(process.pid, "SIGKILL"))`,
        ],
        { stdio: "ignore" },
      );
      const deadline = setTimeout(() => child.kill("SIGKILL"), CHILD_DEADLINE_MS);
      await new Promise<void>((resolve) => child.on("close", () => resolve()));
      clearTimeout(deadline);
      expect(lstatSync(path).isSocket()).toBe(true);

      await prepareUnixSocketPath(path, LABEL);
      expect(existsSync(path)).toBe(false);
    });
  });
});
