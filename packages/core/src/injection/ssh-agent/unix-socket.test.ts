import { spawn } from "node:child_process";
import { existsSync, lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import type { Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ErrorCode, maxUnixSocketPathBytes } from "@harpoc/shared";
import { prepareUnixSocketPath } from "./unix-socket.js";
import { expectVaultError } from "@harpoc/test-utils";

const LABEL = "test socket";
const CHILD_DEADLINE_MS = 10_000;
const REAL_PLATFORM = process.platform;

let dir: string;

/** The platform `prepareUnixSocketPath` reads by default, stubbed for one row and put back after it. */
function stubPlatform(value: NodeJS.Platform): void {
  Object.defineProperty(process, "platform", { value, configurable: true });
}

/** This platform's bound, read when the row runs. */
function bound(): number {
  return maxUnixSocketPathBytes(process.platform);
}

/** A path under the row's directory of exactly `bytes` bytes. */
function pathOf(bytes: number): string {
  const path = join(dir, "x".repeat(bytes - Buffer.byteLength(dir) - 1));
  expect(Buffer.byteLength(path)).toBe(bytes);
  return path;
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "harpoc-unix-socket-"));
});

afterEach(() => {
  stubPlatform(REAL_PLATFORM);
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("prepareUnixSocketPath", () => {
  it("refuses a path one byte over this platform's bound (107; darwin 103), naming its length and the bound, before touching the filesystem", async () => {
    const path = pathOf(bound() + 1);

    const err = await expectVaultError(
      () => prepareUnixSocketPath(path, LABEL),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(
      `test socket: path is ${String(bound() + 1)} bytes, over the ${String(bound())} a Unix socket address holds: ${path}`,
    );
    expect(existsSync(path)).toBe(false);
  });

  it("passes a path of this platform's bound (107; darwin 103) that does not exist and creates nothing", async () => {
    const path = pathOf(bound());

    await expect(prepareUnixSocketPath(path, LABEL)).resolves.toBeUndefined();
    expect(existsSync(path)).toBe(false);
  });

  it("darwin's bound on any host (the platform passed): a 104-byte path is refused naming its length and the 103", async () => {
    const path = pathOf(104);

    const err = await expectVaultError(
      () => prepareUnixSocketPath(path, LABEL, "darwin"),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(
      `test socket: path is 104 bytes, over the 103 a Unix socket address holds: ${path}`,
    );
    expect(existsSync(path)).toBe(false);
  });

  it("the platform defaults to process.platform: stubbed to darwin, a 104-byte path is refused naming the 103", async () => {
    const path = pathOf(104);
    stubPlatform("darwin");

    const err = await expectVaultError(
      () => prepareUnixSocketPath(path, LABEL),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(
      `test socket: path is 104 bytes, over the 103 a Unix socket address holds: ${path}`,
    );
  });

  it("darwin's bound on any host (the platform passed): a 103-byte path that does not exist passes and creates nothing", async () => {
    const path = pathOf(103);

    await expect(prepareUnixSocketPath(path, LABEL, "darwin")).resolves.toBeUndefined();
    expect(existsSync(path)).toBe(false);
  });

  it("FreeBSD's bound on any host (the platform passed): a 104-byte path is refused naming the 103", async () => {
    const path = pathOf(104);

    const err = await expectVaultError(
      () => prepareUnixSocketPath(path, LABEL, "freebsd"),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(
      `test socket: path is 104 bytes, over the 103 a Unix socket address holds: ${path}`,
    );
    expect(existsSync(path)).toBe(false);
  });

  // A real bind needs a Unix socket file, which exists on POSIX only (a Windows `listen(path)`
  // is a named pipe): the macOS legs bind at 103 bytes, Linux at 107.
  it.skipIf(process.platform === "win32")(
    "a real listen on a path of exactly this platform's bound succeeds after the ladder passes it (POSIX)",
    async () => {
      const path = pathOf(bound());
      await prepareUnixSocketPath(path, LABEL);

      const server: Server = createServer();
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(path, () => resolve());
      });
      try {
        expect(lstatSync(path).isSocket()).toBe(true);
      } finally {
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    },
  );

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
