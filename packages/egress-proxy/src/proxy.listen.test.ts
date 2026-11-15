import { spawn } from "node:child_process";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { connect, createServer } from "node:net";
import type { AddressInfo, Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode, VaultError, maxUnixSocketPathBytes } from "@harpoc/shared";
import { createEgressProxy } from "./proxy.js";
import type { EgressProxy } from "./proxy.js";
import { SECRET_VALUE, TOKENS, engineDouble } from "./__fixtures__/engine-double.js";
import type { EngineDouble } from "./__fixtures__/engine-double.js";
import { PROXY_CLIENT_TIMEOUT_MS, proxyRequest } from "./__fixtures__/proxy-client.js";
import { startUpstream } from "./__fixtures__/upstream-server.js";
import type { UpstreamFixture } from "./__fixtures__/upstream-server.js";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, chmodSync: vi.fn(actual.chmodSync) };
});

let double: EngineDouble;
let proxy: EgressProxy;

beforeEach(() => {
  double = engineDouble();
  proxy = createEgressProxy({ engine: double.engine });
});

afterEach(async () => {
  await proxy.close();
});

/** Whether a TCP connect to the loopback port is accepted. */
function tcpAccepts(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = connect(port, "127.0.0.1");
    probe.setTimeout(PROXY_CLIENT_TIMEOUT_MS, () => probe.destroy());
    probe.on("connect", () => {
      probe.destroy();
      resolve(true);
    });
    probe.on("error", () => resolve(false));
  });
}

/** Whether a connect to the Unix socket at `path` is accepted. */
function socketAccepts(path: string): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = connect(path);
    probe.setTimeout(PROXY_CLIENT_TIMEOUT_MS, () => probe.destroy());
    probe.on("connect", () => {
      probe.destroy();
      resolve(true);
    });
    probe.on("error", () => resolve(false));
    probe.on("close", () => resolve(false));
  });
}

describe("listenTcp", () => {
  it.each(["0.0.0.0", "::", "192.168.1.10"])(
    "refuses the non-loopback host %s before anything binds or is recorded",
    async (host) => {
      const err = await expectVaultError(() => proxy.listenTcp(0, host), ErrorCode.INVALID_INPUT);
      expect(err.message).toBe(
        `Egress proxy: the TCP listener binds loopback only (127.0.0.1, ::1 or localhost), not ${JSON.stringify(host)}`,
      );
      expect(double.auditServerStart).not.toHaveBeenCalled();
    },
  );

  it("binds loopback and writes one server.start row with transport proxy, after the bind", async () => {
    const { port } = await proxy.listenTcp(0, "127.0.0.1");

    expect(port).toBeGreaterThan(0);
    expect(await tcpAccepts(port)).toBe(true);
    expect(double.auditServerStart).toHaveBeenCalledTimes(1);
    expect(double.auditServerStart).toHaveBeenCalledWith({
      transport: "proxy",
      tokenless: false,
      port,
      host: "127.0.0.1",
    });
  });

  it("a bind failure rejects as node raised it and writes no row", async () => {
    const holder = createServer();
    await new Promise<void>((resolve) => holder.listen(0, "127.0.0.1", resolve));
    const taken = (holder.address() as AddressInfo).port;
    try {
      await expect(proxy.listenTcp(taken, "127.0.0.1")).rejects.toMatchObject({
        code: "EADDRINUSE",
      });
      expect(double.auditServerStart).not.toHaveBeenCalled();
    } finally {
      await new Promise<void>((resolve) => holder.close(() => resolve()));
    }
  });

  it("an unwritable start row undoes the bind", async () => {
    let bound = 0;
    const probe = createEgressProxy({
      engine: {
        ...double.engine,
        auditServerStart: (options) => {
          bound = options.port ?? 0;
          throw VaultError.vaultLocked();
        },
      },
    });
    await expectVaultError(() => probe.listenTcp(0, "127.0.0.1"), ErrorCode.VAULT_LOCKED);
    await probe.close();

    expect(bound).toBeGreaterThan(0);
    expect(await tcpAccepts(bound)).toBe(false);
  });

  it("close() closes the listener and is idempotent", async () => {
    const { port } = await proxy.listenTcp(0, "127.0.0.1");
    await proxy.close();
    await proxy.close();

    expect(await tcpAccepts(port)).toBe(false);
  });
});

describe.runIf(process.platform === "win32")("listenSocket on Windows", () => {
  it("is refused INVALID_INPUT (no socket directory mode to rely on; the named pipe is a later tranche's)", async () => {
    const err = await expectVaultError(
      () => proxy.listenSocket("C:\\harpoc\\run\\agent\\proxy.sock"),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(
      "Egress proxy socket: not supported on Windows (no socket directory mode to rely on): C:\\harpoc\\run\\agent\\proxy.sock",
    );
    expect(double.auditServerStart).not.toHaveBeenCalled();
  });
});

// The Unix-socket listener exists on POSIX only: Windows has no Unix socket
// directory whose mode is the second factor (DB-14) — the refusal above is its arm.
describe.skipIf(process.platform === "win32")("listenSocket (POSIX)", () => {
  let upstream: UpstreamFixture;
  let dir: string;

  beforeAll(async () => {
    upstream = await startUpstream();
  });

  afterAll(async () => {
    await upstream.close();
  });

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "harpoc-proxy-sock-"));
  });

  afterEach(() => {
    vi.mocked(chmodSync).mockReset();
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("binds mode 0660, writes no row of its own, and brokers like the TCP listener", async () => {
    const path = join(dir, "proxy.sock");
    await proxy.listenSocket(path);

    expect(lstatSync(path).isSocket()).toBe(true);
    expect(statSync(path).mode & 0o777).toBe(0o660);
    // The sockets ride the TCP listener's server.start / server.stop pair (RA-4).
    expect(double.auditServerStart).not.toHaveBeenCalled();

    upstream.script((req, res) => {
      res.end(`saw ${req.headers.authorization ?? ""}`);
    });
    const reply = await proxyRequest({
      socketPath: path,
      path: `/127.0.0.1:${upstream.port}/user`,
      headers: {
        "proxy-authorization": `Bearer ${TOKENS.use}`,
        authorization: "Bearer harpoc:gh-pat",
      },
    });
    expect(reply.status).toBe(200);
    expectAbsent(reply.raw, SECRET_VALUE);
    expect(reply.body).toBe("saw Bearer [REDACTED]");
    // The socket peer has no address: the caller carries none (a NULL ip_address).
    expect(double.resolveForProxy.mock.calls[0]?.[1]).not.toHaveProperty("remote_address");
  });

  it("refuses a path one byte over this platform's bound (107; darwin 103), naming its length, before anything is created", async () => {
    const bound = maxUnixSocketPathBytes(process.platform);
    const path = join(dir, "x".repeat(bound + 1 - Buffer.byteLength(dir) - 1));
    expect(Buffer.byteLength(path)).toBe(bound + 1);

    const err = await expectVaultError(() => proxy.listenSocket(path), ErrorCode.INVALID_INPUT);
    expect(err.message).toBe(
      `Egress proxy socket: path is ${String(bound + 1)} bytes, over the ${String(bound)} a Unix socket address holds: ${path}`,
    );
    expect(existsSync(path)).toBe(false);
  });

  it("unlinks a stale socket file nothing accepts on, then binds", async () => {
    const path = join(dir, "proxy.sock");
    // A listener SIGKILLed after its bind leaves its socket file behind.
    const child = spawn(
      process.execPath,
      [
        "-e",
        `require("net").createServer().listen(${JSON.stringify(path)}, () => process.kill(process.pid, "SIGKILL"))`,
      ],
      { stdio: "ignore" },
    );
    const deadline = setTimeout(() => child.kill("SIGKILL"), PROXY_CLIENT_TIMEOUT_MS);
    await new Promise<void>((resolve) => child.on("close", () => resolve()));
    clearTimeout(deadline);
    expect(lstatSync(path).isSocket()).toBe(true);

    await proxy.listenSocket(path);
    expect(statSync(path).mode & 0o777).toBe(0o660);
  });

  it("refuses a path another listener accepts on", async () => {
    const path = join(dir, "proxy.sock");
    const other: Server = createServer();
    await new Promise<void>((resolve) => other.listen(path, resolve));
    try {
      const err = await expectVaultError(() => proxy.listenSocket(path), ErrorCode.INVALID_INPUT);
      expect(err.message).toBe(`Egress proxy socket: another process is listening on ${path}`);
    } finally {
      await new Promise<void>((resolve) => other.close(() => resolve()));
    }
  });

  it("refuses a path that is a regular file and leaves it untouched", async () => {
    const path = join(dir, "proxy.sock");
    writeFileSync(path, "not a socket");

    const err = await expectVaultError(() => proxy.listenSocket(path), ErrorCode.INVALID_INPUT);
    expect(err.message).toBe(`Egress proxy socket: ${path} exists and is not a socket`);
    expect(readFileSync(path, "utf8")).toBe("not a socket");
  });

  // Root binds whatever the directory's mode: this row needs an unprivileged user.
  it.skipIf(process.getuid?.() === 0)(
    "a bind refused EACCES (a directory it may not write) is INVALID_INPUT naming the path and the errno, never node's text, and creates nothing",
    async () => {
      const locked = join(dir, "locked");
      mkdirSync(locked);
      chmodSync(locked, 0o555);
      const path = join(locked, "proxy.sock");

      const err = await expectVaultError(() => proxy.listenSocket(path), ErrorCode.INVALID_INPUT);
      expect(err.message).toBe(`Egress proxy socket: cannot listen on ${path} (EACCES)`);
      expect(err.message).not.toContain("permission denied");
      expect(existsSync(path)).toBe(false);
      expect(double.auditServerStart).not.toHaveBeenCalled();
    },
  );

  it("a bind refused EADDRINUSE (another listener bound the path after the ladder ran) is INVALID_INPUT naming the path, never node's text, and leaves that listener's socket serving past the refused proxy's close()", async () => {
    const path = join(dir, "proxy.sock");
    const other = createEgressProxy({ engine: double.engine });
    try {
      // Both ladders find the path free; the first bind takes it before the second binds.
      const first = other.listenSocket(path);
      const err = await expectVaultError(() => proxy.listenSocket(path), ErrorCode.INVALID_INPUT);
      await first;

      expect(err.message).toBe(`Egress proxy socket: another process is listening on ${path}`);
      expect(err.message).not.toContain("address already in use");
      await proxy.close();
      expect(statSync(path).mode & 0o777).toBe(0o660);
      expect(await socketAccepts(path)).toBe(true);
    } finally {
      await other.close();
    }
  });

  it("a path under a regular file (ENOTDIR at the ladder's lstat) is INVALID_INPUT naming the path and the errno, never node's text, and leaves the file", async () => {
    const file = join(dir, "not-a-directory");
    writeFileSync(file, "a file");
    const path = join(file, "proxy.sock");

    const err = await expectVaultError(() => proxy.listenSocket(path), ErrorCode.INVALID_INPUT);
    expect(err.message).toBe(`Egress proxy socket: cannot listen on ${path} (ENOTDIR)`);
    expect(err.message).not.toContain("not a directory");
    expect(readFileSync(file, "utf8")).toBe("a file");
  });

  it("a failed mode change (chmod refused EPERM) is INVALID_INPUT naming the path and the errno, never node's text, and closes the listener and removes its socket", async () => {
    const path = join(dir, "proxy.sock");
    vi.mocked(chmodSync).mockImplementationOnce(() => {
      throw Object.assign(new Error(`EPERM: operation not permitted, chmod '${path}'`), {
        code: "EPERM",
      });
    });

    const err = await expectVaultError(() => proxy.listenSocket(path), ErrorCode.INVALID_INPUT);
    expect(err.message).toBe(`Egress proxy socket: cannot listen on ${path} (EPERM)`);
    expect(err.message).not.toContain("operation not permitted");
    expect(chmodSync).toHaveBeenCalledWith(path, 0o660);
    expect(existsSync(path)).toBe(false);
    expect(await socketAccepts(path)).toBe(false);
  });

  it("close() removes the socket file", async () => {
    const path = join(dir, "proxy.sock");
    await proxy.listenSocket(path);
    await proxy.close();

    expect(existsSync(path)).toBe(false);
  });
});
