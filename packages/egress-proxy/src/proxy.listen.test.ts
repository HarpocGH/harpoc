import { spawn } from "node:child_process";
import {
  existsSync,
  lstatSync,
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
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { createEgressProxy } from "./proxy.js";
import type { EgressProxy } from "./proxy.js";
import { SECRET_VALUE, TOKENS, engineDouble } from "./__fixtures__/engine-double.js";
import type { EngineDouble } from "./__fixtures__/engine-double.js";
import { PROXY_CLIENT_TIMEOUT_MS, proxyRequest } from "./__fixtures__/proxy-client.js";
import { startUpstream } from "./__fixtures__/upstream-server.js";
import type { UpstreamFixture } from "./__fixtures__/upstream-server.js";
import { expectVaultError } from "@harpoc/test-utils";

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
    expect(reply.body).toBe("saw Bearer [REDACTED]");
    expect(reply.raw).not.toContain(SECRET_VALUE);
    // The socket peer has no address: the caller carries none (a NULL ip_address).
    expect(double.resolveForProxy.mock.calls[0]?.[1]).not.toHaveProperty("remote_address");
  });

  it("refuses a path over 107 bytes, naming its length, before anything is created", async () => {
    const path = join(dir, "x".repeat(108 - dir.length - 1));
    expect(Buffer.byteLength(path)).toBe(108);

    const err = await expectVaultError(() => proxy.listenSocket(path), ErrorCode.INVALID_INPUT);
    expect(err.message).toBe(
      `Egress proxy socket: path is 108 bytes, over the 107 a Unix socket address holds: ${path}`,
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

  it("close() removes the socket file", async () => {
    const path = join(dir, "proxy.sock");
    await proxy.listenSocket(path);
    await proxy.close();

    expect(existsSync(path)).toBe(false);
  });
});
