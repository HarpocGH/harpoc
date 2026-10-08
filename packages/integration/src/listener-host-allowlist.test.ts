import { mkdtempSync, rmSync } from "node:fs";
import { request } from "node:http";
import { createServer, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { RAW_GET_TIMEOUT_MS, runCli, startCliServerOnFreePort } from "./helpers/spawn-cli.js";

const PASSWORD = "listener-allowlist-integration-pw";

/** node:http request with an explicit Host header (fetch forbids setting one). */
function rawGet(
  port: number,
  path: string,
  headers: Record<string, string>,
  timeoutMs = RAW_GET_TIMEOUT_MS,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
      let data = "";
      res.on("data", (chunk: Buffer) => (data += chunk.toString("utf8")));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: data }));
    });
    req.on("error", reject);
    req.setTimeout(timeoutMs, () => {
      req.destroy(
        new Error(`rawGet ${path} on port ${String(port)} timed out after ${String(timeoutMs)} ms`),
      );
    });
    req.end();
  });
}

describe("harpoc server start --rest and the listener host allowlist (R11/D61)", () => {
  let vault: TestVault;

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
  });

  afterAll(async () => {
    await destroyTestVault(vault);
  });

  it("refuses a non-loopback bind without --allowed-host before the vault opens", async () => {
    const empty = mkdtempSync(join(tmpdir(), "harpoc-bind-refusal-"));
    try {
      const result = await runCli(
        ["server", "start", "--rest", "--host", "0.0.0.0", "--port", "3999"],
        { vaultDir: empty },
      );
      expect(result.code).toBe(1);
      expect(result.stderr).toContain("requires --allowed-host");
      expect(result.stderr).not.toContain("Vault is locked");
      expect(result.stderr).not.toContain("listening");
    } finally {
      rmSync(empty, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  }, 30_000);

  it("an allowed host admits its name, the loopback names stay admitted, and the rest answer 421", async () => {
    const { server, port } = await startCliServerOnFreePort(
      (p) => ["server", "start", "--rest", "--port", String(p), "--allowed-host", "vault.example"],
      { vaultDir: vault.tmpDir },
    );
    try {
      expect((await rawGet(port, "/api/v1/health", { host: "vault.example" })).status).toBe(200);
      expect(
        (await rawGet(port, "/api/v1/health", { host: `127.0.0.1:${String(port)}` })).status,
      ).toBe(200);
      const evil = await rawGet(port, "/api/v1/health", { host: "evil.example" });
      expect(evil.status).toBe(421);
      expect((JSON.parse(evil.body) as { error: string }).error).toBe("MISDIRECTED_REQUEST");
      expect(evil.body).toContain("evil.example");
    } finally {
      await server.stop();
    }
  }, 60_000);
});

describe("rawGet", () => {
  it("rejects and frees the socket when the server never answers", async () => {
    const silent = createServer((socket) => {
      socket.resume();
    });
    await new Promise<void>((resolve) => silent.listen(0, "127.0.0.1", resolve));
    const { port } = silent.address() as AddressInfo;
    await expect(rawGet(port, "/api/v1/health", { host: "localhost" }, 200)).rejects.toThrow(
      /timed out after 200 ms/,
    );
    await new Promise<void>((resolve) => silent.close(() => resolve()));
  }, 10_000);
});
