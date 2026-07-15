import { execFile } from "node:child_process";
import { createServer } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  DpapiSessionKeyProtector,
  KeychainWrappingKeyStore,
  KeyringWrappingKeyStore,
  KeystoreWrappedSessionKeyProtector,
  SecretServiceWrappingKeyStore,
  VaultEngine,
  findLinuxKeystoreBinary,
} from "@harpoc/core";
import type { SessionKeyProtector } from "@harpoc/core";
import { createMcpServer } from "@harpoc/mcp-server";
import { createApp } from "@harpoc/rest-api";
import { InjectionType, PrincipalType, SecretType, VaultState } from "@harpoc/shared";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { callTool } from "./helpers/mcp-helpers.js";

const PASSWORD = "session-sharing-pw";
const SECRET_NAME = "shared-key";
const SECRET_VALUE = "sk-shared-abc1234567890xyz";

describe("Session Sharing", () => {
  let vault1: TestVault;
  let engine2: VaultEngine;
  let mcpServer: McpServer;
  let echoServer: Server;
  let echoUrl: string;
  let handle: string;
  let token: string;

  beforeAll(async () => {
    // Echo server for use_secret
    echoServer = createServer((req, res) => {
      const body = JSON.stringify({ headers: req.headers });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(body);
    });
    await new Promise<void>((resolve) => {
      echoServer.listen(0, "127.0.0.1", resolve);
    });
    const echoAddr = echoServer.address() as AddressInfo;
    echoUrl = `http://127.0.0.1:${echoAddr.port}`;

    // Engine1 inits vault and creates a secret
    vault1 = createTestVault();
    await vault1.engine.initVault(PASSWORD);

    const result = await vault1.engine.createSecret({
      name: SECRET_NAME,
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from(SECRET_VALUE)),
    });
    handle = result.handle;

    // Create JWT token from Engine1
    token = vault1.engine.createToken("test-agent", ["admin"]);

    // Engine2 loads session from same files (simulates MCP/REST process)
    engine2 = new VaultEngine({
      dbPath: vault1.dbPath,
      sessionPath: vault1.sessionPath,
    });
    const loaded = await engine2.loadSession();
    expect(loaded).toBe(true);

    // MCP server running on Engine2
    mcpServer = createMcpServer({ engine: engine2 });
  });

  afterAll(async () => {
    await engine2?.destroy();
    await vault1?.engine.destroy();
    await new Promise<void>((resolve, reject) => {
      echoServer?.close((err) => (err ? reject(err) : resolve()));
    });
    destroyTestVault(vault1).catch(() => {});
  });

  // ---- Test 1: loadSession succeeds on Engine2 ----------------------------
  it("Engine2 loadSession succeeds and is UNLOCKED", () => {
    expect(engine2.getState()).toBe(VaultState.UNLOCKED);
  });

  // ---- Test 2: Engine2 sees Engine1's secrets -----------------------------
  it("Engine2 listSecrets sees secrets created by Engine1", () => {
    const secrets = engine2.listSecrets();
    expect(secrets).toHaveLength(1);
    expect(secrets[0]!.handle).toBe(handle);
  });

  // ---- Test 3: Engine2 getSecretInfo works --------------------------------
  it("Engine2 getSecretInfo returns correct metadata", async () => {
    const info = await engine2.getSecretInfo(handle);
    expect(info.name).toBe(SECRET_NAME);
    expect(info.type).toBe(SecretType.API_KEY);
    expect(info.status).toBe("active");
  });

  // ---- Test 4: MCP on Engine2 sees Engine1's secrets ----------------------
  it("MCP server on Engine2 sees Engine1's secrets", async () => {
    const result = await callTool(mcpServer, "list_secrets", {});
    const secrets = JSON.parse(result.content[0]!.text) as Array<{ handle: string }>;
    expect(secrets).toHaveLength(1);
    expect(secrets[0]!.handle).toBe(handle);
  });

  // ---- Test 5: REST on Engine2 serves Engine1's secrets -------------------
  it("REST app on Engine2 serves Engine1's secrets", async () => {
    const app = createApp(engine2);
    const res = await app.request("/api/v1/secrets", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: Array<{ handle: string }> };
    expect(body.data).toHaveLength(1);
    expect(body.data[0]!.handle).toBe(handle);
  });

  // ---- Test 6: Engine2 can getSecretValue + useSecret ---------------------
  it("Engine2 can getSecretValue and useSecret with echo server", async () => {
    const value = await engine2.getSecretValue(handle);
    expect(Buffer.from(value).toString("utf8")).toBe(SECRET_VALUE);

    const response = await engine2.useSecret(handle, {
      type: "http",
      method: "GET",
      url: echoUrl,
      injection: { type: InjectionType.BEARER },
    });
    expect(response.status).toBe(200);
    const body = JSON.parse(response.body!) as { headers: Record<string, string> };
    // Exact-match redaction in VaultEngine.useSecret() scrubs the secret value
    expect(body.headers.authorization).toBe("Bearer [REDACTED]");
  });

  // ---- Test 7: Token from Engine1 valid on Engine2 (REST auth) ------------
  it("token created by Engine1 is valid on Engine2 for REST auth", async () => {
    const app = createApp(engine2);
    const res = await app.request("/api/v1/secrets", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
  });

  // ---- Test 8: Audit events from both engines visible to both -------------
  it("audit events from both engines are visible to both", () => {
    const events1 = vault1.engine.queryAudit();
    const events2 = engine2.queryAudit();

    // Both should see the vault.unlock and secret.create events
    const types1 = events1.map((e) => e.event_type);
    const types2 = events2.map((e) => e.event_type);

    expect(types1).toContain("vault.unlock");
    expect(types1).toContain("secret.create");
    expect(types2).toContain("vault.unlock");
    expect(types2).toContain("secret.create");

    // Engine2's secret.read events should also be visible
    expect(types2).toContain("secret.read");
  });

  // ---- Test 9: Policy from Engine1 visible to Engine2 ---------------------
  it("policy granted by Engine1 is visible to Engine2", async () => {
    const secretId = await vault1.engine.resolveSecretId(handle);
    vault1.engine.grantPolicy(
      {
        secretId,
        principalType: PrincipalType.AGENT,
        principalId: "mcp-agent",
        permissions: ["read", "use"],
      },
      "test-admin",
    );

    const policies = engine2.listPolicies(secretId);
    expect(policies.length).toBeGreaterThanOrEqual(1);
    expect(policies.some((p) => p.principal_id === "mcp-agent")).toBe(true);
  });

  // ---- Test 10: Both engines remain functional concurrently ---------------
  it("both engines remain functional concurrently (no SQLite lock contention)", async () => {
    // Parallel reads from both engines
    const [secrets1, secrets2, info1, info2] = await Promise.all([
      Promise.resolve(vault1.engine.listSecrets()),
      Promise.resolve(engine2.listSecrets()),
      vault1.engine.getSecretInfo(handle),
      engine2.getSecretInfo(handle),
    ]);

    expect(secrets1).toHaveLength(1);
    expect(secrets2).toHaveLength(1);
    expect(info1.name).toBe(SECRET_NAME);
    expect(info2.name).toBe(SECRET_NAME);
  });
});

// Thesis §4.6 off-host session-file hardening: the real platform keystore path.
// Tests above run with HARPOC_SESSION_KEYSTORE=off; this suite opts back in with
// explicit DPAPI protectors and therefore only runs on Windows.
describe.runIf(process.platform === "win32")("DPAPI-protected session sharing (Windows)", () => {
  it("shares a DPAPI-wrapped session file between engines", async () => {
    // Generous helper timeout: a cold PowerShell + BCL load on a thrashed CI
    // runner has exceeded the 15 s default, tripping writeSession's fallback
    // and failing the scheme assertion with key_protection "none".
    await expectSharedWrappedSession(
      () => new DpapiSessionKeyProtector({ timeoutMs: 45_000 }),
      "dpapi",
      "dpapi-integ-pw",
    );
  });
});

/**
 * Init a vault with engine A under the given protector, assert the on-disk
 * scheme tag, and load the session with a fresh engine B (the DPAPI-suite
 * body, generalized for the keychain/secret-service/keyring schemes).
 */
async function expectSharedWrappedSession(
  makeProtector: () => SessionKeyProtector,
  expectedScheme: string,
  password: string,
): Promise<void> {
  const tmpDir = mkdtempSync(join(tmpdir(), `harpoc-${expectedScheme}-`));
  const dbPath = join(tmpDir, "default.vault.db");
  const sessionPath = join(tmpDir, "session.json");

  const engineA = new VaultEngine({
    dbPath,
    sessionPath,
    sessionKeyProtector: makeProtector(),
  });
  try {
    await engineA.initVault(password);

    const file = JSON.parse(readFileSync(sessionPath, "utf8")) as { key_protection?: string };
    expect(file.key_protection).toBe(expectedScheme);

    const engineB = new VaultEngine({
      dbPath,
      sessionPath,
      sessionKeyProtector: makeProtector(),
    });
    try {
      expect(await engineB.loadSession()).toBe(true);
      expect(engineB.getState()).toBe(VaultState.UNLOCKED);
      expect(engineB.listSecrets()).toEqual([]);
    } finally {
      await engineB.destroy();
    }
  } finally {
    await engineA.destroy();
    rmSync(tmpDir, { recursive: true, force: true });
  }
}

/** Probe a protector roundtrip; skip (never fail) where the keystore is unusable. */
async function probeProtector(makeProtector: () => SessionKeyProtector): Promise<boolean> {
  try {
    const protector = makeProtector();
    const key = new Uint8Array(32).fill(7);
    const blob = await protector.protect(key);
    const unwrapped = await protector.unprotect(blob);
    return Buffer.from(unwrapped).equals(Buffer.from(key));
  } catch {
    return false;
  }
}

const execFileAsync = promisify(execFile);

describe.runIf(process.platform === "darwin")("Keychain-protected session sharing (macOS)", () => {
  const service = `harpoc.test-share.${process.pid}.${Date.now()}`;
  const keychain = process.env["HARPOC_TEST_KEYCHAIN"];
  const makeProtector = (): SessionKeyProtector =>
    new KeystoreWrappedSessionKeyProtector(
      new KeychainWrappingKeyStore({ service, ...(keychain ? { keychain } : {}) }),
    );
  let available = false;

  beforeAll(async () => {
    available = await probeProtector(makeProtector);
  });

  afterAll(async () => {
    await execFileAsync("/usr/bin/security", [
      "delete-generic-password",
      "-s",
      service,
      "-a",
      "harpoc",
      ...(keychain ? [keychain] : []),
    ]).catch(() => {});
  });

  it("shares a keychain-wrapped session file between engines", async (ctx) => {
    if (!available) return ctx.skip();
    await expectSharedWrappedSession(makeProtector, "keychain", "keychain-integ-pw");
  });
});

describe.runIf(process.platform === "linux")("Keyring-protected session sharing (Linux)", () => {
  const description = `harpoc:test-share:${process.pid}:${Date.now()}`;
  const executablePath = findLinuxKeystoreBinary("keyctl");
  const makeProtector = (): SessionKeyProtector =>
    new KeystoreWrappedSessionKeyProtector(
      new KeyringWrappingKeyStore({ executablePath: executablePath as string, description }),
    );
  let available = false;

  beforeAll(async () => {
    if (!executablePath) return;
    available = await probeProtector(makeProtector);
  });

  afterAll(async () => {
    if (!executablePath) return;
    await execFileAsync(executablePath, ["purge", "user", description]).catch(() => {});
  });

  it("shares a keyring-wrapped session file between engines", async (ctx) => {
    if (!available) return ctx.skip();
    await expectSharedWrappedSession(makeProtector, "keyring", "keyring-integ-pw");
  });
});

describe.runIf(process.platform === "linux")(
  "Secret-Service-protected session sharing (Linux)",
  () => {
    const service = `harpoc.test-share.${process.pid}.${Date.now()}`;
    const executablePath = findLinuxKeystoreBinary("secret-tool");
    const makeProtector = (): SessionKeyProtector =>
      new KeystoreWrappedSessionKeyProtector(
        new SecretServiceWrappingKeyStore({ executablePath: executablePath as string, service }),
      );
    let available = false;

    beforeAll(async () => {
      if (!executablePath || (process.env["DBUS_SESSION_BUS_ADDRESS"] ?? "") === "") return;
      available = await probeProtector(makeProtector);
    });

    afterAll(async () => {
      if (!executablePath) return;
      await execFileAsync(executablePath, ["clear", "service", service, "account", "harpoc"]).catch(
        () => {},
      );
    });

    it("shares a secret-service-wrapped session file between engines", async (ctx) => {
      if (!available) return ctx.skip();
      await expectSharedWrappedSession(makeProtector, "secret-service", "secretsvc-integ-pw");
    });
  },
);
