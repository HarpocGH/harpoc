import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { VaultEngine } from "@harpoc/core";
import { createApp } from "@harpoc/rest-api";
import {
  AuditEventType,
  ErrorCode,
  SESSION_FILE_NAME,
  SecretType,
  VAULT_DB_NAME,
} from "@harpoc/shared";
import {
  createTestVault,
  destroyTestVault,
  grantOn,
  registerAgents,
} from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { CLI_ENTRY, runCli, startCliServerOnFreePort } from "./helpers/spawn-cli.js";

const PASSWORD = "audit-lifecycle-pw";
const VALUE = new Uint8Array(Buffer.from("lifecycle-value"));

async function waitFor(
  check: () => boolean,
  timeoutMs: number,
  detail: () => string,
): Promise<void> {
  const started = Date.now();
  while (!check()) {
    if (Date.now() - started > timeoutMs) throw new Error(`timed out: ${detail()}`);
    await new Promise<void>((resolve) => setTimeout(resolve, 50));
  }
}

// R4/D67 and E75i through the real binary: the CLI process writes the rows,
// an in-process engine on the same vault reads them back.
describe("server lifecycle rows through the spawned CLI", () => {
  let vaultDir: string;
  let engine: VaultEngine;

  beforeAll(async () => {
    vaultDir = mkdtempSync(join(tmpdir(), "harpoc-lifecycle-"));
    const init = new VaultEngine({
      dbPath: join(vaultDir, VAULT_DB_NAME),
      sessionPath: join(vaultDir, SESSION_FILE_NAME),
    });
    await init.initVault(PASSWORD);
    await init.destroy();
    const unlock = await runCli(["unlock"], {
      vaultDir,
      stdin: `${PASSWORD}\n`,
    });
    expect(unlock.code).toBe(0);
    engine = new VaultEngine({
      dbPath: join(vaultDir, VAULT_DB_NAME),
      sessionPath: join(vaultDir, SESSION_FILE_NAME),
    });
    expect(await engine.loadSession()).toBe(true);
  }, 120_000);

  afterAll(async () => {
    await engine.destroy();
    rmSync(vaultDir, { recursive: true, force: true });
  });

  it("stdin EOF is a graceful stop: a server.stop row with trigger transport_closed, exit 0", async () => {
    registerAgents(engine, "eof-agent");
    const token = engine.createToken("eof-agent", ["read", "list"]);
    const env = { ...process.env };
    delete env.HARPOC_TOKEN;
    const child = spawn(
      process.execPath,
      [CLI_ENTRY, "--vault-dir", vaultDir, "server", "start", "--mcp", "--token", token],
      { stdio: ["pipe", "pipe", "pipe"], env, windowsHide: true },
    );
    try {
      let stderr = "";
      child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString("utf8")));
      await waitFor(
        () => stderr.includes("MCP server running on stdio"),
        30_000,
        () => stderr,
      );

      child.stdin.end();
      const code = await new Promise<number | null>((resolve) => child.once("close", resolve));
      expect(code).toBe(0);
    } finally {
      if (child.exitCode === null) child.kill();
    }

    const start = engine
      .queryAudit({ eventType: AuditEventType.SERVER_START })
      .find((r) => r.detail?.subject === "eof-agent");
    expect(start?.detail).toMatchObject({
      transport: "stdio",
      tokenless: false,
    });
    const stops = engine.queryAudit({ eventType: AuditEventType.SERVER_STOP });
    expect(stops).toHaveLength(1);
    expect(stops[0]?.detail).toMatchObject({
      transport: "stdio",
      tokenless: false,
      trigger: "transport_closed",
    });
    expect(stops[0]?.principal_type).toBeNull();
    expect(engine.verifyAuditChain().valid).toBe(true);
  }, 60_000);

  it("a REST request's socket peer lands in ip_address (E75i)", async () => {
    registerAgents(engine, "ip-agent");
    await engine.createSecret({
      name: "ip-key",
      type: SecretType.API_KEY,
      value: VALUE,
    });
    await grantOn(engine, "secret://ip-key", "ip-agent", ["read", "list"]);
    const token = engine.createToken("ip-agent", ["read", "list", "admin"]);

    const { server, port } = await startCliServerOnFreePort(
      (p) => ["server", "start", "--rest", "--port", String(p)],
      { vaultDir },
    );
    try {
      const auth = { Authorization: `Bearer ${token}` };
      const info = await fetch(`http://127.0.0.1:${String(port)}/api/v1/secrets/ip-key`, {
        headers: auth,
      });
      expect(info.status).toBe(200);

      const audit = await fetch(
        `http://127.0.0.1:${String(port)}/api/v1/audit?event_type=secret.read`,
        { headers: auth },
      );
      expect(audit.status).toBe(200);
      const rows = (
        (await audit.json()) as {
          data: Array<{
            principal_id: string | null;
            ip_address: string | null;
          }>;
        }
      ).data;
      const mine = rows.filter((r) => r.principal_id === "ip-agent");
      expect(mine.length).toBeGreaterThan(0);
      for (const row of mine) expect(row.ip_address).toBe("127.0.0.1");

      const restStart = engine
        .queryAudit({ eventType: AuditEventType.SERVER_START })
        .find((r) => r.detail?.transport === "rest");
      expect(restStart?.detail).toMatchObject({ tokenless: false, port });
    } finally {
      await server.stop();
    }
  }, 60_000);
});

// D7 over the REST wire: an unknown-handle probe on a route that resolves
// before its id-addressed call leaves an attributed row; an ambiguous handle
// reads like an unknown one to a grantless token and stays 409 to a holder.
describe("unknown-handle probes and ambiguity over the REST wire", () => {
  let vault: TestVault;
  let app: ReturnType<typeof createApp>;

  const auth = (token: string) => ({ authorization: `Bearer ${token}` });

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    registerAgents(vault.engine, "probe-agent", "holder");
    app = createApp(vault.engine);
  });

  afterAll(async () => {
    await destroyTestVault(vault).catch(() => {});
  });

  it("an unknown handle on the oauth status route writes an attributed failed secret.read row", async () => {
    const token = vault.engine.createToken("probe-agent", ["read", "list"]);
    const res = await app.request("/api/v1/oauth/ghost/status", {
      headers: auth(token),
    });
    expect(res.status).toBe(404);

    const row = vault.engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .find((r) => !r.success && r.principal_id === "probe-agent");
    expect(row?.detail).toMatchObject({
      handle: "secret://ghost",
      error: ErrorCode.SECRET_NOT_FOUND,
      interface: "rest",
    });
  });

  it("two revoked secrets of one name: a grantless token reads the unknown-handle 404, a holder reads 409", async () => {
    await vault.engine.createSecret({
      name: "twice",
      type: SecretType.API_KEY,
      value: VALUE,
    });
    await grantOn(vault.engine, "secret://twice", "holder", ["read"]);
    await vault.engine.revokeSecret("secret://twice");
    await vault.engine.createSecret({
      name: "twice",
      type: SecretType.API_KEY,
      value: VALUE,
    });
    await vault.engine.revokeSecret("secret://twice");

    const grantless = vault.engine.createToken("probe-agent", ["read", "list"]);
    const ambiguous = await app.request("/api/v1/secrets/twice", {
      headers: auth(grantless),
    });
    expect(ambiguous.status).toBe(404);
    const body = (await ambiguous.json()) as { error: string; message: string };
    expect(body.error).toBe(ErrorCode.SECRET_NOT_FOUND);
    expect(body.message).toBe("Secret not found: secret://twice");

    const holder = vault.engine.createToken("holder", ["read", "list"]);
    const kept = await app.request("/api/v1/secrets/twice", {
      headers: auth(holder),
    });
    expect(kept.status).toBe(409);

    const row = vault.engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .find(
        (r) =>
          !r.success && r.principal_id === "probe-agent" && r.detail?.handle === "secret://twice",
      );
    expect(row?.detail?.error).toBe(ErrorCode.AMBIGUOUS_HANDLE);
  });

  it("a policy revoke leaves no NULL-principal access_policies read row (E75a fallout)", async () => {
    await vault.engine.createSecret({
      name: "revocable",
      type: SecretType.API_KEY,
      value: VALUE,
    });
    await grantOn(vault.engine, "secret://revocable", "revoker", ["admin"]);
    const doomed = await grantOn(vault.engine, "secret://revocable", "grantee", ["read"]);
    const token = vault.engine.createToken("revoker", ["admin"]);

    const res = await app.request(`/api/v1/secrets/revocable/policies/${doomed.id}`, {
      method: "DELETE",
      headers: auth(token),
    });
    expect(res.status).toBe(200);

    const unattributed = vault.engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .filter((r) => r.principal_type === null && r.detail?.config === "access_policies");
    expect(unattributed).toHaveLength(0);

    const revoked = vault.engine
      .queryAudit({ eventType: AuditEventType.POLICY_REVOKE })
      .find((r) => r.detail?.policy_id === doomed.id);
    expect(revoked?.principal_type).toBe("agent");
    expect(revoked?.principal_id).toBe("revoker");
  });
});
