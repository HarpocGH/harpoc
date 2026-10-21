import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext, McpServerConfig, Permission } from "@harpoc/shared";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";
import { registerAgents } from "./__fixtures__/engine-seams.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

const HANDLE = "secret://mcp";

const STDIO: McpServerConfig = {
  server_name: "gh",
  transport: "stdio",
  protocol: "2025-11-25",
  command: "node",
  args: ["server.js"],
  env_var: "GH_TOKEN",
};

const HTTP: McpServerConfig = {
  server_name: "docs",
  transport: "http",
  protocol: "2025-11-25",
  url: "https://mcp.example.com/mcp",
};

let tempDir: string;
let engine: VaultEngine;
let secretId: string;

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-mcpcfg-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
  await engine.createSecret({
    name: "mcp",
    type: "api_key",
    value: new Uint8Array(Buffer.from("S3CRET-TOKEN-xyz")),
  });
  secretId = await engine.resolveSecretId(HANDLE);
});

afterEach(async () => {
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function agentWith(id: string, permissions: Permission[], adminScope = false): CallerContext {
  registerAgents(engine, id);
  engine.grantPolicy({ secretId, principalType: "agent", principalId: id, permissions }, "admin");
  const caller: CallerContext = { principal_type: "agent", principal_id: id, interface: "rest" };
  if (adminScope) caller.admin_scope = true;
  return caller;
}

function failedGrantRows(principalId: string): Record<string, unknown>[] {
  return engine
    .queryAudit({ eventType: AuditEventType.POLICY_GRANT, secretId, success: false })
    .filter((row) => row.principal_id === principalId)
    .map((row) => row.detail ?? {});
}

function scopeRefusalRows(principalId: string): Record<string, unknown>[] {
  return engine
    .queryAudit({ eventType: AuditEventType.ACCESS_DENIED })
    .filter((row) => row.principal_id === principalId)
    .map((row) => row.detail ?? {});
}

async function expectStored(expected: McpServerConfig | undefined): Promise<void> {
  expect(await engine.getMcpServerConfig(HANDLE)).toEqual(expected);
}

describe("setMcpServerConfig — rotate pins endpoints, admin launches (TC-14)", () => {
  it("refuses a rotate-only token's first stdio config with one access.denied row and stores nothing", async () => {
    const rotator = agentWith("rotator", ["rotate"]);

    const err = await expectVaultError(
      () => engine.setMcpServerConfig(HANDLE, STDIO, rotator),
      ErrorCode.ACCESS_DENIED,
    );

    expect(err.message).toBe("Access denied: Token lacks permission: admin");
    expect(scopeRefusalRows("rotator")).toEqual([
      {
        operation: "setMcpServerConfig",
        error: ErrorCode.ACCESS_DENIED,
        reason: "permission",
        interface: "rest",
      },
    ]);
    expect(failedGrantRows("rotator")).toEqual([]);
    await expectStored(undefined);
  });

  it("accepts a rotate-only token's first http config", async () => {
    const rotator = agentWith("rotator", ["rotate"]);

    await engine.setMcpServerConfig(HANDLE, HTTP, rotator);

    await expectStored(HTTP);
    expect(scopeRefusalRows("rotator")).toEqual([]);
  });

  it("accepts a rotate-only token's pin-only edit of a stdio config (command, server name)", async () => {
    await engine.setMcpServerConfig(HANDLE, STDIO);
    const rotator = agentWith("rotator", ["rotate"]);
    const pinned: McpServerConfig = { ...STDIO, server_name: "gh2", command: "deno" };

    await engine.setMcpServerConfig(HANDLE, pinned, rotator);

    await expectStored(pinned);
  });

  it("accepts a rotate-only token's url edit of an http config", async () => {
    await engine.setMcpServerConfig(HANDLE, HTTP);
    const rotator = agentWith("rotator", ["rotate"]);
    const moved: McpServerConfig = { ...HTTP, url: "https://mcp2.example.com/mcp" };

    await engine.setMcpServerConfig(HANDLE, moved, rotator);

    await expectStored(moved);
  });

  it("treats absent args and an empty args list as the same launch", async () => {
    const bare: McpServerConfig = { ...STDIO };
    delete bare.args;
    await engine.setMcpServerConfig(HANDLE, bare);
    const rotator = agentWith("rotator", ["rotate"]);

    await engine.setMcpServerConfig(HANDLE, { ...bare, args: [] }, rotator);

    expect((await engine.getMcpServerConfig(HANDLE))?.args).toEqual([]);
  });

  const launchEdits: { field: string; next: McpServerConfig }[] = [
    { field: "args (replaced)", next: { ...STDIO, args: ["--import=./evil.mjs"] } },
    { field: "args (appended)", next: { ...STDIO, args: ["server.js", "--inspect=0.0.0.0"] } },
    { field: "working_directory", next: { ...STDIO, working_directory: "/tmp/elsewhere" } },
    { field: "env_var", next: { ...STDIO, env_var: "OTHER_TOKEN" } },
  ];
  for (const { field, next } of launchEdits) {
    it(`refuses a rotate-only token's ${field} edit and leaves the stored config unchanged`, async () => {
      await engine.setMcpServerConfig(HANDLE, STDIO);
      const rotator = agentWith("rotator", ["rotate"]);

      await expectVaultError(
        () => engine.setMcpServerConfig(HANDLE, next, rotator),
        ErrorCode.ACCESS_DENIED,
      );

      expect(scopeRefusalRows("rotator")).toHaveLength(1);
      await expectStored(STDIO);
    });
  }

  it("refuses a rotate-only token's change of an http config to stdio", async () => {
    await engine.setMcpServerConfig(HANDLE, HTTP);
    const rotator = agentWith("rotator", ["rotate"]);

    await expectVaultError(
      () => engine.setMcpServerConfig(HANDLE, STDIO, rotator),
      ErrorCode.ACCESS_DENIED,
    );

    await expectStored(HTTP);
  });

  it("refuses a rotate-only token's change to stdio of an http config that already carries the launch fields", async () => {
    const carried: McpServerConfig = { ...HTTP, args: STDIO.args, env_var: STDIO.env_var };
    await engine.setMcpServerConfig(HANDLE, carried);
    const rotator = agentWith("rotator", ["rotate"]);
    const launching: McpServerConfig = { ...STDIO, url: HTTP.url };

    await expectVaultError(
      () => engine.setMcpServerConfig(HANDLE, launching, rotator),
      ErrorCode.ACCESS_DENIED,
    );

    await expectStored(carried);
  });

  it("accepts a rotate-only token's change of a stdio config to http (it launches nothing)", async () => {
    await engine.setMcpServerConfig(HANDLE, STDIO);
    const rotator = agentWith("rotator", ["rotate"]);

    await engine.setMcpServerConfig(HANDLE, HTTP, rotator);

    await expectStored(HTTP);
  });

  it("accepts a launch-field write from an admin-granted caller whose token carries admin", async () => {
    const admin = agentWith("launcher", ["admin"], true);

    await engine.setMcpServerConfig(HANDLE, STDIO, admin);

    await expectStored(STDIO);
    const granted = engine
      .queryAudit({ eventType: AuditEventType.POLICY_GRANT, secretId, success: true })
      .filter((row) => row.principal_id === "launcher");
    expect(granted.map((row) => row.detail)).toEqual([
      { policy: "mcp_server", server_name: "gh", transport: "stdio", interface: "rest" },
    ]);
  });

  it("refuses a launch-field write from an admin-granted caller whose token lacks admin (the token attenuates)", async () => {
    const attenuated = agentWith("launcher", ["admin"]);

    await expectVaultError(
      () => engine.setMcpServerConfig(HANDLE, STDIO, attenuated),
      ErrorCode.ACCESS_DENIED,
    );

    expect(scopeRefusalRows("launcher")).toHaveLength(1);
    expect(failedGrantRows("launcher")).toEqual([]);
    await expectStored(undefined);
  });

  it("refuses a launch-field write from an admin-scoped token holding only rotate, with one failed policy.grant row requiring admin", async () => {
    const rotator = agentWith("rotator", ["rotate"], true);

    const err = await expectVaultError(
      () => engine.setMcpServerConfig(HANDLE, STDIO, rotator),
      ErrorCode.ACCESS_DENIED,
    );

    expect(err.message).toBe("Access denied: Principal lacks 'admin' permission on this secret");
    expect(failedGrantRows("rotator")).toEqual([
      {
        policy: "mcp_server",
        handle: HANDLE,
        required_permission: "admin",
        error: ErrorCode.ACCESS_DENIED,
        interface: "rest",
      },
    ]);
    expect(scopeRefusalRows("rotator")).toEqual([]);
    await expectStored(undefined);
  });

  it("accepts a launch-field write from an admin-scoped user token without a grant (R7)", async () => {
    const operator: CallerContext = {
      principal_type: "user",
      principal_id: "operator",
      interface: "rest",
      admin_scope: true,
    };

    await engine.setMcpServerConfig(HANDLE, STDIO, operator);

    await expectStored(STDIO);
  });

  it("accepts a launch-field change on the trusted path", async () => {
    await engine.setMcpServerConfig(HANDLE, STDIO);
    const changed: McpServerConfig = { ...STDIO, args: ["other.js"], working_directory: "/srv" };

    await engine.setMcpServerConfig(HANDLE, changed);

    await expectStored(changed);
  });

  it("keeps deleteMcpServerConfig on rotate for a rotate-only token", async () => {
    await engine.setMcpServerConfig(HANDLE, STDIO);
    const rotator = agentWith("rotator", ["rotate"]);

    expect(await engine.deleteMcpServerConfig(HANDLE, rotator)).toBe(true);

    await expectStored(undefined);
  });
});
