import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createApp } from "@harpoc/rest-api";
import { SecretType } from "@harpoc/shared";
import {
  createTestVault,
  destroyTestVault,
  grantOn,
  registerAgents,
} from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";

const PASSWORD = "rest-scope-denial-pw";

function decodeJti(token: string): string {
  const payload = JSON.parse(
    Buffer.from(token.split(".")[1] as string, "base64url").toString("utf8"),
  ) as { jti: string };
  return payload.jti;
}

// End-to-end REST authorization: real VaultEngine, real signed tokens, full
// middleware stack — no mocks. Complements the route-level denial matrix in
// rest-api/src/routes/secrets.test.ts (code review 2026-07-07, M12).
describe("REST scope enforcement end-to-end", () => {
  let vault: TestVault;
  let app: ReturnType<typeof createApp>;

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    registerAgents(vault.engine, "expired-agent", "pattern-agent", "revoked-agent", "scoped-agent");
    await vault.engine.createSecret({
      name: "db-prod",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("s3cret-value")),
    });
    app = createApp(vault.engine);
  });

  afterAll(async () => {
    await destroyTestVault(vault).catch(() => {});
  });

  it("read/list-scoped token without a grant is told not-found; its use and policy writes stay scope-refused", async () => {
    const token = vault.engine.createToken("scoped-agent", ["read", "list"]);
    const auth = { authorization: `Bearer ${token}`, host: "localhost" };
    const jsonAuth = { ...auth, "content-type": "application/json" };

    const info = await app.request("/api/v1/secrets/db-prod", { headers: auth });
    expect(info.status).toBe(404);

    const use = await app.request("/api/v1/secrets/db-prod/use", {
      method: "POST",
      headers: jsonAuth,
      body: JSON.stringify({
        action: {
          type: "http",
          method: "GET",
          url: "https://api.example.com/data",
          injection: { type: "bearer" },
        },
      }),
    });
    expect(use.status).toBe(403);

    const put = await app.request("/api/v1/secrets/db-prod/injection-policy", {
      method: "PUT",
      headers: jsonAuth,
      body: JSON.stringify({ url_allowlist: ["https://attacker.example/*"] }),
    });
    expect(put.status).toBe(403);

    const policyRes = await app.request("/api/v1/secrets/db-prod/injection-policy", {
      headers: auth,
    });
    expect(policyRes.status).toBe(404);
  });

  it("name-pattern token is denied on out-of-pattern secrets", async () => {
    const token = vault.engine.createToken(
      "pattern-agent",
      ["read", "list", "use", "rotate"],
      undefined,
      { secrets: ["api-*"] },
    );
    const auth = { authorization: `Bearer ${token}`, host: "localhost" };

    const denied = await app.request("/api/v1/secrets/db-prod", { headers: auth });
    expect(denied.status).toBe(403);

    const listRes = await app.request("/api/v1/secrets", { headers: auth });
    expect(listRes.status).toBe(200);
    const listBody = (await listRes.json()) as { data: unknown[] };
    expect(listBody.data).toHaveLength(0);
  });

  it("expired token is rejected with 401", async () => {
    const token = vault.engine.createToken("expired-agent", ["admin"], 0);
    const res = await app.request("/api/v1/secrets", {
      headers: { authorization: `Bearer ${token}`, host: "localhost" },
    });
    expect(res.status).toBe(401);
  });

  it("revoked token is rejected with 401", async () => {
    const token = vault.engine.createToken("revoked-agent", ["admin"]);
    vault.engine.revokeToken(decodeJti(token));
    const res = await app.request("/api/v1/secrets", {
      headers: { authorization: `Bearer ${token}`, host: "localhost" },
    });
    expect(res.status).toBe(401);
  });

  // D6/R14: both config PUTs are deliberately `rotate`, not `admin` (the
  // asymmetry the route file documents). The denial matrix pinned the refusals
  // only, so nothing proved a rotate-only holder can actually complete them.
  it("a rotate-only agent completes both config PUTs end to end", async () => {
    await grantOn(vault.engine, "secret://db-prod", "rotate-agent", ["rotate"]);
    const token = vault.engine.createToken("rotate-agent", ["rotate"]);
    const jsonAuth = {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      host: "localhost",
    };

    const mcp = await app.request("/api/v1/secrets/db-prod/mcp-server", {
      method: "PUT",
      headers: jsonAuth,
      body: JSON.stringify({
        server_name: "rotate-only-mcp",
        transport: "stdio",
        command: "node",
        args: ["server.js"],
        env_var: "GITHUB_TOKEN",
      }),
    });
    expect(mcp.status).toBe(200);
    expect((await mcp.json()) as { data: { updated: boolean } }).toEqual({
      data: { updated: true },
    });

    const connection = await app.request("/api/v1/secrets/db-prod/connection-config", {
      method: "PUT",
      headers: jsonAuth,
      body: JSON.stringify({ database: { tls_mode: "require" } }),
    });
    expect(connection.status).toBe(200);

    // Read back on the trusted path: a 200 that stored nothing would pass the
    // route assertions above.
    const storedMcp = await vault.engine.getMcpServerConfig("secret://db-prod");
    expect(storedMcp?.server_name).toBe("rotate-only-mcp");
    const storedConnection = await vault.engine.getConnectionConfig("secret://db-prod");
    expect(storedConnection?.database?.tls_mode).toBe("require");
  });
});
