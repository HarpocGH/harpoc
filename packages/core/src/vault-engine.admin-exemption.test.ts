import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  CallerContext,
  OAuthProviderConfig,
  Permission,
  TokenPrincipalType,
} from "@harpoc/shared";
import { callerFromToken, ErrorCode, SecretType, VaultError } from "@harpoc/shared";
import { VaultEngine } from "./vault-engine.js";

/**
 * R7 (v1.4.1): an admin-scoped user-type token is the operator's own proxy, so
 * it passes the per-secret presence gate and the W2 enumeration filter without
 * a grant of its own. Every other caller class — agent, tool, and a user token
 * without admin scope — stays gated exactly as before.
 */

vi.mock("./crypto/argon2.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("./crypto/argon2.js")>();
  return {
    ...original,
    deriveKey: async (password: string, salt: Uint8Array) => {
      const { createHash } = await import("node:crypto");
      return new Uint8Array(createHash("sha256").update(password).update(salt).digest());
    },
  };
});

let tempDir: string;
let engine: VaultEngine;

/**
 * Derive callers the way the interface layers do. `callerFromToken` is the only
 * producer of `admin_scope`, so a hand-built caller literal could never be
 * exempt — minting a real token is what makes these tests prove the seam.
 */
function callerFor(
  subject: string,
  scope: Permission[],
  principalType: TokenPrincipalType,
): CallerContext {
  const jwt = engine.createToken(subject, scope, 60_000, { principalType });
  return callerFromToken(engine.verifyToken(jwt), "rest");
}

async function makeSecret(name: string): Promise<string> {
  await engine.createSecret({
    name,
    type: SecretType.API_KEY,
    value: new Uint8Array(Buffer.from("v", "utf8")),
  });
  return engine.resolveSecretId(`secret://${name}`);
}

function oauthConfig(): OAuthProviderConfig {
  return {
    provider: "github",
    grant_type: "authorization_code",
    token_endpoint: "https://github.com/login/oauth/access_token",
    auth_endpoint: "https://github.com/login/oauth/authorize",
    client_id: "my-client-id",
    client_secret: "my-client-secret",
    scopes: ["repo"],
  };
}

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-r7-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
});

afterEach(async () => {
  vi.restoreAllMocks();
  await engine.destroy();
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
});

describe("R7 admin-user exemption", () => {
  let secretId: string;

  beforeEach(async () => {
    secretId = await makeSecret("gated-key");
    engine.registerAgent({ name: "cell-agent" });
    // Gate the secret through the trusted path — the caller-less flip R7's
    // self-grant alternative could not cover.
    engine.setAgentPermissions("cell-agent", secretId, ["read"], undefined, "test");
  });

  it("a user+admin caller passes the per-secret gate without a grant of its own", async () => {
    const caller = callerFor("web-ui", ["admin"], "user");

    await expect(engine.getSecretInfo("secret://gated-key", caller)).resolves.toMatchObject({
      name: "gated-key",
    });
  });

  it("a user+admin caller writes a second matrix cell on the gated secret", () => {
    engine.registerAgent({ name: "second-agent" });
    const caller = callerFor("web-ui", ["admin"], "user");

    const flip = engine.setAgentPermissions(
      "second-agent",
      secretId,
      ["read"],
      undefined,
      "web-ui",
      caller,
    );

    expect(flip.gated_before).toBe(true);
    expect(flip.gated_after).toBe(true);
  });

  it("agent+admin and tool+admin callers stay gated (ACCESS_DENIED)", () => {
    engine.registerAgent({ name: "gov-admin" });

    for (const caller of [
      callerFor("gov-admin", ["admin"], "agent"),
      callerFor("ops-tool", ["admin"], "tool"),
    ]) {
      try {
        engine.setAgentPermissions("cell-agent", secretId, ["read", "use"], undefined, "x", caller);
        expect.fail(`expected ACCESS_DENIED for ${caller.principal_type}`);
      } catch (err) {
        expect(err).toBeInstanceOf(VaultError);
        expect((err as VaultError).code).toBe(ErrorCode.ACCESS_DENIED);
      }
    }
  });

  it("a user caller without admin scope stays gated", async () => {
    const caller = callerFor("viewer", ["read", "list"], "user");

    await expect(engine.getSecretInfo("secret://gated-key", caller)).rejects.toMatchObject({
      code: ErrorCode.ACCESS_DENIED,
    });
  });

  it("listSecrets keeps the gated secret visible for the exempt caller only", () => {
    const exempt = callerFor("web-ui", ["admin"], "user");
    const gatedOut = callerFor("viewer2", ["admin", "list"], "tool");

    expect(engine.listSecrets(undefined, exempt).map((s) => s.name)).toContain("gated-key");
    expect(engine.listSecrets(undefined, gatedOut).map((s) => s.name)).not.toContain("gated-key");
  });

  it("the expiring-OAuth projection keeps a gated secret for the exempt caller only", async () => {
    const oauth = await engine.createOAuthSecret("gated-oauth", oauthConfig());
    await engine.completeOAuthFlow(oauth.secretId, "at-1", "rt-1", Date.now() + 30 * 60_000);
    engine.setAgentPermissions("cell-agent", oauth.secretId, ["read"], undefined, "test");

    const exempt = callerFor("web-ui", ["admin"], "user");
    const gatedOut = callerFor("viewer3", ["admin", "list"], "tool");

    expect(engine.getExpiringOAuthTokenStatuses(60 * 60_000, exempt).map((i) => i.name)).toContain(
      "gated-oauth",
    );
    expect(engine.getExpiringOAuthTokenStatuses(60 * 60_000, gatedOut)).toEqual([]);
  });
});
