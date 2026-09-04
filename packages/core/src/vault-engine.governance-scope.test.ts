import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext } from "@harpoc/shared";
import { ErrorCode, SecretType } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";

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

/** An admin-scoped user caller with no project claim — the unscoped admin every governance route expects. */
const UNSCOPED: CallerContext = {
  principal_type: "user",
  principal_id: "admin-1",
  interface: "rest",
  admin_scope: true,
};

/** The same caller with a project claim: R7's admin_scope does not waive N12. */
const PROJECT_SCOPED: CallerContext = { ...UNSCOPED, project: "acme" };

const MESSAGE = "Access denied: governance requires an unscoped admin token";

let tempDir: string;
let engine: VaultEngine;
let secretId: string;
let jti: string;

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-gov-scope-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
  engine.registerAgent({ name: "deploy-bot" });
  await engine.createSecret({
    name: "k",
    type: SecretType.API_KEY,
    value: new Uint8Array(Buffer.from("v")),
  });
  secretId = await engine.resolveSecretId("secret://k");
  engine.createToken("deploy-bot", ["read"], 60_000);
  jti = (engine.listIssuedTokens()[0] as { jti: string }).jti;
});

afterEach(async () => {
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true });
});

/** What a refused call must leave untouched. */
function snapshot(): string {
  return JSON.stringify({
    agents: engine.listAgents("all"),
    policies: engine.listAgentPolicies("deploy-bot"),
    tokens: engine.listIssuedTokens(),
  });
}

const CASES: Array<[string, (caller: CallerContext | undefined) => unknown]> = [
  ["registerAgent", (c) => engine.registerAgent({ name: "other-bot" }, c)],
  ["getAgent", (c) => engine.getAgent("deploy-bot", c)],
  ["listAgents", (c) => engine.listAgents("all", c)],
  ["updateAgent", (c) => engine.updateAgent("deploy-bot", { description: "x" }, c)],
  ["deactivateAgent", (c) => engine.deactivateAgent("deploy-bot", c)],
  ["activateAgent", (c) => engine.activateAgent("deploy-bot", c)],
  ["deleteAgent", (c) => engine.deleteAgent("deploy-bot", c)],
  [
    "setAgentPermissions",
    (c) => engine.setAgentPermissions("deploy-bot", secretId, ["read"], undefined, "test", c),
  ],
  ["listAgentPolicies", (c) => engine.listAgentPolicies("deploy-bot", c)],
  ["listIssuedTokens", (c) => engine.listIssuedTokens(undefined, c)],
  ["revokeToken", (c) => engine.revokeToken(jti, c)],
];

describe("N12: governance is vault-wide — a project-claimed caller is refused", () => {
  it.each(CASES)("%s refuses ACCESS_DENIED and writes nothing", async (_name, call) => {
    const before = snapshot();
    const err = await expectVaultError(
      () => Promise.resolve().then(() => call(PROJECT_SCOPED)),
      ErrorCode.ACCESS_DENIED,
    );
    expect(err.message).toBe(MESSAGE);
    expect(snapshot()).toBe(before);
  });

  it.each(CASES)("%s admits an unscoped admin caller", async (_name, call) => {
    await expect(Promise.resolve().then(() => call(UNSCOPED))).resolves.not.toThrow();
  });

  it.each(CASES)("%s keeps the trusted path (no caller) exempt", async (_name, call) => {
    await expect(Promise.resolve().then(() => call(undefined))).resolves.not.toThrow();
  });
});
