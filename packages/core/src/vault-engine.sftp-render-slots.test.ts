import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  CallerContext,
  InjectionPolicyInput,
  RateLimiter,
  RenderApproval,
  RenderEntry,
  UseSecretAction,
} from "@harpoc/shared";
import {
  AuditEventType,
  ErrorCode,
  injectionPolicyInputSchema,
  PrincipalType,
  SecretStatus,
  VaultError,
} from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import {
  installRenderSeam,
  nonReadAuditCount,
  registerAgents,
  registryOf,
  seedLiveStdioEntry,
  storeInjectionPolicyBlob,
} from "./__fixtures__/engine-seams.js";
import { resolveNativeSshClient } from "./injection/__fixtures__/native-ssh-client.js";
import { approval, ENTRY, ENTRY_ONE, keyPolicy } from "./injection/__fixtures__/render-entries.js";
import { BLOCK, KEY_A } from "./injection/__fixtures__/ssh-public-keys.js";
import { controlledPathDirs } from "./injection/allowlist.js";
import type { PolicyEngine } from "./access/policy-engine.js";
import type { SecretManager } from "./secrets/secret-manager.js";
import type { SqliteStore } from "./storage/sqlite-store.js";
import { VaultEngine } from "./vault-engine.js";
import { system32Path } from "./win32-paths.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

// A slot is judged after the render's client resolved; on Windows only the native
// Win32-OpenSSH client is accepted, so its directory leads the PATH. A host without one skips.
if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}
const SSH = resolveNativeSshClient("ssh");
const describeSsh = describe.skipIf(SSH === null);

const CERTS = join(dirname(fileURLToPath(import.meta.url)), "__fixtures__", "certs");
const KEY = "secret://deploy-key";
const BOT = "secret://bot-token";
const API = "secret://api-key";
const DB = "secret://db-pass";
const X = "secret://x-slot";
const SLOTS = [BOT, API, DB];
const RESULT = { type: "sftp_render", status: "written" };
const REST = { interface: "rest" };
const J = { handle: BOT, context: "sftp", operation: "render", entry: "env", key: KEY };
const ENTRY_X: RenderEntry = { ...ENTRY, name: "x", template: "X={{secret://x-slot}}\n" };
const JX = { ...J, handle: X, entry: "x" };
const SLOT_REFUSED = VaultError.renderSlotRefused().message;

let tempDir: string;
let engine: VaultEngine;
let keyId: string;
let ids: Record<string, string>;
let calls: ReturnType<typeof installRenderSeam>;

interface EngineInternals {
  secretManager: SecretManager;
  store: SqliteStore;
  policyEngine: PolicyEngine;
  renderSlotLimiter: RateLimiter;
  bootstrapHolds: Map<string, string>;
}

function internals(): EngineInternals {
  return engine as unknown as EngineInternals;
}

function render(entry = "env"): UseSecretAction {
  return { type: "sftp", operation: "render", entry } as UseSecretAction;
}

function agent(id: string, extra: Partial<CallerContext> = {}): CallerContext {
  return { principal_type: "agent", principal_id: id, interface: "rest", ...extra };
}

const ALICE = agent("alice");
const BOB = agent("bob");

function draw(): string {
  return randomBytes(18).toString("hex");
}

function bytes(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, "utf8"));
}

async function makeSecret(handle: string, value?: string, expiresAt?: number): Promise<string> {
  const rest = handle.slice("secret://".length);
  const slash = rest.indexOf("/");
  await engine.createSecret({
    name: slash < 0 ? rest : rest.slice(slash + 1),
    project: slash < 0 ? undefined : rest.slice(0, slash),
    type: "api_key",
    ...(value === undefined ? {} : { value: bytes(value) }),
    expiresAt,
  });
  return engine.resolveSecretId(handle);
}

function grant(secretId: string, principalId: string, permissions: ("use" | "read")[]): void {
  engine.grantPolicy(
    { secretId, principalType: PrincipalType.AGENT, principalId, permissions },
    "test",
  );
}

async function approve(
  handle: string,
  entries: RenderEntry[],
  extra: InjectionPolicyInput = {},
): Promise<void> {
  await engine.setInjectionPolicy(handle, {
    ...extra,
    render: { entries: [], approvals: entries.map((entry) => approval(keyId, entry)) },
  });
}

function useRows() {
  return engine
    .queryAudit({ eventType: AuditEventType.SECRET_USE })
    .reverse()
    .map((row) => ({ secret: row.secret_id, success: row.success, detail: row.detail }));
}

/** The refusal every slot row answers: one code, one text without the slot, nothing decrypted, nothing run. */
async function expectSlotRefused(
  as: CallerContext | undefined,
  slot: string,
  action: UseSecretAction = render(),
): Promise<void> {
  const decrypt = vi.spyOn(internals().secretManager, "getSecretValue");
  const err = await expectVaultError(
    () => engine.useSecret(KEY, action, as),
    ErrorCode.RENDER_SLOT_REFUSED,
  );
  expect(err.message).toBe(SLOT_REFUSED);
  expect(err.message).not.toContain(slot.slice("secret://".length));
  expect(decrypt).not.toHaveBeenCalled();
  expect(calls).toHaveLength(0);
  decrypt.mockRestore();
}

// vault-engine.sftp-render.test.ts's engine-building hook, the same as this one, ran past core's
// 30 s on the loaded windows-latest Node 24 leg (ci.yml run 45594869586).
const HOOK_TIMEOUT_MS = 120_000;

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-slots-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
  keyId = await makeSecret(KEY, draw());
  ids = { [KEY]: keyId };
  for (const handle of SLOTS) ids[handle] = await makeSecret(handle, draw());
  await engine.setInjectionPolicy(KEY, keyPolicy([ENTRY]));
  for (const handle of SLOTS) await approve(handle, [ENTRY]);
  registerAgents(engine, "alice", "bob");
  for (const id of Object.values(ids)) grant(id, "alice", ["use"]);
  calls = installRenderSeam(engine);
}, HOOK_TIMEOUT_MS);

afterEach(async () => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}, HOOK_TIMEOUT_MS);

describeSsh("a slot's token scope (4.1)", () => {
  it.each([
    { what: "a token whose name patterns do not admit the slot", as: { secrets: ["deploy-*"] } },
    { what: "a project-claimed token and a project-less slot", as: { project: "ops" } },
  ])("$what", async ({ as }) => {
    const resolve = vi.spyOn(internals().secretManager, "resolveHandle");

    await expectSlotRefused(agent("alice", as), BOT);

    expect(resolve.mock.calls.map((call) => call[0])).toStrictEqual([KEY]);
    expect(useRows()).toStrictEqual([
      { secret: null, success: false, detail: { ...J, error: ErrorCode.ACCESS_DENIED, ...REST } },
    ]);
  });

  it("a project-claimed token and a slot of its project is admitted, the grant through the project principal", async () => {
    const ops: RenderEntry = { ...ENTRY, name: "ops", template: "T={{secret://ops/bot-token}}\n" };
    await engine.setInjectionPolicy(KEY, keyPolicy([ENTRY, ops]));
    const slotId = await makeSecret("secret://ops/bot-token", draw());
    await approve("secret://ops/bot-token", [ops]);
    engine.grantPolicy(
      {
        secretId: slotId,
        principalType: PrincipalType.PROJECT,
        principalId: "ops",
        permissions: ["use"],
      },
      "test",
    );

    await expect(
      engine.useSecret(KEY, render("ops"), agent("alice", { project: "ops" })),
    ).resolves.toStrictEqual(RESULT);
  });

  it("no caller passes", async () => {
    await expect(engine.useSecret(KEY, render())).resolves.toStrictEqual(RESULT);
  });
});

describeSsh("a slot's resolution (4.2)", () => {
  it("a slot no secret has", async () => {
    const missing: RenderEntry = { ...ENTRY, name: "missing", template: "N={{secret://nope}}\n" };
    await engine.setInjectionPolicy(KEY, keyPolicy([ENTRY, missing]));

    await expectSlotRefused(ALICE, "secret://nope", render("missing"));

    expect(useRows()).toStrictEqual([
      {
        secret: null,
        success: false,
        detail: {
          ...J,
          handle: "secret://nope",
          entry: "missing",
          error: ErrorCode.SECRET_NOT_FOUND,
          ...REST,
        },
      },
    ]);
  });

  it("an ambiguous slot", async () => {
    await engine.revokeSecret(BOT);
    await makeSecret(BOT, draw());
    await engine.revokeSecret(BOT);

    await expectSlotRefused(ALICE, BOT);

    expect(useRows()).toStrictEqual([
      {
        secret: null,
        success: false,
        detail: { ...J, error: ErrorCode.AMBIGUOUS_HANDLE, ...REST },
      },
    ]);
  });
});

describeSsh("a slot's use grant (4.3)", () => {
  beforeEach(() => {
    for (const handle of [KEY, API, DB]) grant(ids[handle] as string, "bob", ["use"]);
  });

  it.each([
    { what: "no grant", grants: [] as ("use" | "read")[] },
    { what: "a holder of read alone is told the same", grants: ["read"] as ("use" | "read")[] },
  ])("$what", async ({ grants }) => {
    if (grants.length > 0) grant(ids[BOT] as string, "bob", grants);
    const terminate = vi.spyOn(registryOf(engine), "terminate");

    await expectSlotRefused(BOB, BOT);

    expect(useRows()).toStrictEqual([
      {
        secret: ids[BOT],
        success: false,
        detail: { ...J, required_permission: "use", error: ErrorCode.ACCESS_DENIED, ...REST },
      },
    ]);
    expect(terminate).toHaveBeenCalledWith(ids[BOT], "use_denied", expect.anything());
  });

  it("an administrator-user caller needs no grant and still the approval", async () => {
    const root: CallerContext = {
      principal_type: "user",
      principal_id: "root",
      interface: "rest",
      admin_scope: true,
    };
    await expect(engine.useSecret(KEY, render(), root)).resolves.toStrictEqual(RESULT);

    await approve(BOT, []);
    calls.length = 0;
    await expectSlotRefused(root, BOT);
    expect(useRows().at(-1)).toStrictEqual({
      secret: ids[BOT],
      success: false,
      detail: { ...J, error: ErrorCode.RENDER_NOT_APPROVED, ...REST },
    });
  });
});

describeSsh("a slot's secret and policy (4.4)", () => {
  const fx = (name: string): string => readFileSync(join(CERTS, name), "utf8");
  const approved = { render: { entries: [] as RenderEntry[], approvals: [] as RenderApproval[] } };

  beforeEach(async () => {
    await engine.setInjectionPolicy(KEY, keyPolicy([ENTRY, ENTRY_X]));
    approved.render.approvals = [approval(keyId, ENTRY_X)];
  });

  /** The x slot as each row needs it; answers its id. */
  async function plainX(value: string = draw()): Promise<string> {
    const id = await makeSecret(X, value);
    grant(id, "alice", ["use"]);
    return id;
  }

  function stored(id: string, policy: InjectionPolicyInput): void {
    storeInjectionPolicyBlob(engine, id, injectionPolicyInputSchema.parse(policy));
  }

  it.each([
    {
      what: "a vault-managed certificate",
      code: ErrorCode.CERT_VALUE_UNSUPPORTED,
      ends: "secret_unusable",
      arrange: async () => {
        const { secretId } = await engine.importCertificate("x-slot", fx("rsa-key.pem"), {
          certificatePem: fx("rsa-cert.pem"),
        });
        grant(secretId, "alice", ["use"]);
        return secretId;
      },
    },
    {
      what: "an oauth_token",
      code: ErrorCode.RENDER_SLOT_UNSUPPORTED,
      ends: undefined,
      arrange: async () => {
        await engine.createSecret({ name: "x-slot", type: "oauth_token", value: bytes(draw()) });
        const id = await engine.resolveSecretId(X);
        grant(id, "alice", ["use"]);
        return id;
      },
    },
    {
      what: "revoked",
      code: ErrorCode.SECRET_REVOKED,
      ends: "secret_unusable",
      arrange: async () => {
        const id = await plainX();
        await engine.revokeSecret(X);
        return id;
      },
    },
    {
      what: "pending",
      code: ErrorCode.SECRET_VALUE_REQUIRED,
      ends: "secret_unusable",
      arrange: async () => {
        const id = await makeSecret(X);
        grant(id, "alice", ["use"]);
        return id;
      },
    },
    {
      what: "a stored block",
      code: ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED,
      ends: "ssh_bootstrap_enabled",
      arrange: async () => {
        const id = await plainX();
        stored(id, { ...approved, command_allowlist: ["ssh"], ssh_bootstrap: BLOCK });
        return id;
      },
    },
    {
      what: "a held mark",
      code: ErrorCode.SSH_BOOTSTRAP_IN_FLIGHT,
      ends: undefined,
      arrange: async () => {
        const id = await plainX();
        stored(id, approved);
        internals().store.claimBootstrapMark(id, "held", 1_700_000_000_000);
        internals().bootstrapHolds.set(id, "held");
        return id;
      },
    },
    {
      what: "entries of its own",
      code: ErrorCode.RENDER_SLOT_UNSUPPORTED,
      ends: "render_enabled",
      arrange: async () => {
        const id = await plainX();
        stored(id, {
          ...keyPolicy([ENTRY]),
          render: { entries: [ENTRY], approvals: approved.render.approvals },
        });
        return id;
      },
    },
    {
      what: "network_isolation",
      code: ErrorCode.RENDER_SLOT_UNSUPPORTED,
      ends: undefined,
      arrange: async () => {
        const id = await plainX();
        stored(id, { ...approved, network_isolation: true });
        return id;
      },
    },
  ])("$what", async ({ code, ends, arrange }) => {
    const id = await arrange();
    await seedLiveStdioEntry(engine, id);
    const terminate = vi.spyOn(registryOf(engine), "terminate");
    const before = useRows().length;

    await expectSlotRefused(ALICE, X, render("x"));

    expect(useRows().slice(before)).toStrictEqual([
      { secret: id, success: false, detail: { ...JX, error: code, ...REST } },
    ]);
    if (ends === undefined) expect(terminate).not.toHaveBeenCalled();
    else expect(terminate).toHaveBeenCalledWith(id, ends, expect.anything());
  });

  it("expired, with its secret.expire row", async () => {
    const id = await plainX();
    internals().store.updateSecret(id, { expires_at: 1 });

    await expectSlotRefused(ALICE, X, render("x"));

    expect(useRows()).toStrictEqual([
      { secret: id, success: false, detail: { ...JX, error: ErrorCode.SECRET_EXPIRED, ...REST } },
    ]);
    expect(
      engine.queryAudit({ eventType: AuditEventType.SECRET_EXPIRE, secretId: id }),
    ).toHaveLength(1);
  });

  it("a mark nobody holds ends the slot", async () => {
    const id = await plainX();
    stored(id, approved);
    internals().store.claimBootstrapMark(id, "lost", 1_700_000_000_000);

    await expectSlotRefused(ALICE, X, render("x"));

    expect(useRows()).toStrictEqual([
      {
        secret: id,
        success: false,
        detail: {
          ...JX,
          error: ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED,
          secret_ended: true,
          mark_at: 1_700_000_000_000,
          ...REST,
        },
      },
    ]);
    expect(internals().store.getSecret(id)?.status).toBe(SecretStatus.REVOKED);
    const revokes = engine.queryAudit({ eventType: AuditEventType.SECRET_REVOKE, secretId: id });
    expect(revokes.map((row) => [row.principal_id, row.detail])).toStrictEqual([
      ["alice", { handle: X, reason: "ssh_bootstrap", ...REST }],
    ]);
  });

  it("the key's own handle, met first as a secret with entries of its own", async () => {
    const self: RenderEntry = { ...ENTRY, name: "self", template: "K={{secret://deploy-key}}\n" };
    await engine.setInjectionPolicy(KEY, keyPolicy([ENTRY, self]));
    await seedLiveStdioEntry(engine, keyId);
    const terminate = vi.spyOn(registryOf(engine), "terminate");

    await expectSlotRefused(ALICE, KEY, render("self"));

    expect(terminate.mock.calls.map((call) => [call[0], call[1]])).toStrictEqual([
      [keyId, "render_enabled"],
    ]);

    expect(useRows()).toStrictEqual([
      {
        secret: keyId,
        success: false,
        detail: {
          ...J,
          handle: KEY,
          entry: "self",
          error: ErrorCode.RENDER_SLOT_UNSUPPORTED,
          ...REST,
        },
      },
    ]);
  });

  it("the key's own handle, its entries gone under the call, is the key by id", async () => {
    const self: RenderEntry = { ...ENTRY, name: "self", template: "K={{secret://deploy-key}}\n" };
    await engine.setInjectionPolicy(KEY, keyPolicy([ENTRY, self]));
    calls = installRenderSeam(engine, undefined, {
      refuseOldClient: async () => {
        await engine.setInjectionPolicy(KEY, { command_allowlist: ["ssh"] });
      },
    });
    const terminate = vi.spyOn(registryOf(engine), "terminate");

    await expectSlotRefused(ALICE, KEY, render("self"));

    expect(useRows()).toStrictEqual([
      {
        secret: keyId,
        success: false,
        detail: {
          ...J,
          handle: KEY,
          entry: "self",
          error: ErrorCode.RENDER_SLOT_UNSUPPORTED,
          ...REST,
        },
      },
    ]);
    expect(terminate).not.toHaveBeenCalled();
  });

  it.each([
    {
      pair: "an oauth_token that is pending (4.4b before 4.4c)",
      code: ErrorCode.RENDER_SLOT_UNSUPPORTED,
      arrange: async () => {
        await engine.createSecret({ name: "x-slot", type: "oauth_token" });
        const id = await engine.resolveSecretId(X);
        grant(id, "alice", ["use"]);
        return id;
      },
    },
    {
      pair: "a vault-managed certificate that expired (4.4a before 4.4c)",
      code: ErrorCode.CERT_VALUE_UNSUPPORTED,
      arrange: async () => {
        const { secretId } = await engine.importCertificate("x-slot", fx("rsa-key.pem"), {
          certificatePem: fx("rsa-cert.pem"),
        });
        grant(secretId, "alice", ["use"]);
        internals().store.updateSecret(secretId, { expires_at: 1 });
        return secretId;
      },
    },
    {
      pair: "a revoked secret with a stored block (4.4c before 4.4d)",
      code: ErrorCode.SECRET_REVOKED,
      arrange: async () => {
        const id = await plainX();
        stored(id, { ...approved, command_allowlist: ["ssh"], ssh_bootstrap: BLOCK });
        await engine.revokeSecret(X);
        return id;
      },
    },
    {
      pair: "a stored block and a held mark (4.4d before 4.4e)",
      code: ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED,
      arrange: async () => {
        const id = await plainX();
        stored(id, { ...approved, command_allowlist: ["ssh"], ssh_bootstrap: BLOCK });
        internals().store.claimBootstrapMark(id, "held", 1_700_000_000_000);
        internals().bootstrapHolds.set(id, "held");
        return id;
      },
    },
    {
      pair: "a held mark and entries of its own (4.4e before 4.4f)",
      code: ErrorCode.SSH_BOOTSTRAP_IN_FLIGHT,
      arrange: async () => {
        const id = await plainX();
        stored(id, {
          ...keyPolicy([ENTRY]),
          render: { entries: [ENTRY], approvals: approved.render.approvals },
        });
        internals().store.claimBootstrapMark(id, "held", 1_700_000_000_000);
        internals().bootstrapHolds.set(id, "held");
        return id;
      },
    },
  ])("two of § 6.5's tests met at once, the earlier answers — $pair", async ({ code, arrange }) => {
    const id = await arrange();
    const before = useRows().length;

    await expectSlotRefused(ALICE, X, render("x"));

    expect(useRows().slice(before)).toStrictEqual([
      { secret: id, success: false, detail: { ...JX, error: code, ...REST } },
    ]);
  });
});

describeSsh("a raw throw inside a slot's judgement", () => {
  it.each([
    {
      at: "the use grant's check",
      inject: () => {
        const policies = internals().policyEngine;
        const granted = policies.grantedPermissions.bind(policies);
        vi.spyOn(policies, "grantedPermissions").mockImplementation((secretId, principals) => {
          if (secretId === ids[BOT]) throw new Error("the store failed");
          return granted(secretId, principals);
        });
      },
    },
    {
      at: "the block's refusal",
      inject: () => {
        const at = engine as unknown as { refuseBootstrapOnly: (...args: unknown[]) => void };
        const refuse = at.refuseBootstrapOnly.bind(engine);
        vi.spyOn(at, "refuseBootstrapOnly").mockImplementation((...args: unknown[]) => {
          if (args[1] === ids[BOT]) throw new Error("the store failed");
          refuse(...args);
        });
      },
    },
    {
      at: "the mark's reading",
      inject: () => {
        const live = internals().store;
        const read = live.readBootstrapMark.bind(live);
        vi.spyOn(live, "readBootstrapMark").mockImplementation((secretId) => {
          if (secretId === ids[BOT]) throw new Error("the store failed");
          return read(secretId);
        });
      },
    },
  ])(
    "at $at is no refusal: the slot's one row holds INTERNAL_ERROR and its child is not ended",
    async ({ inject }) => {
      await seedLiveStdioEntry(engine, ids[BOT] as string);
      inject();
      const terminate = vi.spyOn(registryOf(engine), "terminate");

      await expectSlotRefused(ALICE, BOT);

      expect(useRows()).toStrictEqual([
        {
          secret: ids[BOT],
          success: false,
          detail: { ...J, error: ErrorCode.INTERNAL_ERROR, ...REST },
        },
      ]);
      expect(terminate).not.toHaveBeenCalled();
    },
  );
});

describeSsh("a slot's approval (4.5)", () => {
  function expectNotApproved(): void {
    expect(useRows()).toStrictEqual([
      {
        secret: ids[BOT],
        success: false,
        detail: { ...J, error: ErrorCode.RENDER_NOT_APPROVED, ...REST },
      },
    ]);
  }

  it("no approval", async () => {
    await approve(BOT, []);
    await expectSlotRefused(ALICE, BOT);
    expectNotApproved();
  });

  it.each([
    { what: "of another key", approval: () => ({ ...approval(keyId, ENTRY), key: ids[API] }) },
    { what: "of another entry", approval: () => ({ ...approval(keyId, ENTRY), entry: "other" }) },
  ])("an approval $what", async ({ approval: made }) => {
    await engine.setInjectionPolicy(BOT, {
      render: { entries: [], approvals: [made() as ReturnType<typeof approval>] },
    });
    await expectSlotRefused(ALICE, BOT);
    expectNotApproved();
  });

  it.each([
    { part: "host", changed: { host: "h2.example" } },
    { part: "port", changed: { port: 2222 } },
    { part: "user", changed: { user: "deployer" } },
    { part: "path", changed: { path: "/srv/app/.env.local" } },
    { part: "a host key", changed: { host_keys: [KEY_A] } },
    { part: "one byte of the template", changed: { template: ENTRY.template.replace("N", "n") } },
  ])("a change of the entry voids it — $part", async ({ changed }) => {
    await engine.setInjectionPolicy(KEY, {
      ...keyPolicy([{ ...ENTRY, ...changed }]),
      host_allowlist: ["h1.example", "h2.example"],
    });
    await expectSlotRefused(ALICE, BOT);
    expectNotApproved();
  });

  it("a key created again under the name voids it", async () => {
    await engine.revokeSecret(KEY);
    const again = await makeSecret(KEY, draw());
    await engine.setInjectionPolicy(KEY, keyPolicy([ENTRY]));
    grant(again, "alice", ["use"]);

    await expectSlotRefused(ALICE, BOT);
    expectNotApproved();
  });
});

describeSsh("the slot limiter (4.6)", () => {
  const LIMIT = "Per-secret rate limit exceeded";
  const ENTRY_API: RenderEntry = { ...ENTRY, name: "api", template: "{{secret://api-key}}" };

  it("the 121st render of one caller over one slot is refused with no row; another caller and another slot have their own bucket; a minute later it is served", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    await engine.setInjectionPolicy(KEY, keyPolicy([ENTRY, ENTRY_ONE, ENTRY_API]));
    await approve(BOT, [ENTRY, ENTRY_ONE]);
    await approve(API, [ENTRY, ENTRY_API]);
    for (const id of Object.values(ids)) grant(id, "bob", ["use"]);
    for (let i = 0; i < 120; i++) await engine.useSecret(KEY, render("pem"), ALICE);
    const before = nonReadAuditCount(engine);

    const err = await expectVaultError(
      () => engine.useSecret(KEY, render("pem"), ALICE),
      ErrorCode.RATE_LIMIT_EXCEEDED,
    );

    expect(err.message).toBe(LIMIT);
    expect(nonReadAuditCount(engine)).toBe(before);
    await expect(engine.useSecret(KEY, render("pem"), BOB)).resolves.toStrictEqual(RESULT);
    await expect(engine.useSecret(KEY, render("api"), ALICE)).resolves.toStrictEqual(RESULT);
    vi.setSystemTime(Date.now() + 60_000);
    await expect(engine.useSecret(KEY, render("pem"), ALICE)).resolves.toStrictEqual(RESULT);
  });

  it("charged last: refused judgements charge nothing", async () => {
    await approve(BOT, []);
    const charge = vi.spyOn(internals().renderSlotLimiter, "checkSecret");

    for (let i = 0; i < 3; i++) await expectSlotRefused(ALICE, BOT);

    expect(charge).not.toHaveBeenCalled();
  });

  it("a slot judged before a refused one keeps its charge", async () => {
    await approve(API, []);
    const charge = vi.spyOn(internals().renderSlotLimiter, "checkSecret");

    await expectSlotRefused(ALICE, API);

    expect(charge.mock.calls).toStrictEqual([[`agent:alice:${ids[BOT] as string}`, true]]);
  });

  it("the trusted path is not charged", async () => {
    const charge = vi.spyOn(internals().renderSlotLimiter, "checkSecret");

    await expect(engine.useSecret(KEY, render())).resolves.toStrictEqual(RESULT);

    expect(charge).not.toHaveBeenCalled();
  });
});

describeSsh("the order of the slots' judgements", () => {
  it("the slots are judged in the order of first occurrence, each whole before the next", async () => {
    for (const handle of [KEY, BOT, DB]) grant(ids[handle] as string, "bob", ["use"]);
    await approve(BOT, []);
    const resolve = vi.spyOn(internals().secretManager, "resolveHandle");

    await expectSlotRefused(BOB, BOT);

    expect(resolve.mock.calls.map((call) => call[0])).toStrictEqual([KEY, BOT]);
    expect(useRows()).toStrictEqual([
      {
        secret: ids[BOT],
        success: false,
        detail: { ...J, error: ErrorCode.RENDER_NOT_APPROVED, ...REST },
      },
    ]);
  });

  it("one slot's refusals keep § 6.5's order", async () => {
    for (const handle of [KEY, API, DB]) grant(ids[handle] as string, "bob", ["use"]);
    await engine.setInjectionPolicy(BOT, {
      network_isolation: true,
      render: { entries: [], approvals: [] },
    });

    await expectSlotRefused(agent("bob", { secrets: ["deploy-*"] }), BOT);
    await expectSlotRefused(BOB, BOT);
    grant(ids[BOT] as string, "bob", ["use"]);
    await expectSlotRefused(BOB, BOT);
    await engine.setInjectionPolicy(BOT, { render: { entries: [], approvals: [] } });
    await expectSlotRefused(BOB, BOT);
    await approve(BOT, [ENTRY]);
    await expect(engine.useSecret(KEY, render(), BOB)).resolves.toStrictEqual(RESULT);

    expect(useRows().map((row) => row.detail?.error)).toStrictEqual([
      ErrorCode.ACCESS_DENIED,
      ErrorCode.ACCESS_DENIED,
      ErrorCode.RENDER_SLOT_UNSUPPORTED,
      ErrorCode.RENDER_NOT_APPROVED,
      undefined,
      undefined,
      undefined,
      undefined,
    ]);
    expect(useRows()[1]?.detail?.required_permission).toBe("use");
  });
});
