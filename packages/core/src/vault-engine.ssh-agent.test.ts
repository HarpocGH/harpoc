import { createPublicKey, verify } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext, InjectionPolicyInput, Permission } from "@harpoc/shared";
import {
  agentSocketCaller,
  AuditEventType,
  ErrorCode,
  RATE_LIMIT_USE_SECRET,
  SecretType,
  tokenlessStdioCaller,
} from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";
import type { AgentBinding, AgentSignRequest } from "./injection/ssh-agent/agent-connection.js";
import {
  nonReadAuditCount,
  registerAgents,
  registryOf,
  retainDecryptedValues,
} from "./__fixtures__/engine-seams.js";
import {
  buildUserauthRequest,
  fixtureKnownHostsLine,
  fixturePublicBlob,
  readSshFixture,
} from "./injection/__fixtures__/agent-client.js";
import {
  CAPTURED_HOST_KEY_FIXTURE,
  CAPTURED_SESSION_BIND,
  CAPTURED_SIGN_DATA,
  CAPTURED_SIGN_FLAGS,
  CAPTURED_USER_KEY_FIXTURE,
} from "./injection/__fixtures__/ssh-agent-capture.js";
import { parseSessionBind, verifyHostKeySignature } from "./injection/ssh-agent/session-bind.js";
import { SshReader } from "./injection/ssh-agent/ssh-wire.js";
import type { AgentRegistry } from "./access/agent-registry.js";
import type { SecretManager } from "./secrets/secret-manager.js";
import type { SqliteStore } from "./storage/sqlite-store.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

const readFixture = readSshFixture;
/** A fixture's public key pinned as a known_hosts line for `hosts` (`host`, `[host]:port`, a list). */
const knownHost = (hosts: string, name: string): string => fixtureKnownHostsLine(name, hosts);

const CONSUMER = "ci-bot";
const ED_KEY = fixturePublicBlob("ed25519_openssh");
const EC_KEY = fixturePublicBlob("ecdsa256_openssh");
const OPTOUT_KEY = fixturePublicBlob("ecdsa256_pem");
const OTHER_KEY = fixturePublicBlob("rsa_openssh");
const UNKNOWN_KEY = fixturePublicBlob("ed25519_enc");
/** Server host keys: github.test's, gitlab.test's (pinned as [gitlab.test]:2222) and one nobody pins. */
const HOST_A = fixturePublicBlob("ecdsa384_openssh");
const HOST_B = fixturePublicBlob("ecdsa521_openssh");
const HOST_C = fixturePublicBlob("rsa_pem");
const SESSION = Buffer.alloc(32, 0x5a);
const NOT_A_KEY = "api-token-value-not-a-key-b3";

let tempDir: string;
let engine: VaultEngine;
const ids: Record<string, string> = {};

async function addSecret(
  name: string,
  value: string,
  policy: InjectionPolicyInput,
  grants: Array<[string, Permission[]]> = [[CONSUMER, ["use"]]],
  knownHosts = [knownHost("github.test", "ecdsa384_openssh")],
): Promise<void> {
  const handle = `secret://${name}`;
  await engine.createSecret({
    name,
    type: SecretType.API_KEY,
    value: new Uint8Array(Buffer.from(value)),
  });
  ids[name] = await engine.resolveSecretId(handle);
  await engine.setInjectionPolicy(handle, policy);
  await engine.setConnectionConfig(handle, { ssh: { known_hosts: knownHosts } });
  for (const [principalId, permissions] of grants) {
    engine.grantPolicy(
      { secretId: ids[name] as string, principalType: "agent", principalId, permissions },
      "test-admin",
    );
  }
}

const caller = (): CallerContext => agentSocketCaller(CONSUMER);
const boundTo = (hostKeyBlob: Buffer, sessionId = SESSION): AgentBinding => ({
  hostKeyBlob,
  sessionId,
});

/** The sign request lane P's responder hands the engine: by default the data is the userauth request ssh signs for `keyBlob` in session `SESSION`. */
function signRequest(
  keyBlob: Buffer,
  binding: AgentBinding | null,
  overrides: { data?: Buffer; forwarding?: boolean } = {},
): AgentSignRequest {
  const data =
    overrides.data ??
    buildUserauthRequest({
      sessionId: SESSION,
      user: "git",
      algorithm: new SshReader(keyBlob).readCString(),
      publicKeyBlob: keyBlob,
    });
  return { keyBlob, data, flags: 0, binding, forwarding: overrides.forwarding ?? false };
}

function ed25519PublicKey(blob: Buffer): KeyObject {
  const reader = new SshReader(blob);
  reader.readString();
  const x = reader.readString().toString("base64url");
  return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x }, format: "jwk" });
}

const useRows = (secretId?: string) =>
  engine.queryAudit({ eventType: AuditEventType.SECRET_USE, secretId });
const LISTING = "agent_socket_identities";
const listingRows = () =>
  engine
    .queryAudit({ eventType: AuditEventType.VAULT_READ })
    .filter((row) => row.detail?.["operation"] === LISTING);
const allZero = (buf: Uint8Array): boolean => buf.every((b) => b === 0);
const store = (): SqliteStore => (engine as unknown as { store: SqliteStore }).store;
const agentRegistry = (): AgentRegistry =>
  (engine as unknown as { agentRegistry: AgentRegistry }).agentRegistry;

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-sshagent-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
  registerAgents(engine, CONSUMER, "other-bot");
  await addSecret("deploy-ed", readFixture("ed25519_openssh"), {
    host_allowlist: ["github.test"],
    ssh_agent_socket: true,
  });
  await addSecret(
    "deploy-ec",
    readFixture("ecdsa256_openssh"),
    { host_allowlist: ["gitlab.test"], ssh_agent_socket: true },
    [[CONSUMER, ["use"]]],
    [knownHost("[gitlab.test]:2222", "ecdsa521_openssh")],
  );
  await addSecret("api-token", NOT_A_KEY, {
    host_allowlist: ["github.test"],
    ssh_agent_socket: true,
  });
  await addSecret("ec-optout", readFixture("ecdsa256_pem"), { host_allowlist: ["github.test"] });
  await addSecret(
    "rsa-other",
    readFixture("rsa_openssh"),
    { host_allowlist: ["github.test"], ssh_agent_socket: true },
    [["other-bot", ["use"]]],
  );
});

afterEach(async () => {
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("listAgentSocketIdentities — the keys a consumer's socket lists", () => {
  it("unbound: every granted, opted-in, active key under its handle; a non-key, an ungranted and an opted-out key absent", async () => {
    expect(await engine.listAgentSocketIdentities(caller(), null)).toEqual([
      { publicKeyBlob: EC_KEY, comment: "secret://deploy-ec" },
      { publicKeyBlob: ED_KEY, comment: "secret://deploy-ed" },
    ]);
  });

  it("bound: only the keys whose secret pins the bound host key (R-P3)", async () => {
    expect(await engine.listAgentSocketIdentities(caller(), boundTo(HOST_A))).toEqual([
      { publicKeyBlob: ED_KEY, comment: "secret://deploy-ed" },
    ]);
    expect(await engine.listAgentSocketIdentities(caller(), boundTo(HOST_B))).toEqual([
      { publicKeyBlob: EC_KEY, comment: "secret://deploy-ec" },
    ]);
    expect(await engine.listAgentSocketIdentities(caller(), boundTo(HOST_C))).toEqual([]);
  });

  it("bound to a pinned host the allowlist does not admit: the key is still listed — the sign judges the allowlist and records the refusal (RT-1)", async () => {
    await engine.setInjectionPolicy("secret://deploy-ed", {
      host_allowlist: ["elsewhere.test"],
      ssh_agent_socket: true,
    });
    expect(await engine.listAgentSocketIdentities(caller(), boundTo(HOST_A))).toEqual([
      { publicKeyBlob: ED_KEY, comment: "secret://deploy-ed" },
    ]);
    await expectVaultError(
      () => engine.signForAgentSocket(caller(), signRequest(ED_KEY, boundTo(HOST_A))),
      ErrorCode.HOST_NOT_ALLOWED,
    );
    expect(useRows(ids["deploy-ed"]).map((row) => row.detail?.["error"])).toEqual([
      ErrorCode.HOST_NOT_ALLOWED,
    ]);
  });

  it("needs use or admin — a read-only grant lists nothing, an admin grant lists the key", async () => {
    await addSecret(
      "key-reader",
      readFixture("ecdsa384_openssh"),
      { host_allowlist: ["github.test"], ssh_agent_socket: true },
      [[CONSUMER, ["read"]]],
    );
    await addSecret(
      "key-admin",
      readFixture("ecdsa521_openssh"),
      { host_allowlist: ["github.test"], ssh_agent_socket: true },
      [[CONSUMER, ["admin"]]],
    );
    const comments = (await engine.listAgentSocketIdentities(caller(), null)).map(
      (identity) => identity.comment,
    );
    expect(comments).toEqual(["secret://deploy-ec", "secret://deploy-ed", "secret://key-admin"]);
  });

  it("a deactivated or unregistered consumer is served nothing", async () => {
    engine.deactivateAgent(CONSUMER);
    expect(await engine.listAgentSocketIdentities(caller(), null)).toEqual([]);
    expect(await engine.listAgentSocketIdentities(agentSocketCaller("ghost"), null)).toEqual([]);
  });

  it("an expired key drops out without the lazy transition — the enumeration writes its one vault.read row and no other", async () => {
    store().updateSecret(ids["deploy-ed"] as string, { expires_at: Date.now() - 1000 });
    const before = nonReadAuditCount(engine);

    expect(await engine.listAgentSocketIdentities(caller(), null)).toEqual([
      { publicKeyBlob: EC_KEY, comment: "secret://deploy-ec" },
    ]);
    expect(engine.queryAudit({ eventType: AuditEventType.SECRET_EXPIRE })).toHaveLength(0);
    expect(useRows()).toHaveLength(0);
    expect(nonReadAuditCount(engine)).toBe(before);
    expect(listingRows().map((row) => row.detail?.["count"])).toEqual([1]);
  });

  it("decrypts only the keys it may serve, each once per stored value, and wipes every buffer; a rotation re-derives", async () => {
    const retained = retainDecryptedValues(engine);

    await engine.listAgentSocketIdentities(caller(), null);
    expect(retained).toHaveLength(3);
    expect(retained.every(allZero)).toBe(true);

    await engine.listAgentSocketIdentities(caller(), boundTo(HOST_A));
    await engine.listAgentSocketIdentities(caller(), null);
    expect(retained).toHaveLength(3);

    await engine.rotateSecret(
      "secret://deploy-ed",
      new Uint8Array(Buffer.from(readFixture("ecdsa384_openssh"))),
    );
    const after = await engine.listAgentSocketIdentities(caller(), null);
    expect(retained).toHaveLength(4);
    expect(retained.every(allZero)).toBe(true);
    expect(after.find((identity) => identity.comment === "secret://deploy-ed")).toEqual({
      publicKeyBlob: HOST_A,
      comment: "secret://deploy-ed",
    });
  });

  it("refuses a caller that is not an agent socket's INVALID_INPUT, and a sealed engine VAULT_LOCKED", async () => {
    await expectVaultError(
      () => engine.listAgentSocketIdentities(tokenlessStdioCaller("mcp"), null),
      ErrorCode.INVALID_INPUT,
    );
    await expectVaultError(
      () =>
        engine.listAgentSocketIdentities(
          { principal_type: "agent", principal_id: CONSUMER, interface: "rest" },
          null,
        ),
      ErrorCode.INVALID_INPUT,
    );
    await engine.lock();
    await expectVaultError(
      () => engine.listAgentSocketIdentities(caller(), null),
      ErrorCode.VAULT_LOCKED,
    );
  });
});

describe("listAgentSocketIdentities — the listing's vault.read row and its bucket (A6)", () => {
  const HOST_A_FINGERPRINT = "SHA256:bP78DfpGjDBVPrHoEx6Q+ZZrTMW6YdkiLJaMDLnQSvU";
  const HOST_C_FINGERPRINT = "SHA256:x0wqZripSfHc9nQIqNx1c05R9Fpe0qmpL2Vg/S8iAh8";
  const NAMES = ["deploy-ed", "deploy-ec", "api-token", "ec-optout", "rsa-other", CONSUMER];

  it("an unbound listing writes one row after the read — bound false, the count, the consumer's principal — naming no handle and no key", async () => {
    const before = nonReadAuditCount(engine);

    expect(await engine.listAgentSocketIdentities(caller(), null)).toHaveLength(2);

    expect(nonReadAuditCount(engine)).toBe(before);
    const rows = listingRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      event_type: AuditEventType.VAULT_READ,
      secret_id: null,
      principal_type: "agent",
      principal_id: CONSUMER,
      ip_address: null,
      success: true,
    });
    expect(rows[0]?.detail).toEqual({
      operation: LISTING,
      bound: false,
      count: 2,
      interface: "ssh_agent",
    });
    const serialized = JSON.stringify(rows[0]?.detail);
    for (const name of NAMES) expect(serialized.includes(name)).toBe(false);
    for (const blob of [ED_KEY, EC_KEY]) {
      expect(serialized.includes(blob.toString("base64"))).toBe(false);
    }
  });

  it("a bound listing records the bound host key's fingerprint; a host key no served secret pins writes count 0 with its own (the unpinned hop)", async () => {
    expect(await engine.listAgentSocketIdentities(caller(), boundTo(HOST_A))).toHaveLength(1);
    expect(await engine.listAgentSocketIdentities(caller(), boundTo(HOST_C))).toEqual([]);

    const rows = listingRows();
    expect(rows.map((row) => [row.success, row.principal_id, row.detail])).toEqual([
      [
        true,
        CONSUMER,
        {
          operation: LISTING,
          bound: true,
          count: 0,
          host_key_fingerprint: HOST_C_FINGERPRINT,
          interface: "ssh_agent",
        },
      ],
      [
        true,
        CONSUMER,
        {
          operation: LISTING,
          bound: true,
          count: 1,
          host_key_fingerprint: HOST_A_FINGERPRINT,
          interface: "ssh_agent",
        },
      ],
    ]);
    const serialized = JSON.stringify(rows.map((row) => row.detail));
    for (const name of [...NAMES, "github.test", "gitlab.test"]) {
      expect(serialized.includes(name)).toBe(false);
    }
    for (const blob of [HOST_A, HOST_C, ED_KEY]) {
      expect(serialized.includes(blob.toString("base64"))).toBe(false);
    }
  });

  it("a deactivated or unregistered consumer is listed nothing and writes a failed row naming it and the code, no key decrypted", async () => {
    const retained = retainDecryptedValues(engine);
    engine.deactivateAgent(CONSUMER);
    const before = nonReadAuditCount(engine);

    expect(await engine.listAgentSocketIdentities(caller(), null)).toEqual([]);
    expect(
      await engine.listAgentSocketIdentities(agentSocketCaller("ghost"), boundTo(HOST_A)),
    ).toEqual([]);

    expect(retained).toHaveLength(0);
    expect(nonReadAuditCount(engine)).toBe(before);
    expect(
      listingRows().map((row) => [
        row.success,
        row.secret_id,
        row.principal_type,
        row.principal_id,
        row.detail,
      ]),
    ).toEqual([
      [
        false,
        null,
        "agent",
        "ghost",
        {
          operation: LISTING,
          bound: true,
          host_key_fingerprint: HOST_A_FINGERPRINT,
          error: ErrorCode.AGENT_NOT_FOUND,
          interface: "ssh_agent",
        },
      ],
      [
        false,
        null,
        "agent",
        CONSUMER,
        {
          operation: LISTING,
          bound: false,
          error: ErrorCode.AGENT_INACTIVE,
          interface: "ssh_agent",
        },
      ],
    ]);
    const serialized = JSON.stringify(listingRows().map((row) => row.detail));
    for (const name of [...NAMES, "ghost"]) expect(serialized.includes(name)).toBe(false);
  });

  it("the 121st listing of one consumer inside a minute is refused RATE_LIMIT_EXCEEDED with no row, while a signature in the same minute is still served", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      for (let i = 0; i < RATE_LIMIT_USE_SECRET; i++) {
        await engine.listAgentSocketIdentities(caller(), boundTo(HOST_A));
      }
      expect(listingRows()).toHaveLength(RATE_LIMIT_USE_SECRET);

      await expectVaultError(
        () => engine.listAgentSocketIdentities(caller(), boundTo(HOST_A)),
        ErrorCode.RATE_LIMIT_EXCEEDED,
      );
      expect(listingRows()).toHaveLength(RATE_LIMIT_USE_SECRET);
      await engine.signForAgentSocket(caller(), signRequest(ED_KEY, boundTo(HOST_A)));
      expect(useRows(ids["deploy-ed"]).map((row) => row.success)).toEqual([true]);
      expect(
        await engine.listAgentSocketIdentities(agentSocketCaller("other-bot"), null),
      ).toHaveLength(1);

      vi.setSystemTime(Date.now() + 60_000);
      expect(await engine.listAgentSocketIdentities(caller(), boundTo(HOST_A))).toHaveLength(1);
      expect(listingRows().filter((row) => row.principal_id === CONSUMER)).toHaveLength(
        RATE_LIMIT_USE_SECRET + 1,
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("the bucket comes first: served, empty and refused listings draw on one consumer's bucket, and past it the refusal writes no row", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      const served = Math.floor(RATE_LIMIT_USE_SECRET / 3);
      const refused = RATE_LIMIT_USE_SECRET - 2 * served;
      for (let i = 0; i < served; i++) {
        expect(await engine.listAgentSocketIdentities(caller(), null)).toHaveLength(2);
        expect(await engine.listAgentSocketIdentities(caller(), boundTo(HOST_C))).toEqual([]);
      }
      engine.deactivateAgent(CONSUMER);
      for (let i = 0; i < refused; i++) {
        expect(await engine.listAgentSocketIdentities(caller(), null)).toEqual([]);
      }
      expect(listingRows().map((row) => row.success)).toEqual([
        ...Array<boolean>(refused).fill(false),
        ...Array<boolean>(2 * served).fill(true),
      ]);

      await expectVaultError(
        () => engine.listAgentSocketIdentities(caller(), null),
        ErrorCode.RATE_LIMIT_EXCEEDED,
      );
      expect(listingRows()).toHaveLength(RATE_LIMIT_USE_SECRET);
      expect(
        await engine.listAgentSocketIdentities(agentSocketCaller("other-bot"), null),
      ).toHaveLength(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it.each([
    ["a served listing", CONSUMER],
    ["an unregistered consumer's listing", "ghost"],
  ])(
    "%s throws the logger's error and returns nothing when its row cannot be written",
    async (_label, consumer) => {
      vi.spyOn(store(), "insertAuditEvent").mockImplementationOnce(() => {
        throw new Error("audit unavailable");
      });

      let answer: unknown;
      await expect(
        (async () => {
          answer = await engine.listAgentSocketIdentities(agentSocketCaller(consumer), null);
        })(),
      ).rejects.toThrow("audit unavailable");
      expect(answer).toBeUndefined();
      expect(listingRows()).toEqual([]);
    },
  );

  it("an admin scoped to a project finds no listing row on the trail; an unscoped read finds it (A-2)", async () => {
    await engine.listAgentSocketIdentities(caller(), null);

    const scoped = engine.queryAudit({}, { project: "web" });
    expect(scoped.length).toBeGreaterThan(0);
    expect(scoped.filter((row) => row.event_type === AuditEventType.VAULT_READ)).toEqual([]);
    expect(listingRows().map((row) => row.principal_id)).toEqual([CONSUMER]);
  });
});

describe("signForAgentSocket — a bound, allowlisted signature", () => {
  it("signs the userauth request with the granted key and writes one secret.use row naming the bound host", async () => {
    const request = signRequest(ED_KEY, boundTo(HOST_A));
    const signature = await engine.signForAgentSocket(caller(), request);

    const reader = new SshReader(signature);
    expect(reader.readCString()).toBe("ssh-ed25519");
    expect(
      verify(null, Buffer.from(request.data), ed25519PublicKey(ED_KEY), reader.readString()),
    ).toBe(true);
    const rows = useRows(ids["deploy-ed"]);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      success: true,
      principal_type: "agent",
      principal_id: CONSUMER,
      ip_address: null,
    });
    expect(rows[0]?.detail).toEqual({
      context: "ssh_agent",
      key_type: "ssh-ed25519",
      host: "github.test",
      interface: "ssh_agent",
    });
  });

  it("records the port a [host]:port pin carries, and signs with the ECDSA key", async () => {
    const signature = await engine.signForAgentSocket(
      caller(),
      signRequest(EC_KEY, boundTo(HOST_B)),
    );

    expect(new SshReader(signature).readCString()).toBe("ecdsa-sha2-nistp256");
    expect(useRows(ids["deploy-ec"])[0]?.detail).toEqual({
      context: "ssh_agent",
      key_type: "ecdsa-sha2-nistp256",
      host: "gitlab.test",
      port: 2222,
      interface: "ssh_agent",
    });
  });

  it("accepts the hostbound userauth method when its host key is the bound one", async () => {
    const data = buildUserauthRequest({
      sessionId: SESSION,
      user: "git",
      algorithm: "ssh-ed25519",
      publicKeyBlob: ED_KEY,
      hostKeyBlob: HOST_A,
    });
    await engine.signForAgentSocket(caller(), signRequest(ED_KEY, boundTo(HOST_A), { data }));
    expect(useRows(ids["deploy-ed"]).map((row) => row.success)).toEqual([true]);
  });

  it("signs the userauth request a real Win32-OpenSSH 9.5p2 client sent in its captured, bound session", async () => {
    const contents = CAPTURED_SESSION_BIND.subarray(1 + 4 + "session-bind@openssh.com".length);
    const bind = parseSessionBind(contents);
    expect(bind).not.toBeNull();
    const { hostKeyBlob, sessionId, signature: hostSignature } = bind as NonNullable<typeof bind>;
    expect(hostKeyBlob).toEqual(fixturePublicBlob(CAPTURED_HOST_KEY_FIXTURE));
    expect(verifyHostKeySignature(hostKeyBlob, hostSignature, sessionId)).toBe(true);
    await engine.setConnectionConfig("secret://deploy-ed", {
      ssh: { known_hosts: [knownHost("captured.test", CAPTURED_HOST_KEY_FIXTURE)] },
    });
    await engine.setInjectionPolicy("secret://deploy-ed", {
      host_allowlist: ["captured.test"],
      ssh_agent_socket: true,
    });
    const keyBlob = fixturePublicBlob(CAPTURED_USER_KEY_FIXTURE);

    const signature = await engine.signForAgentSocket(caller(), {
      keyBlob,
      data: CAPTURED_SIGN_DATA,
      flags: CAPTURED_SIGN_FLAGS,
      binding: { hostKeyBlob, sessionId },
      forwarding: false,
    });

    const reader = new SshReader(signature);
    expect(reader.readCString()).toBe("ssh-ed25519");
    expect(verify(null, CAPTURED_SIGN_DATA, ed25519PublicKey(keyBlob), reader.readString())).toBe(
      true,
    );
    expect(useRows(ids["deploy-ed"])[0]?.detail).toEqual({
      context: "ssh_agent",
      key_type: "ssh-ed25519",
      host: "captured.test",
      interface: "ssh_agent",
    });
  });

  it("names a bracketed IPv6 pin's host unbracketed — the spelling the allowlist must carry and the row records", async () => {
    await engine.setConnectionConfig("secret://deploy-ed", {
      ssh: { known_hosts: [knownHost("[2001:db8::1]:2222", "ecdsa384_openssh")] },
    });
    await engine.setInjectionPolicy("secret://deploy-ed", {
      host_allowlist: ["[2001:db8::1]"],
      ssh_agent_socket: true,
    });
    const err = await expectVaultError(
      () => engine.signForAgentSocket(caller(), signRequest(ED_KEY, boundTo(HOST_A))),
      ErrorCode.HOST_NOT_ALLOWED,
    );
    expect(err.message).toBe("Host not in secret allowlist: 2001:db8::1");

    await engine.setInjectionPolicy("secret://deploy-ed", {
      host_allowlist: ["2001:db8::1"],
      ssh_agent_socket: true,
    });
    await engine.signForAgentSocket(caller(), signRequest(ED_KEY, boundTo(HOST_A)));
    expect(useRows(ids["deploy-ed"])[0]?.detail).toEqual({
      context: "ssh_agent",
      key_type: "ssh-ed25519",
      host: "2001:db8::1",
      port: 2222,
      interface: "ssh_agent",
    });
  });

  it("wipes the decrypted key once the signature is made", async () => {
    const retained = retainDecryptedValues(engine);
    await engine.signForAgentSocket(caller(), signRequest(ED_KEY, boundTo(HOST_A)));
    expect(retained.length).toBeGreaterThanOrEqual(1);
    expect(retained.every(allZero)).toBe(true);
  });

  it("a seal between the decrypt and the sign refuses VAULT_LOCKED: no signature, the key wiped, no row, no slide", async () => {
    await engine.listAgentSocketIdentities(caller(), null);
    const retained = retainDecryptedValues(engine);
    const manager = (engine as unknown as { secretManager: SecretManager }).secretManager;
    const decrypt = manager.getSecretValue.bind(manager);
    manager.getSecretValue = async (...args: Parameters<SecretManager["getSecretValue"]>) => {
      const value = await decrypt(...args);
      await engine.lock();
      return value;
    };
    const slide = vi.spyOn(engine as unknown as { touchSession: () => void }, "touchSession");

    await expectVaultError(
      () => engine.signForAgentSocket(caller(), signRequest(ED_KEY, boundTo(HOST_A))),
      ErrorCode.VAULT_LOCKED,
    );
    expect(retained).toHaveLength(1);
    expect(retained.every(allZero)).toBe(true);
    expect(slide).not.toHaveBeenCalled();
    await engine.unlock("password");
    expect(useRows(ids["deploy-ed"])).toHaveLength(0);
  });
});

describe("signForAgentSocket — the binding refusals, after the grant, the status and the opt-in", () => {
  it.each([
    ["unbound", null, {}],
    ["forwarding", null, { forwarding: true }],
    ["session_mismatch", boundTo(HOST_A, Buffer.alloc(32, 0x11)), {}],
    ["host_unpinned", boundTo(HOST_C), {}],
  ] as const)(
    "%s: SSH_AGENT_UNBOUND with the reason, a failed row naming no host, the key never handed to a signer",
    async (reason, binding, overrides) => {
      const retained = retainDecryptedValues(engine);
      const err = await expectVaultError(
        () => engine.signForAgentSocket(caller(), signRequest(ED_KEY, binding, overrides)),
        ErrorCode.SSH_AGENT_UNBOUND,
      );
      expect(err.details).toEqual({ reason });
      expect(retained.every(allZero)).toBe(true);
      const rows = useRows(ids["deploy-ed"]);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ success: false, principal_id: CONSUMER });
      expect(rows[0]?.detail).toEqual({
        context: "ssh_agent",
        key_type: "ssh-ed25519",
        reason,
        error: ErrorCode.SSH_AGENT_UNBOUND,
        interface: "ssh_agent",
      });
    },
  );

  it.each([
    ["random bytes", "not_userauth", Buffer.from("not a userauth request")],
    [
      "another key's request",
      "session_mismatch",
      buildUserauthRequest({
        sessionId: SESSION,
        user: "git",
        algorithm: "ecdsa-sha2-nistp256",
        publicKeyBlob: EC_KEY,
      }),
    ],
    [
      "an SSHSIG preamble",
      "not_userauth",
      Buffer.concat([Buffer.from("SSHSIG"), Buffer.alloc(32, 0x5a)]),
    ],
    [
      "a hostbound request naming another host key",
      "session_mismatch",
      buildUserauthRequest({
        sessionId: SESSION,
        user: "git",
        algorithm: "ssh-ed25519",
        publicKeyBlob: ED_KEY,
        hostKeyBlob: HOST_B,
      }),
    ],
  ])("data that is %s is refused %s", async (_label, reason, data) => {
    const err = await expectVaultError(
      () => engine.signForAgentSocket(caller(), signRequest(ED_KEY, boundTo(HOST_A), { data })),
      ErrorCode.SSH_AGENT_UNBOUND,
    );
    expect(err.details).toEqual({ reason });
  });

  it("a pinned host outside host_allowlist is HOST_NOT_ALLOWED, naming the host as the pin spells it", async () => {
    await engine.setInjectionPolicy("secret://deploy-ed", {
      host_allowlist: ["elsewhere.test"],
      ssh_agent_socket: true,
    });

    const err = await expectVaultError(
      () => engine.signForAgentSocket(caller(), signRequest(ED_KEY, boundTo(HOST_A))),
      ErrorCode.HOST_NOT_ALLOWED,
    );
    expect(err.message).toBe("Host not in secret allowlist: github.test");
    expect(useRows(ids["deploy-ed"])[0]?.detail).toEqual({
      context: "ssh_agent",
      key_type: "ssh-ed25519",
      host: "github.test",
      error: ErrorCode.HOST_NOT_ALLOWED,
      interface: "ssh_agent",
    });
  });

  it("a host key pinned for two hosts signs when one of them is allowlisted, recording that one", async () => {
    await engine.setConnectionConfig("secret://deploy-ed", {
      ssh: { known_hosts: [knownHost("mirror.test,github.test", "ecdsa384_openssh")] },
    });
    await engine.signForAgentSocket(caller(), signRequest(ED_KEY, boundTo(HOST_A)));
    expect(useRows(ids["deploy-ed"])[0]).toMatchObject({
      success: true,
      detail: { host: "github.test" },
    });
  });
});

describe("signForAgentSocket — the secret refusals, in use_secret's order", () => {
  it("a key no secret holds is SECRET_NOT_FOUND with a row that has no secret id and carries the fingerprint", async () => {
    const err = await expectVaultError(
      () => engine.signForAgentSocket(caller(), signRequest(UNKNOWN_KEY, boundTo(HOST_A))),
      ErrorCode.SECRET_NOT_FOUND,
    );
    expect(err.message).toBe("Secret not found");
    const rows = useRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ success: false, secret_id: null, principal_id: CONSUMER });
    expect(rows[0]?.detail).toEqual({
      context: "ssh_agent",
      key_fingerprint: "SHA256:PGqy9HboxVdR2ZmHzKjzZGO89j/0Y276AqDV/8sysIs",
      error: ErrorCode.SECRET_NOT_FOUND,
      interface: "ssh_agent",
    });
  });

  it("a key never opted in is never decrypted and reads as unknown", async () => {
    const retained = retainDecryptedValues(engine);
    await expectVaultError(
      () => engine.signForAgentSocket(caller(), signRequest(OPTOUT_KEY, boundTo(HOST_A))),
      ErrorCode.SECRET_NOT_FOUND,
    );
    expect(retained).toHaveLength(3);
    expect(useRows(ids["ec-optout"])).toHaveLength(0);
  });

  it("another consumer's key: unknown until its own socket derived it, then the concealed refusal with the real id (R5)", async () => {
    await expectVaultError(
      () => engine.signForAgentSocket(caller(), signRequest(OTHER_KEY, boundTo(HOST_A))),
      ErrorCode.SECRET_NOT_FOUND,
    );
    expect(useRows(ids["rsa-other"])).toHaveLength(0);
    expect(useRows()[0]?.detail).toMatchObject({
      key_fingerprint: "SHA256:poiwVN6oYcPs3mDK0YP6qDeI3B6dQBdlEbg4G87OE5Y",
    });

    await engine.listAgentSocketIdentities(agentSocketCaller("other-bot"), null);
    const terminate = vi.spyOn(registryOf(engine), "terminate");
    await expectVaultError(
      () => engine.signForAgentSocket(caller(), signRequest(OTHER_KEY, boundTo(HOST_A))),
      ErrorCode.SECRET_NOT_FOUND,
    );
    expect(useRows(ids["rsa-other"])[0]?.detail).toEqual({
      handle: "secret://rsa-other",
      context: "ssh_agent",
      key_type: "ssh-rsa",
      required_permission: "use",
      error: ErrorCode.ACCESS_DENIED,
      interface: "ssh_agent",
    });
    expect(terminate).toHaveBeenCalledWith(ids["rsa-other"], "use_denied", expect.anything());
  });

  it("a consumer holding read but not use is told ACCESS_DENIED", async () => {
    await engine.listAgentSocketIdentities(agentSocketCaller("other-bot"), null);
    engine.grantPolicy(
      {
        secretId: ids["rsa-other"] as string,
        principalType: "agent",
        principalId: CONSUMER,
        permissions: ["read"],
      },
      "test-admin",
    );
    const err = await expectVaultError(
      () => engine.signForAgentSocket(caller(), signRequest(OTHER_KEY, boundTo(HOST_A))),
      ErrorCode.ACCESS_DENIED,
    );
    expect(err.message).toBe("Access denied: Principal lacks 'use' permission on this secret");
  });

  it("a served key whose opt-in is withdrawn is ACCESS_DENIED naming the remedy, ahead of the binding", async () => {
    await engine.listAgentSocketIdentities(caller(), null);
    await engine.setInjectionPolicy("secret://deploy-ed", { host_allowlist: ["github.test"] });

    const err = await expectVaultError(
      () => engine.signForAgentSocket(caller(), signRequest(ED_KEY, null)),
      ErrorCode.ACCESS_DENIED,
    );
    expect(err.message).toBe(
      "Access denied: the secret is not enabled for the agent socket (harpoc secret allow --ssh-agent-socket)",
    );
    expect(useRows(ids["deploy-ed"])[0]?.detail).toEqual({
      context: "ssh_agent",
      key_type: "ssh-ed25519",
      required_policy: "ssh_agent_socket",
      error: ErrorCode.ACCESS_DENIED,
      interface: "ssh_agent",
    });
  });

  it("a served key that expired is SECRET_EXPIRED ahead of the opt-in and the binding, with the lazy transition's row", async () => {
    await engine.listAgentSocketIdentities(caller(), null);
    await engine.setInjectionPolicy("secret://deploy-ed", { host_allowlist: ["github.test"] });
    store().updateSecret(ids["deploy-ed"] as string, { expires_at: Date.now() - 1000 });
    const terminate = vi.spyOn(registryOf(engine), "terminate");

    await expectVaultError(
      () => engine.signForAgentSocket(caller(), signRequest(ED_KEY, null)),
      ErrorCode.SECRET_EXPIRED,
    );
    expect(useRows(ids["deploy-ed"])[0]?.detail).toEqual({
      handle: "secret://deploy-ed",
      context: "ssh_agent",
      key_type: "ssh-ed25519",
      error: ErrorCode.SECRET_EXPIRED,
      interface: "ssh_agent",
    });
    expect(
      engine.queryAudit({ eventType: AuditEventType.SECRET_EXPIRE, secretId: ids["deploy-ed"] }),
    ).toHaveLength(1);
    expect(terminate).toHaveBeenCalledWith(ids["deploy-ed"], "secret_unusable", expect.anything());
  });

  it("a deactivated consumer is AGENT_INACTIVE, an unregistered one AGENT_NOT_FOUND — each a row with the fingerprint and no secret", async () => {
    engine.deactivateAgent(CONSUMER);
    await expectVaultError(
      () => engine.signForAgentSocket(caller(), signRequest(ED_KEY, boundTo(HOST_A))),
      ErrorCode.AGENT_INACTIVE,
    );
    await expectVaultError(
      () =>
        engine.signForAgentSocket(agentSocketCaller("ghost"), signRequest(ED_KEY, boundTo(HOST_A))),
      ErrorCode.AGENT_NOT_FOUND,
    );
    const rows = useRows();
    expect(rows.map((row) => [row.secret_id, row.principal_id, row.detail?.["error"]])).toEqual([
      [null, "ghost", ErrorCode.AGENT_NOT_FOUND],
      [null, CONSUMER, ErrorCode.AGENT_INACTIVE],
    ]);
    expect(rows[1]?.detail).toEqual({
      context: "ssh_agent",
      key_fingerprint: "SHA256:vKqyAVTrbMF3MHOKboGKqIW51KxwLjApBtP/N48OLeo",
      error: ErrorCode.AGENT_INACTIVE,
      interface: "ssh_agent",
    });
  });

  it("refuses a caller that is not an agent socket's INVALID_INPUT, unaudited, and a sealed engine VAULT_LOCKED", async () => {
    await expectVaultError(
      () =>
        engine.signForAgentSocket(
          tokenlessStdioCaller("mcp"),
          signRequest(ED_KEY, boundTo(HOST_A)),
        ),
      ErrorCode.INVALID_INPUT,
    );
    expect(useRows()).toHaveLength(0);
    await engine.lock();
    await expectVaultError(
      () => engine.signForAgentSocket(caller(), signRequest(ED_KEY, boundTo(HOST_A))),
      ErrorCode.VAULT_LOCKED,
    );
  });
});

describe("the agent socket's session slide and signature budget", () => {
  it("only a signature slides the session: listings and refused signs keep no session alive", async () => {
    const slide = vi.spyOn(engine as unknown as { touchSession: () => void }, "touchSession");

    await engine.listAgentSocketIdentities(caller(), null);
    await engine.listAgentSocketIdentities(caller(), boundTo(HOST_A));
    await expectVaultError(
      () => engine.signForAgentSocket(caller(), signRequest(ED_KEY, null)),
      ErrorCode.SSH_AGENT_UNBOUND,
    );
    await expectVaultError(
      () => engine.signForAgentSocket(caller(), signRequest(UNKNOWN_KEY, boundTo(HOST_A))),
      ErrorCode.SECRET_NOT_FOUND,
    );
    expect(slide).not.toHaveBeenCalled();

    await engine.signForAgentSocket(caller(), signRequest(ED_KEY, boundTo(HOST_A)));
    expect(slide).toHaveBeenCalledTimes(1);
  });

  it("limits each key to use_secret's budget a minute across its consumers, counted after the grant; the next request is RATE_LIMIT_EXCEEDED with no row", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      registerAgents(engine, "third-bot");
      engine.grantPolicy(
        {
          secretId: ids["deploy-ed"] as string,
          principalType: "agent",
          principalId: "other-bot",
          permissions: ["use"],
        },
        "test-admin",
      );
      await engine.listAgentSocketIdentities(caller(), null);
      for (let i = 0; i < 5; i++) {
        await expectVaultError(
          () =>
            engine.signForAgentSocket(
              agentSocketCaller("third-bot"),
              signRequest(ED_KEY, boundTo(HOST_A)),
            ),
          ErrorCode.SECRET_NOT_FOUND,
        );
      }
      const mine = Math.ceil(RATE_LIMIT_USE_SECRET / 2);
      for (const [consumer, count] of [
        [CONSUMER, mine],
        ["other-bot", RATE_LIMIT_USE_SECRET - mine],
      ] as const) {
        for (let i = 0; i < count; i++) {
          await expectVaultError(
            () => engine.signForAgentSocket(agentSocketCaller(consumer), signRequest(ED_KEY, null)),
            ErrorCode.SSH_AGENT_UNBOUND,
          );
        }
      }
      const rows = useRows(ids["deploy-ed"]).length;

      await expectVaultError(
        () => engine.signForAgentSocket(caller(), signRequest(ED_KEY, boundTo(HOST_A))),
        ErrorCode.RATE_LIMIT_EXCEEDED,
      );
      expect(useRows(ids["deploy-ed"])).toHaveLength(rows);
      await engine.signForAgentSocket(caller(), signRequest(EC_KEY, boundTo(HOST_B)));

      vi.setSystemTime(Date.now() + 60_000);
      await engine.signForAgentSocket(caller(), signRequest(ED_KEY, boundTo(HOST_A)));
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("signForAgentSocket — the consumer's signature bucket, ahead of the first row", () => {
  const failedUseRows = (consumer: string) =>
    useRows().filter((row) => !row.success && row.principal_id === consumer);

  it("an unknown key blob: each request inside the consumer's budget writes one failed row, the first past it is RATE_LIMIT_EXCEEDED with none; another consumer has its own budget", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      for (let i = 0; i < RATE_LIMIT_USE_SECRET; i++) {
        await expectVaultError(
          () => engine.signForAgentSocket(caller(), signRequest(UNKNOWN_KEY, boundTo(HOST_A))),
          ErrorCode.SECRET_NOT_FOUND,
        );
      }
      expect(failedUseRows(CONSUMER)).toHaveLength(RATE_LIMIT_USE_SECRET);

      await expectVaultError(
        () => engine.signForAgentSocket(caller(), signRequest(UNKNOWN_KEY, boundTo(HOST_A))),
        ErrorCode.RATE_LIMIT_EXCEEDED,
      );
      await expectVaultError(
        () => engine.signForAgentSocket(caller(), signRequest(ED_KEY, boundTo(HOST_A))),
        ErrorCode.RATE_LIMIT_EXCEEDED,
      );
      expect(useRows()).toHaveLength(RATE_LIMIT_USE_SECRET);

      await expectVaultError(
        () =>
          engine.signForAgentSocket(
            agentSocketCaller("other-bot"),
            signRequest(UNKNOWN_KEY, boundTo(HOST_A)),
          ),
        ErrorCode.SECRET_NOT_FOUND,
      );
      expect(failedUseRows("other-bot")).toHaveLength(1);

      vi.setSystemTime(Date.now() + 60_000);
      await engine.signForAgentSocket(caller(), signRequest(ED_KEY, boundTo(HOST_A)));
      expect(useRows(ids["deploy-ed"]).map((row) => row.success)).toEqual([true]);
    } finally {
      vi.useRealTimers();
    }
  });

  it.each([
    ["an unregistered consumer", "ghost", ErrorCode.AGENT_NOT_FOUND],
    ["a deactivated consumer", CONSUMER, ErrorCode.AGENT_INACTIVE],
  ])(
    "%s: each request inside its budget writes one failed row, the first past it is RATE_LIMIT_EXCEEDED with none, before the registry is read",
    async (_label, consumer, code) => {
      vi.useFakeTimers({ toFake: ["Date"] });
      try {
        if (consumer === CONSUMER) engine.deactivateAgent(CONSUMER);
        for (let i = 0; i < RATE_LIMIT_USE_SECRET; i++) {
          await expectVaultError(
            () =>
              engine.signForAgentSocket(
                agentSocketCaller(consumer),
                signRequest(ED_KEY, boundTo(HOST_A)),
              ),
            code,
          );
        }
        expect(failedUseRows(consumer)).toHaveLength(RATE_LIMIT_USE_SECRET);

        const findByName = vi.spyOn(agentRegistry(), "findByName");
        await expectVaultError(
          () =>
            engine.signForAgentSocket(
              agentSocketCaller(consumer),
              signRequest(ED_KEY, boundTo(HOST_A)),
            ),
          ErrorCode.RATE_LIMIT_EXCEEDED,
        );
        expect(findByName).not.toHaveBeenCalled();
        expect(useRows()).toHaveLength(RATE_LIMIT_USE_SECRET);
      } finally {
        vi.useRealTimers();
      }
    },
  );

  it("the listing's bucket and the signature's do not drain each other", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      for (let i = 0; i < RATE_LIMIT_USE_SECRET; i++) {
        await expectVaultError(
          () => engine.signForAgentSocket(caller(), signRequest(UNKNOWN_KEY, boundTo(HOST_A))),
          ErrorCode.SECRET_NOT_FOUND,
        );
      }
      await expectVaultError(
        () => engine.signForAgentSocket(caller(), signRequest(ED_KEY, boundTo(HOST_A))),
        ErrorCode.RATE_LIMIT_EXCEEDED,
      );

      expect(await engine.listAgentSocketIdentities(caller(), boundTo(HOST_A))).toHaveLength(1);
      expect(listingRows().map((row) => [row.success, row.principal_id])).toEqual([
        [true, CONSUMER],
      ]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("a signature counts against the consumer's bucket: its budget is shared across its keys", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      const withEd = Math.ceil(RATE_LIMIT_USE_SECRET / 2);
      for (let i = 0; i < withEd; i++) {
        await engine.signForAgentSocket(caller(), signRequest(ED_KEY, boundTo(HOST_A)));
      }
      for (let i = withEd; i < RATE_LIMIT_USE_SECRET; i++) {
        await engine.signForAgentSocket(caller(), signRequest(EC_KEY, boundTo(HOST_B)));
      }
      expect(useRows().filter((row) => row.success)).toHaveLength(RATE_LIMIT_USE_SECRET);

      await expectVaultError(
        () => engine.signForAgentSocket(caller(), signRequest(EC_KEY, boundTo(HOST_B))),
        ErrorCode.RATE_LIMIT_EXCEEDED,
      );
      await expectVaultError(
        () => engine.signForAgentSocket(caller(), signRequest(ED_KEY, boundTo(HOST_A))),
        ErrorCode.RATE_LIMIT_EXCEEDED,
      );
      expect(useRows()).toHaveLength(RATE_LIMIT_USE_SECRET);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("signForAgentSocket — nothing secret leaves in a message or a row", () => {
  it("no thrown message and no row carries the key, the session identifier, the data, the signature or the user name", async () => {
    const messages: string[] = [];
    const attempt = async (request: AgentSignRequest): Promise<void> => {
      try {
        await engine.signForAgentSocket(caller(), request);
      } catch (err) {
        messages.push((err as Error).message);
      }
    };
    const signature = await engine.signForAgentSocket(
      caller(),
      signRequest(ED_KEY, boundTo(HOST_A)),
    );
    await attempt(signRequest(ED_KEY, null));
    await attempt(signRequest(ED_KEY, boundTo(HOST_A, Buffer.alloc(32, 0x11))));
    await attempt(signRequest(ED_KEY, boundTo(HOST_C)));
    await attempt(signRequest(UNKNOWN_KEY, boundTo(HOST_A)));
    await attempt(signRequest(EC_KEY, boundTo(HOST_A)));

    const pemLines = ["ed25519_openssh", "ecdsa256_openssh", "ecdsa256_pem"].flatMap((name) =>
      readFixture(name)
        .split(/\r?\n/)
        .filter((line) => line.length >= 16 && !line.startsWith("-----")),
    );
    const data = signRequest(ED_KEY, boundTo(HOST_A)).data;
    const needles = [
      ...pemLines,
      SESSION.toString("base64"),
      SESSION.toString("hex"),
      data.toString("base64"),
      data.toString("hex"),
      signature.toString("base64"),
      signature.toString("hex"),
      '"git"',
    ];
    const haystack = [...messages, JSON.stringify(useRows())].join("\n");
    expect(messages).toHaveLength(5);
    expect(pemLines.length).toBeGreaterThan(6);
    for (const needle of needles) expect(haystack.includes(needle)).toBe(false);
  });
});
