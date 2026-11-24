import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { AuditEventType, ErrorCode, Permission, SecretStatus, VaultError } from "@harpoc/shared";
import { assertOpaque } from "./assert/opacity.js";
import type { AuditRow } from "./harness/audit.js";
import { assertFleetUp } from "./harness/backends.js";
import {
  SSHD_BOOTSTRAP,
  agentPrivateKeyPem,
  agentPublicKey,
  assertFreshHost,
  bootstrapHostKey,
  bootstrapPassword,
  hostState,
} from "./harness/bootstrap.js";
import type { HostState } from "./harness/bootstrap.js";
import { resolveSsh } from "./harness/fixtures.js";
import { startMcpHttpSurface } from "./harness/surfaces/mcp-http.js";
import type { CallOutcome, McpHttpSurface } from "./harness/surfaces/mcp-http.js";
import { createHarnessVault, grantOn, storeSecret } from "./harness/vault.js";
import type { HarnessVault } from "./harness/vault.js";

const WIN32 = process.platform === "win32";
const AGENT = "e2e-bootstrap-agent";
const NOTHING: HostState = { keyLines: 0, dropIn: null, sudoWaiting: false };

interface PasswordSecret {
  handle: string;
  id: string;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function until(what: string, ms: number, check: () => boolean): Promise<void> {
  const deadline = Date.now() + ms;
  while (!check()) {
    if (Date.now() > deadline) throw new Error(`${what}: not seen within ${String(ms)} ms`);
    await sleep(250);
  }
}

function parsed(outcome: CallOutcome): Record<string, unknown> {
  return JSON.parse(outcome.text) as Record<string, unknown>;
}

describe.each(Object.values(SSHD_BOOTSTRAP))("the ssh bootstrap against $service", (target) => {
  let vault: HarnessVault;
  let surface: McpHttpSurface;
  let sshBin: string;
  let password: string;
  let agentKey: string;
  let keyHandle: string;

  beforeAll(async () => {
    assertFleetUp(target.service);
    sshBin = resolveSsh();
    password = bootstrapPassword();
    vault = await createHarnessVault(randomBytes(18).toString("base64url"));
    agentKey = agentPrivateKeyPem();
    keyHandle = await storeSecret(vault, "agent-key", agentKey);
    await vault.engine.setInjectionPolicy(keyHandle, {
      url_allowlist: [],
      command_allowlist: [sshBin],
      env_allowlist: [],
      host_allowlist: [target.host],
    });
    await vault.engine.setConnectionConfig(keyHandle, {
      ssh: { known_hosts: [`[${target.host}]:${String(target.port)} ${bootstrapHostKey()}`] },
    });
    await grantOn(vault, keyHandle, AGENT, [Permission.USE]);
    surface = await startMcpHttpSurface(vault, AGENT, [Permission.USE]);
  });

  afterAll(async () => {
    await surface?.close();
    await vault?.destroy();
  });

  async function passwordSecret(
    name: string,
    user: string,
    block: { sudoers?: boolean; hostKey?: string } = {},
  ): Promise<PasswordSecret> {
    const handle = await storeSecret(vault, name, password);
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: [sshBin],
      env_allowlist: [],
      host_allowlist: [],
      ssh_bootstrap: {
        host: target.host,
        port: target.port,
        user,
        host_keys: [block.hostKey ?? bootstrapHostKey()],
        install_keys: [agentPublicKey()],
        sudoers: block.sudoers ?? false,
      },
    });
    await grantOn(vault, handle, AGENT, [Permission.USE]);
    return { handle, id: await vault.engine.resolveSecretId(handle) };
  }

  async function bootstrap(
    secret: PasswordSecret,
    user: string,
    action: { public_key?: string; sudoers?: boolean } = {},
  ): Promise<CallOutcome> {
    const outcome = await surface.callUseSecret(secret.handle, {
      type: "ssh",
      operation: "bootstrap",
      host: target.host,
      port: target.port,
      user,
      public_key: action.public_key ?? agentPublicKey(),
      ...(action.sudoers === undefined ? {} : { sudoers: action.sudoers }),
    });
    assertOpaque(password, {
      result: outcome.result,
      error: outcome.errorText,
      auditRows: vault.engine.queryAudit(),
      parentEnv: process.env,
    });
    return outcome;
  }

  async function sshAs(user: string, command: string): Promise<Record<string, unknown>> {
    const outcome = await surface.callUseSecret(keyHandle, {
      type: "ssh",
      host: target.host,
      port: target.port,
      user,
      command,
    });
    assertOpaque(agentKey, {
      result: outcome.result,
      error: outcome.errorText,
      auditRows: vault.engine.queryAudit(),
      parentEnv: process.env,
    });
    expect(outcome.ok, outcome.text).toBe(true);
    return parsed(outcome);
  }

  function useRows(secret: PasswordSecret): AuditRow[] {
    return vault.engine.queryAudit({
      secretId: secret.id,
      eventType: AuditEventType.SECRET_USE,
    }) as unknown as AuditRow[];
  }

  function revokeRows(secret: PasswordSecret): AuditRow[] {
    return vault.engine.queryAudit({
      secretId: secret.id,
      eventType: AuditEventType.SECRET_REVOKE,
    }) as unknown as AuditRow[];
  }

  function began(secret: PasswordSecret): number {
    return useRows(secret).filter((row) => row.detail?.["began"] === true).length;
  }

  function failedWith(secret: PasswordSecret, code: string): AuditRow[] {
    return useRows(secret).filter((row) => !row.success && row.detail?.["error"] === code);
  }

  async function statusOf(secret: PasswordSecret): Promise<string> {
    return (await vault.engine.getSecretInfo(secret.handle)).status;
  }

  function expectRefused(outcome: CallOutcome, error: VaultError): void {
    expect(outcome.ok, outcome.text).toBe(false);
    expect(outcome.errorText ?? "").toContain(error.message);
  }

  async function expectEnded(secret: PasswordSecret, user: string): Promise<void> {
    expect(await statusOf(secret)).toBe(SecretStatus.REVOKED);
    const before = began(secret);
    const again = await bootstrap(secret, user);
    expectRefused(again, VaultError.secretRevoked(secret.handle));
    expect(failedWith(secret, ErrorCode.SECRET_REVOKED)).toHaveLength(1);
    expect(began(secret)).toBe(before);
  }

  // The bootstrap is not served on a Windows vault host (SSH_CLIENT_UNSUPPORTED): the row of
  // the describe below pins that refusal there.
  describe.skipIf(WIN32)("on a vault host that serves the bootstrap", () => {
    let plain: PasswordSecret;

    beforeAll(() => {
      assertFreshHost(target.service);
    });

    it("an unlisted public key, a host key that is not the stored one, the flag without the opt-in: each refused with its failed row, nothing on the host, every secret usable", async () => {
      const before = hostState(target.service, "plain");

      const unlisted = await passwordSecret("unlisted-key", "plain");
      const first = await bootstrap(unlisted, "plain", { public_key: bootstrapHostKey() });
      expectRefused(first, VaultError.sshBootstrapNotAllowed("key"));
      const firstRows = failedWith(unlisted, ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED);
      expect(firstRows.map((row) => row.detail?.["reason"])).toEqual(["key"]);

      const otherHost = await passwordSecret("other-host-key", "plain", {
        hostKey: agentPublicKey(),
      });
      const second = await bootstrap(otherHost, "plain");
      expectRefused(second, VaultError.sshHostKeyMismatch());
      const secondRows = failedWith(otherHost, ErrorCode.SSH_HOST_KEY_MISMATCH);
      expect(secondRows).toHaveLength(1);
      expect(secondRows[0]?.detail?.["outcome"]).toBe("refused");
      expect(secondRows[0]?.detail?.["secret_ended"]).toBe(false);

      const noOptIn = await passwordSecret("no-opt-in", "plain");
      const third = await bootstrap(noOptIn, "plain", { sudoers: true });
      expectRefused(third, VaultError.sshBootstrapNotAllowed("sudoers"));
      const thirdRows = failedWith(noOptIn, ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED);
      expect(thirdRows.map((row) => row.detail?.["reason"])).toEqual(["sudoers"]);

      expect(hostState(target.service, "plain")).toEqual(before);
      for (const secret of [unlisted, otherHost, noOptIn]) {
        expect(await statusOf(secret)).toBe(SecretStatus.ACTIVE);
        expect(revokeRows(secret)).toHaveLength(0);
      }
      expect(began(unlisted)).toBe(0);
      expect(began(noOptIn)).toBe(0);
    });

    it("the key is installed, and the `ssh` context logs in with it (plain)", async () => {
      plain = await passwordSecret("plain", "plain");
      const outcome = await bootstrap(plain, "plain");

      expect(outcome.ok, outcome.text).toBe(true);
      expect(parsed(outcome)).toEqual({
        type: "ssh_bootstrap",
        key: "installed",
        sudoers: "not_asked",
      });
      expect(hostState(target.service, "plain")).toEqual({ ...NOTHING, keyLines: 1 });

      const rows = useRows(plain);
      expect(rows).toHaveLength(2);
      expect(rows.filter((row) => row.success && row.detail?.["began"] === true)).toHaveLength(1);
      const done = rows.filter((row) => row.success && row.detail?.["outcome"] === "done");
      expect(done).toHaveLength(1);
      expect(done[0]?.detail?.["secret_ended"]).toBe(true);
      expect(revokeRows(plain).map((row) => row.detail?.["reason"])).toEqual(["ssh_bootstrap"]);

      const login = await sshAs("plain", "id -un");
      expect(login["exit_code"], JSON.stringify(login)).toBe(0);
      expect(String(login["stdout"]).trim()).toBe("plain");
    });

    it("a second call on the same secret is refused SECRET_REVOKED, with its failed row and no connection", async () => {
      await expectEnded(plain, "plain");
      expect(hostState(target.service, "plain").keyLines).toBe(1);
    });

    it("with the flag the agent has root through the drop-in (rooted)", async () => {
      const rooted = await passwordSecret("rooted", "rooted", { sudoers: true });
      const outcome = await bootstrap(rooted, "rooted", { sudoers: true });

      expect(outcome.ok, outcome.text).toBe(true);
      expect(parsed(outcome)).toEqual({
        type: "ssh_bootstrap",
        key: "installed",
        sudoers: "written",
      });
      expect(hostState(target.service, "rooted")).toEqual({
        keyLines: 1,
        dropIn: "440:root",
        sudoWaiting: false,
      });

      const root = await sshAs("rooted", "sudo -n id -u");
      expect(root["exit_code"], JSON.stringify(root)).toBe(0);
      expect(String(root["stdout"]).trim()).toBe("0");
    });

    it("a user outside sudoers: nothing is installed and the secret stays (outside)", async () => {
      const outside = await passwordSecret("outside", "outside", { sudoers: true });
      const refused = await bootstrap(outside, "outside", { sudoers: true });

      expectRefused(refused, VaultError.sshBootstrapStepFailed("refused", "not_attempted"));
      const rows = failedWith(outside, ErrorCode.SSH_BOOTSTRAP_STEP_FAILED);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.detail?.["drop_in"]).toBe("refused");
      expect(rows[0]?.detail?.["key"]).toBe("not_attempted");
      expect(hostState(target.service, "outside")).toEqual(NOTHING);
      expect(await statusOf(outside)).toBe(SecretStatus.ACTIVE);

      const again = await bootstrap(outside, "outside");
      expect(again.ok, again.text).toBe(true);
      expect(parsed(again)).toEqual({
        type: "ssh_bootstrap",
        key: "installed",
        sudoers: "not_asked",
      });
      expect(hostState(target.service, "outside")).toEqual({ ...NOTHING, keyLines: 1 });
    });

    it("a start-up file that reads its input ends the secret without a key (startup)", async () => {
      const startup = await passwordSecret("startup", "startup", { sudoers: true });
      const outcome = await bootstrap(startup, "startup", { sudoers: true });

      expectRefused(outcome, VaultError.sshBootstrapUnconfirmed());
      expect(failedWith(startup, ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED)).toHaveLength(1);
      expect(hostState(target.service, "startup")).toEqual(NOTHING);
      await expectEnded(startup, "startup");
    });

    it("an expired password ends the secret without a key (expired)", async () => {
      const expired = await passwordSecret("expired", "expired");
      const outcome = await bootstrap(expired, "expired");

      expectRefused(outcome, VaultError.sshBootstrapUnconfirmed());
      expect(failedWith(expired, ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED)).toHaveLength(1);
      expect(hostState(target.service, "expired")).toEqual(NOTHING);
      expect(await statusOf(expired)).toBe(SecretStatus.REVOKED);
    });

    it("a client killed while the script runs: the script finishes, and the secret has ended (slow)", async () => {
      const slow = await passwordSecret("slow", "slow", { sudoers: true });
      const pending = bootstrap(slow, "slow", { sudoers: true });

      await until(
        "sudo waiting for the slow account",
        15_000,
        () => hostState(target.service, "slow").sudoWaiting,
      );
      const killed = spawnSync("pkill", ["-KILL", "-P", String(process.pid), "-x", "ssh"]);
      expect(killed.status).toBe(0);

      const outcome = await pending;
      expectRefused(outcome, VaultError.sshBootstrapUnconfirmed());
      expect(failedWith(slow, ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED)).toHaveLength(1);
      await until("the key and the drop-in of the slow account", 30_000, () => {
        const state = hostState(target.service, "slow");
        return state.keyLines === 1 && state.dropIn === "440:root";
      });
      await expectEnded(slow, "slow");
    });

    it("a home that others can write: the line is installed and the server refuses the key (loose)", async () => {
      const loose = await passwordSecret("loose", "loose");
      const outcome = await bootstrap(loose, "loose");

      expect(outcome.ok, outcome.text).toBe(true);
      expect(parsed(outcome)).toEqual({
        type: "ssh_bootstrap",
        key: "installed",
        sudoers: "not_asked",
      });
      expect(await statusOf(loose)).toBe(SecretStatus.REVOKED);
      expect(hostState(target.service, "loose").keyLines).toBe(1);

      const login = await sshAs("loose", "id -un");
      expect(login["exit_code"], JSON.stringify(login)).toBe(255);
      expect(login["error"]).toBe(ErrorCode.SSH_CONNECT_FAILED);
    });
  });

  describe.runIf(WIN32)("on a Windows vault host", () => {
    it("is refused SSH_CLIENT_UNSUPPORTED before the client starts, and nothing reaches the host", async () => {
      const before = hostState(target.service, "plain");
      const secret = await passwordSecret("windows", "plain");
      const outcome = await bootstrap(secret, "plain");

      expectRefused(outcome, VaultError.sshBootstrapOnWindows());
      expect(failedWith(secret, ErrorCode.SSH_CLIENT_UNSUPPORTED)).toHaveLength(1);
      expect(began(secret)).toBe(0);
      expect(await statusOf(secret)).toBe(SecretStatus.ACTIVE);
      expect(hostState(target.service, "plain")).toEqual(before);
    });
  });
});
