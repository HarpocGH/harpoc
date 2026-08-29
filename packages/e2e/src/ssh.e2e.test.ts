import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Permission } from "@harpoc/shared";
import { assertOpaque } from "./assert/opacity.js";
import { createHarnessVault, storeSecret } from "./harness/vault.js";
import type { HarnessVault } from "./harness/vault.js";
import { expectAttributedSuccess } from "./harness/audit.js";
import type { AuditRow } from "./harness/audit.js";
import { recordArm } from "./harness/evidence.js";
import { startMcpHttpSurface } from "./harness/surfaces/mcp-http.js";
import type { CallOutcome, McpHttpSurface } from "./harness/surfaces/mcp-http.js";
import { preferNativeSsh, resolveSsh } from "./harness/fixtures.js";
import { clientKeyPem, knownHostPin, knownHostPinOnPort } from "./harness/ssh.js";
import {
  SSHD_PINNED,
  SSHD_PINNED_ALT_PORT,
  SSHD_ROGUE,
  assertFleetUp,
} from "./harness/backends.js";
import { SSH_PINNED_PAYLOAD, SSH_ROGUE_PAYLOAD } from "./harness/payloads.js";

const PASSWORD = "e2e-ssh-pw";

/** The SshResult carried in the tool response's text (already surface-joined). */
function sshResult(outcome: CallOutcome): {
  exit_code?: number;
  stdout?: string;
  stderr?: string;
  error?: string;
} {
  return JSON.parse(outcome.text) as {
    exit_code?: number;
    stdout?: string;
    stderr?: string;
    error?: string;
  };
}

/**
 * The `ssh` context, exercised against a live OpenSSH server through the real
 * MCP Streamable-HTTP wire with a scoped token — the first completed `ssh`
 * injection anywhere in the repository. The stored secret is the client private
 * key; it lives only in the vault's in-process agent and never crosses to the
 * server on the wire, which is the opacity claim `assertOpaque` verifies.
 *
 * One vault, three handles: a single Argon2id derivation covers all three arms.
 */
describe("ssh context — live OpenSSH over the fixture host keys", () => {
  let vault: HarnessVault;
  let surface: McpHttpSurface;
  let sshKey: string;
  let happyHandle: string;
  let mismatchHandle: string;
  let notAllowedHandle: string;
  let altPortHandle: string;
  let altPortBarePinHandle: string;
  let altPortBareWrongPinHandle: string;

  beforeAll(async () => {
    assertFleetUp("sshd-pinned");
    assertFleetUp("sshd-rogue");
    // Put the native OpenSSH client first on PATH so the vault resolves and
    // allowlists the same binary (F-6). No-op on Linux.
    preferNativeSsh();
    const sshBin = resolveSsh();
    sshKey = clientKeyPem();

    vault = await createHarnessVault(PASSWORD);

    // Happy path: pin the server we will actually reach.
    happyHandle = await storeSecret(vault, "ssh-happy", sshKey);
    await vault.engine.setInjectionPolicy(happyHandle, {
      url_allowlist: [],
      command_allowlist: [sshBin],
      env_allowlist: [],
      host_allowlist: [SSHD_PINNED.host],
    });
    await vault.engine.setConnectionConfig(happyHandle, {
      ssh: { known_hosts: [knownHostPin(SSHD_PINNED.host, "pinned")] },
    });

    // Mismatch: pin the PINNED server's key but connect to rogue, which answers
    // with its own different key — host-key verification must fail (no TOFU).
    mismatchHandle = await storeSecret(vault, "ssh-mismatch", sshKey);
    await vault.engine.setInjectionPolicy(mismatchHandle, {
      url_allowlist: [],
      command_allowlist: [sshBin],
      env_allowlist: [],
      host_allowlist: [SSHD_ROGUE.host],
    });
    await vault.engine.setConnectionConfig(mismatchHandle, {
      ssh: { known_hosts: [knownHostPin(SSHD_ROGUE.host, "pinned")] },
    });

    // Unlisted host: the pin is correct, only the allowlist withholds the target,
    // so the refusal is provably the allowlist and not a broken fixture.
    notAllowedHandle = await storeSecret(vault, "ssh-notallowed", sshKey);
    await vault.engine.setInjectionPolicy(notAllowedHandle, {
      url_allowlist: [],
      command_allowlist: [sshBin],
      env_allowlist: [],
      host_allowlist: ["10.0.0.9"],
    });
    await vault.engine.setConnectionConfig(notAllowedHandle, {
      ssh: { known_hosts: [knownHostPin(SSHD_PINNED.host, "pinned")] },
    });

    // The same pinned server on 127.0.0.1:55022 (D59): the pin is stored in
    // OpenSSH's bracketed `[host]:port` form, which the vault writes verbatim
    // — it never rewrites a pin to match the action's port.
    altPortHandle = await storeSecret(vault, "ssh-alt-port", sshKey);
    await vault.engine.setInjectionPolicy(altPortHandle, {
      url_allowlist: [],
      command_allowlist: [sshBin],
      env_allowlist: [],
      host_allowlist: ["127.0.0.1"],
    });
    await vault.engine.setConnectionConfig(altPortHandle, {
      ssh: { known_hosts: [knownHostPinOnPort("127.0.0.1", SSHD_PINNED_ALT_PORT, "pinned")] },
    });

    // The correct key pinned under the BARE host. OpenSSH looks `[host]:port`
    // up first and, finding no such entry, falls back to the bare-host line
    // when its key matches ("found matching key w/out port" — verified against
    // OpenSSH 9.6 on Ubuntu 24.04 and Win32-OpenSSH 9.5, 2026-08-29), so this
    // pin is ACCEPTED. The arm's original expectation (a refusal) was wrong
    // and failed on its first Linux run.
    altPortBarePinHandle = await storeSecret(vault, "ssh-alt-port-bare-pin", sshKey);
    await vault.engine.setInjectionPolicy(altPortBarePinHandle, {
      url_allowlist: [],
      command_allowlist: [sshBin],
      env_allowlist: [],
      host_allowlist: ["127.0.0.1"],
    });
    await vault.engine.setConnectionConfig(altPortBarePinHandle, {
      ssh: { known_hosts: [knownHostPin("127.0.0.1", "pinned")] },
    });

    // The negative twin: the fallback is key-gated. The bare host pinned with
    // the ROGUE key vouches for nothing the pinned server presents, so the
    // non-22 connection must be refused as an unknown host.
    altPortBareWrongPinHandle = await storeSecret(vault, "ssh-alt-port-bare-wrong-pin", sshKey);
    await vault.engine.setInjectionPolicy(altPortBareWrongPinHandle, {
      url_allowlist: [],
      command_allowlist: [sshBin],
      env_allowlist: [],
      host_allowlist: ["127.0.0.1"],
    });
    await vault.engine.setConnectionConfig(altPortBareWrongPinHandle, {
      ssh: { known_hosts: [knownHostPin("127.0.0.1", "rogue")] },
    });

    surface = await startMcpHttpSurface(vault, "e2e-ssh-agent", [Permission.USE]);
  });

  afterAll(async () => {
    await surface?.close();
    await vault?.destroy();
  });

  it("authenticates with the pinned key and runs a command, leaking no key material", async () => {
    const outcome = await surface.callUseSecret(happyHandle, {
      type: "ssh",
      host: SSHD_PINNED.host,
      user: SSHD_PINNED.user,
      command: "id -un",
    });

    expect(outcome.ok).toBe(true);
    // The remote shell really ran: exit 0, no in-band error, and `id -un` put
    // the authenticated user on STDOUT. The ssh-injector reports auth failures
    // in-band (exit 255, error: SSH_CONNECT_FAILED, ok still true) with the
    // user echoed in ssh's own stderr ("harpoc@…: Permission denied"), so a
    // whole-result substring match would pass on a failed authentication.
    const r = sshResult(outcome);
    expect(r.exit_code, outcome.text).toBe(0);
    expect(r.error).toBeUndefined();
    expect(r.stdout ?? "").toContain(SSHD_PINNED.user);

    const auditRows = vault.engine.queryAudit({ eventType: "secret.use" });
    assertOpaque(sshKey, { result: outcome.result, auditRows, parentEnv: process.env });

    const record = recordArm(
      {
        scenario: "ssh-happy-path",
        context: "ssh",
        surface: "mcp-http",
        interface: "mcp",
        arm: "harpoc",
      },
      "SUCCEEDED",
    );
    expect(record.match).toBe(true);
  });

  it("writes a successful ssh audit row attributed to the mcp-http interface", () => {
    expectAttributedSuccess(vault, "ssh");
  });

  it("reaches the pinned server on a non-22 port and records it in the audit row", async () => {
    const outcome = await surface.callUseSecret(altPortHandle, {
      type: "ssh",
      host: "127.0.0.1",
      port: SSHD_PINNED_ALT_PORT,
      user: SSHD_PINNED.user,
      command: "id -un",
    });

    expect(outcome.ok).toBe(true);
    const r = sshResult(outcome);
    expect(r.exit_code, outcome.text).toBe(0);
    expect(r.error).toBeUndefined();
    expect(r.stdout ?? "").toContain(SSHD_PINNED.user);

    const auditRows = vault.engine.queryAudit({ eventType: "secret.use" }) as unknown as AuditRow[];
    const row = auditRows.find(
      (candidate) => (candidate.detail ?? {})["port"] === SSHD_PINNED_ALT_PORT,
    );
    expect(row?.success).toBe(true);
    assertOpaque(sshKey, { result: outcome.result, auditRows, parentEnv: process.env });
  });

  it("accepts the non-22 server through OpenSSH's port-less fallback when the bare-host pin holds its key", async () => {
    const outcome = await surface.callUseSecret(altPortBarePinHandle, {
      type: "ssh",
      host: "127.0.0.1",
      port: SSHD_PINNED_ALT_PORT,
      user: SSHD_PINNED.user,
      command: "id -un",
    });

    expect(outcome.ok).toBe(true);
    const r = sshResult(outcome);
    expect(r.exit_code, outcome.text).toBe(0);
    expect(r.error).toBeUndefined();
    expect(r.stdout ?? "").toContain(SSHD_PINNED.user);

    const auditRows = vault.engine.queryAudit({ eventType: "secret.use" }) as unknown as AuditRow[];
    assertOpaque(sshKey, { result: outcome.result, auditRows, parentEnv: process.env });
  });

  it("refuses the non-22 server when the bare-host pin holds a different key (the fallback is key-gated)", async () => {
    const outcome = await surface.callUseSecret(altPortBareWrongPinHandle, {
      type: "ssh",
      host: "127.0.0.1",
      port: SSHD_PINNED_ALT_PORT,
      user: SSHD_PINNED.user,
      command: "id -un",
    });

    expect(outcome.ok).toBe(false);
    // The refusal REASON is host-key verification: OpenSSH finds neither a
    // `[127.0.0.1]:55022` entry nor a bare entry holding the presented key.
    expect(outcome.errorText ?? "").toContain("host key does not match the pinned key");
    expect(JSON.stringify(outcome.result ?? "")).not.toContain(SSHD_PINNED.user);

    const auditRows = vault.engine.queryAudit({ eventType: "secret.use" });
    assertOpaque(sshKey, { result: outcome.result, error: outcome.errorText, auditRows });
  });

  it("refuses a server whose host key does not match the pin (no TOFU)", async () => {
    const outcome = await surface.callUseSecret(mismatchHandle, SSH_ROGUE_PAYLOAD);

    expect(outcome.ok).toBe(false);
    // The refusal REASON is the host-key mismatch — an agent-start failure or
    // allowlist drift would also produce ok === false and must not satisfy the
    // arm that certifies no-TOFU pinning.
    expect(outcome.errorText ?? "").toContain("host key does not match the pinned key");
    // The rogue shell never ran: no authenticated user in the result.
    expect(JSON.stringify(outcome.result ?? "")).not.toContain(SSHD_ROGUE.user);

    const auditRows = vault.engine.queryAudit({ eventType: "secret.use" });
    assertOpaque(sshKey, { result: outcome.result, error: outcome.errorText, auditRows });

    const record = recordArm(
      {
        scenario: "ssh-host-key-mismatch",
        context: "ssh",
        surface: "mcp-http",
        interface: "mcp",
        arm: "harpoc",
      },
      "REJECTED",
    );
    expect(record.match).toBe(true);
  });

  it("refuses a host outside the allowlist before any connection", async () => {
    const outcome = await surface.callUseSecret(notAllowedHandle, SSH_PINNED_PAYLOAD);

    expect(outcome.ok).toBe(false);
    // The refusal REASON is the host allowlist — this is what makes the arm
    // evidence for allowlist enforcement rather than any pre-spawn failure.
    expect(outcome.errorText ?? "").toContain("Host not in secret allowlist");
    expect(JSON.stringify(outcome.result ?? "")).not.toContain(SSHD_PINNED.user);

    const auditRows = vault.engine.queryAudit({ eventType: "secret.use" });
    assertOpaque(sshKey, { result: outcome.result, error: outcome.errorText, auditRows });

    const record = recordArm(
      {
        scenario: "ssh-host-not-allowed",
        context: "ssh",
        surface: "mcp-http",
        interface: "mcp",
        arm: "harpoc",
      },
      "REJECTED",
    );
    expect(record.match).toBe(true);
  });
});
