import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Permission } from "@harpoc/shared";
import { assertOpaque } from "./assert/opacity.js";
import { createHarnessVault, storeSecret } from "./harness/vault.js";
import type { HarnessVault } from "./harness/vault.js";
import { expectAttributedSuccess } from "./harness/audit.js";
import { recordArm } from "./harness/evidence.js";
import { startMcpHttpSurface } from "./harness/surfaces/mcp-http.js";
import type { CallOutcome, McpHttpSurface } from "./harness/surfaces/mcp-http.js";
import { preferNativeSsh, resolveSsh } from "./harness/fixtures.js";
import { clientKeyPem, knownHostPin } from "./harness/ssh.js";
import { SSHD_PINNED, SSHD_ROGUE, assertFleetUp } from "./harness/backends.js";

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

  it("refuses a server whose host key does not match the pin (no TOFU)", async () => {
    const outcome = await surface.callUseSecret(mismatchHandle, {
      type: "ssh",
      host: SSHD_ROGUE.host,
      user: SSHD_ROGUE.user,
      command: "id -un",
    });

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
    const outcome = await surface.callUseSecret(notAllowedHandle, {
      type: "ssh",
      host: SSHD_PINNED.host,
      user: SSHD_PINNED.user,
      command: "id -un",
    });

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
