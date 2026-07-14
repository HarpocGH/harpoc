import type { ConnectionConfig, InjectionPolicy, SshAction, SshResult } from "@harpoc/shared";
import { DEFAULT_SSH_TIMEOUT_MS, ErrorCode, VaultError } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { controlledPathDirs, matchesHostAllowlist, resolveAndMatchCommand } from "./allowlist.js";
import { spawnCaptured } from "./spawn-captured.js";
import { EphemeralSshAgent } from "./ssh-agent/index.js";
import { buildSshEnv, isHostKeyFailure, sshHardeningArgs, writeKnownHosts } from "./ssh-common.js";

/**
 * Executes a remote command over SSH with the private key served through an
 * ephemeral in-process ssh-agent (process-mediated injection, thesis §4.5.7).
 *
 * Security controls realized here:
 *  - Host target allowlist — fail-safe deny (an empty allowlist blocks SSH).
 *  - Strict host-key verification against the pinned known_hosts (no TOFU).
 *  - Command allowlist: the ssh binary is pinned to a resolved absolute path.
 *  - The private key is confined to the ephemeral agent; only signatures leave it.
 *  - Output capture, sanitization and a timeout, as in the process context.
 */
export class SshInjector {
  constructor(private readonly auditLogger: AuditLogger | null) {}

  async executeWithSecret(
    action: SshAction,
    secretValue: Uint8Array,
    policy: InjectionPolicy,
    config: ConnectionConfig | undefined,
    secretId?: string,
  ): Promise<SshResult> {
    // Defense in depth beside the schema's first-character anchor: host and
    // user reach ssh's argv, so a leading dash must never parse as an option.
    if (action.host.startsWith("-") || action.user.startsWith("-")) {
      this.audit(action, secretId, { error: "INVALID_SSH_CONFIG" }, false);
      throw VaultError.invalidSshConfig("host and user must not start with '-'");
    }

    // Host target allowlist — fail-safe deny (process-mediated posture).
    if (
      policy.host_allowlist.length === 0 ||
      !matchesHostAllowlist(action.host, policy.host_allowlist)
    ) {
      this.audit(action, secretId, { error: "HOST_NOT_ALLOWED" }, false);
      throw VaultError.hostNotAllowed(action.host);
    }

    // Pinned host keys are required — no trust-on-first-use.
    const knownHosts = config?.ssh?.known_hosts;
    if (!knownHosts || knownHosts.length === 0) {
      this.audit(action, secretId, { error: "SSH_NOT_CONFIGURED" }, false);
      throw VaultError.sshNotConfigured();
    }

    // Resolve + allowlist the ssh binary (fail-safe deny, absolute-path pinned).
    let sshPath: string;
    try {
      sshPath = resolveAndMatchCommand("ssh", policy.command_allowlist, controlledPathDirs());
    } catch (err) {
      if (err instanceof VaultError) this.audit(action, secretId, { error: err.code }, false);
      throw err;
    }

    const keyPem = Buffer.from(secretValue).toString("utf8");
    const timeoutMs = action.timeout_ms ?? DEFAULT_SSH_TIMEOUT_MS;
    const kh = writeKnownHosts(knownHosts);

    let agent: EphemeralSshAgent;
    try {
      agent = await EphemeralSshAgent.start(keyPem);
    } catch (err) {
      kh.dispose();
      if (err instanceof VaultError) this.audit(action, secretId, { error: err.code }, false);
      throw err;
    }

    try {
      const args = [
        ...sshHardeningArgs(kh.file, Math.max(1, Math.ceil(timeoutMs / 1000))),
        "-l",
        action.user,
        "--",
        action.host,
        action.command,
      ];
      const env = buildSshEnv(agent.authSock, policy.env_allowlist);
      const r = await spawnCaptured(sshPath, args, { env, timeoutMs, redact: [keyPem] });

      // A pinned-key mismatch (or unknown host) is a security rejection, not a result.
      if (isHostKeyFailure(r.stderr)) {
        this.audit(action, secretId, { error: "SSH_HOST_KEY_MISMATCH" }, false);
        throw VaultError.sshHostKeyMismatch(action.host);
      }

      const error = r.spawn_failed
        ? ErrorCode.SSH_CONNECT_FAILED
        : r.timed_out
          ? ErrorCode.PROCESS_TIMEOUT
          : r.exit_code === 255
            ? ErrorCode.SSH_CONNECT_FAILED
            : undefined;

      const result: SshResult = {
        type: "ssh",
        exit_code: r.exit_code,
        stdout: r.stdout,
        stderr: r.stderr,
        timed_out: r.timed_out ? true : undefined,
        truncated: r.truncated ? true : undefined,
        signal: r.signal ?? undefined,
        error,
      };
      this.audit(action, secretId, { exit_code: r.exit_code, timed_out: r.timed_out }, error === undefined);
      return result;
    } finally {
      agent.dispose();
      kh.dispose();
    }
  }

  private audit(
    action: SshAction,
    secretId: string | undefined,
    detail: Record<string, unknown>,
    success: boolean,
  ): void {
    this.auditLogger?.log({
      eventType: "secret.use",
      secretId,
      detail: { context: "ssh", host: action.host, user: action.user, ...detail },
      success,
    });
  }
}
