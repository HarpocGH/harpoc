import { statSync } from "node:fs";
import type { ProcessAction, ProcessResult } from "@harpoc/shared";
import { DEFAULT_PROCESS_TIMEOUT_MS, ErrorCode, VaultError } from "@harpoc/shared";
import type { AuditAttribution } from "../audit/attribution.js";
import { withAttribution } from "../audit/attribution.js";
import type { AuditLogger } from "../audit/audit-logger.js";
import { controlledPathDirs, resolveAndMatchCommand } from "./allowlist.js";
import { buildCleanEnv } from "./clean-env.js";
import { spawnCaptured } from "./spawn-captured.js";

/**
 * Executes a subprocess with an injected credential (process-mediated injection,
 * thesis §4.5.2). The credential is placed in the child's environment; the
 * command and args are passed as data with no shell interpretation. stdout and
 * stderr are captured, sanitized and returned to the caller — the credential is
 * never returned to the agent.
 *
 * Security invariants realized here:
 *  - No shell: spawn with shell:false so args cannot become instruction vehicles.
 *  - Command allowlisting: the command is pinned to a resolved absolute path.
 *  - Clean environment: only PATH, allowlisted vars and the injected credential.
 *  - Output sanitization: the value and its common encodings are redacted.
 */
export class ProcessInjector {
  constructor(private readonly auditLogger: AuditLogger | null) {}

  async executeWithSecret(
    action: ProcessAction,
    secretValue: Uint8Array,
    policy: { command_allowlist: string[]; env_allowlist: string[]; network_isolation?: boolean },
    secretId?: string,
    attribution?: AuditAttribution,
  ): Promise<ProcessResult> {
    const pathDirs = controlledPathDirs();

    let resolvedPath: string;
    try {
      resolvedPath = resolveAndMatchCommand(action.command, policy.command_allowlist, pathDirs);
      if (action.working_directory !== undefined) {
        this.assertDirectory(action.working_directory);
      }
    } catch (err) {
      if (err instanceof VaultError) {
        this.audit(action, secretId, { error: err.code }, false, attribution);
        throw err;
      }
      throw err;
    }

    const valueStr = Buffer.from(secretValue).toString("utf8");
    const env = buildCleanEnv(action.env_var, valueStr, policy.env_allowlist);
    const args = action.args ?? [];
    const timeoutMs = action.timeout_ms ?? DEFAULT_PROCESS_TIMEOUT_MS;
    const networkIsolation = policy.network_isolation === true;

    let run: { result: ProcessResult; isolationMechanism?: string };
    try {
      run = await this.runProcess(
        resolvedPath,
        args,
        env,
        action.working_directory,
        timeoutMs,
        valueStr,
        networkIsolation,
      );
    } catch (err) {
      // Fail-closed refusal from the spawn seam (NETWORK_ISOLATION_UNAVAILABLE):
      // no process was spawned; audit the denial like an allowlist rejection.
      if (err instanceof VaultError) {
        this.audit(
          action,
          secretId,
          { error: err.code, network_isolation: networkIsolation },
          false,
          attribution,
        );
      }
      throw err;
    }
    const result = run.result;

    this.audit(
      action,
      secretId,
      {
        exit_code: result.exit_code,
        timed_out: result.timed_out ?? false,
        truncated: result.truncated ?? false,
        network_isolation: networkIsolation,
        ...(run.isolationMechanism ? { isolation_mechanism: run.isolationMechanism } : {}),
      },
      result.error === undefined,
      attribution,
    );

    return result;
  }

  private async runProcess(
    command: string,
    args: string[],
    env: Record<string, string>,
    cwd: string | undefined,
    timeoutMs: number,
    secretStr: string,
    networkIsolation: boolean,
  ): Promise<{ result: ProcessResult; isolationMechanism?: string }> {
    const r = await spawnCaptured(command, args, {
      env,
      cwd,
      timeoutMs,
      redact: [secretStr],
      networkIsolation,
    });
    return {
      result: {
        type: "process",
        exit_code: r.exit_code,
        stdout: r.stdout,
        stderr: r.stderr,
        timed_out: r.timed_out ? true : undefined,
        truncated: r.truncated ? true : undefined,
        signal: r.signal ?? undefined,
        error: r.spawn_failed
          ? ErrorCode.PROCESS_SPAWN_FAILED
          : r.timed_out
            ? ErrorCode.PROCESS_TIMEOUT
            : undefined,
      },
      isolationMechanism: r.isolation_mechanism,
    };
  }

  private assertDirectory(dir: string): void {
    try {
      if (!statSync(dir).isDirectory()) {
        throw VaultError.invalidProcessConfig(`working_directory is not a directory: ${dir}`);
      }
    } catch (err) {
      if (err instanceof VaultError) throw err;
      throw VaultError.invalidProcessConfig(`working_directory does not exist: ${dir}`);
    }
  }

  private audit(
    action: ProcessAction,
    secretId: string | undefined,
    detail: Record<string, unknown>,
    success: boolean,
    attribution?: AuditAttribution,
  ): void {
    this.auditLogger?.log(
      withAttribution(
        {
          eventType: "secret.use",
          secretId,
          detail: {
            context: "process",
            command: action.command,
            args_count: action.args?.length ?? 0,
            ...detail,
          },
          success,
        },
        attribution,
      ),
    );
  }
}
