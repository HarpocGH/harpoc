import { spawn } from "node:child_process";
import { statSync } from "node:fs";
import type { ProcessAction, ProcessResult } from "@harpoc/shared";
import {
  DEFAULT_PROCESS_TIMEOUT_MS,
  ErrorCode,
  MAX_PROCESS_OUTPUT_BYTES,
  VaultError,
} from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { controlledPathDirs, resolveAndMatchCommand } from "./allowlist.js";
import { CappedOutput } from "./capped-output.js";
import { buildCleanEnv } from "./clean-env.js";
import { redactSecretEncodings } from "./output-sanitizer.js";

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
    policy: { command_allowlist: string[]; env_allowlist: string[] },
    secretId?: string,
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
        this.audit(action, secretId, { error: err.code }, false);
        throw err;
      }
      throw err;
    }

    const valueStr = Buffer.from(secretValue).toString("utf8");
    const env = buildCleanEnv(action.env_var, valueStr, policy.env_allowlist);
    const args = action.args ?? [];
    const timeoutMs = action.timeout_ms ?? DEFAULT_PROCESS_TIMEOUT_MS;

    const result = await this.runProcess(resolvedPath, args, env, action.working_directory, timeoutMs, valueStr);

    this.audit(
      action,
      secretId,
      {
        exit_code: result.exit_code,
        timed_out: result.timed_out ?? false,
        truncated: result.truncated ?? false,
      },
      result.error === undefined,
    );

    return result;
  }

  private runProcess(
    command: string,
    args: string[],
    env: Record<string, string>,
    cwd: string | undefined,
    timeoutMs: number,
    secretStr: string,
  ): Promise<ProcessResult> {
    const stdout = new CappedOutput(MAX_PROCESS_OUTPUT_BYTES);
    const stderr = new CappedOutput(MAX_PROCESS_OUTPUT_BYTES);

    return new Promise<ProcessResult>((resolvePromise) => {
      let child: ReturnType<typeof spawn>;
      try {
        child = spawn(command, args, { shell: false, env, cwd, windowsHide: true });
      } catch (err) {
        resolvePromise({
          type: "process",
          exit_code: null,
          stdout: "",
          stderr: "",
          error: ErrorCode.PROCESS_SPAWN_FAILED,
        });
        void err;
        return;
      }

      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill("SIGKILL");
      }, timeoutMs);
      if (timer.unref) timer.unref();

      child.stdout?.on("data", (chunk: Buffer) => stdout.push(chunk));
      child.stderr?.on("data", (chunk: Buffer) => stderr.push(chunk));

      child.on("error", () => {
        clearTimeout(timer);
        resolvePromise({
          type: "process",
          exit_code: null,
          stdout: redactSecretEncodings(stdout.toString(), secretStr),
          stderr: redactSecretEncodings(stderr.toString(), secretStr),
          error: ErrorCode.PROCESS_SPAWN_FAILED,
        });
      });

      child.on("close", (code, signal) => {
        clearTimeout(timer);
        const truncated = stdout.truncated || stderr.truncated;
        resolvePromise({
          type: "process",
          exit_code: code,
          stdout: redactSecretEncodings(stdout.toString(), secretStr),
          stderr: redactSecretEncodings(stderr.toString(), secretStr),
          timed_out: timedOut ? true : undefined,
          truncated: truncated ? true : undefined,
          signal: signal ?? undefined,
          error: timedOut ? ErrorCode.PROCESS_TIMEOUT : undefined,
        });
      });
    });
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
  ): void {
    this.auditLogger?.log({
      eventType: "secret.use",
      secretId,
      detail: {
        context: "process",
        command: action.command,
        args_count: action.args?.length ?? 0,
        ...detail,
      },
      success,
    });
  }
}
