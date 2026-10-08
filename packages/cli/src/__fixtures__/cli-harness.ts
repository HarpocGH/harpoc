import { Command } from "commander";
import { vi, type MockInstance } from "vitest";
import type { VaultApiToken } from "@harpoc/shared";

/** A verified token's claims: an agent principal holding `read`, unless overridden. */
export function tokenFixture(overrides: Partial<VaultApiToken> = {}): VaultApiToken {
  return {
    sub: "agent-1",
    vault_id: "vault-1",
    scope: ["read"],
    iat: 0,
    exp: 2_000_000_000,
    jti: "jti-1",
    principal_type: "agent",
    ...overrides,
  };
}

export interface CliSpies {
  /** `process.exit`, stubbed to throw `Error("process.exit")`. */
  exitSpy: MockInstance;
  /** `console.error`, muted. */
  errorSpy: MockInstance;
  /** `console.log`, muted. */
  logSpy: MockInstance;
  /** Every `console.log` call, its arguments space-joined, one line per call. */
  stdout(): string;
  /** Every `console.error` call, the same way. */
  stderr(): string;
  /** Restores the three spies and puts `HARPOC_TOKEN` back as it was. */
  restore(): void;
}

/**
 * The spies a command test runs under, created in a `beforeEach` and restored by `restore()` in
 * the `afterEach`. `HARPOC_TOKEN` is removed until `restore()`. Only these spies are restored: a
 * blanket `vi.restoreAllMocks()` would also reset a file's `vi.mock`'d module functions.
 */
export function spyCli(): CliSpies {
  const savedToken = process.env.HARPOC_TOKEN;
  delete process.env.HARPOC_TOKEN;
  const exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
    throw new Error("process.exit");
  });
  const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  const text = (spy: MockInstance): string =>
    spy.mock.calls.map((call) => call.map(String).join(" ")).join("\n");
  return {
    exitSpy,
    errorSpy,
    logSpy,
    stdout: () => text(logSpy),
    stderr: () => text(errorSpy),
    restore: () => {
      exitSpy.mockRestore();
      errorSpy.mockRestore();
      logSpy.mockRestore();
      if (savedToken === undefined) delete process.env.HARPOC_TOKEN;
      else process.env.HARPOC_TOKEN = savedToken;
    },
  };
}

/**
 * A runner over a fresh program per call: `register` adds the commands under test to the root,
 * `prefix` is the command path every call parses under. `exitOverride()` and the muted `writeErr`
 * are set before any `.command()`, because commander copies both into a subcommand when it is
 * created: a parse error anywhere in the tree rejects with a `CommanderError` and prints nothing,
 * and a refusal the command renders itself still reaches the stubbed `process.exit`.
 */
export function buildCli(
  register: (program: Command) => void,
  prefix: string[] = [],
): (args: string[]) => Promise<void> {
  return async (args) => {
    const program = new Command();
    program.exitOverride();
    program.configureOutput({ writeErr: () => {} });
    program.option("--vault-dir <path>", "Path to vault directory");
    register(program);
    await program.parseAsync(["node", "harpoc", ...prefix, ...args]);
  };
}
