import { describe, it, expect, afterEach } from "vitest";
import { Permission, useSecretActionSchema } from "@harpoc/shared";
import { createHarnessVault, grantOn, storeSecret } from "../vault.js";
import type { HarnessVault } from "../vault.js";
import { actionToFlags, startCliSurface } from "./cli.js";
import type { CliSurface } from "./cli.js";
import { assertOpaque } from "../../assert/opacity.js";
import { expectAttributedSuccess } from "../audit.js";
import { resolvePrintenv } from "../fixtures.js";

const PASSWORD = "e2e-cli-pw";
const SECRET = 'sk-cli/ab+cd 123"x';

describe("cli surface", () => {
  let vault: HarnessVault | undefined;
  let surface: CliSurface | undefined;

  afterEach(async () => {
    await surface?.close();
    await vault?.destroy();
    surface = undefined;
    vault = undefined;
  });

  async function setup(commandAllowlist: string[]): Promise<string> {
    vault = await createHarnessVault(PASSWORD);
    const handle = await storeSecret(vault, "cli-key", SECRET);
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: commandAllowlist,
      env_allowlist: [],
      host_allowlist: [],
    });
    await grantOn(vault, handle, "e2e-cli-agent", [Permission.USE, Permission.READ]);
    return handle;
  }

  it("runs the compiled binary with a scoped token and attributes it to cli", async () => {
    const printenv = resolvePrintenv();
    const handle = await setup([printenv]);
    const harness = vault as HarnessVault;

    surface = await startCliSurface(harness, "e2e-cli-agent", [Permission.USE]);
    const outcome = await surface.callUseSecret(handle, {
      type: "process",
      command: printenv,
      args: ["TOKEN"],
      env_var: "TOKEN",
    });

    expect(outcome.ok).toBe(true);
    expect((outcome.result as { type?: string }).type).toBe("process");
    expect(outcome.text).toContain("[REDACTED]");
    // A real child's own streams, not just the parsed result (C-6).
    assertOpaque(SECRET, {
      result: outcome.result,
      stdout: outcome.stdout,
      stderr: outcome.stderr,
    });

    expectAttributedSuccess(harness, {
      context: "process",
      interface: "cli",
      principal: "e2e-cli-agent",
    });
  }, 60_000);

  it("reports a refusal on stderr as a non-ok outcome", async () => {
    const handle = await setup([]);
    const harness = vault as HarnessVault;

    surface = await startCliSurface(harness, "e2e-cli-agent", [Permission.USE]);
    const outcome = await surface.callUseSecret(handle, {
      type: "process",
      command: resolvePrintenv(),
      args: ["TOKEN"],
      env_var: "TOKEN",
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.errorText ?? "").toMatch(/not in secret allowlist/i);
    assertOpaque(SECRET, {
      error: outcome.errorText,
      stdout: outcome.stdout,
      stderr: outcome.stderr,
    });
  }, 60_000);

  it("refuses an out-of-scope token — the CLI token is enforced, not decorative", async () => {
    const printenv = resolvePrintenv();
    const handle = await setup([printenv]);
    const harness = vault as HarnessVault;

    surface = await startCliSurface(harness, "e2e-cli-agent", [Permission.READ]);
    const outcome = await surface.callUseSecret(handle, {
      type: "process",
      command: printenv,
      args: ["TOKEN"],
      env_var: "TOKEN",
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.errorText ?? "").toMatch(/permission|denied/i);
  }, 60_000);
});

/**
 * The flag mapping is the inverse of the command's own `buildAction`, so a
 * regression must fail HERE and not as a puzzling schema error inside a
 * demonstration cell. Each mapping is round-tripped through the same schema the
 * command validates against.
 */
describe("actionToFlags round-trips every context", () => {
  const CASES: Record<string, unknown>[] = [
    {
      type: "http",
      method: "POST",
      url: "https://api.example.com/v1",
      injection: { type: "header", header_name: "X-Api-Key" },
      headers: { "X-Trace": "abc" },
      body: "payload",
    },
    {
      type: "process",
      command: "/usr/bin/printenv",
      args: ["TOKEN", "HOME"],
      env_var: "TOKEN",
    },
    { type: "mcp", server: "downstream", tool: "reveal", arguments: { n: 1 } },
    {
      type: "database",
      engine: "postgresql",
      host: "db.internal",
      port: 5432,
      database: "app",
      query: "SELECT 42",
      params: ["x"],
    },
    {
      type: "git",
      operation: "clone",
      repository: "https://git.example.com/x.git",
      args: ["--depth=1"],
    },
    { type: "ssh", host: "10.0.0.5", user: "deploy", command: "id -un" },
  ];

  it.each(CASES)("maps a $type action onto flags the schema accepts", (action) => {
    const flags = actionToFlags(action);
    expect(flags[0]).toBe("--action");
    expect(flags[1]).toBe(action["type"]);
    // Every value the action carries must appear among the flag values —
    // a dropped flag is exactly the silent regression this pins.
    for (const [key, value] of Object.entries(action)) {
      if (key === "type" || typeof value === "object") continue;
      expect(flags).toContain(String(value));
    }
    expect(useSecretActionSchema.safeParse(action).success).toBe(true);
  });

  it("maps an ssh action's non-22 port onto --port", () => {
    const action = {
      type: "ssh",
      host: "127.0.0.1",
      port: 55022,
      user: "harpoc",
      command: "id -un",
    };
    const flags = actionToFlags(action);
    expect(flags.slice(flags.indexOf("--port"), flags.indexOf("--port") + 2)).toEqual([
      "--port",
      "55022",
    ]);
    expect(useSecretActionSchema.safeParse(action).success).toBe(true);
  });

  it("refuses an unknown action type instead of emitting a broken flag list", () => {
    expect(() => actionToFlags({ type: "telepathy" })).toThrow(/unsupported action type/i);
  });
});
