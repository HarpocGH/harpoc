import { describe, it, expect, afterEach } from "vitest";
import { spawn } from "node:child_process";
import { Permission } from "@harpoc/shared";
import { createHarnessVault, grantOn, storeSecret } from "../vault.js";
import type { HarnessVault } from "../vault.js";
import { startMcpStdioSurface } from "./mcp-stdio.js";
import type { McpStdioSurface } from "./mcp-stdio.js";
import { assertOpaque } from "../../assert/opacity.js";
import { expectAttributedSuccess } from "../audit.js";
import { resolveMcpServerEntry, resolvePrintenv } from "../fixtures.js";

const PASSWORD = "e2e-stdio-pw";
const SECRET = 'sk-stdio/ab+cd 123"x';

describe("mcp-stdio surface", () => {
  let vault: HarnessVault | undefined;
  let surface: McpStdioSurface | undefined;

  afterEach(async () => {
    await surface?.close();
    await vault?.destroy();
    surface = undefined;
    vault = undefined;
  });

  async function setup(commandAllowlist: string[]): Promise<string> {
    vault = await createHarnessVault(PASSWORD);
    const handle = await storeSecret(vault, "stdio-key", SECRET);
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: commandAllowlist,
      env_allowlist: [],
      host_allowlist: [],
    });
    await grantOn(vault, handle, "e2e-stdio-agent", [Permission.USE]);
    return handle;
  }

  it("drives the compiled server as a real child, attributed to the mcp interface", async () => {
    const printenv = resolvePrintenv();
    const handle = await setup([printenv]);
    const harness = vault as HarnessVault;

    surface = await startMcpStdioSurface(harness, "e2e-stdio-agent", [Permission.USE]);
    const outcome = await surface.callUseSecret(handle, {
      type: "process",
      command: printenv,
      args: ["TOKEN"],
      env_var: "TOKEN",
    });

    expect(outcome.ok).toBe(true);
    expect((JSON.parse(outcome.text) as { type?: string }).type).toBe("process");
    expect(outcome.text).toContain("[REDACTED]");
    // The child's own stderr is captured and scanned, not merely piped: it is a
    // channel assertOpaque claims to cover, and an unread pipe would block the
    // child once the OS buffer filled.
    expect(typeof outcome.stderr).toBe("string");
    assertOpaque(SECRET, { result: outcome.result, stderr: outcome.stderr });

    // The child holds its own engine over the same vault directory, so the row
    // it wrote is visible to the harness's engine: two processes, one vault.
    expectAttributedSuccess(harness, {
      context: "process",
      interface: "mcp",
      principal: "e2e-stdio-agent",
    });
  }, 60_000);

  it("reports a refusal as a non-ok outcome with its text", async () => {
    const handle = await setup([]);
    const harness = vault as HarnessVault;

    surface = await startMcpStdioSurface(harness, "e2e-stdio-agent", [Permission.USE]);
    const outcome = await surface.callUseSecret(handle, {
      type: "process",
      command: resolvePrintenv(),
      args: ["TOKEN"],
      env_var: "TOKEN",
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.errorText ?? "").toMatch(/not in secret allowlist/i);
    assertOpaque(SECRET, { result: outcome.result, error: outcome.errorText });
  }, 60_000);

  it("passes the whole parent environment to the child, not the SDK's allowlist", async () => {
    // Regression pin for the transport's default env filtering: without the
    // explicit forward the child loses HARPOC_SESSION_KEYSTORE (session read
    // fails closed), NODE_EXTRA_CA_CERTS (the http cell's TLS fails) and the
    // Windows PATH ordering — each failing far from this cause.
    //
    // The probe reads the MCP SERVER child's environment, which is where those
    // variables have to land. It is routed out through the vault's env
    // allowlist because the injected grandchild gets a clean environment by
    // design — only allowlisted names are forwarded from the vault process.
    process.env["HARPOC_E2E_ENV_PROBE"] = "probe-value";
    try {
      vault = await createHarnessVault(PASSWORD);
      const harness = vault;
      const handle = await storeSecret(harness, "stdio-key", SECRET);
      await harness.engine.setInjectionPolicy(handle, {
        url_allowlist: [],
        command_allowlist: [resolvePrintenv()],
        env_allowlist: ["HARPOC_E2E_ENV_PROBE"],
        host_allowlist: [],
      });
      await grantOn(harness, handle, "e2e-stdio-agent", [Permission.USE]);

      surface = await startMcpStdioSurface(harness, "e2e-stdio-agent", [Permission.USE]);
      const outcome = await surface.callUseSecret(handle, {
        type: "process",
        command: resolvePrintenv(),
        args: ["HARPOC_E2E_ENV_PROBE"],
        env_var: "TOKEN",
      });
      expect(outcome.ok).toBe(true);
      expect(outcome.text).toContain("probe-value");
    } finally {
      delete process.env["HARPOC_E2E_ENV_PROBE"];
    }
  }, 60_000);

  it("refuses to start tokenless (V3) — the surface never waives the gate", async () => {
    vault = await createHarnessVault(PASSWORD);
    const harness = vault;
    const result = await new Promise<{ code: number | null; stderr: string }>((resolve, reject) => {
      const child = spawn(
        process.execPath,
        [resolveMcpServerEntry(), "--vault-dir", harness.tmpDir],
        { env: { ...process.env, HARPOC_TOKEN: "" }, windowsHide: true },
      );
      let stderr = "";
      child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString("utf8")));
      child.on("error", reject);
      child.on("close", (code) => resolve({ code, stderr }));
      child.stdin.end();
    });

    expect(result.code).toBe(1);
    // The bin reports the V3 gate as its guidance text, not as the error code
    // (the code appears on the CLI's `server start --mcp` path). Both
    // recoveries must be named, or a blocked client has nowhere to go.
    expect(result.stderr).toMatch(/launch token is required/i);
    expect(result.stderr).toContain("harpoc auth token");
    expect(result.stderr).toContain("--allow-tokenless");
  }, 60_000);
});
