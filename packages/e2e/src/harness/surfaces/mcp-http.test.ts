import { describe, it, expect, afterEach } from "vitest";
import { Permission } from "@harpoc/shared";
import { createHarnessVault, storeSecret } from "../vault.js";
import type { HarnessVault } from "../vault.js";
import { startMcpHttpSurface } from "./mcp-http.js";
import type { McpHttpSurface } from "./mcp-http.js";
import { assertOpaque } from "../../assert/opacity.js";
import { resolvePrintenv } from "../fixtures.js";

const PASSWORD = "e2e-surface-pw";
const SECRET = 'sk-surface/ab+cd 123"x';

describe("mcp-http surface", () => {
  let vault: HarnessVault | undefined;
  let surface: McpHttpSurface | undefined;

  afterEach(async () => {
    await surface?.close();
    await vault?.destroy();
    surface = undefined;
    vault = undefined;
  });

  it("carries a scoped token over the real transport (C-2)", async () => {
    const printenv = resolvePrintenv();
    vault = await createHarnessVault(PASSWORD);
    const handle = await storeSecret(vault, "surface-key", SECRET);
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: [printenv],
      env_allowlist: [],
      host_allowlist: [],
    });

    surface = await startMcpHttpSurface(vault, "e2e-agent", [Permission.USE]);
    const outcome = await surface.callUseSecret(handle, {
      type: "process",
      command: printenv,
      args: ["TOKEN"],
      env_var: "TOKEN",
    });

    expect(outcome.ok).toBe(true);
    // The credential reached the child and came back redacted, over the wire.
    expect(JSON.stringify(outcome.result)).toContain("[REDACTED]");
    // `text` carries the JSON-serialized use_secret response on ok outcomes —
    // arms parse it instead of re-joining the content parts themselves.
    expect((JSON.parse(outcome.text) as { type?: string }).type).toBe("process");
    assertOpaque(SECRET, { result: outcome.result });
  });

  it("reports a refusal as a non-ok outcome with its text", async () => {
    vault = await createHarnessVault(PASSWORD);
    const handle = await storeSecret(vault, "surface-key", SECRET);
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [],
    });

    surface = await startMcpHttpSurface(vault, "e2e-agent", [Permission.USE]);
    const outcome = await surface.callUseSecret(handle, {
      type: "process",
      command: resolvePrintenv(),
      args: ["TOKEN"],
      env_var: "TOKEN",
    });

    expect(outcome.ok).toBe(false);
    // The agent-facing surface conveys the human-readable refusal, NOT the
    // machine-readable error code: the SDK renders a thrown VaultError as its
    // `.message`, and `.code` never crosses the wire. Scenario classification
    // therefore keys on the outcome, not on a code the surface never emits.
    expect(outcome.errorText ?? "").toMatch(/not in secret allowlist/i);
    assertOpaque(SECRET, { result: outcome.result, error: outcome.errorText });
  });
});
