import { describe, it, expect, afterEach } from "vitest";
import { Permission } from "@harpoc/shared";
import { createHarnessVault, storeSecret } from "../vault.js";
import type { HarnessVault } from "../vault.js";
import { startRestSurface } from "./rest.js";
import { startSdkSurface } from "./sdk.js";
import type { Surface } from "./surface.js";
import { assertOpaque } from "../../assert/opacity.js";
import { expectAttributedSuccess } from "../audit.js";
import { resolvePrintenv } from "../fixtures.js";

const PASSWORD = "e2e-rest-sdk-pw";
const SECRET = 'sk-restsdk/ab+cd 123"x';

type Starter = (vault: HarnessVault, principal: string, scopes: Permission[]) => Promise<Surface>;

const DRIVERS: [name: string, start: Starter][] = [
  ["rest", startRestSurface],
  ["sdk", startSdkSurface],
];

describe.each(DRIVERS)("%s surface", (name, start) => {
  let vault: HarnessVault | undefined;
  let surface: Surface | undefined;

  afterEach(async () => {
    await surface?.close();
    await vault?.destroy();
    surface = undefined;
    vault = undefined;
  });

  async function setup(commandAllowlist: string[]): Promise<string> {
    vault = await createHarnessVault(PASSWORD);
    const handle = await storeSecret(vault, "rest-sdk-key", SECRET);
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: commandAllowlist,
      env_allowlist: [],
      host_allowlist: [],
    });
    return handle;
  }

  it("carries a scoped token to a real listener and returns the result (C-2)", async () => {
    const printenv = resolvePrintenv();
    const handle = await setup([printenv]);
    const harness = vault as HarnessVault;

    surface = await start(harness, `e2e-${name}-agent`, [Permission.USE]);
    const outcome = await surface.callUseSecret(handle, {
      type: "process",
      command: printenv,
      args: ["TOKEN"],
      env_var: "TOKEN",
    });

    expect(outcome.ok).toBe(true);
    expect((outcome.result as { type?: string }).type).toBe("process");
    // The credential reached the child and came back redacted, over a socket.
    expect(JSON.stringify(outcome.result)).toContain("[REDACTED]");
    assertOpaque(SECRET, { result: outcome.result });

    // Both drivers reach the engine over the REST wire, so both attribute as
    // `rest`; the per-surface principal is what tells their rows apart.
    expectAttributedSuccess(harness, {
      context: "process",
      interface: "rest",
      principal: `e2e-${name}-agent`,
    });
  });

  it("reports a refusal as a non-ok outcome with its text", async () => {
    const handle = await setup([]);
    const harness = vault as HarnessVault;

    surface = await start(harness, `e2e-${name}-agent`, [Permission.USE]);
    const outcome = await surface.callUseSecret(handle, {
      type: "process",
      command: resolvePrintenv(),
      args: ["TOKEN"],
      env_var: "TOKEN",
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.errorText ?? "").toMatch(/not in secret allowlist/i);
    assertOpaque(SECRET, { result: outcome.result, error: outcome.errorText });
  });

  it("refuses an out-of-scope token — the token is enforced, not decorative", async () => {
    const printenv = resolvePrintenv();
    const handle = await setup([printenv]);
    const harness = vault as HarnessVault;

    // READ, not USE: if the surface's token were ignored, this would succeed.
    surface = await start(harness, `e2e-${name}-agent`, [Permission.READ]);
    const outcome = await surface.callUseSecret(handle, {
      type: "process",
      command: printenv,
      args: ["TOKEN"],
      env_var: "TOKEN",
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.errorText ?? "").toMatch(/permission|denied/i);
    assertOpaque(SECRET, { result: outcome.result, error: outcome.errorText });
  });
});
