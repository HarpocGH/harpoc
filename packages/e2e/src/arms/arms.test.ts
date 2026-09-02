import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Permission } from "@harpoc/shared";
import { createHarnessVault, grantOn, storeSecret } from "../harness/vault.js";
import type { HarnessVault } from "../harness/vault.js";
import { assertOpaque, assertPresent } from "../assert/opacity.js";
import { ECHO_HTTPS, assertFleetUp } from "../harness/backends.js";
import { resolvePrintenv } from "../harness/fixtures.js";
import { startBaselineArm } from "./baseline.js";
import { startHarpocArm } from "./harpoc.js";
import type { Arm } from "./arm.js";

/**
 * The C-3 self-check, and the most load-bearing test in Phase 4.
 *
 * Every paired scenario row rests on the baseline arm actually leaking. A
 * baseline that quietly fails to reach its target — a typo'd URL, an unbuilt
 * fixture, a tool that returns an error the arm records as "did not leak" —
 * would render every "baseline: LEAKED" cell in the generated §6.2 table
 * vacuous while the suite stayed green, and the two-arm construction would
 * collapse back into the assertion it exists to replace.
 *
 * So the leak is asserted directly, here, before any scenario depends on it.
 * The Harpoc arm answering the IDENTICAL payload is the paired control: it is
 * what shows the difference is the credential-handling layer and not the
 * payload, the transport or the backend.
 */
const PASSWORD = "e2e-arms-selfcheck-pw";
const CREDENTIAL = "baseline-arm-credential-9d2f";
const MARKER = "baseline-arm-benign-marker-9d2f";

const httpAction = () => ({
  type: "http",
  method: "GET",
  url: `https://${ECHO_HTTPS.host}:${String(ECHO_HTTPS.port)}/echo`,
  injection: { type: "bearer" },
  headers: { [ECHO_HTTPS.markerHeader]: MARKER },
});

const processAction = (command: string) => ({
  type: "process",
  command,
  args: ["ARMS_TOKEN", "HARPOC_E2E_ARMS_MARKER"],
  env_var: "ARMS_TOKEN",
});

describe("two-arm harness (C-3)", () => {
  let vault: HarnessVault;
  let baseline: Arm;
  let harpoc: Arm;
  let handle: string;
  const printenv = resolvePrintenv();

  beforeAll(async () => {
    assertFleetUp("echo-https");
    process.env["HARPOC_E2E_ARMS_MARKER"] = MARKER;

    vault = await createHarnessVault(PASSWORD);
    handle = await storeSecret(vault, "arms-selfcheck", CREDENTIAL);
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [`https://${ECHO_HTTPS.host}:${String(ECHO_HTTPS.port)}/*`],
      command_allowlist: [printenv],
      env_allowlist: ["HARPOC_E2E_ARMS_MARKER"],
      host_allowlist: [],
    });
    await grantOn(vault, handle, "arms-selfcheck-principal", [
      Permission.READ,
      Permission.USE,
      Permission.LIST,
    ]);

    baseline = await startBaselineArm(CREDENTIAL);
    harpoc = await startHarpocArm(vault, "arms-selfcheck-principal", [
      Permission.READ,
      Permission.USE,
      Permission.LIST,
    ]);
  }, 180_000);

  afterAll(async () => {
    delete process.env["HARPOC_E2E_ARMS_MARKER"];
    await baseline?.close();
    await harpoc?.close();
    // destroy() removes its own mkdtemp directory; anything broader here would
    // be reaching outside what this test created.
    await vault?.destroy();
  });

  it("baseline: the http call hands the credential straight back to the caller", async () => {
    const outcome = await baseline.invoke(handle, httpAction());
    expect(outcome.ok).toBe(true);

    // Reached the backend, and did not merely fail with the credential in an
    // error message: assertPresent alone cannot tell those apart, and a
    // "leak" that is really a failure is the worst false positive available
    // here — it would make every paired row read as a controlled comparison
    // when one arm never ran.
    const result = JSON.parse(outcome.text) as { status?: number; body?: string };
    expect(result.status).toBe(200);
    expect(result.body ?? "").toContain(MARKER);

    // The §2.3 status quo: no sanitizer in the path, so the echoing backend's
    // reflection reaches the agent verbatim.
    assertPresent(CREDENTIAL, { result: outcome.result });
  });

  it("baseline: a real child receives the credential and its output is echoed verbatim", async () => {
    const outcome = await baseline.invoke(handle, processAction(printenv));
    expect(outcome.ok).toBe(true);

    const result = JSON.parse(outcome.text) as { exit_code?: number; stdout?: string };
    expect(result.exit_code).toBe(0);
    // printenv echoed the injected variable, so the child really received it.
    expect(result.stdout ?? "").toContain(CREDENTIAL);

    assertPresent(CREDENTIAL, { result: outcome.result });
  });

  it("baseline: the metadata surfaces expose the value, not a handle", async () => {
    const outcome = await baseline.probeMetadata();
    expect(outcome.ok).toBe(true);
    assertPresent(CREDENTIAL, { result: outcome.result });
  });

  it("harpoc: the identical http payload comes back opaque", async () => {
    const outcome = await harpoc.invoke(handle, httpAction());
    expect(outcome.ok).toBe(true);
    assertOpaque(CREDENTIAL, { result: outcome.result });
    // The backend did echo it — otherwise this proves nothing about the vault.
    expect(outcome.text).toContain("[REDACTED]");
    assertPresent(MARKER, { result: outcome.result });
  });

  it("harpoc: the identical metadata probe returns handles, never values", async () => {
    const outcome = await harpoc.probeMetadata();
    expect(outcome.ok).toBe(true);
    assertOpaque(CREDENTIAL, { result: outcome.result });
  });

  it("the two arms are distinguishable by name, so evidence cannot be misfiled", () => {
    expect(baseline.name).toBe("baseline");
    expect(harpoc.name).toBe("harpoc");
  });
});
