import { describe, it, expect, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { assertOpaque, assertPresent } from "./assert/opacity.js";
import { createHarnessVault, storeSecret, EVIDENCE_FILE } from "./harness/vault.js";
import type { HarnessVault } from "./harness/vault.js";
import { recordArm } from "./harness/evidence.js";
import { resolvePrintenv } from "./harness/fixtures.js";

const PASSWORD = "e2e-machinery-pw";
const SECRET = 'sk-machinery/ab+cd 123"x';
const MARKER = "benign-marker-keep-me";
const MARKER_VAR = "HARPOC_E2E_MARKER";

describe("harness machinery, proven against the process context", () => {
  let vault: HarnessVault | undefined;

  afterEach(async () => {
    await vault?.destroy();
    vault = undefined;
    delete process.env[MARKER_VAR];
  });

  it("a spawned child receives the credential while the caller sees only redaction", async () => {
    const printenv = resolvePrintenv();
    // Passed through to the child via env_allowlist so the child prints one
    // line the vault must redact and one it must leave alone.
    process.env[MARKER_VAR] = MARKER;

    vault = await createHarnessVault(PASSWORD);
    const handle = await storeSecret(vault, "machinery-key", SECRET);

    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: [printenv],
      env_allowlist: [MARKER_VAR],
      host_allowlist: [],
    });

    const result = await vault.engine.useSecret(handle, {
      type: "process",
      command: printenv,
      args: ["TOKEN", MARKER_VAR],
      env_var: "TOKEN",
    });

    const auditRows = vault.engine.queryAudit({ eventType: "secret.use" });
    const observation = { result, auditRows, parentEnv: process.env };

    // Without this the test would pass vacuously: had TOKEN never reached the
    // child, printenv would have printed nothing for it and the credential
    // would be "absent" rather than "redacted". The placeholder proves the
    // child genuinely received the credential and the vault replaced it.
    expect(JSON.stringify(result)).toContain("[REDACTED]");

    // Criteria 1 and 2 across every channel the caller can observe.
    assertOpaque(SECRET, observation);
    // Negative control: redaction must be targeted, not blanket. Scoped to the
    // result alone — the broad observation includes parentEnv, where this test
    // itself planted the marker, which would satisfy the check vacuously even
    // if the vault had scrubbed the child's entire stdout.
    assertPresent(MARKER, { result });

    const record = recordArm(
      { scenario: "machinery-selfcheck", context: "process", surface: "engine", arm: "harpoc" },
      "OPAQUE",
    );

    expect(record.match).toBe(true);
    expect(readFileSync(EVIDENCE_FILE, "utf8")).toContain("machinery-selfcheck");
  });

  it("refuses to allowlist an interpreter without the explicit acknowledgement", async () => {
    // Pins why the fixture uses printenv: the §4.5.3 gate makes `node` a
    // deliberate, audited policy decision rather than routine harness setup.
    vault = await createHarnessVault(PASSWORD);
    const handle = await storeSecret(vault, "interpreter-key", SECRET);

    await expect(
      vault.engine.setInjectionPolicy(handle, {
        url_allowlist: [],
        command_allowlist: [process.execPath],
        env_allowlist: [],
        host_allowlist: [],
      }),
    ).rejects.toThrow(/INTERPRETER_NOT_ACKNOWLEDGED|interpreter/i);
  });
});
