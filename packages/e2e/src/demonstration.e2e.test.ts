import { rmSync } from "node:fs";
import { dirname } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Permission } from "@harpoc/shared";
import { createHarnessVault, PREREGISTRATION_FILE } from "./harness/vault.js";
import type { HarnessVault } from "./harness/vault.js";
import { loadExpectations } from "./evidence/preregistration.js";
import type { EvidenceRecord } from "./evidence/record.js";
import { assertFleetUp } from "./harness/backends.js";
import { preferNativeSsh } from "./harness/fixtures.js";
import { assertOpaque, assertPresent } from "./assert/opacity.js";
import { expectAttributedSuccess } from "./harness/audit.js";
import { recordArm } from "./harness/evidence.js";
import { startMcpHttpSurface } from "./harness/surfaces/mcp-http.js";
import { startMcpStdioSurface } from "./harness/surfaces/mcp-stdio.js";
import { startRestSurface } from "./harness/surfaces/rest.js";
import { startSdkSurface } from "./harness/surfaces/sdk.js";
import { startCliSurface } from "./harness/surfaces/cli.js";
import type { Surface } from "./harness/surfaces/surface.js";
import { CONTEXT_ARMS, writeEmptyGitConfig } from "./demonstration/contexts.js";
import type { ContextFixture } from "./demonstration/contexts.js";

/**
 * The demonstration matrix — Chapter 1 §1.4's literal commitment:
 *
 *   "deployment of the prototype across all six execution contexts and four
 *    access interfaces with real agent clients, exercising both injection
 *    mechanisms."
 *
 * Six contexts × four interfaces = 24 cells, each one successful,
 * opacity-checked `use_secret` call through a real surface carrying a scoped
 * token (C-2). MCP is one interface with two transports, so `mcp-http`
 * represents it in the matrix and `mcp-stdio` is reported beside it as
 * transport coverage; the `mcp` context additionally runs a stdio-DOWNSTREAM
 * variant (D10), likewise reported as coverage rather than as a matrix cell.
 * Seven context arms × five surfaces = 35 pre-registered, evidence-emitting
 * cells.
 *
 * One vault, one fleet check, five persistent surfaces: the surfaces are
 * distinguished in the audit trail by their per-surface principals, which is
 * what lets `rest` and `sdk` — which share the `rest` access interface, since
 * the SDK reaches the vault over that wire — be told apart at all.
 */
const PASSWORD = "e2e-demonstration-pw";

interface Cell {
  surface: Surface;
  fixture: ContextFixture;
}

/** The matrix Ch. 1 §1.4 commits to: six contexts × four access interfaces. */
const MATRIX_CONTEXTS = ["http", "process", "mcp", "database", "git", "ssh"] as const;
const MATRIX_INTERFACES = ["mcp", "rest", "sdk", "cli"] as const;
const SURFACE_NAMES = ["mcp-http", "mcp-stdio", "rest", "sdk", "cli"] as const;

describe("demonstration matrix — six contexts × four interfaces", () => {
  let vault: HarnessVault;
  const surfaces: Surface[] = [];
  const fixtures = new Map<string, ContextFixture>();
  const savedEnv: Record<string, string | undefined> = {};
  let gitConfigPath: string | undefined;
  /** Every record this file emitted, for the closing coverage assertion. */
  const emitted: EvidenceRecord[] = [];

  beforeAll(async () => {
    for (const arm of CONTEXT_ARMS) {
      for (const service of arm.services) assertFleetUp(service);
    }
    preferNativeSsh();

    // Neutralize ambient git config so the vault's askpass is the only
    // credential source, identically on Linux CI and a Windows dev host.
    gitConfigPath = writeEmptyGitConfig();
    for (const key of ["GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL"]) {
      savedEnv[key] = process.env[key];
    }
    process.env["GIT_CONFIG_NOSYSTEM"] = "1";
    process.env["GIT_CONFIG_GLOBAL"] = gitConfigPath;

    vault = await createHarnessVault(PASSWORD);
    for (const arm of CONTEXT_ARMS) {
      fixtures.set(arm.scenario, await arm.setup(vault));
    }

    // Started AFTER the fixtures: the out-of-process surfaces inherit the
    // environment the fixtures set up (the git config above, the process
    // context's marker), which a child spawned earlier would not have.
    surfaces.push(
      await startMcpHttpSurface(vault, "e2e-demo-mcp-http", [Permission.USE]),
      await startMcpStdioSurface(vault, "e2e-demo-mcp-stdio", [Permission.USE]),
      await startRestSurface(vault, "e2e-demo-rest", [Permission.USE]),
      await startSdkSurface(vault, "e2e-demo-sdk", [Permission.USE]),
      await startCliSurface(vault, "e2e-demo-cli", [Permission.USE]),
    );
  }, 180_000);

  afterAll(async () => {
    for (const surface of surfaces) await surface.close();
    for (const fixture of fixtures.values()) fixture.cleanup?.();
    await vault?.destroy();
    if (gitConfigPath !== undefined) {
      rmSync(dirname(gitConfigPath), { recursive: true, force: true });
    }
    for (const [key, value] of Object.entries(savedEnv)) {
      if (value === undefined) Reflect.deleteProperty(process.env, key);
      else process.env[key] = value;
    }
  });

  /** One cell: call, prove the backend was reached, prove nothing leaked. */
  async function runCell(cell: Cell, arm: (typeof CONTEXT_ARMS)[number]): Promise<void> {
    const { surface, fixture } = cell;
    // The action is held, not rebuilt: the arm's proof may live outside the
    // result (git's working tree), and it must be THIS call's action that is
    // verified, never a fixture-remembered last one.
    const action = await fixture.action();
    const outcome = await surface.callUseSecret(fixture.handle, action);

    if (!outcome.ok) {
      throw new Error(
        `${arm.scenario} via ${surface.name} did not complete: ${outcome.errorText ?? outcome.text}`,
      );
    }
    await fixture.assertReached(outcome, action);

    // C-6: every structural position, on every channel this surface exposes —
    // including a real child's own streams for the surfaces that spawn one.
    const auditRows = vault.engine.queryAudit({ eventType: "secret.use" });
    const observation = {
      result: outcome.result,
      auditRows,
      parentEnv: process.env,
      stdout: outcome.stdout,
      stderr: outcome.stderr,
    };
    for (const subject of fixture.opacitySubjects) {
      assertOpaque(subject, observation);
    }
    // Negative control: redaction must be surgical. A mutation that redacts
    // everything would pass every assertion above and fail this one.
    if (fixture.benignMarker !== undefined) {
      assertPresent(fixture.benignMarker, { result: outcome.result });
    }

    expectAttributedSuccess(vault, {
      context: arm.context,
      interface: surface.auditInterface,
      principal: surface.principal,
      // The `mcp` context runs two arms; without the downstream server name
      // either one's row would satisfy the other's assertion.
      server: arm.auditServer,
    });

    const record = recordArm(
      {
        scenario: arm.scenario,
        context: arm.context,
        surface: surface.name,
        interface: surface.interfaceId,
        arm: "harpoc",
      },
      "SUCCEEDED",
    );
    expect(record.match).toBe(true);
    emitted.push(record);
  }

  // The loop: every context through every surface. Adding a seventh context
  // costs one fixture, not five tests.
  for (const surfaceName of SURFACE_NAMES) {
    describe(surfaceName, () => {
      for (const arm of CONTEXT_ARMS) {
        it(`${arm.context}: ${arm.scenario}`, async () => {
          const surface = surfaces.find((s) => s.name === surfaceName);
          const fixture = fixtures.get(arm.scenario);
          if (surface === undefined) throw new Error(`surface ${surfaceName} did not start`);
          if (fixture === undefined) throw new Error(`fixture ${arm.scenario} was not set up`);
          await runCell({ surface, fixture }, arm);
        }, 120_000);
      }

      it("the audit chain still verifies after this surface's cells", () => {
        expect(vault.engine.verifyAuditChain().valid).toBe(true);
      });
    });
  }

  /**
   * The Chapter 1 claim, asserted rather than assumed. Without this the matrix
   * is only as large as the loop happens to be: deleting a context arm or a
   * surface driver shrinks it in silence, and pre-registration cannot notice —
   * `expectationFor` errors on an UNREGISTERED key, never on a registered
   * expectation that no cell exercised.
   *
   * Asserted over the records this file emitted, not over the shared evidence
   * file, which other suites append to.
   */
  it("covers the committed matrix: 24 (context × interface) cells, 35 cells in all", () => {
    expect(emitted).toHaveLength(CONTEXT_ARMS.length * SURFACE_NAMES.length);
    expect(emitted.every((r) => r.match)).toBe(true);

    const pairs = new Set(emitted.map((r) => `${r.context}|${r.interface}`));
    const expectedPairs = new Set(
      MATRIX_CONTEXTS.flatMap((c) => MATRIX_INTERFACES.map((i) => `${c}|${i}`)),
    );
    expect(pairs.size).toBe(24);
    expect([...expectedPairs].filter((p) => !pairs.has(p))).toEqual([]);

    // Every pre-registered demonstration outcome was actually exercised — the
    // direction `expectationFor` cannot check.
    const registered = loadExpectations(PREREGISTRATION_FILE)
      .filter((e) => e.scenario.startsWith("demo-"))
      .map((e) => `${e.scenario}|${e.surface}`);
    const ran = new Set(emitted.map((r) => `${r.scenario}|${r.surface}`));
    expect(registered.filter((k) => !ran.has(k))).toEqual([]);
    expect(registered).toHaveLength(emitted.length);
  });
});
