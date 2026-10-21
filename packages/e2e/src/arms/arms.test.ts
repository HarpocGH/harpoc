import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Permission, useSecretActionSchema } from "@harpoc/shared";
import { createHarnessVault, grantOn, storeSecret } from "../harness/vault.js";
import type { HarnessVault } from "../harness/vault.js";
import { assertOpaque, assertPresent } from "../assert/opacity.js";
import { ECHO_HTTPS, assertFleetUp } from "../harness/backends.js";
import { resolvePrintenv } from "../harness/fixtures.js";
import { startBaselineArm } from "./baseline.js";
import { probeHarpocSurface, startHarpocArm } from "./harpoc.js";
import type { ProbeSurface } from "./harpoc.js";
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

/*
 * What the §6.2.1 surface probe asks the server, pinned without a fleet or a
 * vault (test-review-2026-10-09 M-T1-7): a recording double stands in for the
 * connected MCP client, answering every read but `secret://vault/audit/recent`,
 * which it refuses as the real server refuses a token without `admin`. The real
 * answers are the harness's, on `e2e.yml`.
 */
const AUDIT_REFUSAL = "Access denied: Token lacks permission: admin";
const USE_SECRET_TOOLS = {
  tools: [{ name: "use_secret", inputSchema: { type: "object", required: ["handle", "action"] } }],
};

interface Recording {
  calls: string[];
  toolActions: unknown[];
  toolHandles: unknown[];
  failingActions: unknown[];
  surface: ProbeSurface;
}

function recordingSurface(): Recording {
  const calls: string[] = [];
  const toolActions: unknown[] = [];
  const toolHandles: unknown[] = [];
  const failingActions: unknown[] = [];
  const client = {
    callTool: (params: { name: string; arguments?: Record<string, unknown> }) => {
      calls.push(`callTool ${params.name}`);
      if (params.name === "use_secret") {
        toolActions.push(params.arguments?.action);
        toolHandles.push(params.arguments?.handle);
      }
      return Promise.resolve({ content: [{ type: "text", text: `${params.name} answer` }] });
    },
    readResource: (params: { uri: string }) => {
      calls.push(`readResource ${params.uri}`);
      if (params.uri === "secret://vault/audit/recent") {
        return Promise.reject(new Error(AUDIT_REFUSAL));
      }
      return Promise.resolve({ contents: [{ uri: params.uri, text: `${params.uri} answer` }] });
    },
    listTools: () => {
      calls.push("listTools");
      return Promise.resolve(USE_SECRET_TOOLS);
    },
  };
  return {
    calls,
    toolActions,
    toolHandles,
    failingActions,
    surface: {
      client: client as unknown as ProbeSurface["client"],
      callUseSecret: (handle, action) => {
        calls.push(`callUseSecret ${handle}`);
        failingActions.push(action);
        return Promise.resolve({
          ok: false,
          text: `Secret not found: ${handle}`,
          errorText: `Secret not found: ${handle}`,
        });
      },
    },
  };
}

describe("harpoc arm: the §6.2.1 surface probe, fleet-free", () => {
  it("issues the whole surface in order: two tools, five resources, the argument surface, the failing call", async () => {
    const { calls, surface } = recordingSurface();
    await probeHarpocSurface(surface, "secret://prod/db-pass");
    expect(calls).toEqual([
      "callTool list_secrets",
      "callTool get_secret_info",
      "readResource secret://vault/secrets",
      "readResource secret://vault/secrets/prod%2Fdb-pass",
      "readResource secret://vault/health",
      "readResource secret://vault/projects",
      "readResource secret://vault/audit/recent",
      "listTools",
      "callTool use_secret",
      "callUseSecret secret://does-not-exist",
    ]);
  });

  it.each([
    { label: "a global handle", handle: "secret://my-key", path: "my-key" },
    { label: "a project-scoped handle", handle: "secret://prod/db-pass", path: "prod%2Fdb-pass" },
    { label: "no handle, secret://unknown", handle: undefined, path: "unknown" },
  ])(
    "reads the five resources once each, the by-name read at the handle path of $label",
    async ({ handle, path }) => {
      const { calls, surface } = recordingSurface();
      await probeHarpocSurface(surface, handle);
      expect(calls.filter((call) => call.startsWith("readResource "))).toEqual([
        "readResource secret://vault/secrets",
        `readResource secret://vault/secrets/${path}`,
        "readResource secret://vault/health",
        "readResource secret://vault/projects",
        "readResource secret://vault/audit/recent",
      ]);
    },
  );

  it("probes the use_secret argument surface: the advertised schema captured, a malformed action the tool's schema refuses", async () => {
    const { toolActions, toolHandles, surface } = recordingSurface();
    const outcome = await probeHarpocSurface(surface, "secret://my-key");
    expect((outcome.result as Record<string, unknown>).useSecretArgs).toEqual({
      tools: USE_SECRET_TOOLS,
      malformed: { content: [{ type: "text", text: "use_secret answer" }] },
    });
    expect(toolActions).toHaveLength(1);
    expect(useSecretActionSchema.safeParse(toolActions[0]).success).toBe(false);
    expect(toolHandles).toEqual(["secret://my-key"]);
  });

  it("the failing call's action passes the tool's schema, so its refusal is the engine's not-found", async () => {
    const { failingActions, surface } = recordingSurface();
    const outcome = await probeHarpocSurface(surface, "secret://my-key");
    expect(failingActions).toHaveLength(1);
    expect(useSecretActionSchema.safeParse(failingActions[0]).success).toBe(true);
    expect((outcome.result as Record<string, unknown>).failing).toBe(
      "Secret not found: secret://does-not-exist",
    );
  });

  it("every output joins result and text, the refused read captured as its error, never thrown", async () => {
    const { surface } = recordingSurface();
    const outcome = await probeHarpocSurface(surface, "secret://my-key");
    expect(outcome.ok).toBe(true);
    expect(outcome.text).toContain("list_secrets answer");
    expect(outcome.text).toContain("get_secret_info answer");
    const result = outcome.result as Record<string, unknown>;
    expect(Object.keys(result)).toEqual([
      "list",
      "info",
      "resource",
      "resources",
      "useSecretArgs",
      "failing",
    ]);
    const resources = result.resources as Record<string, unknown>;
    expect(Object.keys(resources)).toEqual(["secret", "health", "projects", "auditRecent"]);
    expect(resources.auditRecent).toBeInstanceOf(Error);
    for (const uri of [
      "secret://vault/secrets",
      "secret://vault/secrets/my-key",
      "secret://vault/health",
      "secret://vault/projects",
    ]) {
      expect(outcome.text).toContain(`${uri} answer`);
    }
    expect(outcome.text).toContain(AUDIT_REFUSAL);
    expect(outcome.text).toContain('"required":["handle","action"]');
    expect(outcome.text).toContain("use_secret answer");
    expect(outcome.text).toContain("Secret not found: secret://does-not-exist");
  });
});
