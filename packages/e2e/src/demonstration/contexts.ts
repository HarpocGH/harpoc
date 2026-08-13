import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import type { HarnessVault } from "../harness/vault.js";
import { storeSecret } from "../harness/vault.js";
import { ECHO_HTTPS, GIT_HTTP, MCP_DOWNSTREAM, PG, SSHD_PINNED } from "../harness/backends.js";
import type { FleetService } from "../harness/backends.js";
import { caPem } from "../harness/pki.js";
import { clientKeyPem, knownHostPin } from "../harness/ssh.js";
import { resolveGit, resolvePrintenv, resolveSsh } from "../harness/fixtures.js";
import type { CallOutcome } from "../harness/surfaces/surface.js";

/**
 * One demonstration cell's context half: what the vault must hold, what call to
 * issue, and what proves the backend was really reached. The surface half is
 * the other loop dimension — every context here runs unchanged through all five
 * drivers, which is what makes the matrix a loop rather than 24 hand-written
 * tests.
 */
export interface ContextArm {
  /** Pre-registration scenario id. */
  scenario: string;
  /** The thesis execution context this cell demonstrates. */
  context: "http" | "process" | "mcp" | "database" | "git" | "ssh";
  /** Fleet services that must be running; a missing one fails, never skips. */
  services: FleetService[];
  /**
   * Downstream MCP server name, for the one context that runs two arms. Without
   * it both `mcp` arms would match on (context, interface, principal) alone and
   * either one's audit row could satisfy the other's assertion.
   */
  auditServer?: string;
  /** The credential to store, and everything else the cell needs set up. */
  setup(vault: HarnessVault): Promise<ContextFixture>;
}

export interface ContextFixture {
  handle: string;
  /** Every string that must be absent from every observable channel. */
  opacitySubjects: string[];
  /** Built per call: git needs a fresh working directory for each surface. */
  action(): Promise<unknown> | unknown;
  /**
   * Proof the backend was reached. Throws with a specific message on failure —
   * `ok: true` alone would pass for a call that never left the vault.
   *
   * The action this outcome came from is handed back rather than remembered by
   * the fixture: an arm whose proof lives on the filesystem (git) must read the
   * directory THIS call used, and a fixture-held "last one" is only correct
   * while the loop stays strictly sequential. Since every cell clones the same
   * repository, reading a neighbouring cell's tree would be a false pass, not
   * an error.
   */
  assertReached(outcome: CallOutcome, action: unknown): Promise<void> | void;
  /** Marker that must survive redaction, proving it is surgical, not blanket. */
  benignMarker?: string;
  cleanup?: () => void;
}

const NONCE = Math.floor(Date.now() % 1_000_000).toString(36);

function textOfResult(outcome: CallOutcome): string {
  return typeof outcome.text === "string" && outcome.text !== ""
    ? outcome.text
    : JSON.stringify(outcome.result);
}

function parseResult(outcome: CallOutcome): Record<string, unknown> {
  const raw = textOfResult(outcome);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`result is not JSON: ${raw.slice(0, 400)}`);
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error(`result is not an object: ${raw.slice(0, 400)}`);
  }
  return parsed as Record<string, unknown>;
}

function expectRedacted(outcome: CallOutcome, what: string): void {
  const text = textOfResult(outcome);
  if (!text.includes("[REDACTED]")) {
    throw new Error(`${what}: no [REDACTED] marker — the backend never echoed the credential back`);
  }
}

/** http — TLS echo backend reflects the injected bearer in every encoding. */
const HTTP_ARM: ContextArm = {
  scenario: "demo-http",
  context: "http",
  services: ["echo-https"],
  async setup(vault) {
    const secret = `demo-http-token-${NONCE}`;
    const marker = `demo-http-marker-${NONCE}`;
    const handle = await storeSecret(vault, "demo-http", secret);
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [`https://${ECHO_HTTPS.host}:${String(ECHO_HTTPS.port)}/*`],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [],
    });
    return {
      handle,
      opacitySubjects: [secret],
      benignMarker: marker,
      action: () => ({
        type: "http",
        method: "GET",
        url: `https://${ECHO_HTTPS.host}:${String(ECHO_HTTPS.port)}/echo`,
        injection: { type: "bearer" },
        headers: { [ECHO_HTTPS.markerHeader]: marker },
      }),
      assertReached(outcome) {
        const result = parseResult(outcome);
        if (result["status"] !== 200) {
          throw new Error(`http status ${String(result["status"])}, expected 200`);
        }
        // The echo server reflects the credential raw and in five encodings; a
        // [REDACTED] body proves the server received it AND that the vault —
        // not the server's silence — is what keeps it from the caller.
        expectRedacted(outcome, "http");
      },
    };
  },
};

/** process — the injected value reaches a real child's environment. */
const PROCESS_ARM: ContextArm = {
  scenario: "demo-process",
  context: "process",
  services: [],
  async setup(vault) {
    const secret = `demo-process-token-${NONCE}`;
    const marker = `demo-process-marker-${NONCE}`;
    const printenv = resolvePrintenv();
    const handle = await storeSecret(vault, "demo-process", secret);
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: [printenv],
      env_allowlist: ["HARPOC_E2E_DEMO_MARKER"],
      host_allowlist: [],
    });
    process.env["HARPOC_E2E_DEMO_MARKER"] = marker;
    return {
      handle,
      opacitySubjects: [secret],
      benignMarker: marker,
      action: () => ({
        type: "process",
        command: printenv,
        args: ["DEMO_TOKEN", "HARPOC_E2E_DEMO_MARKER"],
        env_var: "DEMO_TOKEN",
      }),
      assertReached(outcome) {
        const result = parseResult(outcome);
        if (result["exit_code"] !== 0) {
          throw new Error(`process exit_code ${String(result["exit_code"])}, expected 0`);
        }
        // printenv echoed the injected variable, so the child really received
        // it; the vault redacted it on the way back.
        expectRedacted(outcome, "process");
      },
      cleanup: () => {
        delete process.env["HARPOC_E2E_DEMO_MARKER"];
      },
    };
  },
};

/** mcp (http downstream) — the matrix representative for the MCP context. */
const MCP_HTTP_DOWNSTREAM_ARM: ContextArm = {
  scenario: "demo-mcp",
  context: "mcp",
  services: ["mcp-downstream"],
  auditServer: MCP_DOWNSTREAM.serverName,
  async setup(vault) {
    const secret = `demo-mcp-http-token-${NONCE}`;
    const handle = await storeSecret(vault, "demo-mcp-http", secret);
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [`${MCP_DOWNSTREAM.endpoint}*`],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [],
    });
    await vault.engine.setMcpServerConfig(handle, {
      server_name: MCP_DOWNSTREAM.serverName,
      transport: "http",
      url: MCP_DOWNSTREAM.endpoint,
    });
    return {
      handle,
      opacitySubjects: [secret],
      // The downstream returns it beside the credential, so a mutation that
      // redacted the whole tool result would satisfy every opacity assertion
      // and fail here — the `mcp` arms had no such control before.
      benignMarker: MCP_DOWNSTREAM.benignMarker,
      action: async () => {
        // The recorder accumulates across the whole run and the fixture's
        // credential is the same for all five surfaces, so without this reset
        // the first cell's entry would satisfy every later cell's out-of-band
        // check — the one assertion whose whole purpose is to be independent
        // of the vault's own reporting.
        const cleared = await fetch(MCP_DOWNSTREAM.recordedUrl, { method: "DELETE" });
        if (!cleared.ok) {
          throw new Error(
            `could not reset the downstream recorder: HTTP ${String(cleared.status)}`,
          );
        }
        // Asserted, not assumed: this is what makes the per-cell property
        // falsifiable. Drop the reset and every cell after the first starts
        // from a non-empty recorder — the state in which the out-of-band check
        // passes without this call having reached the downstream at all.
        const after = (await (await fetch(MCP_DOWNSTREAM.recordedUrl)).json()) as {
          authorizations: string[];
        };
        if (after.authorizations.length !== 0) {
          throw new Error(
            `downstream recorder still holds ${String(after.authorizations.length)} entr(ies) ` +
              "after the reset — this cell's out-of-band check would not be its own",
          );
        }
        return {
          type: "mcp",
          server: MCP_DOWNSTREAM.serverName,
          tool: MCP_DOWNSTREAM.tool,
        };
      },
      async assertReached(outcome) {
        const result = parseResult(outcome);
        if (result["type"] !== "mcp") {
          throw new Error(`expected an mcp result, got ${String(result["type"])}`);
        }
        expectRedacted(outcome, "mcp");
        // The other half, read out of band so it cannot be an artifact of the
        // vault's own reporting: the downstream really was handed the bearer.
        // The recorder was emptied immediately before this call, so a match
        // here is THIS cell's request, not a neighbour's.
        const response = await fetch(MCP_DOWNSTREAM.recordedUrl);
        const body = (await response.json()) as { authorizations: string[] };
        if (!body.authorizations.includes(`Bearer ${secret}`)) {
          throw new Error(
            "downstream never recorded the injected bearer — the credential did not reach it",
          );
        }
      },
    };
  },
};

/** mcp (stdio downstream) — the D10 variant: real framing, interpreter gate. */
const STDIO_DOWNSTREAM_SERVER = "e2e-stdio-downstream";
/**
 * Kept byte-identical in `fixtures/mcp/downstream-server.mjs`, which cannot
 * import this module (the vault spawns it as a bare node script). The pin in
 * `mcp-stdio-fixture.test.ts` fails if the two drift apart.
 */
export const STDIO_DOWNSTREAM_MARKER = "stdio-downstream-benign-marker";

const MCP_STDIO_DOWNSTREAM_ARM: ContextArm = {
  scenario: "demo-mcp-stdio-downstream",
  context: "mcp",
  services: [],
  auditServer: STDIO_DOWNSTREAM_SERVER,
  async setup(vault) {
    const secret = `demo-mcp-stdio-token-${NONCE}`;
    const script = downstreamScriptPath();
    const handle = await storeSecret(vault, "demo-mcp-stdio", secret);
    // `node` is a known interpreter, so the allowlist entry is acknowledgement
    // -gated (§4.5.3). Passing the acknowledgement here is the honest setup for
    // a stdio downstream: the gate is part of what this variant demonstrates.
    await vault.engine.setInjectionPolicy(
      handle,
      {
        url_allowlist: [],
        command_allowlist: [process.execPath],
        env_allowlist: [],
        host_allowlist: [],
      },
      { acknowledge_interpreters: true },
    );
    await vault.engine.setMcpServerConfig(handle, {
      server_name: STDIO_DOWNSTREAM_SERVER,
      transport: "stdio",
      command: process.execPath,
      args: [script],
      env_var: "DOWNSTREAM_TOKEN",
    });
    return {
      handle,
      opacitySubjects: [secret],
      // Same control as the http-downstream arm: the child returns the marker
      // beside the credential, so blanket redaction cannot pass for surgical.
      benignMarker: STDIO_DOWNSTREAM_MARKER,
      action: () => ({
        type: "mcp",
        server: STDIO_DOWNSTREAM_SERVER,
        tool: "reveal",
      }),
      assertReached(outcome) {
        const result = parseResult(outcome);
        if (result["type"] !== "mcp") {
          throw new Error(`expected an mcp result, got ${String(result["type"])}`);
        }
        // The downstream child reflects the env var the vault injected, so a
        // [REDACTED] result proves receipt plus redaction. There is no
        // out-of-band recorder here: the child is vault-managed and dies with
        // the connection.
        expectRedacted(outcome, "mcp-stdio-downstream");
      },
    };
  },
};

function downstreamScriptPath(): string {
  const path = fileURLToPath(new URL("../../fixtures/mcp/downstream-server.mjs", import.meta.url));
  if (!existsSync(path)) {
    throw new Error(`stdio downstream fixture missing at ${path}`);
  }
  return path;
}

/** database — real PostgreSQL over the fixture CA. */
const DATABASE_ARM: ContextArm = {
  scenario: "demo-database",
  context: "database",
  services: ["postgres-tls"],
  async setup(vault) {
    const secret = `${PG.user}:${PG.password}`;
    const handle = await storeSecret(vault, "demo-database", secret);
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [`${PG.host}:${String(PG.port)}`],
    });
    await vault.engine.setConnectionConfig(handle, {
      database: { tls_mode: "require", ca_pem: caPem() },
    });
    return {
      handle,
      opacitySubjects: [secret, PG.password],
      action: () => ({
        type: "database",
        engine: "postgresql",
        host: PG.host,
        port: PG.port,
        database: PG.database,
        query: "SELECT 42 AS answer",
      }),
      assertReached(outcome) {
        const result = parseResult(outcome);
        if (result["row_count"] !== 1) {
          throw new Error(`row_count ${String(result["row_count"])}, expected 1`);
        }
        if (!JSON.stringify(result["rows"]).includes("42")) {
          throw new Error("the query result does not carry the server's answer");
        }
      },
    };
  },
};

/** git — a real clone over http with basic auth. */
const GIT_ARM: ContextArm = {
  scenario: "demo-git",
  context: "git",
  services: ["git-http"],
  async setup(vault) {
    const secret = `${GIT_HTTP.user}:${GIT_HTTP.password}`;
    const base = `http://${GIT_HTTP.host}:${String(GIT_HTTP.port)}`;
    const handle = await storeSecret(vault, "demo-git", secret);
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [`${base}/*`],
      command_allowlist: [resolveGit()],
      env_allowlist: ["GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL"],
      host_allowlist: [],
    });
    const dirs: string[] = [];
    return {
      handle,
      opacitySubjects: [secret, GIT_HTTP.password],
      action: () => {
        const dest = mkdtempSync(join(tmpdir(), "harpoc-demo-clone-"));
        dirs.push(dest);
        return {
          type: "git",
          operation: "clone",
          repository: `${base}/git/clean.git`,
          working_directory: dest,
        };
      },
      assertReached(outcome, action) {
        const result = parseResult(outcome);
        if (result["exit_code"] !== 0) {
          throw new Error(
            `git exit_code ${String(result["exit_code"])}: ${String(result["stderr"] ?? "")}`,
          );
        }
        // From THIS call's action, not from a fixture-held "last one": every
        // cell clones the same repository, so a neighbour's tree would satisfy
        // the check and the cell would pass for the wrong reason.
        const dest = (action as { working_directory?: unknown }).working_directory;
        if (typeof dest !== "string") {
          throw new Error("the git action carried no working_directory to verify");
        }
        if (!existsSync(join(dest, "README.md"))) {
          throw new Error(`the clone produced no working tree at ${dest}`);
        }
      },
      cleanup: () => {
        for (const dir of dirs) {
          rmSync(dir, { recursive: true, force: true });
        }
      },
    };
  },
};

/** ssh — a real authenticated session against the pinned host key. */
const SSH_ARM: ContextArm = {
  scenario: "demo-ssh",
  context: "ssh",
  services: ["sshd-pinned"],
  async setup(vault) {
    const key = clientKeyPem();
    const handle = await storeSecret(vault, "demo-ssh", key);
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: [resolveSsh()],
      env_allowlist: [],
      host_allowlist: [SSHD_PINNED.host],
    });
    await vault.engine.setConnectionConfig(handle, {
      ssh: { known_hosts: [knownHostPin(SSHD_PINNED.host, "pinned")] },
    });
    return {
      handle,
      opacitySubjects: [key],
      action: () => ({
        type: "ssh",
        host: SSHD_PINNED.host,
        user: SSHD_PINNED.user,
        command: "id -un",
      }),
      assertReached(outcome) {
        const result = parseResult(outcome);
        // An ssh auth failure returns in-band with ok:true and exit 255, so the
        // exit code and the absence of an error field are both load-bearing.
        if (result["error"] !== undefined) {
          throw new Error(`ssh reported ${String(result["error"])}`);
        }
        if (result["exit_code"] !== 0) {
          throw new Error(
            `ssh exit_code ${String(result["exit_code"])}: ${String(result["stderr"] ?? "")}`,
          );
        }
        if (!String(result["stdout"] ?? "").includes(SSHD_PINNED.user)) {
          throw new Error("the remote command did not report the expected user");
        }
      },
    };
  },
};

/**
 * The seven context arms the demonstration loop runs against every surface.
 * Six are the matrix's contexts; the seventh is the D10 stdio-downstream
 * variant of `mcp`, reported as transport coverage rather than as a matrix
 * cell.
 */
export const CONTEXT_ARMS: ContextArm[] = [
  HTTP_ARM,
  PROCESS_ARM,
  MCP_HTTP_DOWNSTREAM_ARM,
  MCP_STDIO_DOWNSTREAM_ARM,
  DATABASE_ARM,
  GIT_ARM,
  SSH_ARM,
];

/**
 * An empty gitconfig for the loop to point GIT_CONFIG_GLOBAL at. Ambient
 * credential helpers must not intercept the request ahead of the vault's
 * askpass — on a Windows dev host Git-for-Windows would otherwise inject
 * credential.helper=manager and the git cells would behave differently there
 * than on Linux CI.
 */
export function writeEmptyGitConfig(): string {
  const path = join(mkdtempSync(join(tmpdir(), "harpoc-demo-gitcfg-")), "gitconfig");
  writeFileSync(path, "");
  return path;
}
