import { spawn } from "node:child_process";
import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { auditChainAnchorSchema, VAULT_DB_NAME } from "@harpoc/shared";
import { SqliteStore } from "@harpoc/core";
import type { AuditChainAnchor } from "@harpoc/shared";

const CLI_PATH = resolve(dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");
const MASTER_PASSWORD = "smoke-master-pw-1";
const CLIENT_SECRET = "smoke-cc-s3cret-value";

let vaultDir: string;
let tokenServer: Server;
let tokenServerUrl: string;
let tokenHandler: (req: IncomingMessage, res: ServerResponse) => void;
/** Every byte the binary ever wrote, for the secrets-never-logged sweep. */
const capturedOutputs: string[] = [];

interface CliResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

function runCli(args: string[], options?: { stdin?: string }): Promise<CliResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, [CLI_PATH, "--vault-dir", vaultDir, ...args], {
      env: { ...process.env, HARPOC_OAUTH_CLIENT_SECRET: CLIENT_SECRET },
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", rejectPromise);
    child.on("close", (code) => {
      capturedOutputs.push(stdout, stderr);
      resolvePromise({ code, stdout, stderr });
    });
    if (options?.stdin !== undefined) {
      child.stdin.write(options.stdin);
    }
    child.stdin.end();
  });
}

beforeAll(async () => {
  expect(existsSync(CLI_PATH)).toBe(true);

  tokenServer = createServer((req, res) => {
    tokenHandler(req, res);
  });
  await new Promise<void>((resolvePromise) => {
    tokenServer.listen(0, "127.0.0.1", () => resolvePromise());
  });
  const addr = tokenServer.address() as { port: number };
  tokenServerUrl = `http://127.0.0.1:${addr.port}`;
  tokenHandler = (_req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ access_token: "smoke-access-token", expires_in: 3600 }));
  };

  vaultDir = join(tmpdir(), `harpoc-smoke-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(vaultDir, { recursive: true });

  // Real binary, real argon2, piped-stdin password prompts (init asks twice).
  const init = await runCli(["init"], { stdin: `${MASTER_PASSWORD}\n${MASTER_PASSWORD}\n` });
  if (init.code !== 0) {
    throw new Error(`harpoc init failed (exit ${String(init.code)}): ${init.stderr}`);
  }
}, 60_000);

afterAll(() => {
  tokenServer.close();
  try {
    rmSync(vaultDir, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

describe("compiled binary smoke: oauth connect (client_credentials)", () => {
  it("connects an OAuth secret end-to-end against a loopback provider", async () => {
    const result = await runCli([
      "oauth",
      "connect",
      "smoke-cc",
      "--client-credentials",
      "--provider",
      "custom",
      "--client-id",
      "smoke-client",
      "--token-endpoint",
      tokenServerUrl,
      "--json",
    ]);

    expect(result.code).toBe(0);
    const printed = JSON.parse(result.stdout) as Record<string, unknown>;
    expect(printed.status).toBe("authorized");
    expect(printed.handle).toBe("secret://smoke-cc");
  }, 30_000);

  it("secret get shows the connected secret as an active oauth_token", async () => {
    const result = await runCli(["secret", "get", "secret://smoke-cc", "--json"]);

    expect(result.code).toBe(0);
    const info = JSON.parse(result.stdout) as Record<string, unknown>;
    expect(info.status).toBe("active");
    expect(info.type).toBe("oauth_token");
  }, 30_000);

  it("a failing token endpoint exits 1 and never reports authorized (negative control)", async () => {
    tokenHandler = (_req, res) => {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_client" }));
    };

    const result = await runCli([
      "oauth",
      "connect",
      "smoke-cc-fail",
      "--client-credentials",
      "--provider",
      "custom",
      "--client-id",
      "smoke-client",
      "--token-endpoint",
      tokenServerUrl,
      "--json",
    ]);

    expect(result.code).toBe(1);
    expect(result.stdout).not.toContain("authorized");
    expect(result.stderr).toContain("OAUTH");
  }, 30_000);

  it("the client secret never appears in any stdout/stderr", () => {
    for (const output of capturedOutputs) {
      expect(output).not.toContain(CLIENT_SECRET);
    }
    expect(capturedOutputs.length).toBeGreaterThan(0);
  });
});

describe("compiled binary smoke: audit anchor / verify --anchor", () => {
  it("anchor prints schema-valid JSON to stdout and the off-host guidance to stderr", async () => {
    const result = await runCli(["audit", "anchor"]);
    expect(result.code).toBe(0);
    const anchor = auditChainAnchorSchema.parse(JSON.parse(result.stdout));
    expect(anchor.last_id).toBeGreaterThan(0);
    expect(result.stderr).toContain("OFF-HOST");
    expect(result.stdout).not.toContain("OFF-HOST");
  }, 30_000);

  it("anchor --out, verify --anchor roundtrip, truncation detection", async () => {
    const anchorPath = join(vaultDir, "smoke.anchor");
    const anchored = await runCli(["audit", "anchor", "--out", anchorPath]);
    expect(anchored.code).toBe(0);
    const anchor = auditChainAnchorSchema.parse(
      JSON.parse(readFileSync(anchorPath, "utf8")),
    ) as AuditChainAnchor;

    const clean = await runCli(["audit", "verify", "--anchor", anchorPath]);
    expect(clean.code).toBe(0);
    expect(clean.stdout).toContain(`Anchor OK — row ${anchor.last_id} intact`);
    expect(clean.stdout).toContain("Tail link: row");

    // Attacker deletes the anchored tail row directly in the DB.
    const store = new SqliteStore(join(vaultDir, VAULT_DB_NAME));
    try {
      store.db.prepare("DELETE FROM audit_log WHERE id >= ?").run(anchor.last_id);
    } finally {
      store.close();
    }

    // The plain verify stays blind to the truncation — the pinned vulnerability.
    const plain = await runCli(["audit", "verify"]);
    expect(plain.code).toBe(0);

    const detected = await runCli(["audit", "verify", "--anchor", anchorPath]);
    expect(detected.code).toBe(1);
    expect(detected.stderr).toContain("FAILS the anchor check");
  }, 30_000);
});

describe("compiled binary smoke: transactional audit writes (NM3)", () => {
  it("audit verify exits 0 after a lifecycle incl. an acknowledged-interpreter grant", async () => {
    const set = await runCli(["secret", "set", "atomic-smoke"], { stdin: "smoke-value\n" });
    expect(set.code).toBe(0);

    // Grant + interpreter acknowledgement commit as one multi-row transaction.
    const allow = await runCli([
      "secret",
      "allow",
      "secret://atomic-smoke",
      "--command",
      process.execPath,
      "--acknowledge-interpreter",
    ]);
    expect(allow.code).toBe(0);

    const rotate = await runCli(["secret", "rotate", "secret://atomic-smoke"], {
      stdin: "smoke-value-2\n",
    });
    expect(rotate.code).toBe(0);

    const verify = await runCli(["audit", "verify"]);
    expect(verify.code).toBe(0);
  }, 60_000);
});

describe("compiled binary smoke: audit table attribution (V2)", () => {
  it("the audit table carries a Principal column; trusted-local rows render '-'", async () => {
    const audit = await runCli(["audit", "--limit", "5"]);
    expect(audit.code).toBe(0);
    const [header, , ...rows] = audit.stdout.split("\n");
    expect(header).toContain("Principal");
    // Every row of this CLI-only lifecycle is the trusted local path (D4):
    // NULL principal columns render "-", never a fabricated "local".
    expect(rows.length).toBeGreaterThan(0);
    expect(audit.stdout).not.toContain("local");
  }, 30_000);
});

// Windows is the platform where isolation is unsupported by design, so the
// compiled binary exercises the REAL fail-closed refusal path — no test
// hook, no mock (review T2: the third pinning level for the refusal).
const describeWindows = process.platform === "win32" ? describe : describe.skip;

describeWindows("compiled binary smoke: network-isolation refusal (Windows)", () => {
  it("a policy-demanding process use exits 1 and the denial is audited", async () => {
    const set = await runCli(["secret", "set", "net-refuse"], {
      stdin: "refuse-secret-value\n",
    });
    expect(set.code).toBe(0);

    const allow = await runCli([
      "secret",
      "allow",
      "secret://net-refuse",
      "--command",
      process.execPath,
      "--acknowledge-interpreter",
      "--network-isolation",
    ]);
    expect(allow.code).toBe(0);

    const use = await runCli([
      "secret",
      "use",
      "secret://net-refuse",
      "--action",
      "process",
      "--command",
      process.execPath,
      "--arg=-e",
      "--arg=process.exit(0)",
      "--env-var",
      "TOKEN",
      "--json",
    ]);
    expect(use.code).toBe(1);
    expect(use.stderr).toContain("NETWORK_ISOLATION_UNAVAILABLE");
    // The payload must never have run: a refusal happens BEFORE any spawn.
    expect(use.stdout).not.toContain("exit_code");

    const audit = await runCli(["audit", "--json"]);
    expect(audit.code).toBe(0);
    const events = JSON.parse(audit.stdout) as {
      success?: boolean | number;
      detail?: Record<string, unknown>;
    }[];
    const denied = events.find((e) => e.detail?.error === "NETWORK_ISOLATION_UNAVAILABLE");
    expect(denied).toBeDefined();
    expect(denied?.detail?.network_isolation).toBe(true);
    expect(Boolean(denied?.success)).toBe(false);
  }, 60_000);
});
