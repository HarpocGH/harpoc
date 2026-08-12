import { spawn } from "node:child_process";
import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { existsSync, mkdirSync, readFileSync, rmSync, statSync } from "node:fs";
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

describe("compiled binary smoke: stdio MCP token gate (V3)", () => {
  it("server start --mcp without a token exits 1 with the TOKEN_REQUIRED guidance", async () => {
    const result = await runCli(["server", "start", "--mcp"]);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("TOKEN_REQUIRED");
    expect(result.stderr).toContain("harpoc auth token");
    expect(result.stderr).toContain("--allow-tokenless");
  }, 30_000);

  it("server start --mcp --allow-tokenless starts with the unrestricted warning", async () => {
    const child = spawn(
      process.execPath,
      [CLI_PATH, "--vault-dir", vaultDir, "server", "start", "--mcp", "--allow-tokenless"],
      { windowsHide: true },
    );
    let stderr = "";
    try {
      await new Promise<void>((resolvePromise, rejectPromise) => {
        const timer = setTimeout(() => {
          rejectPromise(new Error(`server never reported ready: ${stderr}`));
        }, 25_000);
        child.stderr.on("data", (chunk: Buffer) => {
          stderr += chunk.toString("utf8");
          if (stderr.includes("MCP server running on stdio")) {
            clearTimeout(timer);
            resolvePromise();
          }
        });
        child.on("error", (err) => {
          clearTimeout(timer);
          rejectPromise(err);
        });
        child.on("close", (code) => {
          clearTimeout(timer);
          rejectPromise(new Error(`exited early (${String(code)}): ${stderr}`));
        });
      });
      expect(stderr).toContain("WARNING");
      expect(stderr).toContain("unrestricted");
    } finally {
      child.kill();
    }
  }, 30_000);

  // W6: the waiver the previous test triggered must survive the process that
  // made it — stderr is a log pipe, the chain is the record.
  it("the tokenless start left a verifiable server.start row in the audit trail", async () => {
    const audit = await runCli(["audit", "--json", "--event", "server.start"]);
    expect(audit.code).toBe(0);
    const rows = JSON.parse(audit.stdout) as Array<{
      event_type: string;
      success: boolean;
      principal_type: string | null;
      detail: { tokenless?: boolean; transport?: string } | null;
    }>;
    expect(rows.length).toBeGreaterThan(0);
    const row = rows[0];
    expect(row?.event_type).toBe("server.start");
    expect(row?.success).toBe(true);
    expect(row?.detail?.tokenless).toBe(true);
    expect(row?.detail?.transport).toBe("stdio");
    expect(row?.principal_type).toBeNull();

    const table = await runCli(["audit", "--limit", "50"]);
    expect(table.code).toBe(0);
    expect(table.stdout).toContain("server.start");

    const verify = await runCli(["audit", "verify"]);
    expect(verify.code).toBe(0);
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

// L11: the vault directory and database were created with no explicit mode —
// on POSIX umask-dependent, typically world-readable — while the session file
// beside them is deliberately 0600. Walked through the real binary, which is
// the only place the directory is created.
describe("compiled binary smoke: vault directory and database modes (L11)", () => {
  it.runIf(process.platform !== "win32")(
    "init creates 0700 dir and 0600 database",
    async () => {
      const freshDir = join(
        tmpdir(),
        `harpoc-modes-${Date.now()}-${Math.random().toString(36).slice(2)}`,
      );

      const init = await new Promise<CliResult>((resolvePromise, rejectPromise) => {
        const child = spawn(process.execPath, [CLI_PATH, "--vault-dir", freshDir, "init"], {
          windowsHide: true,
        });
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (c: Buffer) => (stdout += c.toString("utf8")));
        child.stderr.on("data", (c: Buffer) => (stderr += c.toString("utf8")));
        child.on("error", rejectPromise);
        child.on("close", (code) => resolvePromise({ code, stdout, stderr }));
        child.stdin.write(`${MASTER_PASSWORD}\n${MASTER_PASSWORD}\n`);
        child.stdin.end();
      });

      try {
        expect(init.code).toBe(0);
        expect(statSync(freshDir).mode & 0o777).toBe(0o700);
        expect(statSync(join(freshDir, VAULT_DB_NAME)).mode & 0o777).toBe(0o600);
      } finally {
        rmSync(freshDir, { recursive: true, force: true });
      }
    },
    60_000,
  );
});

// Phase 3 D1: `secret use` accepts a scoped token, so the CLI is no longer
// exempt from the token checks every other interface applies. Walked through
// the real binary — the surface the e2e demonstration matrix drives.
describe("compiled binary smoke: token-scoped secret use (D1)", () => {
  let scopedToken: string;
  let foreignToken: string;

  beforeAll(async () => {
    const set = await runCli(["secret", "set", "token-scoped"], { stdin: "tok-secret-value\n" });
    expect(set.code).toBe(0);

    const allow = await runCli([
      "secret",
      "allow",
      "secret://token-scoped",
      "--command",
      process.execPath,
      "--acknowledge-interpreter",
    ]);
    expect(allow.code).toBe(0);

    const minted = await runCli([
      "auth",
      "token",
      "--scope",
      "use",
      "--secrets",
      "token-scoped",
      "--agent",
      "demo-agent",
      "--json",
    ]);
    expect(minted.code).toBe(0);
    scopedToken = (JSON.parse(minted.stdout) as { token: string }).token;

    const other = await runCli([
      "auth",
      "token",
      "--scope",
      "use",
      "--secrets",
      "other-*",
      "--json",
    ]);
    expect(other.code).toBe(0);
    foreignToken = (JSON.parse(other.stdout) as { token: string }).token;
  }, 60_000);

  function useArgs(): string[] {
    return [
      "secret",
      "use",
      "secret://token-scoped",
      "--action",
      "process",
      "--command",
      process.execPath,
      "--arg=-e",
      "--arg=process.exit(0)",
      "--env-var",
      "TOKEN",
    ];
  }

  it("an in-scope token completes the injection and attributes it to the cli interface", async () => {
    const use = await runCli([...useArgs(), "--token", scopedToken, "--json"]);
    expect(use.code).toBe(0);
    const result = JSON.parse(use.stdout) as { type: string; exit_code: number };
    expect(result.type).toBe("process");
    expect(result.exit_code).toBe(0);

    const audit = await runCli(["audit", "--json", "--limit", "20"]);
    expect(audit.code).toBe(0);
    const rows = JSON.parse(audit.stdout) as Array<{
      event_type: string;
      success?: boolean | number;
      principal_id: string | null;
      principal_type: string | null;
      detail?: Record<string, unknown> | null;
    }>;
    const attributed = rows.find(
      (r) => r.event_type === "secret.use" && r.principal_id === "demo-agent",
    );
    expect(attributed).toBeDefined();
    expect(attributed?.principal_type).toBe("agent");
    expect(attributed?.detail?.interface).toBe("cli");
    expect(Boolean(attributed?.success)).toBe(true);

    const verify = await runCli(["audit", "verify"]);
    expect(verify.code).toBe(0);
  }, 60_000);

  it("an out-of-scope token is refused before the child ever runs", async () => {
    const use = await runCli([...useArgs(), "--token", foreignToken, "--json"]);
    expect(use.code).toBe(1);
    expect(use.stderr).toContain("ACCESS_DENIED");
    expect(use.stdout).not.toContain("exit_code");
  }, 60_000);

  // D9: the default output is the human summary; --json is the machine shape.
  it("prints a readable summary by default and exact JSON under --json", async () => {
    const human = await runCli([...useArgs(), "--token", scopedToken]);
    expect(human.code).toBe(0);
    expect(() => JSON.parse(human.stdout)).toThrow();
    expect(human.stdout).toContain("exit_code");

    const json = await runCli([...useArgs(), "--token", scopedToken, "--json"]);
    expect(json.code).toBe(0);
    expect((JSON.parse(json.stdout) as { type: string }).type).toBe("process");
  }, 60_000);

  it("the ambient HARPOC_TOKEN is honored when no flag is given (D8)", async () => {
    const child = await new Promise<CliResult>((resolvePromise, rejectPromise) => {
      const proc = spawn(process.execPath, [CLI_PATH, "--vault-dir", vaultDir, ...useArgs()], {
        env: { ...process.env, HARPOC_TOKEN: foreignToken },
        windowsHide: true,
      });
      let stdout = "";
      let stderr = "";
      proc.stdout.on("data", (c: Buffer) => (stdout += c.toString("utf8")));
      proc.stderr.on("data", (c: Buffer) => (stderr += c.toString("utf8")));
      proc.on("error", rejectPromise);
      proc.on("close", (code) => resolvePromise({ code, stdout, stderr }));
      proc.stdin.end();
    });
    capturedOutputs.push(child.stdout, child.stderr);
    expect(child.code).toBe(1);
    expect(child.stderr).toContain("ACCESS_DENIED");
  }, 60_000);
});
