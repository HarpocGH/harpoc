import { createHash } from "node:crypto";
import { createServer } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AuditEventType, ErrorCode, SecretType } from "@harpoc/shared";
import type { InjectionPolicyInput, UseSecretAction, UseSecretResponse } from "@harpoc/shared";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { expectVaultError } from "@harpoc/test-utils";

/**
 * The durable audit row as an output channel (test-review-2026-10-09 M-T1-5;
 * thesis §6.1's per-context tracing, position M9): an audit row persists and is
 * re-served on every later admin-scoped read, so the injected credential must
 * reach no `secret.use` row in any encoding at any structural position — key or
 * value. The e2e harness sweeps it for the six thesis contexts on `e2e.yml`
 * (`assertOpaque` over `queryAudit({ eventType: "secret.use" })`, the refused
 * uses' rows included); this file reproduces that sweep in the gate over one
 * real vault: http, process and mcp end to end on loopback (each backend echoes
 * the credential back, and each proves it held the credential by a digest that
 * is not one of the swept encodings), database, git and ssh on their audited
 * allowlist refusals — the row written after the credential was decrypted,
 * before any connection. The credentials carry no character JSON escapes, so a
 * substring test is the harness's escape-tolerant match here.
 */

const PASSWORD = "audit-row-position-pw";
const NODE = process.execPath;
const HOST = "127.0.0.1";
const UNUSED_HOST = "192.0.2.1";

const ECHO_SCRIPT = [
  "const t = process.env.TOKEN ?? '';",
  "const digest = require('node:crypto').createHash('sha256').update(t).digest('hex');",
  "process.stdout.write(digest + '\\n' + t + '\\n' + Buffer.from(t).toString('base64'));",
  "process.stderr.write(Buffer.from(t).toString('hex'));",
].join("\n");

const DOWNSTREAM_SERVER = `
const readline = require("node:readline");
const t = process.env.TOKEN || "";
const digest = require("node:crypto").createHash("sha256").update(t).digest("hex");
const rl = readline.createInterface({ input: process.stdin });
function send(msg) { process.stdout.write(JSON.stringify(msg) + "\\n"); }
rl.on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === "initialize") {
    send({ jsonrpc: "2.0", id: m.id, result: {
      protocolVersion: m.params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "m9-downstream", version: "1.0.0" },
    }});
  } else if (m.method === "tools/call") {
    send({ jsonrpc: "2.0", id: m.id, result: {
      content: [{ type: "text", text: digest }, { type: "text", text: t }],
    }});
  }
});
`;

interface Sighting {
  path: string;
  position: "key" | "value";
  encoding: string;
}

/** The harness's encoding set (`e2e/src/assert/encodings.ts`). */
function encodingsOf(secret: string): Array<[string, string]> {
  const buf = Buffer.from(secret, "utf8");
  return [
    ["raw", secret],
    ["base64", buf.toString("base64")],
    ["base64url", buf.toString("base64url")],
    ["hex", buf.toString("hex")],
    ["hexUpper", buf.toString("hex").toUpperCase()],
    ["urlEncoded", encodeURIComponent(secret)],
  ];
}

/** Every key and value position the secret surfaces at, in any encoding. */
function sightings(secret: string, root: unknown): Sighting[] {
  const encodings = encodingsOf(secret);
  const hits: Sighting[] = [];
  const test = (text: string, path: string, position: "key" | "value"): void => {
    const hit = encodings.find(([, needle]) => text.includes(needle));
    if (hit) hits.push({ path, position, encoding: hit[0] });
  };
  const walk = (node: unknown, path: string): void => {
    if (typeof node === "string") {
      test(node, path, "value");
      return;
    }
    if (typeof node !== "object" || node === null) return;
    for (const [key, value] of Object.entries(node)) {
      test(key, `${path}.${key}`, "key");
      walk(value, `${path}.${key}`);
    }
  };
  walk(root, "$");
  return hits;
}

const sha256 = (value: string): string => createHash("sha256").update(value).digest("hex");

interface ContextUse {
  context: "http" | "process" | "mcp" | "database" | "git" | "ssh";
  credential: string;
  policy(): InjectionPolicyInput;
  action(): UseSecretAction;
  /** The success's proof the backend held the credential, or the refusal's code. */
  outcome: { reached(result: UseSecretResponse): void } | { refused: ErrorCode };
}

let vault: TestVault;
let echo: Server;
let echoBase: string;
const echoedAuthorization: string[] = [];

const USES: ContextUse[] = [
  {
    context: "http",
    credential: "m9-http-Q7v2k9w4x1z8n3",
    policy: () => ({ url_allowlist: [`${echoBase}/*`] }),
    action: () => ({
      type: "http",
      method: "GET",
      url: `${echoBase}/echo`,
      injection: { type: "bearer" },
    }),
    outcome: {
      reached: (result) => {
        if (result.type !== "http") throw new Error("expected an http result");
        expect(result.status).toBe(200);
        expect(echoedAuthorization).toContain("Bearer m9-http-Q7v2k9w4x1z8n3");
      },
    },
  },
  {
    context: "process",
    credential: "m9-process-H4j8s2d6f0g5",
    policy: () => ({ command_allowlist: [NODE] }),
    action: () => ({ type: "process", command: NODE, args: ["-e", ECHO_SCRIPT], env_var: "TOKEN" }),
    outcome: {
      reached: (result) => {
        if (result.type !== "process") throw new Error("expected a process result");
        expect(result.exit_code).toBe(0);
        expect(result.stdout).toContain(sha256("m9-process-H4j8s2d6f0g5"));
      },
    },
  },
  {
    context: "mcp",
    credential: "m9-mcp-T3y7u1i5o9p2",
    policy: () => ({ command_allowlist: [NODE] }),
    action: () => ({ type: "mcp", server: "m9-downstream", tool: "digest", arguments: {} }),
    outcome: {
      reached: (result) => {
        if (result.type !== "mcp") throw new Error("expected an mcp result");
        expect(JSON.stringify(result.content)).toContain(sha256("m9-mcp-T3y7u1i5o9p2"));
      },
    },
  },
  {
    context: "database",
    credential: "app_user:m9-database-B6n0m4q8w2e7",
    policy: () => ({ host_allowlist: [`${UNUSED_HOST}:5432`] }),
    action: () => ({
      type: "database",
      engine: "postgresql",
      host: HOST,
      port: 5432,
      database: "app",
      query: "SELECT 1",
    }),
    outcome: { refused: ErrorCode.HOST_NOT_ALLOWED },
  },
  {
    context: "git",
    credential: "x-access-token:m9-git-R5t9y3u7i1o6",
    policy: () => ({ url_allowlist: [`https://${HOST}/*`] }),
    action: () => ({ type: "git", operation: "clone", repository: `https://${HOST}/team/app.git` }),
    outcome: { refused: ErrorCode.COMMAND_NOT_ALLOWED },
  },
  {
    context: "ssh",
    credential: "m9-ssh-K2l6z0x4c8v3",
    policy: () => ({ host_allowlist: [UNUSED_HOST] }),
    action: () => ({ type: "ssh", host: HOST, user: "deploy", command: "uptime" }),
    outcome: { refused: ErrorCode.HOST_NOT_ALLOWED },
  },
];

const handleOf = (use: ContextUse): string => `secret://m9-${use.context}`;

/** The credential and its secret half: a `user:secret` value leaks either way. */
const needlesOf = (use: ContextUse): string[] =>
  use.credential.includes(":")
    ? [use.credential, use.credential.slice(use.credential.indexOf(":") + 1)]
    : [use.credential];

beforeAll(async () => {
  echo = createServer((req, res) => {
    const auth = req.headers.authorization ?? "";
    echoedAuthorization.push(auth);
    const token = auth.replace("Bearer ", "");
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ echoed: token, b64: Buffer.from(token).toString("base64") }));
  });
  await new Promise<void>((resolve, reject) => {
    echo.once("error", reject);
    echo.listen(0, HOST, resolve);
  });
  echoBase = `http://${HOST}:${String((echo.address() as AddressInfo).port)}`;

  vault = createTestVault();
  await vault.engine.initVault(PASSWORD);
  for (const use of USES) {
    await vault.engine.createSecret({
      name: `m9-${use.context}`,
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from(use.credential, "utf8")),
    });
    await vault.engine.setInjectionPolicy(handleOf(use), use.policy(), {
      acknowledge_interpreters: true,
    });
  }
  await vault.engine.setMcpServerConfig(handleOf(USES[2] as ContextUse), {
    server_name: "m9-downstream",
    transport: "stdio",
    protocol: "2025-11-25",
    command: NODE,
    args: ["-e", DOWNSTREAM_SERVER],
    env_var: "TOKEN",
  });
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    const server = echo as Server | undefined;
    if (server === undefined) {
      resolve();
      return;
    }
    server.close((err) => (err ? reject(err) : resolve()));
  });
  if ((vault as TestVault | undefined) !== undefined) await destroyTestVault(vault);
});

describe("the durable audit row (M9) across the six thesis contexts", () => {
  it.each(USES.map((use) => [use.context, use] as const))(
    "%s: one use leaves its secret.use row, carrying the credential at no key or value in any encoding",
    async (_context, use) => {
      let observed: unknown;
      if ("reached" in use.outcome) {
        const result = await vault.engine.useSecret(handleOf(use), use.action());
        use.outcome.reached(result);
        observed = result;
      } else {
        const err = await expectVaultError(
          () => vault.engine.useSecret(handleOf(use), use.action()),
          use.outcome.refused,
        );
        observed = { message: err.message, error: { ...err } };
      }

      const secretId = await vault.engine.resolveSecretId(handleOf(use));
      const rows = vault.engine.queryAudit({ eventType: AuditEventType.SECRET_USE, secretId });
      expect(rows).toHaveLength(1);
      expect(rows[0]?.success).toBe("reached" in use.outcome);
      expect(rows[0]?.detail?.context).toBe(use.context);
      if ("refused" in use.outcome) expect(rows[0]?.detail?.error).toBe(use.outcome.refused);
      for (const needle of needlesOf(use)) {
        expect(sightings(needle, { rows, observed })).toEqual([]);
      }
    },
  );

  it("the whole trail, every event type, carries none of the six credentials", () => {
    const rows = vault.engine.queryAudit({});
    expect(rows.filter((r) => r.event_type === AuditEventType.SECRET_USE)).toHaveLength(6);
    for (const use of USES) {
      for (const needle of needlesOf(use)) {
        expect(sightings(needle, rows), use.context).toEqual([]);
      }
    }
    expect(vault.engine.verifyAuditChain().valid).toBe(true);
  });

  it("the sweep reports a planted credential at a key and in a value, by encoding", () => {
    const secret = (USES[0] as ContextUse).credential;
    const escapable = (USES[3] as ContextUse).credential;
    const planted = {
      detail: {
        [Buffer.from(secret).toString("hex")]: true,
        note: `x${Buffer.from(secret).toString("base64url")}y`,
        url: `https://${HOST}/?t=${secret}`,
        blob: Buffer.from(secret).toString("base64"),
        dump: Buffer.from(secret).toString("hex").toUpperCase(),
        query: `https://${HOST}/?dsn=${encodeURIComponent(escapable)}`,
      },
    };
    expect(sightings(secret, [planted])).toEqual([
      {
        path: `$.0.detail.${Buffer.from(secret).toString("hex")}`,
        position: "key",
        encoding: "hex",
      },
      { path: "$.0.detail.note", position: "value", encoding: "base64url" },
      { path: "$.0.detail.url", position: "value", encoding: "raw" },
      { path: "$.0.detail.blob", position: "value", encoding: "base64" },
      { path: "$.0.detail.dump", position: "value", encoding: "hexUpper" },
    ]);
    expect(sightings(escapable, [planted])).toEqual([
      { path: "$.0.detail.query", position: "value", encoding: "urlEncoded" },
    ]);
  });
});
