import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { createApp } from "@harpoc/rest-api";
import { startMcpHttpServer } from "@harpoc/mcp-server";
import type { McpHttpServer } from "@harpoc/mcp-server";
import { AuditEventType, ErrorCode, SecretType } from "@harpoc/shared";
import type { InjectionPolicyInput, UseSecretAction } from "@harpoc/shared";
import {
  createTestVault,
  destroyTestVault,
  grantOn,
  registerAgents,
} from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { FIXTURE_CA_PEM, startFakeSmtp } from "./helpers/fake-smtp-server.js";
import type { FakeSmtp } from "./helpers/fake-smtp-server.js";
import { startFakeImap } from "./helpers/fake-imap-server.js";
import type { FakeImap } from "./helpers/fake-imap-server.js";
import { startFakeWsServer } from "./helpers/fake-ws-server.js";
import type { FakeWsServer } from "./helpers/fake-ws-server.js";
import { silenceAuditLines } from "@harpoc/test-utils";

silenceAuditLines();

/**
 * The v1.3 contexts' `use_secret` through the gated interfaces against a real
 * engine (test-review-2026-10-09 I13, M-P2-26): one vault, the in-process REST
 * app and the MCP server over Streamable HTTP, a scoped token per interface and
 * one secret per cell, so every `secret.use` row is attributable to its cell.
 * smtp, imap and websocket run end to end against the integration fakes on
 * 127.0.0.1 (a sent message, a searched mailbox, an exchanged frame); sftp and
 * docker_registry have no backend in the gate, so their cells are the audited
 * allowlist refusal through the interface — the real engine's refusal path, the
 * credit database, git and ssh carry (TU-11); the positive round trips stay the
 * harness's. Every cell asserts the interface's rendering, the credential absent
 * from it, and the row with `interface` set and the action's fields whole.
 */

const PASSWORD = "use-secret-interfaces-pw";
const REST_AGENT = "uif-rest-agent";
const MCP_TOOL = "uif-mcp-tool";
const HOST = "127.0.0.1";
const UNUSED_HOST = "192.0.2.1";

type Via = "rest" | "mcp";

const VIAS: Via[] = ["rest", "mcp"];

const INTERFACE: Record<Via, string> = { rest: "rest", mcp: "mcp-http" };

interface Rendered {
  refused: boolean;
  /** The REST body or the MCP tool text, as the caller receives it. */
  text: string;
  status?: number;
}

type Outcome = { result: Record<string, unknown> } | { code: ErrorCode; message: string };

interface Cell {
  context: "smtp" | "imap" | "websocket" | "sftp" | "docker_registry";
  title: string;
  user?: string;
  mail?: boolean;
  policy(): InjectionPolicyInput;
  action(via: Via): UseSecretAction;
  /** The decrypted `secret.use` detail the cell's one row carries, `interface` aside. */
  detail(via: Via): Record<string, unknown>;
  /** A round trip's result as the engine returns it, or the refusal's code and message. */
  outcome: Outcome;
  /** What the fake server observed — absent for the two refusal cells. */
  observed?(via: Via, credential: string): void;
}

let vault: TestVault;
let app: ReturnType<typeof createApp>;
let mcpServer: McpHttpServer;
let mcpClient: Client;
let restToken: string;
let smtp: FakeSmtp;
let imap: FakeImap;
let ws: FakeWsServer;

function secretName(cell: Cell, via: Via): string {
  return `uif-${cell.context.replace("_", "-")}-${via}`;
}

function credentialOf(cell: Cell, via: Via): string {
  const password = `${secretName(cell, via)}-pw-7d41c9`;
  return cell.user ? `${cell.user}:${password}` : password;
}

const CELLS: Cell[] = [
  {
    context: "smtp",
    title: "the message reaches the fake, sent with the vault's credential",
    user: "uif-smtp-user",
    mail: true,
    policy: () => ({ host_allowlist: [`${HOST}:${String(smtp.port)}`] }),
    action: (via) => ({
      type: "smtp",
      host: HOST,
      port: smtp.port,
      security: "tls",
      from: "agent@harpoc.local",
      to: ["ops@example.com"],
      subject: `uif report via ${via}`,
      text: "nightly",
    }),
    detail: () => ({
      context: "smtp",
      host: HOST,
      from: "agent@harpoc.local",
      recipients: ["ops@example.com"],
      attachment_paths: [],
      attachment_total_bytes: 0,
    }),
    outcome: { result: { type: "smtp", accepted: 1, message_id: expect.any(String) as unknown } },
    observed: (via, credential) => {
      const [user, password] = credential.split(":") as [string, string];
      const wire = smtp.wire().postTls.toString("latin1");
      const plain = Buffer.from(`\0${user}\0${password}`, "utf8").toString("base64");
      expect(wire).toContain(`AUTH PLAIN ${plain}\r\n`);
      expect(wire).toContain(`Subject: uif report via ${via}\r\n`);
    },
  },
  {
    context: "imap",
    title: "the mailbox is searched at the fake, logged in with the vault's credential",
    user: "uif-imap-user",
    mail: true,
    policy: () => ({ host_allowlist: [`${HOST}:${String(imap.port)}`] }),
    action: (via) => ({
      type: "imap",
      host: HOST,
      port: imap.port,
      mailbox: "INBOX",
      operation: { kind: "search", subject: `uif-${via}` },
    }),
    detail: () => ({
      context: "imap",
      host: HOST,
      mailbox: "INBOX",
      operation: "search",
      uid_count: 2,
    }),
    outcome: { result: { type: "imap", operation: "search", uids: [301, 302] } },
    observed: (via, credential) => {
      const password = credential.split(":")[1] as string;
      const commands = imap.commands();
      expect(commands.find((c) => c.name === "LOGIN")?.text).toContain(password);
      expect(commands.find((c) => c.name === "UID SEARCH")?.text).toContain(`uif-${via}`);
    },
  },
  {
    context: "websocket",
    title: "the frame is exchanged with the fake over a handshake carrying the credential",
    policy: () => ({ url_allowlist: [`ws://${HOST}:${String(ws.port)}/*`] }),
    action: (via) => ({
      type: "websocket",
      url: `ws://${HOST}:${String(ws.port)}/feed-${via}`,
      injection: { type: "bearer" },
      message: `ping via ${via}`,
      collect: { max_messages: 1, window_ms: 5000 },
    }),
    detail: (via) => ({
      context: "websocket",
      url: `ws://${HOST}:${String(ws.port)}/feed-${via}`,
      sent: 1,
      received: 1,
    }),
    outcome: { result: { type: "websocket", messages: ["pong"], close_code: 1000 } },
    observed: (via, credential) => {
      const request = ws.requests().find((r) => r.url === `/feed-${via}`);
      expect(request?.headers.authorization).toBe(`Bearer ${credential}`);
      const frames = ws.clientFrames().map((f) => f.payload.toString("utf8"));
      expect(frames).toContain(`ping via ${via}`);
    },
  },
  {
    context: "sftp",
    title: "the host allowlist refuses the target, audited, before any spawn",
    policy: () => ({ host_allowlist: [UNUSED_HOST] }),
    action: (via) => ({
      type: "sftp",
      host: HOST,
      user: "deploy",
      operation: "download",
      remote_path: `/srv/reports/${via}.csv`,
      local_path: `/var/harpoc/${via}.csv`,
    }),
    detail: (via) => ({
      context: "sftp",
      host: HOST,
      operation: "download",
      port: null,
      remote_path: `/srv/reports/${via}.csv`,
      local_path: `/var/harpoc/${via}.csv`,
      network_isolation: false,
      fs_isolation: false,
      error: ErrorCode.HOST_NOT_ALLOWED,
    }),
    outcome: { code: ErrorCode.HOST_NOT_ALLOWED, message: `Host not in secret allowlist: ${HOST}` },
  },
  {
    context: "docker_registry",
    title: "the registry allowlist refuses the image's registry, audited, before any spawn",
    user: "uif-docker-user",
    policy: () => ({ host_allowlist: [`${UNUSED_HOST}:5000`] }),
    action: (via) => ({
      type: "docker_registry",
      operation: "pull",
      image: `${HOST}:5000/team/app:${via}`,
      timeout_ms: 300_000,
    }),
    detail: (via) => ({
      context: "docker_registry",
      registry: `${HOST}:5000`,
      image: `${HOST}:5000/team/app:${via}`,
      operation: "pull",
      error: ErrorCode.HOST_NOT_ALLOWED,
    }),
    outcome: {
      code: ErrorCode.HOST_NOT_ALLOWED,
      message: `Host not in secret allowlist: ${HOST}:5000`,
    },
  },
];

async function viaRest(name: string, action: UseSecretAction): Promise<Rendered> {
  const res = await app.request(`/api/v1/secrets/${name}/use`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${restToken}`,
      "content-type": "application/json",
      host: "localhost",
    },
    body: JSON.stringify({ action }),
  });
  return { refused: res.status !== 200, text: await res.text(), status: res.status };
}

async function viaMcp(name: string, action: UseSecretAction): Promise<Rendered> {
  const result = (await mcpClient.callTool({
    name: "use_secret",
    arguments: { handle: `secret://${name}`, action },
  })) as { isError?: boolean; content: Array<{ text: string }> };
  return { refused: result.isError ?? false, text: result.content[0]?.text ?? "" };
}

beforeAll(async () => {
  smtp = await startFakeSmtp({
    starttls: false,
    implicitTls: true,
    authMechanisms: ["PLAIN"],
    auth: "ok",
    rcpt: "ok",
  });
  imap = await startFakeImap({ auth: "ok", searchResults: [301, 302] });
  ws = await startFakeWsServer({ messages: ["pong"] });

  vault = createTestVault();
  await vault.engine.initVault(PASSWORD);
  registerAgents(vault.engine, REST_AGENT);
  for (const cell of CELLS) {
    for (const via of VIAS) {
      const handle = `secret://${secretName(cell, via)}`;
      await vault.engine.createSecret({
        name: secretName(cell, via),
        type: SecretType.API_KEY,
        value: new Uint8Array(Buffer.from(credentialOf(cell, via), "utf8")),
      });
      await vault.engine.setInjectionPolicy(handle, cell.policy());
      if (cell.mail) {
        await vault.engine.setConnectionConfig(handle, { mail: { tls: { ca: FIXTURE_CA_PEM } } });
      }
      if (via === "rest") await grantOn(vault.engine, handle, REST_AGENT, ["use"]);
      else await grantOn(vault.engine, handle, MCP_TOOL, ["use"], "tool");
    }
  }

  app = createApp(vault.engine);
  restToken = vault.engine.createToken(REST_AGENT, ["use"]);
  mcpServer = await startMcpHttpServer({ engine: vault.engine, port: 0 });
  const mcpToken = vault.engine.createToken(MCP_TOOL, ["use"], 3600_000, {
    principalType: "tool",
  });
  mcpClient = new Client({ name: "uif-client", version: "1.0.0" });
  await mcpClient.connect(
    new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${String(mcpServer.port)}${mcpServer.endpoint}`),
      { requestInit: { headers: { Authorization: `Bearer ${mcpToken}` } } },
    ),
  );
});

afterAll(async () => {
  await (mcpClient as Client | undefined)?.close();
  await (mcpServer as McpHttpServer | undefined)?.close();
  if ((vault as TestVault | undefined) !== undefined) await destroyTestVault(vault);
  await (smtp as FakeSmtp | undefined)?.close();
  await (imap as FakeImap | undefined)?.close();
  await (ws as FakeWsServer | undefined)?.close();
});

describe("use_secret through REST and MCP Streamable HTTP — the v1.3 contexts on a real engine", () => {
  for (const cell of CELLS) {
    for (const via of VIAS) {
      it(`${cell.context} via ${via}: ${cell.title}`, async () => {
        const name = secretName(cell, via);
        const credential = credentialOf(cell, via);

        const action = cell.action(via);
        const rendered = via === "rest" ? await viaRest(name, action) : await viaMcp(name, action);

        const outcome = cell.outcome;
        if ("result" in outcome) {
          expect(rendered.refused, rendered.text).toBe(false);
          const payload = JSON.parse(rendered.text) as { data?: unknown };
          expect(via === "rest" ? payload.data : payload).toEqual(outcome.result);
          cell.observed?.(via, credential);
        } else if (via === "rest") {
          expect(rendered.status).toBe(403);
          expect(JSON.parse(rendered.text)).toEqual({
            error: outcome.code,
            message: outcome.message,
          });
        } else {
          expect(rendered.refused).toBe(true);
          expect(rendered.text).toBe(outcome.message);
        }
        expect(rendered.text).not.toContain(credential.split(":").at(-1) as string);

        const secretId = await vault.engine.resolveSecretId(`secret://${name}`);
        const rows = vault.engine.queryAudit({ eventType: AuditEventType.SECRET_USE, secretId });
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({
          success: "result" in outcome,
          principal_type: via === "rest" ? "agent" : "tool",
          principal_id: via === "rest" ? REST_AGENT : MCP_TOOL,
          session_id: expect.any(String) as unknown,
        });
        expect(rows[0]?.detail).toEqual({ ...cell.detail(via), interface: INTERFACE[via] });
      });
    }
  }

  it("the audit chain verifies after the ten cells", () => {
    expect(vault.engine.queryAudit({ eventType: AuditEventType.SECRET_USE })).toHaveLength(10);
    expect(vault.engine.verifyAuditChain().valid).toBe(true);
  });
});
