import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { createApp } from "@harpoc/rest-api";
import { startMcpHttpServer } from "@harpoc/mcp-server";
import type { McpHttpServer } from "@harpoc/mcp-server";
import { DirectClient, RestClient } from "@harpoc/sdk";
import type { VaultClient } from "@harpoc/sdk";
import { ErrorCode, SecretType, VaultError } from "@harpoc/shared";
import type { HttpAction } from "@harpoc/shared";
import { expectAbsent, silenceAuditLines } from "@harpoc/test-utils";
import { createTestVault, destroyTestVault, grantOn } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { startTestServer } from "./helpers/rest-helpers.js";
import type { TestServer } from "./helpers/rest-helpers.js";
import { CLI_ENTRY, runCommand } from "./helpers/spawn-cli.js";

silenceAuditLines();

/**
 * A use's error text as every interface returns it, against a real engine: one
 * http secret whose value is a word of the allowlist refusal. A recorded error
 * leaves written from its record, the URL as the caller sent it and no marker;
 * an unrecorded one, forced through the engine's http injector, leaves with the
 * value redacted.
 */

const PASSWORD = "use-error-text-interfaces-pw";
const VALUE_WORD = "allowlist";
const NAME = "uet-http";
const HANDLE = `secret://${NAME}`;
const REST_AGENT = "uet-rest-agent";
const MCP_TOOL = "uet-mcp-tool";
const ALLOWED = "https://api.example.com/v1/*";
const OUTSIDE_URL = `https://api.example.com/${VALUE_WORD}`;
const INSIDE_URL = "https://api.example.com/v1/items";
const SEAM_TEXT = `remote said ${VALUE_WORD}`;

type Surface =
  | "REST"
  | "RestClient"
  | "DirectClient"
  | "MCP use_secret"
  | "CLI secret use"
  | "CLI secret use --url";

interface Refusal {
  refused: boolean;
  code: string | undefined;
  text: string;
}

interface Returned {
  /** The REST body, the SDK error's message, the MCP tool text or the CLI's standard error, whole. */
  raw: string;
  refusal(): Refusal;
}

let vault: TestVault;
let app: ReturnType<typeof createApp>;
let rest: TestServer;
let mcpServer: McpHttpServer;
let mcpClient: Client;
let restToken: string;
let tokenFile: string;

function httpAction(url: string): HttpAction {
  return { type: "http", method: "GET", url, injection: { type: "bearer" } };
}

async function viaRest(action: HttpAction): Promise<Returned> {
  const res = await app.request(`/api/v1/secrets/${NAME}/use`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${restToken}`,
      "content-type": "application/json",
      host: "localhost",
    },
    body: JSON.stringify({ action }),
  });
  const raw = await res.text();
  return {
    raw,
    refusal: () => {
      const body = JSON.parse(raw) as { error?: string; message?: string };
      return { refused: res.status !== 200, code: body.error, text: body.message ?? "" };
    },
  };
}

async function viaSdk(client: VaultClient, action: HttpAction): Promise<Returned> {
  let thrown: unknown;
  try {
    await client.useSecret(HANDLE, action);
  } catch (err) {
    thrown = err;
  }
  const raw = thrown instanceof Error ? thrown.message : "";
  return {
    raw,
    refusal: () => ({
      refused: thrown instanceof VaultError,
      code: thrown instanceof VaultError ? thrown.code : undefined,
      text: raw,
    }),
  };
}

async function viaMcp(action: HttpAction): Promise<Returned> {
  const result = (await mcpClient.callTool({
    name: "use_secret",
    arguments: { handle: HANDLE, action },
  })) as { isError?: boolean; content: Array<{ text: string }> };
  const raw = result.content[0]?.text ?? "";
  return { raw, refusal: () => ({ refused: result.isError ?? false, code: undefined, text: raw }) };
}

async function viaCli(leading: string[], action: HttpAction): Promise<Returned> {
  const env = { ...process.env };
  delete env.HARPOC_TOKEN;
  const run = await runCommand(
    process.execPath,
    [
      CLI_ENTRY,
      ...leading,
      "secret",
      "use",
      HANDLE,
      "--action",
      "http",
      "--url",
      action.url,
      "--json",
    ],
    { env },
  );
  return {
    raw: run.stderr,
    refusal: () => {
      const body = JSON.parse(run.stderr) as { error?: string; message?: string };
      return { refused: run.code !== 0, code: body.error, text: body.message ?? "" };
    },
  };
}

const SURFACES: Record<Surface, (action: HttpAction) => Promise<Returned>> = {
  REST: viaRest,
  RestClient: (action) =>
    viaSdk(new RestClient({ baseUrl: rest.baseUrl, token: restToken }), action),
  DirectClient: (action) => viaSdk(new DirectClient(vault.engine), action),
  "MCP use_secret": viaMcp,
  "CLI secret use": (action) => viaCli(["--vault-dir", vault.tmpDir], action),
  "CLI secret use --url": (action) =>
    viaCli(["--url", rest.baseUrl, "--token-file", tokenFile], action),
};

/** The surfaces whose engine is this process's, where a seam of the engine can be replaced. */
const IN_PROCESS: Surface[] = [
  "REST",
  "RestClient",
  "DirectClient",
  "MCP use_secret",
  "CLI secret use --url",
];

function refusalOn(surface: Surface, code: ErrorCode, text: string): Refusal {
  return { refused: true, code: surface === "MCP use_secret" ? undefined : code, text };
}

beforeAll(async () => {
  vault = createTestVault();
  await vault.engine.initVault(PASSWORD);
  await vault.engine.createSecret({
    name: NAME,
    type: SecretType.API_KEY,
    value: new Uint8Array(Buffer.from(VALUE_WORD, "utf8")),
  });
  await vault.engine.setInjectionPolicy(HANDLE, { url_allowlist: [ALLOWED] });
  await grantOn(vault.engine, HANDLE, REST_AGENT, ["use"]);
  await grantOn(vault.engine, HANDLE, MCP_TOOL, ["use"], "tool");

  app = createApp(vault.engine);
  rest = startTestServer(vault.engine);
  restToken = vault.engine.createToken(REST_AGENT, ["use"]);
  tokenFile = join(vault.tmpDir, "rest-token");
  writeFileSync(tokenFile, `${restToken}\n`, { encoding: "utf8", mode: 0o600 });
  mcpServer = await startMcpHttpServer({ engine: vault.engine, port: 0 });
  const mcpToken = vault.engine.createToken(MCP_TOOL, ["use"], 3600_000, {
    principalType: "tool",
  });
  mcpClient = new Client({ name: "uet-client", version: "1.0.0" });
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
  await (rest as TestServer | undefined)?.close();
  if ((vault as TestVault | undefined) !== undefined) await destroyTestVault(vault);
});

describe("a recorded error leaves written from its record, the caller's field as sent", () => {
  for (const surface of Object.keys(SURFACES) as Surface[]) {
    it(`${surface}: the allowlist refusal quotes the URL as sent, with no marker`, async () => {
      const returned = await SURFACES[surface](httpAction(OUTSIDE_URL));

      expect(returned.refusal()).toEqual(
        refusalOn(
          surface,
          ErrorCode.URL_NOT_ALLOWED,
          `URL not in secret allowlist: ${OUTSIDE_URL}`,
        ),
      );
    });
  }
});

describe("an unrecorded error forced through the engine's http injector is redacted whole", () => {
  let original: unknown;

  beforeAll(() => {
    const internals = vault.engine as unknown as { httpInjector: unknown };
    original = internals.httpInjector;
    internals.httpInjector = {
      executeWithSecret: () => Promise.reject(new VaultError(ErrorCode.TLS_ERROR, SEAM_TEXT)),
    };
  });

  afterAll(() => {
    (vault.engine as unknown as { httpInjector: unknown }).httpInjector = original;
  });

  for (const surface of IN_PROCESS) {
    it(`${surface}: the value is absent and a marker stands`, async () => {
      const returned = await SURFACES[surface](httpAction(INSIDE_URL));

      expectAbsent(returned.raw, VALUE_WORD);
      expect(returned.refusal()).toEqual(
        refusalOn(surface, ErrorCode.TLS_ERROR, "remote said [REDACTED]"),
      );
    });
  }
});
