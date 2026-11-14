import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createMcpServer } from "@harpoc/mcp-server";
import { connectInMemoryClient } from "@harpoc/test-utils";
import type { InMemoryMcpClient } from "@harpoc/test-utils";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { CLI_ENTRY } from "./helpers/spawn-cli.js";

const PROGRAM_URL = pathToFileURL(join(dirname(CLI_ENTRY), "program.js")).href;

const HINT_LEAD = "Secret created. Set the value with: harpoc ";

interface CliCommand {
  readonly commands: readonly CliCommand[];
  name(): string;
  exitOverride(): CliCommand;
  configureOutput(output: { writeOut(str: string): void; writeErr(str: string): void }): CliCommand;
  action(fn: (...args: unknown[]) => void): CliCommand;
  parseAsync(argv: readonly string[], options: { from: "user" }): Promise<CliCommand>;
}

interface SetRecord {
  secretName: unknown;
  type: unknown;
  project: unknown;
  fromFile: unknown;
}

/** Throw instead of exiting, and write nothing, on every command of the tree. */
function quiet(command: CliCommand): void {
  command.exitOverride();
  command.configureOutput({ writeOut: () => undefined, writeErr: () => undefined });
  for (const sub of command.commands) quiet(sub);
}

/** Parse `argv` with the built `harpoc` tree, `secret set`'s action replaced by a recorder. */
async function parseSecretSet(argv: string[]): Promise<SetRecord | undefined> {
  const { buildProgram } = (await import(PROGRAM_URL)) as { buildProgram: () => CliCommand };
  const program = buildProgram();
  quiet(program);
  const secretSet = program.commands
    .find((command) => command.name() === "secret")
    ?.commands.find((command) => command.name() === "set");
  expect(secretSet).toBeDefined();
  let recorded: SetRecord | undefined;
  (secretSet as CliCommand).action((secretName, options) => {
    const parsed = options as { type?: string; project?: string; fromFile?: string };
    recorded = {
      secretName,
      type: parsed.type,
      project: parsed.project,
      fromFile: parsed.fromFile,
    };
  });
  await program.parseAsync(argv, { from: "user" });
  return recorded;
}

interface ConnectOptions {
  provider?: string;
  clientId?: string;
  device?: boolean;
  clientCredentials?: boolean;
  scopes?: string;
  authMethod?: string;
  authEndpoint?: string;
  tokenEndpoint?: string;
  deviceEndpoint?: string;
  project?: string;
}

/** Parse `argv` with the built `harpoc` tree, `oauth connect`'s action replaced by a recorder, as the flow it starts. */
async function parseOAuthConnect(argv: string[]): Promise<Record<string, unknown> | undefined> {
  const { buildProgram } = (await import(PROGRAM_URL)) as { buildProgram: () => CliCommand };
  const program = buildProgram();
  quiet(program);
  const connect = program.commands
    .find((command) => command.name() === "oauth")
    ?.commands.find((command) => command.name() === "connect");
  expect(connect).toBeDefined();
  let recorded: Record<string, unknown> | undefined;
  (connect as CliCommand).action((name, options) => {
    const parsed = options as ConnectOptions;
    recorded = {
      name,
      provider: parsed.provider,
      grant_type: parsed.clientCredentials
        ? "client_credentials"
        : parsed.device
          ? "device_code"
          : "authorization_code",
      client_id: parsed.clientId,
      scopes: parsed.scopes?.split(","),
      token_endpoint_auth_method: parsed.authMethod,
      auth_endpoint: parsed.authEndpoint,
      token_endpoint: parsed.tokenEndpoint,
      device_authorization_endpoint: parsed.deviceEndpoint,
      project: parsed.project,
    };
  });
  await program.parseAsync(argv, { from: "user" });
  return recorded;
}

/** The hint's words after `harpoc`, each quoted word handed on as a shell hands it on. */
function hintArgv(message: string): string[] {
  const at = message.indexOf("with: harpoc ");
  expect(at).toBeGreaterThan(-1);
  return message
    .slice(at + "with: harpoc ".length)
    .split(" ")
    .map((token) =>
      token.length >= 2 && token.startsWith('"') && token.endsWith('"')
        ? token.slice(1, -1)
        : token,
    );
}

describe("create_secret's pending hint parses as the create it answers (C-5)", () => {
  let vault: TestVault;
  let session: InMemoryMcpClient | undefined;

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault("m2-hint-argv-pw");
    const launchToken = vault.engine.createToken("m2-user", ["create"], 3_600_000, {
      principalType: "user",
    });
    session = await connectInMemoryClient(createMcpServer({ engine: vault.engine, launchToken }));
  });

  afterAll(async () => {
    try {
      await session?.close();
    } finally {
      await destroyTestVault(vault);
    }
  });

  it.each([
    { label: "-x, an unscoped api_key create", args: { name: "-x", type: "api_key" } },
    { label: "--help, an unscoped api_key create", args: { name: "--help", type: "api_key" } },
    {
      label: "-p, a create in project proj",
      args: { name: "-p", type: "api_key", project: "proj" },
    },
    {
      label: "--from-file, a certificate-typed create",
      args: { name: "--from-file", type: "certificate" },
    },
  ])(
    "$label: harpoc secret set parses the hint as the name, type and project created",
    async ({ args }) => {
      const result = await (session as InMemoryMcpClient).callTool("create_secret", args);
      const payload = JSON.parse(result.content[0]?.text ?? "") as {
        status: string;
        message: string;
      };
      expect(payload.status).toBe("pending");
      expect(payload.message.startsWith(HINT_LEAD)).toBe(true);

      // A shell hands the quoted "--" on as --; PowerShell would drop a bare --.
      const argv = payload.message
        .slice(HINT_LEAD.length)
        .split(" ")
        .map((token) => (token === '"--"' ? "--" : token));
      const recorded = await parseSecretSet(argv);
      expect(recorded).toEqual({
        secretName: args.name,
        type: args.type,
        project: "project" in args ? args.project : undefined,
        fromFile: undefined,
      });
    },
  );

  it.each([
    { label: "--, an unscoped api_key create", args: { name: "--", type: "api_key" } },
    {
      label: "dash-project, a create in project --",
      args: { name: "dash-project", type: "api_key", project: "--" },
    },
    {
      label: "--, a certificate-typed create in project --",
      args: { name: "--", type: "certificate", project: "--" },
    },
  ])(
    "$label: harpoc secret set parses the quoted -- as the name and project created (C-14)",
    async ({ args }) => {
      const result = await (session as InMemoryMcpClient).callTool("create_secret", args);
      const payload = JSON.parse(result.content[0]?.text ?? "") as {
        status: string;
        message: string;
      };
      expect(payload.status).toBe("pending");
      expect(payload.message.startsWith(HINT_LEAD)).toBe(true);
      const recorded = await parseSecretSet(hintArgv(payload.message));
      expect(recorded).toEqual({
        secretName: args.name,
        type: args.type,
        project: "project" in args ? args.project : undefined,
        fromFile: undefined,
      });
    },
  );
});

describe("start_oauth_flow's hints parse as the flow they answer (C-14)", () => {
  const AUTH = "https://127.0.0.1:8443/authorize";
  const TOKEN = "https://127.0.0.1:8443/token";
  const DEVICE = "https://127.0.0.1:8443/device";

  let vault: TestVault;
  let session: InMemoryMcpClient | undefined;

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault("m1-hint-argv-pw");
    const launchToken = vault.engine.createToken("m1-user", ["create"], 3_600_000, {
      principalType: "user",
    });
    session = await connectInMemoryClient(createMcpServer({ engine: vault.engine, launchToken }));
  });

  afterAll(async () => {
    try {
      await session?.close();
    } finally {
      await destroyTestVault(vault);
    }
  });

  it.each(
    ["authorization_code", "client_credentials"].flatMap((grant) =>
      [
        { label: "no new field", flow: { name: "gh-plain" } },
        { label: "project proj", flow: { name: "gh-proj", project: "proj" } },
        { label: "project proj and the name -x", flow: { name: "-x", project: "proj" } },
        { label: "the single scope repo", flow: { name: "gh-scope", scopes: ["repo"] } },
        {
          label: "scopes repo and read:org",
          flow: { name: "gh-scopes", scopes: ["repo", "read:org"] },
        },
        {
          label: "client_secret_basic",
          flow: { name: "gh-basic", token_endpoint_auth_method: "client_secret_basic" },
        },
        {
          label: "a custom provider's three endpoints",
          flow: {
            name: "gh-custom",
            provider: "custom",
            auth_endpoint: AUTH,
            token_endpoint: TOKEN,
            device_authorization_endpoint: DEVICE,
          },
        },
        { label: "the name --", flow: { name: "--" } },
        { label: "the project --", flow: { name: "gh-dash-project", project: "--" } },
        {
          label: "every option and the name -y",
          flow: {
            name: "-y",
            provider: "custom",
            scopes: ["repo", "read:org"],
            token_endpoint_auth_method: "client_secret_basic",
            auth_endpoint: AUTH,
            token_endpoint: TOKEN,
            device_authorization_endpoint: DEVICE,
            project: "proj-all",
          },
        },
      ].map(({ label, flow }) => ({
        grant,
        label,
        args: { provider: "github", grant_type: grant, client_id: "cid", ...flow },
      })),
    ),
  )(
    "$grant, $label: harpoc oauth connect parses the hint as the flow started",
    async ({ args }) => {
      const result = await (session as InMemoryMcpClient).callTool("start_oauth_flow", args);
      expect(result.isError ?? false).toBe(false);
      const payload = JSON.parse(result.content[0]?.text ?? "") as { message: string };
      expect(await parseOAuthConnect(hintArgv(payload.message))).toEqual(args);
    },
  );
});
