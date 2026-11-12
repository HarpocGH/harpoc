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
});
