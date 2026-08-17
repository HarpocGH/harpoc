import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { registerOAuthProvidersCommand } from "./providers.js";

function buildProgram(): Command {
  const program = new Command();
  program.option("--vault-dir <path>", "Path to vault directory");
  const oauth = program.command("oauth").description("OAuth");
  registerOAuthProvidersCommand(oauth);
  return program;
}

async function run(args: string[]): Promise<void> {
  const program = buildProgram();
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  await program.parseAsync(["node", "harpoc", "oauth", ...args]);
}

describe("oauth providers", () => {
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  it("default output lists all four presets and github's auth endpoint", async () => {
    await run(["providers"]);

    const output = logSpy.mock.calls.map((call) => String(call[0])).join("\n");
    expect(output).toContain("github");
    expect(output).toContain("google");
    expect(output).toContain("microsoft");
    expect(output).toContain("slack");
    expect(output).toContain("https://github.com/login/oauth/authorize");
  });

  it("--json prints { providers: [...] } with the full field set for all four presets", async () => {
    await run(["providers", "--json"]);

    const printed = JSON.parse(logSpy.mock.calls[0]?.[0] as string) as {
      providers: Record<string, unknown>[];
    };

    expect(printed.providers).toHaveLength(4);
    for (const provider of printed.providers) {
      expect(Object.keys(provider).sort()).toEqual(
        [
          "auth_endpoint",
          "default_scopes",
          "device_authorization_endpoint",
          "provider",
          "scopes_separator",
          "token_endpoint",
          "token_endpoint_auth_method",
        ].sort(),
      );
    }

    const github = printed.providers.find((p) => p.provider === "github");
    expect(github?.auth_endpoint).toBe("https://github.com/login/oauth/authorize");
    expect(github?.token_endpoint).toBe("https://github.com/login/oauth/access_token");
  });

  it("is static-data-only: the module source does not import vault-loader", () => {
    const sourcePath = fileURLToPath(new URL("./providers.ts", import.meta.url));
    const source = readFileSync(sourcePath, "utf-8");
    expect(source).not.toContain("vault-loader");
  });
});
