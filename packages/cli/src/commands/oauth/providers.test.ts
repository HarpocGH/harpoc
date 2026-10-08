import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { registerOAuthProvidersCommand } from "./providers.js";
import { buildCli, spyCli, type CliSpies } from "../../__fixtures__/cli-harness.js";

const run = buildCli(
  (program) => registerOAuthProvidersCommand(program.command("oauth").description("OAuth")),
  ["oauth"],
);

describe("oauth providers", () => {
  let spies: CliSpies;

  beforeEach(() => {
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
  });

  it("default output lists all four presets and github's auth endpoint", async () => {
    await run(["providers"]);

    const output = spies.logSpy.mock.calls.map((call) => String(call[0])).join("\n");
    expect(output).toContain("github");
    expect(output).toContain("google");
    expect(output).toContain("microsoft");
    expect(output).toContain("slack");
    expect(output).toContain("https://github.com/login/oauth/authorize");
  });

  it("human output closes with the custom-provider reminder", async () => {
    await run(["providers"]);

    const lastLogged = String(spies.logSpy.mock.calls.at(-1)?.[0]);
    expect(lastLogged).toContain('Provider "custom" is also accepted');
    expect(lastLogged).toContain("--auth-endpoint");
  });

  it("--json prints { providers: [...] } with the full field set for all four presets", async () => {
    await run(["providers", "--json"]);

    const printed = JSON.parse(spies.logSpy.mock.calls[0]?.[0] as string) as {
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
