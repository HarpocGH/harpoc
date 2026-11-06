import { describe, expect, it } from "vitest";
import { Command } from "commander";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { RestClient } from "@harpoc/sdk";
import {
  commandPath,
  extractRestModeOptions,
  parseRestUrl,
  restModeUnsupported,
  runRestMode,
} from "./rest-mode.js";
import { expectVaultError } from "@harpoc/test-utils";

function root(): Command {
  const program = new Command();
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  program.option("--vault-dir <path>");
  return program;
}

describe("extractRestModeOptions", () => {
  // Model A's argument lists: none starts with --url / --token-file, so each comes back as it is.
  it.each([
    [["secret", "use", "secret://k", "--url", "https://api.example.com/v1"]],
    [["server", "start", "--mcp", "--token-file", "/run/launch.jwt"]],
    [["--vault-dir", "/v", "secret", "list"]],
    [["--vault-dir", "--url", "x", "secret", "list"]],
    [["--help"]],
    [[]],
  ])("leaves %j unchanged and stores nothing", (args) => {
    const program = root();
    expect(extractRestModeOptions(program, args)).toEqual(args);
    expect(program.opts()).toEqual({});
  });

  it("takes a leading --url / --token-file pair off, in either order, and keeps --vault-dir", () => {
    const program = root();
    const args = ["--token-file", "/t", "--vault-dir", "/v", "--url", "http://127.0.0.1:3000"];
    expect(extractRestModeOptions(program, [...args, "secret", "list", "--json"])).toEqual([
      "--vault-dir",
      "/v",
      "secret",
      "list",
      "--json",
    ]);
    expect(program.opts()).toEqual({ restTokenFile: "/t", restUrl: "http://127.0.0.1:3000" });
    expect(program.getOptionValueSource("restUrl")).toBe("cli");
  });

  it("reads the = forms and stops at the command path", () => {
    const program = root();
    expect(
      extractRestModeOptions(program, [
        "--url=https://vault.example",
        "--token-file=/t",
        "lock",
        "--url",
        "x",
      ]),
    ).toEqual(["lock", "--url", "x"]);
    expect(program.opts()).toEqual({ restUrl: "https://vault.example", restTokenFile: "/t" });
  });

  it("refuses a --token-file without its value as Commander does", () => {
    expect(() => extractRestModeOptions(root(), ["--token-file"])).toThrow(
      "error: option '--token-file <path>' argument missing",
    );
  });
});

describe("parseRestUrl", () => {
  it.each([
    ["https://vault.example.com", "https://vault.example.com/"],
    ["http://127.0.0.1:3000", "http://127.0.0.1:3000/"],
    ["http://localhost:3000/", "http://localhost:3000/"],
    ["http://[::1]:3000", "http://[::1]:3000/"],
    ["https://vault.example.com/harpoc/", "https://vault.example.com/harpoc/"],
  ])("accepts %s", (value, href) => {
    expect(parseRestUrl(value).href).toBe(href);
  });

  it.each([
    ["-x", "--url: a flag, not a URL"],
    ["localhost:3000", "--url must use HTTPS (plain HTTP is allowed for loopback only)"],
    ["127.0.0.1:3000", "--url: not a URL (give the server's base URL, e.g. http://127.0.0.1:3000)"],
    ["", "--url: not a URL (give the server's base URL, e.g. http://127.0.0.1:3000)"],
    ["vault", "--url: not a URL (give the server's base URL, e.g. http://127.0.0.1:3000)"],
    ["http://vault.example.com", "--url must use HTTPS (plain HTTP is allowed for loopback only)"],
    ["ftp://127.0.0.1", "--url must use HTTPS (plain HTTP is allowed for loopback only)"],
    [
      "https://admin:hunter2@vault.example.com",
      "--url: credentials in the URL are refused; the bearer is read from --token-file",
    ],
    [
      "https://vault.example.com/?token=x",
      "--url: a query or fragment is refused; give the server's base URL",
    ],
    [
      "https://vault.example.com/#frag",
      "--url: a query or fragment is refused; give the server's base URL",
    ],
  ])("refuses %j INVALID_INPUT without naming the value", async (value, message) => {
    const err = await expectVaultError(() => parseRestUrl(value), ErrorCode.INVALID_INPUT);
    expect(err.message).toBe(message);
  });
});

describe("commandPath and restModeUnsupported", () => {
  it("names the command below the root", () => {
    const program = root();
    const list = program.command("secret").command("list");
    expect(commandPath(list)).toBe("secret list");
    expect(commandPath(program)).toBe("");
  });

  it("names the command and where it runs, nothing else", () => {
    const err = restModeUnsupported("auth token");
    expect(err).toBeInstanceOf(VaultError);
    expect(err.code).toBe(ErrorCode.REST_MODE_UNSUPPORTED);
    expect(err.message).toBe("auth token has no REST mode; run it on the vault host");
  });
});

describe("runRestMode", () => {
  const mode = { client: {} as RestClient, origin: "http://127.0.0.1:1" };

  it("maps fetch's bare failure to CONNECTION_REFUSED naming the origin", async () => {
    const err = await expectVaultError(
      () =>
        runRestMode(mode, async () => {
          throw new TypeError("fetch failed");
        }),
      ErrorCode.CONNECTION_REFUSED,
    );
    expect(err.message).toBe("Cannot reach the harpoc server at http://127.0.0.1:1");
  });

  it("rethrows every other failure as it is", async () => {
    const refusal = VaultError.accessDenied("Token lacks permission: read");
    await expect(
      runRestMode(mode, async () => {
        throw refusal;
      }),
    ).rejects.toBe(refusal);
  });
});
