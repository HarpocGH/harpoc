import { createPrivateKey } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import { VaultError } from "@harpoc/shared";
import type { VaultApiToken } from "@harpoc/shared";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    importCertificate: vi.fn(),
    verifyToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { Command } from "commander";
import { loadUnlockedEngine } from "../../utils/vault-loader.js";
import { registerCertCsrCommand } from "./csr.js";

function token(overrides: Partial<VaultApiToken> = {}): VaultApiToken {
  return {
    sub: "agent-1",
    vault_id: "vault-1",
    scope: ["read"],
    iat: 0,
    exp: 2_000_000_000,
    jti: "jti-1",
    principal_type: "agent",
    ...overrides,
  };
}

let exitSpy: MockInstance;
let errorSpy: ReturnType<typeof vi.spyOn>;
let logSpy: ReturnType<typeof vi.spyOn>;
let stdoutSpy: MockInstance;
const savedEnvToken = process.env.HARPOC_TOKEN;

async function run(args: string[]): Promise<void> {
  const program = new Command();
  // exitOverride must precede .command(): commander copies the exit callback
  // into a child by value at creation time, so setting it afterwards would
  // leave the subcommand's own parse errors exiting the test process for real.
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  program.option("--vault-dir <path>", "Path to vault directory");
  const cert = program.command("cert").description("Manage certificate secrets");
  registerCertCsrCommand(cert);
  await program.parseAsync(["node", "harpoc", "cert", ...args]);
}

/** Everything process.stdout.write received, concatenated in call order. */
function stdoutText(): string {
  return stdoutSpy.mock.calls.map((call) => call[0] as string).join("");
}

beforeEach(() => {
  vi.clearAllMocks();
  delete process.env.HARPOC_TOKEN;

  vi.mocked(loadUnlockedEngine).mockResolvedValue(mockEngine as never);
  mockEngine.importCertificate.mockResolvedValue({
    handle: "secret://web",
    secretId: "secret-id-1",
  });
  mockEngine.verifyToken.mockReturnValue(token());

  exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
    throw new Error("process.exit");
  });
  errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  stdoutSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
});

afterEach(() => {
  exitSpy.mockRestore();
  errorSpy.mockRestore();
  logSpy.mockRestore();
  stdoutSpy.mockRestore();
  if (savedEnvToken === undefined) delete process.env.HARPOC_TOKEN;
  else process.env.HARPOC_TOKEN = savedEnvToken;
});

describe("cert csr", () => {
  it("prints a parseable CSR to stdout and stores it as a pending secret", async () => {
    await run(["csr", "web", "--subject", "example.com"]);

    const pem = stdoutText();
    expect(pem).toMatch(
      /^-----BEGIN CERTIFICATE REQUEST-----\n[\s\S]+-----END CERTIFICATE REQUEST-----\n$/,
    );
    const body = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    expect(Buffer.from(body, "base64").length).toBeGreaterThan(0);

    expect(mockEngine.importCertificate).toHaveBeenCalledWith(
      "web",
      expect.stringContaining("BEGIN PRIVATE KEY") as string,
      { csrPem: pem, subject: "CN=example.com" },
      undefined,
      undefined,
    );
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it("never writes guidance to stdout — only the CSR PEM", async () => {
    await run(["csr", "web", "--subject", "example.com"]);

    const pem = stdoutText();
    expect(pem.trim().split("\n")[0]).toBe("-----BEGIN CERTIFICATE REQUEST-----");
    expect(logSpy).not.toHaveBeenCalled();
  });

  it("defaults to an EC key pair", async () => {
    await run(["csr", "web", "--subject", "example.com"]);

    const keyPem = mockEngine.importCertificate.mock.calls[0]?.[1] as string;
    expect(createPrivateKey(keyPem).asymmetricKeyType).toBe("ec");
  });

  it("--algorithm rsa generates an RSA key pair", async () => {
    await run(["csr", "web", "--subject", "example.com", "--algorithm", "rsa"]);

    const keyPem = mockEngine.importCertificate.mock.calls[0]?.[1] as string;
    expect(createPrivateKey(keyPem).asymmetricKeyType).toBe("rsa");
  });

  it("--bits maps onto the RSA modulus length", async () => {
    await run(["csr", "web", "--subject", "example.com", "--algorithm", "rsa", "--bits", "4096"]);

    const keyPem = mockEngine.importCertificate.mock.calls[0]?.[1] as string;
    const key = createPrivateKey(keyPem);
    expect(key.asymmetricKeyDetails?.modulusLength).toBe(4096);
  });

  it("--curve maps onto the EC named curve", async () => {
    await run(["csr", "web", "--subject", "example.com", "--curve", "P-384"]);

    const keyPem = mockEngine.importCertificate.mock.calls[0]?.[1] as string;
    const key = createPrivateKey(keyPem);
    expect(key.asymmetricKeyDetails?.namedCurve).toBe("secp384r1");
  });

  it("--sans forwards the DNS names into the CSR", async () => {
    await run([
      "csr",
      "web",
      "--subject",
      "example.com",
      "--sans",
      "api.example.com,www.example.com",
    ]);

    const pem = stdoutText();
    const der = Buffer.from(
      pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""),
      "base64",
    ).toString("latin1");
    expect(der).toContain("api.example.com");
    expect(der).toContain("www.example.com");
  });

  it("forwards --project", async () => {
    await run(["csr", "web", "--subject", "example.com", "--project", "team-a"]);

    expect(mockEngine.importCertificate).toHaveBeenCalledWith(
      "web",
      expect.any(String),
      expect.objectContaining({ subject: "CN=example.com" }),
      "team-a",
      undefined,
    );
  });

  it("--json prints the handle and the CSR PEM instead of writing to stdout", async () => {
    await run(["csr", "web", "--subject", "example.com", "--json"]);

    expect(stdoutSpy).not.toHaveBeenCalled();
    const printed = JSON.parse(logSpy.mock.calls[0]?.[0] as string) as Record<string, unknown>;
    expect(printed).toEqual({
      handle: "secret://web",
      csrPem: expect.stringContaining("BEGIN CERTIFICATE REQUEST") as string,
    });
  });

  it("an invalid --algorithm is refused before the vault opens", async () => {
    await expect(
      run(["csr", "web", "--subject", "example.com", "--algorithm", "dsa"]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("Invalid algorithm"));
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
    expect(stdoutSpy).not.toHaveBeenCalled();
  });

  it("an invalid --bits is refused before the vault opens", async () => {
    await expect(run(["csr", "web", "--subject", "example.com", "--bits", "1024"])).rejects.toThrow(
      "process.exit",
    );

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("Invalid bits"));
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("an invalid --curve is refused before the vault opens", async () => {
    await expect(
      run(["csr", "web", "--subject", "example.com", "--curve", "P-512"]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("Invalid curve"));
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("--bits under the default (ec) algorithm is refused rather than silently dropped", async () => {
    await expect(run(["csr", "web", "--subject", "example.com", "--bits", "4096"])).rejects.toThrow(
      "process.exit",
    );

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("--bits only applies with --algorithm rsa."),
    );
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
    expect(stdoutSpy).not.toHaveBeenCalled();
  });

  it("--algorithm ec --bits is refused rather than silently dropped", async () => {
    await expect(
      run(["csr", "web", "--subject", "example.com", "--algorithm", "ec", "--bits", "2048"]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("--bits only applies with --algorithm rsa."),
    );
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("--algorithm rsa --curve is refused rather than silently dropped", async () => {
    await expect(
      run(["csr", "web", "--subject", "example.com", "--algorithm", "rsa", "--curve", "P-384"]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("--curve only applies with --algorithm ec."),
    );
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
    expect(stdoutSpy).not.toHaveBeenCalled();
  });

  it("a missing --subject is refused by commander", async () => {
    await expect(run(["csr", "web"])).rejects.toThrow(/required option '--subject/);
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("a sealed vault fails before any key material is generated", async () => {
    vi.mocked(loadUnlockedEngine).mockRejectedValueOnce(VaultError.vaultLocked());

    await expect(run(["csr", "web", "--subject", "example.com"])).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("Vault is locked"));
    expect(mockEngine.importCertificate).not.toHaveBeenCalled();
    expect(stdoutSpy).not.toHaveBeenCalled();
  });

  it("a token without 'create' is refused before any key material is generated", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));

    await expect(
      run(["csr", "web", "--subject", "example.com", "--token", "jwt-value"]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("Token lacks permission: create"),
    );
    expect(mockEngine.importCertificate).not.toHaveBeenCalled();
    expect(stdoutSpy).not.toHaveBeenCalled();
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });

  it("a token with 'create' generates the CSR and attributes the audit rows to its principal", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["create"] }));

    await run(["csr", "web", "--subject", "example.com", "--token", "jwt-value"]);

    expect(mockEngine.verifyToken).toHaveBeenCalledWith("jwt-value");
    expect(mockEngine.importCertificate.mock.calls[0]?.[4]).toEqual({
      principal_type: "agent",
      principal_id: "agent-1",
      interface: "cli",
    });
  });

  it("passes no caller on the trusted local path, keeping the rows NULL-principal", async () => {
    await run(["csr", "web", "--subject", "example.com"]);

    expect(mockEngine.importCertificate.mock.calls[0]?.[4]).toBeUndefined();
  });

  it("an ambient HARPOC_TOKEN is honoured when --token is absent", async () => {
    process.env.HARPOC_TOKEN = "ambient-jwt";
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["create"] }));

    await run(["csr", "web", "--subject", "example.com"]);

    expect(mockEngine.verifyToken).toHaveBeenCalledWith("ambient-jwt");
  });
});
