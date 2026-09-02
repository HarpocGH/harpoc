import { createPrivateKey } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import { VaultError } from "@harpoc/shared";
import type { VaultApiToken } from "@harpoc/shared";

const { mockEngine, mockPromptHidden } = vi.hoisted(() => ({
  mockEngine: {
    importCertificate: vi.fn(),
    getCertificateStatus: vi.fn(),
    verifyToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
  mockPromptHidden: vi.fn(),
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
  resolveSecretId: vi.fn().mockResolvedValue("secret-id-1"),
}));

// Only the prompt is faked: resolveSecretValue itself stays real, so the
// encrypted-key path exercises the actual analyze -> prompt -> decrypt chain.
vi.mock("../../utils/prompt.js", () => ({ promptHidden: mockPromptHidden }));

// Spy wrapper around the real implementation — the returned buffer has to be
// observable to assert it was wiped after the engine handoff.
vi.mock("../../utils/secret-value.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../utils/secret-value.js")>();
  return { ...actual, resolveSecretValue: vi.fn(actual.resolveSecretValue) };
});

import { Command } from "commander";
import { loadUnlockedEngine } from "../../utils/vault-loader.js";
import { resolveSecretValue } from "../../utils/secret-value.js";
import { registerCertImportCommand } from "./import.js";
import { registerCertStatusCommand } from "./status.js";

const FIXTURES = fileURLToPath(new URL("../../__fixtures__/certs/", import.meta.url));
const KEY_PATH = join(FIXTURES, "rsa-key.pem");
const CERT_PATH = join(FIXTURES, "rsa-cert.pem");
const EC_CERT_PATH = join(FIXTURES, "ec-cert.pem");
const KEY_PEM = readFileSync(KEY_PATH, "utf8");
const CERT_PEM = readFileSync(CERT_PATH, "utf8");
const EC_CERT_PEM = readFileSync(EC_CERT_PATH, "utf8");
const KEY_PASSPHRASE = "testpass";

/** Fixture subject/SAN: CN=fixture.example.com, valid 2026-08-16 -> 2036-08-13. */
const STATUS = {
  secret_id: "secret-id-1",
  subject: "CN=fixture.example.com",
  issuer: "CN=fixture.example.com",
  not_before: 1_787_000_000_000,
  not_after: 2_102_000_000_000,
  auto_renew: true,
  renewal_status: "ok" as const,
};

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

let tempDir: string;
let exitSpy: MockInstance;
let errorSpy: ReturnType<typeof vi.spyOn>;
let logSpy: ReturnType<typeof vi.spyOn>;
const savedEnvToken = process.env.HARPOC_TOKEN;

async function run(args: string[]): Promise<void> {
  const program = new Command();
  // exitOverride must precede .command(): commander copies the exit callback
  // into a child by value at creation time, so setting it afterwards would
  // leave the subcommands' own parse errors exiting the test process for real.
  // (configureOutput is order-independent — the child shares the config object
  // by reference and configureOutput mutates it in place.)
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  program.option("--vault-dir <path>", "Path to vault directory");
  const cert = program.command("cert").description("Manage certificate secrets");
  registerCertImportCommand(cert);
  registerCertStatusCommand(cert);
  await program.parseAsync(["node", "harpoc", "cert", ...args]);
}

/** The buffer resolveSecretValue handed the command, for wipe assertions. */
async function resolvedKeyBuffer(): Promise<Buffer> {
  const result = vi.mocked(resolveSecretValue).mock.results[0];
  if (result === undefined || result.type !== "return") throw new Error("no resolved value");
  return (await result.value) as Buffer;
}

function writeTemp(name: string, contents: string): string {
  const path = join(tempDir, name);
  writeFileSync(path, contents);
  return path;
}

beforeEach(() => {
  vi.clearAllMocks();
  delete process.env.HARPOC_TOKEN;
  tempDir = join(tmpdir(), `harpoc-cert-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });

  vi.mocked(loadUnlockedEngine).mockResolvedValue(mockEngine as never);
  mockEngine.importCertificate.mockResolvedValue({
    handle: "secret://web",
    secretId: "secret-id-1",
  });
  mockEngine.getCertificateStatus.mockReturnValue(STATUS);
  mockEngine.verifyToken.mockReturnValue(token());
  mockPromptHidden.mockResolvedValue(KEY_PASSPHRASE);

  exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
    throw new Error("process.exit");
  });
  errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
});

afterEach(() => {
  exitSpy.mockRestore();
  errorSpy.mockRestore();
  logSpy.mockRestore();
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
  if (savedEnvToken === undefined) delete process.env.HARPOC_TOKEN;
  else process.env.HARPOC_TOKEN = savedEnvToken;
});

describe("cert import", () => {
  it("imports a key/certificate pair and reports the handle", async () => {
    await run(["import", "web", "--key", KEY_PATH, "--cert", CERT_PATH]);

    expect(mockEngine.importCertificate).toHaveBeenCalledWith(
      "web",
      KEY_PEM,
      {
        certificatePem: expect.stringContaining("BEGIN CERTIFICATE") as string,
        chainPem: undefined,
        autoRenew: undefined,
        renewBeforeDays: 30,
      },
      undefined,
      undefined,
    );
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining("secret://web"));
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining("imported"));
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it("--json prints exactly the handle record", async () => {
    await run(["import", "web", "--key", KEY_PATH, "--cert", CERT_PATH, "--json"]);

    const printed = JSON.parse(logSpy.mock.calls[0]?.[0] as string) as Record<string, unknown>;
    expect(printed).toEqual({ handle: "secret://web" });
  });

  it("forwards --project and --renew-before-days", async () => {
    await run([
      "import",
      "web",
      "--key",
      KEY_PATH,
      "--cert",
      CERT_PATH,
      "--project",
      "team-a",
      "--renew-before-days",
      "14",
    ]);

    expect(mockEngine.importCertificate).toHaveBeenCalledWith(
      "web",
      KEY_PEM,
      expect.objectContaining({ renewBeforeDays: 14 }),
      "team-a",
      undefined,
    );
  });

  it("no longer accepts --auto-renew (auto_renew is ACME-only)", async () => {
    await expect(
      run(["import", "web", "--key", KEY_PATH, "--cert", CERT_PATH, "--auto-renew"]),
    ).rejects.toThrow("unknown option '--auto-renew'");

    expect(mockEngine.importCertificate).not.toHaveBeenCalled();
  });

  it("splits a bundled certificate file into leaf and chain", async () => {
    const bundle = writeTemp("bundle.pem", `${CERT_PEM}\n${EC_CERT_PEM}`);

    await run(["import", "web", "--key", KEY_PATH, "--cert", bundle]);

    const opts = mockEngine.importCertificate.mock.calls[0]?.[2] as {
      certificatePem: string;
      chainPem?: string;
    };
    expect(opts.certificatePem.match(/BEGIN CERTIFICATE/g)).toHaveLength(1);
    expect(opts.certificatePem.trim()).toBe(CERT_PEM.trim());
    expect(opts.chainPem?.trim()).toBe(EC_CERT_PEM.trim());
  });

  it("an explicit --chain file wins over a chain carried by the bundle", async () => {
    const bundle = writeTemp("bundle.pem", `${CERT_PEM}\n${CERT_PEM}`);
    const chain = writeTemp("chain.pem", EC_CERT_PEM);

    await run(["import", "web", "--key", KEY_PATH, "--cert", bundle, "--chain", chain]);

    const opts = mockEngine.importCertificate.mock.calls[0]?.[2] as { chainPem?: string };
    expect(opts.chainPem?.trim()).toBe(EC_CERT_PEM.trim());
  });

  it("prompts once for the passphrase of an encrypted key and stores it decrypted", async () => {
    const encrypted = createPrivateKey(KEY_PEM)
      .export({
        type: "pkcs8",
        format: "pem",
        cipher: "aes-256-cbc",
        passphrase: KEY_PASSPHRASE,
      })
      .toString();
    expect(encrypted).toContain("BEGIN ENCRYPTED PRIVATE KEY");
    const encryptedPath = writeTemp("enc-key.pem", encrypted);

    await run(["import", "web", "--key", encryptedPath, "--cert", CERT_PATH]);

    expect(mockPromptHidden).toHaveBeenCalledTimes(1);
    expect(mockPromptHidden).toHaveBeenCalledWith("Key passphrase: ", undefined, undefined);
    const storedKey = mockEngine.importCertificate.mock.calls[0]?.[1] as string;
    expect(storedKey).toContain("BEGIN PRIVATE KEY");
    expect(storedKey).not.toContain("ENCRYPTED");
    // Same key material, just unwrapped: it still matches the certificate.
    expect(createPrivateKey(storedKey).export({ type: "pkcs8", format: "pem" })).toBe(
      createPrivateKey(KEY_PEM).export({ type: "pkcs8", format: "pem" }),
    );
  });

  it("a wrong passphrase fails with KEY_PASSPHRASE_INVALID and writes nothing", async () => {
    const encrypted = createPrivateKey(KEY_PEM)
      .export({
        type: "pkcs8",
        format: "pem",
        cipher: "aes-256-cbc",
        passphrase: KEY_PASSPHRASE,
      })
      .toString();
    const encryptedPath = writeTemp("enc-key.pem", encrypted);
    mockPromptHidden.mockResolvedValue("wrong");

    await expect(
      run(["import", "web", "--key", encryptedPath, "--cert", CERT_PATH]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("KEY_PASSPHRASE_INVALID"));
    expect(mockEngine.importCertificate).not.toHaveBeenCalled();
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });

  it("an unencrypted key never prompts", async () => {
    await run(["import", "web", "--key", KEY_PATH, "--cert", CERT_PATH]);
    expect(mockPromptHidden).not.toHaveBeenCalled();
  });

  it("zeroes the resolved key buffer after the engine handoff", async () => {
    await run(["import", "web", "--key", KEY_PATH, "--cert", CERT_PATH]);

    const buffer = await resolvedKeyBuffer();
    expect(buffer.length).toBeGreaterThan(0);
    expect([...buffer].every((byte) => byte === 0)).toBe(true);
  });

  it("zeroes the resolved key buffer even when the engine rejects", async () => {
    mockEngine.importCertificate.mockRejectedValue(VaultError.certPrivateKeyMismatch());

    await expect(run(["import", "web", "--key", KEY_PATH, "--cert", CERT_PATH])).rejects.toThrow(
      "process.exit",
    );

    const buffer = await resolvedKeyBuffer();
    expect([...buffer].every((byte) => byte === 0)).toBe(true);
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });

  it("never echoes key material to stdout or stderr", async () => {
    const keyBody = KEY_PEM.split("\n")[1] as string;
    expect(keyBody.length).toBeGreaterThan(16);

    await run(["import", "web", "--key", KEY_PATH, "--cert", CERT_PATH]);

    const written = [...logSpy.mock.calls, ...errorSpy.mock.calls].flat().join("\n");
    expect(written).not.toContain(keyBody);
    expect(written).not.toContain("PRIVATE KEY");
  });

  it("a missing --cert is refused by commander", async () => {
    await expect(run(["import", "web", "--key", KEY_PATH])).rejects.toThrow(
      /required option '--cert/,
    );
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("a missing --key is refused by commander", async () => {
    await expect(run(["import", "web", "--cert", CERT_PATH])).rejects.toThrow(
      /required option '--key/,
    );
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("an out-of-range --renew-before-days fails before the vault is opened", async () => {
    await expect(
      run(["import", "web", "--key", KEY_PATH, "--cert", CERT_PATH, "--renew-before-days", "4000"]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('Invalid renew-before-days "4000"'),
    );
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("--renew-before-days above the engine's 365 ceiling is refused before the vault is opened", async () => {
    await expect(
      run(["import", "web", "--key", KEY_PATH, "--cert", CERT_PATH, "--renew-before-days", "366"]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('Invalid renew-before-days "366"'),
    );
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("an empty --key is refused instead of falling through to the hidden prompt", async () => {
    // resolveSecretValue guards on truthiness, so an empty path reads as "no
    // file given" and would silently wait for a human to type the key.
    await expect(run(["import", "web", "--key", "", "--cert", CERT_PATH])).rejects.toThrow(
      "process.exit",
    );

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("--key requires a path"));
    expect(mockPromptHidden).not.toHaveBeenCalled();
    expect(resolveSecretValue).not.toHaveBeenCalled();
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("an empty --cert is refused up front", async () => {
    await expect(run(["import", "web", "--key", KEY_PATH, "--cert", ""])).rejects.toThrow(
      "process.exit",
    );

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("--cert requires a path"));
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("an empty --chain is refused rather than silently ignored", async () => {
    await expect(
      run(["import", "web", "--key", KEY_PATH, "--cert", CERT_PATH, "--chain", ""]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("--chain requires a path"));
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("a directory given as --cert is refused, not read", async () => {
    await expect(run(["import", "web", "--key", KEY_PATH, "--cert", tempDir])).rejects.toThrow(
      "process.exit",
    );

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("Cannot read certificate file"));
    expect(resolveSecretValue).not.toHaveBeenCalled();
  });

  it("a certificate file over the 1 MiB cap is refused before it is read", async () => {
    const oversize = writeTemp("huge.pem", "x".repeat(1024 * 1024 + 1));

    await expect(run(["import", "web", "--key", KEY_PATH, "--cert", oversize])).rejects.toThrow(
      "process.exit",
    );

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("certificate file exceeds the 1 MiB limit"),
    );
    expect(resolveSecretValue).not.toHaveBeenCalled();
  });

  it("an empty certificate file is refused", async () => {
    const empty = writeTemp("empty.pem", "   \n");

    await expect(run(["import", "web", "--key", KEY_PATH, "--cert", empty])).rejects.toThrow(
      "process.exit",
    );

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("certificate file is empty"));
    expect(resolveSecretValue).not.toHaveBeenCalled();
  });

  it("an unreadable certificate file fails before the key is read or prompted", async () => {
    await expect(
      run(["import", "web", "--key", KEY_PATH, "--cert", join(tempDir, "missing.pem")]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("Cannot read certificate file"));
    expect(resolveSecretValue).not.toHaveBeenCalled();
    expect(mockPromptHidden).not.toHaveBeenCalled();
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });

  it("a certificate file with no PEM block is refused by the manager", async () => {
    const garbage = writeTemp("garbage.pem", "not a certificate\n");

    await expect(run(["import", "web", "--key", KEY_PATH, "--cert", garbage])).rejects.toThrow(
      "process.exit",
    );

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("CERT_INVALID"));
    expect(mockEngine.importCertificate).not.toHaveBeenCalled();
  });

  it("a sealed vault fails before the key is read", async () => {
    vi.mocked(loadUnlockedEngine).mockRejectedValueOnce(VaultError.vaultLocked());

    await expect(run(["import", "web", "--key", KEY_PATH, "--cert", CERT_PATH])).rejects.toThrow(
      "process.exit",
    );

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("Vault is locked"));
    expect(resolveSecretValue).not.toHaveBeenCalled();
  });

  it("a token without 'create' is refused before any file is read", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));

    await expect(
      run(["import", "web", "--key", KEY_PATH, "--cert", CERT_PATH, "--token", "jwt-value"]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("Token lacks permission: create"),
    );
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("ACCESS_DENIED"));
    expect(resolveSecretValue).not.toHaveBeenCalled();
    expect(mockEngine.importCertificate).not.toHaveBeenCalled();
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });

  it("a token with 'create' imports and attributes the audit rows to its principal", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["create"] }));

    await run(["import", "web", "--key", KEY_PATH, "--cert", CERT_PATH, "--token", "jwt-value"]);

    expect(mockEngine.verifyToken).toHaveBeenCalledWith("jwt-value");
    expect(mockEngine.importCertificate).toHaveBeenCalledTimes(1);
    // V2 parity with `secret set`: without this the secret.create and
    // cert.issue rows are NULL-principal, i.e. indistinguishable from the
    // trusted local path.
    expect(mockEngine.importCertificate.mock.calls[0]?.[4]).toEqual({
      principal_type: "agent",
      principal_id: "agent-1",
      interface: "cli",
    });
  });

  it("passes no caller on the trusted local path, keeping the rows NULL-principal", async () => {
    await run(["import", "web", "--key", KEY_PATH, "--cert", CERT_PATH]);

    expect(mockEngine.importCertificate.mock.calls[0]?.[4]).toBeUndefined();
  });

  it("an ambient HARPOC_TOKEN is honoured when --token is absent", async () => {
    process.env.HARPOC_TOKEN = "ambient-jwt";
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["create"] }));

    await run(["import", "web", "--key", KEY_PATH, "--cert", CERT_PATH]);

    expect(mockEngine.verifyToken).toHaveBeenCalledWith("ambient-jwt");
  });
});

describe("cert status", () => {
  it("prints the certificate record", async () => {
    await run(["status", "secret://web"]);

    expect(mockEngine.getCertificateStatus).toHaveBeenCalledWith(
      "secret-id-1",
      undefined,
      "secret://web",
    );
    const printed = logSpy.mock.calls.flat().join("\n");
    expect(printed).toContain("Subject");
    expect(printed).toContain("CN=fixture.example.com");
    expect(printed).toContain("Issuer");
    expect(printed).toContain("Not before");
    expect(printed).toContain("Not after");
    expect(printed).toContain("Auto renew");
    expect(printed).toContain("Renewal status");
    expect(printed).toContain("ok");
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });

  it("renders the validity window as formatted timestamps, not epoch millis", async () => {
    await run(["status", "secret://web"]);

    const printed = logSpy.mock.calls.flat().join("\n");
    expect(printed).toContain(new Date(STATUS.not_after).toISOString().slice(0, 10));
    expect(printed).not.toContain(String(STATUS.not_after));
  });

  it("renders a certificate with no stored chain metadata", async () => {
    mockEngine.getCertificateStatus.mockReturnValue({
      ...STATUS,
      issuer: null,
      not_before: null,
      not_after: null,
      auto_renew: false,
      renewal_status: "no_certificate",
    });

    await run(["status", "secret://web"]);

    const printed = logSpy.mock.calls.flat().join("\n");
    expect(printed).toContain("no_certificate");
    expect(printed).toMatch(/Not after\s+-/);
  });

  it("--json prints the exact CertificateStatus", async () => {
    await run(["status", "secret://web", "--json"]);

    const printed = JSON.parse(logSpy.mock.calls[0]?.[0] as string) as Record<string, unknown>;
    expect(printed).toEqual(STATUS);
  });

  it("a token with 'read' scope succeeds and attributes the call", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));

    await run(["status", "secret://web", "--token", "jwt-value"]);

    expect(mockEngine.getCertificateStatus).toHaveBeenCalledWith(
      "secret-id-1",
      {
        principal_type: "agent",
        principal_id: "agent-1",
        interface: "cli",
      },
      "secret://web",
    );
  });

  it("a rotate-only token is denied with ACCESS_DENIED before the engine read", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["rotate"] }));

    await expect(run(["status", "secret://web", "--token", "jwt-value"])).rejects.toThrow(
      "process.exit",
    );

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("ACCESS_DENIED"));
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("Token lacks permission: read"));
    expect(mockEngine.getCertificateStatus).not.toHaveBeenCalled();
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });

  it("a sealed vault renders the unlock guidance and exits 1", async () => {
    vi.mocked(loadUnlockedEngine).mockRejectedValueOnce(VaultError.vaultLocked());

    await expect(run(["status", "secret://web"])).rejects.toThrow("process.exit");

    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("Vault is locked"));
  });

  it("--json renders an engine refusal as a JSON error envelope", async () => {
    mockEngine.getCertificateStatus.mockImplementation(() => {
      throw VaultError.certInvalid("no stored certificate");
    });

    await expect(run(["status", "secret://web", "--json"])).rejects.toThrow("process.exit");

    const envelope = JSON.parse(errorSpy.mock.calls[0]?.[0] as string) as Record<string, unknown>;
    expect(envelope.error).toBe("CERT_INVALID");
  });
});
