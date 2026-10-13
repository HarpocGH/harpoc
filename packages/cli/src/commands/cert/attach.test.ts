import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, VaultError } from "@harpoc/shared";
import type { CertificateStatus } from "@harpoc/shared";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    verifyToken: vi.fn(),
    updateCertificate: vi.fn(),
    getCertificateStatus: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
  resolveSecretId: vi.fn().mockResolvedValue("secret-id-1"),
  refuseEmptyVaultDir: vi.fn(),
}));

import { loadUnlockedEngine, resolveSecretId } from "../../utils/vault-loader.js";
import { buildProgram } from "../../program.js";
import { spyCli, tokenFixture, type CliSpies } from "../../__fixtures__/cli-harness.js";

// M-P3-11 (test-review-2026-10-09): the attach step `getting-started.md` and
// the API reference describe for a `cert csr` secret — the issued certificate
// (and a separate chain) read from files and handed to the engine's
// updateCertificate as a non-renewal. Driven through the shipped command tree.
const FIXTURES = fileURLToPath(new URL("../../__fixtures__/certs/", import.meta.url));
const CERT_PATH = join(FIXTURES, "rsa-cert.pem");
const CHAIN_PATH = join(FIXTURES, "ec-cert.pem");
const CERT_PEM = readFileSync(CERT_PATH, "utf8");
const CHAIN_PEM = readFileSync(CHAIN_PATH, "utf8");

const STATUS: CertificateStatus = {
  secret_id: "secret-id-1",
  subject: "CN=fixture.example.com",
  issuer: "CN=fixture.example.com",
  not_before: 1_787_000_000_000,
  not_after: 2_102_000_000_000,
  auto_renew: false,
  renewal_status: "ok",
};

const CALLER = { principal_type: "agent", principal_id: "agent-1", interface: "cli" };

let spies: CliSpies;

async function run(args: string[]): Promise<void> {
  const program = buildProgram();
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  await program.parseAsync(["node", "harpoc", "cert", "attach", ...args]);
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(loadUnlockedEngine).mockResolvedValue(mockEngine as never);
  vi.mocked(resolveSecretId).mockResolvedValue("secret-id-1");
  mockEngine.updateCertificate.mockResolvedValue(undefined);
  mockEngine.getCertificateStatus.mockReturnValue(STATUS);
  mockEngine.verifyToken.mockReturnValue(tokenFixture());
  spies = spyCli();
});

afterEach(() => {
  spies.restore();
});

describe("cert attach", () => {
  it("attaches the certificate and chain files as a non-renewal and prints the status", async () => {
    await run(["secret://web", "--cert", CERT_PATH, "--chain", CHAIN_PATH]);

    expect(mockEngine.updateCertificate).toHaveBeenCalledWith(
      "secret-id-1",
      CERT_PEM,
      CHAIN_PEM,
      { renewed: false, handle: "secret://web" },
      undefined,
    );
    expect(mockEngine.getCertificateStatus).toHaveBeenCalledWith(
      "secret-id-1",
      undefined,
      "secret://web",
    );
    const printed = spies.stdout();
    expect(printed).toContain("secret://web");
    expect(printed).toContain("CN=fixture.example.com");
    expect(printed).toContain(new Date(STATUS.not_after as number).toISOString().slice(0, 10));
    expect(printed).toMatch(/Renewal status\s+ok/);
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
    expect(spies.exitSpy).not.toHaveBeenCalled();
  });

  it("forwards an absent --chain as undefined", async () => {
    await run(["secret://web", "--cert", CERT_PATH]);

    expect(mockEngine.updateCertificate).toHaveBeenCalledWith(
      "secret-id-1",
      CERT_PEM,
      undefined,
      { renewed: false, handle: "secret://web" },
      undefined,
    );
  });

  it("resolves the handle under the cert.issue event type", async () => {
    await run(["secret://web", "--cert", CERT_PATH]);

    expect(resolveSecretId).toHaveBeenCalledWith(
      mockEngine,
      "secret://web",
      undefined,
      AuditEventType.CERT_ISSUE,
    );
  });

  it("--json prints the CertificateStatus verbatim", async () => {
    await run(["secret://web", "--cert", CERT_PATH, "--json"]);

    const printed = JSON.parse(spies.logSpy.mock.calls[0]?.[0] as string) as Record<
      string,
      unknown
    >;
    expect(printed).toEqual(STATUS);
  });

  it("an unreadable --cert file fails before the vault opens", async () => {
    await expect(run(["secret://web", "--cert", join(FIXTURES, "absent.pem")])).rejects.toThrow(
      "process.exit",
    );

    expect(spies.errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("Cannot read certificate file"),
    );
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
    expect(mockEngine.updateCertificate).not.toHaveBeenCalled();
  });

  it("an unreadable --chain file fails before the vault opens", async () => {
    await expect(
      run(["secret://web", "--cert", CERT_PATH, "--chain", join(FIXTURES, "absent.pem")]),
    ).rejects.toThrow("process.exit");

    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("Cannot read chain file"));
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
    expect(mockEngine.updateCertificate).not.toHaveBeenCalled();
  });

  it("an empty --cert is refused before the vault opens", async () => {
    await expect(run(["secret://web", "--cert", ""])).rejects.toThrow("process.exit");

    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("--cert requires a path"));
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("an empty --chain is refused rather than silently ignored", async () => {
    await expect(run(["secret://web", "--cert", CERT_PATH, "--chain", ""])).rejects.toThrow(
      "process.exit",
    );

    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("--chain requires a path"));
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("a token with 'rotate' attaches and threads the caller into the write and the status read", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["rotate"] }));

    await run(["secret://web", "--cert", CERT_PATH, "--token", "jwt-value"]);

    expect(mockEngine.verifyToken).toHaveBeenCalledWith("jwt-value");
    expect(resolveSecretId).toHaveBeenCalledWith(
      mockEngine,
      "secret://web",
      CALLER,
      AuditEventType.CERT_ISSUE,
    );
    expect(mockEngine.updateCertificate).toHaveBeenCalledWith(
      "secret-id-1",
      CERT_PEM,
      undefined,
      { renewed: false, handle: "secret://web" },
      CALLER,
    );
    expect(mockEngine.getCertificateStatus).toHaveBeenCalledWith(
      "secret-id-1",
      CALLER,
      "secret://web",
    );
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });

  it("an ambient HARPOC_TOKEN is honoured when --token is absent", async () => {
    process.env.HARPOC_TOKEN = "ambient-jwt";
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["rotate"] }));

    await run(["secret://web", "--cert", CERT_PATH]);

    expect(mockEngine.verifyToken).toHaveBeenCalledWith("ambient-jwt");
    expect(mockEngine.updateCertificate.mock.calls[0]?.[4]).toEqual(CALLER);
  });

  it("a read-only token is denied with ACCESS_DENIED before the write", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["read"] }));

    await expect(
      run(["secret://web", "--cert", CERT_PATH, "--token", "jwt-value"]),
    ).rejects.toThrow("process.exit");

    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("ACCESS_DENIED"));
    expect(spies.errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("Token lacks permission: rotate"),
    );
    expect(resolveSecretId).not.toHaveBeenCalled();
    expect(mockEngine.updateCertificate).not.toHaveBeenCalled();
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });

  it("--json renders the engine's refusal as an error envelope and still destroys the engine", async () => {
    mockEngine.updateCertificate.mockRejectedValue(VaultError.certPrivateKeyMismatch());

    await expect(run(["secret://web", "--cert", CERT_PATH, "--json"])).rejects.toThrow(
      "process.exit",
    );

    const envelope = JSON.parse(spies.errorSpy.mock.calls[0]?.[0] as string) as Record<
      string,
      unknown
    >;
    expect(envelope.error).toBe("CERT_PRIVATE_KEY_MISMATCH");
    expect(mockEngine.getCertificateStatus).not.toHaveBeenCalled();
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });
});
