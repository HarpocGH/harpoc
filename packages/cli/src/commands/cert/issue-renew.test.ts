import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import { VaultError } from "@harpoc/shared";
import type { CertificateStatus, VaultApiToken } from "@harpoc/shared";
import type { IssueOptions, RenewOptions } from "@harpoc/cert-manager";

const { mockEngine, mockCertManager, mockIssueWithAcme, mockRenewCertificate, mockPromptHidden } =
  vi.hoisted(() => {
    const issueWithAcme = vi.fn();
    const renewCertificate = vi.fn();
    return {
      mockEngine: {
        verifyToken: vi.fn(),
        destroy: vi.fn().mockResolvedValue(undefined),
      },
      mockIssueWithAcme: issueWithAcme,
      mockRenewCertificate: renewCertificate,
      mockCertManager: vi.fn(() => ({ issueWithAcme, renewCertificate })),
      mockPromptHidden: vi.fn(),
    };
  });

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
  resolveSecretId: vi.fn().mockResolvedValue("secret-id-1"),
}));

// The manager is mocked at the module boundary here, unlike the import/csr
// suites: `issueWithAcme` and `renewCertificate` talk to a live ACME CA and
// bind a challenge responder to a port. What this suite pins is the command
// wiring — option parsing, token scope, caller threading, output — not the
// protocol, which cert-manager's own suite covers.
vi.mock("@harpoc/cert-manager", () => ({ CertManager: mockCertManager }));

vi.mock("../../utils/prompt.js", () => ({ promptHidden: mockPromptHidden }));

import { Command } from "commander";
import { loadUnlockedEngine, resolveSecretId } from "../../utils/vault-loader.js";
import { registerCertIssueCommand } from "./issue.js";
import { registerCertRenewCommand } from "./renew.js";

const STATUS: CertificateStatus = {
  secret_id: "secret-id-1",
  subject: "CN=example.com",
  issuer: "CN=Fake LE Intermediate X1",
  not_before: 1_787_000_000_000,
  not_after: 2_102_000_000_000,
  auto_renew: true,
  renewal_status: "ok",
};

const ISSUED = { handle: "secret://web", secretId: "secret-id-1", status: STATUS };

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
const savedEnvToken = process.env.HARPOC_TOKEN;

async function run(args: string[]): Promise<void> {
  const program = new Command();
  // exitOverride must precede .command(): commander copies the exit callback
  // into a child by value at creation time, so setting it afterwards would
  // leave the subcommands' own parse errors exiting the test process for real.
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  program.option("--vault-dir <path>", "Path to vault directory");
  const cert = program.command("cert").description("Manage certificate secrets");
  registerCertIssueCommand(cert);
  registerCertRenewCommand(cert);
  await program.parseAsync(["node", "harpoc", "cert", ...args]);
}

/** The IssueOptions object the command handed the manager. */
function issueOptions(): IssueOptions {
  return mockIssueWithAcme.mock.calls[0]?.[1] as IssueOptions;
}

/** The RenewOptions object the command handed the manager. */
function renewOptions(): RenewOptions {
  return mockRenewCertificate.mock.calls[0]?.[1] as RenewOptions;
}

beforeEach(() => {
  vi.clearAllMocks();
  delete process.env.HARPOC_TOKEN;

  vi.mocked(loadUnlockedEngine).mockResolvedValue(mockEngine as never);
  vi.mocked(resolveSecretId).mockResolvedValue("secret-id-1");
  mockIssueWithAcme.mockResolvedValue(ISSUED);
  mockRenewCertificate.mockResolvedValue(STATUS);
  mockEngine.verifyToken.mockReturnValue(token());
  mockPromptHidden.mockResolvedValue("");

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
  if (savedEnvToken === undefined) delete process.env.HARPOC_TOKEN;
  else process.env.HARPOC_TOKEN = savedEnvToken;
});

describe("cert issue", () => {
  it("issues over ACME and prints the handle and certificate summary", async () => {
    await run(["issue", "web", "--domains", "example.com", "--email", "ops@example.com"]);

    expect(mockCertManager).toHaveBeenCalledWith(mockEngine);
    expect(mockIssueWithAcme).toHaveBeenCalledTimes(1);
    expect(mockIssueWithAcme.mock.calls[0]?.[0]).toBe("web");

    const printed = logSpy.mock.calls.flat().join("\n");
    expect(printed).toContain("secret://web");
    expect(printed).toContain("CN=example.com");
    expect(printed).toContain("ok");
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it("forwards the domain list, email and the issuance defaults", async () => {
    await run([
      "issue",
      "web",
      "--domains",
      "example.com, www.example.com ,api.example.com",
      "--email",
      "ops@example.com",
    ]);

    const opts = issueOptions();
    expect(opts.domains).toEqual(["example.com", "www.example.com", "api.example.com"]);
    expect(opts.email).toBe("ops@example.com");
    expect(opts.staging).toBe(false);
    expect(opts.autoRenew).toBe(false);
    expect(opts.renewBeforeDays).toBe(30);
    expect(opts.httpPort).toBeUndefined();
    expect(opts.dns01).toBeUndefined();
    expect(opts.project).toBeUndefined();
    // EC P-256 is the default on both commands (D8).
    expect(opts.algorithm).toBe("ec");
    expect(opts.modulusLength).toBeUndefined();
    expect(opts.namedCurve).toBeUndefined();
  });

  it("--algorithm ec forwards the EC selection", async () => {
    await run([
      "issue",
      "web",
      "--domains",
      "example.com",
      "--email",
      "ops@example.com",
      "--algorithm",
      "ec",
    ]);

    expect(issueOptions().algorithm).toBe("ec");
  });

  it("--curve forwards the named curve alongside --algorithm ec", async () => {
    await run([
      "issue",
      "web",
      "--domains",
      "example.com",
      "--email",
      "ops@example.com",
      "--algorithm",
      "ec",
      "--curve",
      "P-384",
    ]);

    const opts = issueOptions();
    expect(opts.algorithm).toBe("ec");
    expect(opts.namedCurve).toBe("P-384");
    expect(opts.modulusLength).toBeUndefined();
  });

  it("--bits forwards the modulus length with --algorithm rsa", async () => {
    await run([
      "issue",
      "web",
      "--domains",
      "example.com",
      "--email",
      "ops@example.com",
      "--algorithm",
      "rsa",
      "--bits",
      "4096",
    ]);

    const opts = issueOptions();
    expect(opts.algorithm).toBe("rsa");
    expect(opts.modulusLength).toBe(4096);
    expect(opts.namedCurve).toBeUndefined();
  });

  it("--bits under the default (ec) algorithm is refused rather than silently dropped", async () => {
    await expect(
      run([
        "issue",
        "web",
        "--domains",
        "example.com",
        "--email",
        "ops@example.com",
        "--bits",
        "4096",
      ]),
    ).rejects.toThrow("process.exit");
    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("--bits only applies with --algorithm rsa."),
    );
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
    expect(mockIssueWithAcme).not.toHaveBeenCalled();
  });

  it("--curve under the default (ec) algorithm is accepted", async () => {
    await run([
      "issue",
      "web",
      "--domains",
      "example.com",
      "--email",
      "ops@example.com",
      "--curve",
      "P-384",
    ]);
    const opts = issueOptions();
    expect(opts.algorithm).toBe("ec");
    expect(opts.namedCurve).toBe("P-384");
    expect(opts.modulusLength).toBeUndefined();
  });

  it("an invalid --algorithm is refused before the vault opens", async () => {
    await expect(
      run([
        "issue",
        "web",
        "--domains",
        "example.com",
        "--email",
        "ops@example.com",
        "--algorithm",
        "nonsense",
      ]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('Invalid algorithm "nonsense"'));
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
    expect(mockIssueWithAcme).not.toHaveBeenCalled();
  });

  it("an invalid --bits is refused before the vault opens", async () => {
    await expect(
      run([
        "issue",
        "web",
        "--domains",
        "example.com",
        "--email",
        "ops@example.com",
        "--bits",
        "1024",
      ]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('Invalid bits "1024"'));
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
    expect(mockIssueWithAcme).not.toHaveBeenCalled();
  });

  it("an invalid --curve is refused before the vault opens", async () => {
    await expect(
      run([
        "issue",
        "web",
        "--domains",
        "example.com",
        "--email",
        "ops@example.com",
        "--algorithm",
        "ec",
        "--curve",
        "P-521",
      ]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('Invalid curve "P-521"'));
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
    expect(mockIssueWithAcme).not.toHaveBeenCalled();
  });

  it("forwards --staging, --http-port, --auto-renew, --renew-before-days and --project", async () => {
    await run([
      "issue",
      "web",
      "--domains",
      "example.com",
      "--email",
      "ops@example.com",
      "--staging",
      "--http-port",
      "8080",
      "--auto-renew",
      "--renew-before-days",
      "14",
      "--project",
      "team-a",
    ]);

    const opts = issueOptions();
    expect(opts.staging).toBe(true);
    expect(opts.httpPort).toBe(8080);
    expect(opts.autoRenew).toBe(true);
    expect(opts.renewBeforeDays).toBe(14);
    expect(opts.project).toBe("team-a");
  });

  it("renders the validity window as a formatted timestamp, not epoch millis", async () => {
    await run(["issue", "web", "--domains", "example.com", "--email", "ops@example.com"]);

    const printed = logSpy.mock.calls.flat().join("\n");
    expect(printed).toContain(new Date(STATUS.not_after as number).toISOString().slice(0, 10));
    expect(printed).not.toContain(String(STATUS.not_after));
  });

  it("--json prints the exact issuance result", async () => {
    await run(["issue", "web", "--domains", "example.com", "--email", "ops@example.com", "--json"]);

    const printed = JSON.parse(logSpy.mock.calls[0]?.[0] as string) as Record<string, unknown>;
    expect(printed).toEqual(ISSUED);
  });

  it("--dns supplies a callback that prints the TXT record to stderr and waits for Enter", async () => {
    await run(["issue", "web", "--domains", "example.com", "--email", "ops@example.com", "--dns"]);

    const dns01 = issueOptions().dns01;
    expect(typeof dns01).toBe("function");

    errorSpy.mockClear();
    await dns01?.("example.com", "txt-value");

    const written = errorSpy.mock.calls.flat().join("\n");
    expect(written).toContain("_acme-challenge.example.com TXT txt-value");
    // The stdin wait is what makes dns-01 interactive: without it the command
    // would tell the CA to validate a record nobody has published yet.
    expect(mockPromptHidden).toHaveBeenCalledTimes(1);
  });

  it("the dns-01 TXT record never reaches stdout", async () => {
    await run([
      "issue",
      "web",
      "--domains",
      "example.com",
      "--email",
      "ops@example.com",
      "--dns",
      "--json",
    ]);

    logSpy.mockClear();
    await issueOptions().dns01?.("example.com", "txt-value");

    expect(logSpy).not.toHaveBeenCalled();
  });

  it("--dns paired with --http-port is refused rather than silently dropping the port", async () => {
    // dns-01 never starts the http-01 responder, so the port would be dead
    // configuration — the same silent-drop the csr --bits/--curve check rules out.
    await expect(
      run([
        "issue",
        "web",
        "--domains",
        "example.com",
        "--email",
        "ops@example.com",
        "--dns",
        "--http-port",
        "8080",
      ]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("--http-port only applies to the http-01 challenge"),
    );
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
    expect(mockIssueWithAcme).not.toHaveBeenCalled();
  });

  it("a missing --domains is refused by commander before the vault opens", async () => {
    await expect(run(["issue", "web", "--email", "ops@example.com"])).rejects.toThrow(
      /required option '--domains/,
    );
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
    expect(mockIssueWithAcme).not.toHaveBeenCalled();
  });

  it("a missing --email is refused by commander before the vault opens", async () => {
    await expect(run(["issue", "web", "--domains", "example.com"])).rejects.toThrow(
      /required option '--email/,
    );
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("an empty --domains is refused before the vault opens", async () => {
    await expect(
      run(["issue", "web", "--domains", "", "--email", "ops@example.com"]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("--domains requires"));
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("an empty entry in --domains is refused rather than silently dropped", async () => {
    await expect(
      run(["issue", "web", "--domains", "example.com,", "--email", "ops@example.com"]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("--domains requires"));
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("an empty --email is refused before the vault opens", async () => {
    await expect(
      run(["issue", "web", "--domains", "example.com", "--email", "  "]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("--email requires"));
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("a non-integer --http-port is refused before the vault opens", async () => {
    await expect(
      run([
        "issue",
        "web",
        "--domains",
        "example.com",
        "--email",
        "ops@example.com",
        "--http-port",
        "80.5",
      ]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('Invalid http-port "80.5"'));
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("an out-of-range --renew-before-days is refused before the vault opens", async () => {
    await expect(
      run([
        "issue",
        "web",
        "--domains",
        "example.com",
        "--email",
        "ops@example.com",
        "--renew-before-days",
        "4000",
      ]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('Invalid renew-before-days "4000"'),
    );
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("--renew-before-days above the engine's 365 ceiling is refused before the vault opens", async () => {
    await expect(
      run([
        "issue",
        "web",
        "--domains",
        "example.com",
        "--email",
        "ops@example.com",
        "--renew-before-days",
        "366",
      ]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('Invalid renew-before-days "366"'),
    );
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("a sealed vault fails before any ACME traffic", async () => {
    vi.mocked(loadUnlockedEngine).mockRejectedValueOnce(VaultError.vaultLocked());

    await expect(
      run(["issue", "web", "--domains", "example.com", "--email", "ops@example.com"]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("Vault is locked"));
    expect(mockIssueWithAcme).not.toHaveBeenCalled();
  });

  it("a token without 'create' is refused before any ACME traffic", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));

    await expect(
      run([
        "issue",
        "web",
        "--domains",
        "example.com",
        "--email",
        "ops@example.com",
        "--token",
        "jwt-value",
      ]),
    ).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("Token lacks permission: create"),
    );
    expect(mockIssueWithAcme).not.toHaveBeenCalled();
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });

  it("a token with 'create' issues and attributes the audit rows to its principal", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["create"] }));

    await run([
      "issue",
      "web",
      "--domains",
      "example.com",
      "--email",
      "ops@example.com",
      "--token",
      "jwt-value",
    ]);

    expect(mockEngine.verifyToken).toHaveBeenCalledWith("jwt-value");
    expect(issueOptions().caller).toEqual({
      principal_type: "agent",
      principal_id: "agent-1",
      interface: "cli",
    });
  });

  it("passes no caller on the trusted local path, keeping the rows NULL-principal", async () => {
    await run(["issue", "web", "--domains", "example.com", "--email", "ops@example.com"]);

    expect(issueOptions().caller).toBeUndefined();
  });

  it("an ambient HARPOC_TOKEN is honoured when --token is absent", async () => {
    process.env.HARPOC_TOKEN = "ambient-jwt";
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["create"] }));

    await run(["issue", "web", "--domains", "example.com", "--email", "ops@example.com"]);

    expect(mockEngine.verifyToken).toHaveBeenCalledWith("ambient-jwt");
  });

  it("--json renders a manager refusal as a JSON error envelope", async () => {
    mockIssueWithAcme.mockRejectedValue(
      VaultError.certAcmeFailed("order finished with status invalid"),
    );

    await expect(
      run(["issue", "web", "--domains", "example.com", "--email", "ops@example.com", "--json"]),
    ).rejects.toThrow("process.exit");

    const envelope = JSON.parse(errorSpy.mock.calls[0]?.[0] as string) as Record<string, unknown>;
    expect(envelope.error).toBe("CERT_ACME_FAILED");
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });
});

describe("cert renew", () => {
  it("resolves the handle to a secret id and prints the refreshed status", async () => {
    await run(["renew", "secret://web"]);

    expect(resolveSecretId).toHaveBeenCalledWith(mockEngine, "secret://web");
    expect(mockCertManager).toHaveBeenCalledWith(mockEngine);
    expect(mockRenewCertificate.mock.calls[0]?.[0]).toBe("secret-id-1");

    const printed = logSpy.mock.calls.flat().join("\n");
    expect(printed).toContain("secret://web");
    expect(printed).toContain("CN=example.com");
    expect(printed).toContain("ok");
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it("renders the validity window as a formatted timestamp, not epoch millis", async () => {
    await run(["renew", "secret://web"]);

    const printed = logSpy.mock.calls.flat().join("\n");
    expect(printed).toContain(new Date(STATUS.not_after as number).toISOString().slice(0, 10));
    expect(printed).not.toContain(String(STATUS.not_after));
  });

  it("--json prints the exact refreshed CertificateStatus", async () => {
    await run(["renew", "secret://web", "--json"]);

    const printed = JSON.parse(logSpy.mock.calls[0]?.[0] as string) as Record<string, unknown>;
    expect(printed).toEqual(STATUS);
  });

  it("forwards --http-port to the challenge responder", async () => {
    await run(["renew", "secret://web", "--http-port", "8080"]);

    expect(renewOptions().httpPort).toBe(8080);
  });

  it("a non-integer --http-port is refused before the vault opens", async () => {
    await expect(run(["renew", "secret://web", "--http-port", "eighty"])).rejects.toThrow(
      "process.exit",
    );

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('Invalid http-port "eighty"'));
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
    expect(mockRenewCertificate).not.toHaveBeenCalled();
  });

  it("a token with 'rotate' renews and threads the caller into the manager", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["rotate"] }));

    await run(["renew", "secret://web", "--token", "jwt-value"]);

    expect(mockEngine.verifyToken).toHaveBeenCalledWith("jwt-value");
    // Threading the caller is what makes the engine apply per-secret access
    // policies to the renewal reads and the write (Task 12).
    expect(renewOptions().caller).toEqual({
      principal_type: "agent",
      principal_id: "agent-1",
      interface: "cli",
    });
    expect(renewOptions().handle).toBe("secret://web");
  });

  it("a read-only token is denied with ACCESS_DENIED before the renewal runs", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));

    await expect(run(["renew", "secret://web", "--token", "jwt-value"])).rejects.toThrow(
      "process.exit",
    );

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("ACCESS_DENIED"));
    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("Token lacks permission: rotate"),
    );
    expect(mockRenewCertificate).not.toHaveBeenCalled();
    expect(resolveSecretId).not.toHaveBeenCalled();
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });

  it("passes no caller on the trusted local path", async () => {
    await run(["renew", "secret://web"]);

    expect(renewOptions().caller).toBeUndefined();
    expect(renewOptions().handle).toBe("secret://web");
  });

  it("an ambient HARPOC_TOKEN is honoured when --token is absent", async () => {
    process.env.HARPOC_TOKEN = "ambient-jwt";
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["rotate"] }));

    await run(["renew", "secret://web"]);

    expect(mockEngine.verifyToken).toHaveBeenCalledWith("ambient-jwt");
  });

  it("a sealed vault fails before any ACME traffic", async () => {
    vi.mocked(loadUnlockedEngine).mockRejectedValueOnce(VaultError.vaultLocked());

    await expect(run(["renew", "secret://web"])).rejects.toThrow("process.exit");

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("Vault is locked"));
    expect(mockRenewCertificate).not.toHaveBeenCalled();
  });

  it("--json renders a manager refusal as a JSON error envelope", async () => {
    mockRenewCertificate.mockRejectedValue(
      VaultError.certAcmeFailed("no ACME account for this certificate"),
    );

    await expect(run(["renew", "secret://web", "--json"])).rejects.toThrow("process.exit");

    const envelope = JSON.parse(errorSpy.mock.calls[0]?.[0] as string) as Record<string, unknown>;
    expect(envelope.error).toBe("CERT_ACME_FAILED");
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });
});
