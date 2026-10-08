import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ErrorCode, SecretStatus, SecretType } from "@harpoc/shared";
import type { CertificateStatus } from "@harpoc/shared";
import { createEngine, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { registerCertImportCommand } from "./import.js";
import { registerCertStatusCommand } from "./status.js";
import { buildCli, spyCli, type CliSpies } from "../../__fixtures__/cli-harness.js";
import { expectVaultError } from "@harpoc/test-utils";

/**
 * `cert import` / `cert status` against a real vault: the mocked-engine suite
 * pins the command wiring, this one pins that the wiring actually produces a
 * CERTIFICATE-typed ACTIVE secret whose status the sibling command renders.
 */

const FIXTURES = fileURLToPath(new URL("../../__fixtures__/certs/", import.meta.url));
const KEY_PATH = join(FIXTURES, "rsa-key.pem");
const CERT_PATH = join(FIXTURES, "rsa-cert.pem");
const TEST_PASSWORD = "test-password-123";

let vaultDir: string;
let spies: CliSpies;

function run(args: string[]): Promise<void> {
  return buildCli(
    (program) => {
      const cert = program.command("cert").description("Manage certificate secrets");
      registerCertImportCommand(cert);
      registerCertStatusCommand(cert);
    },
    ["--vault-dir", vaultDir, "cert"],
  )(args);
}

beforeEach(async () => {
  vaultDir = join(tmpdir(), `harpoc-certcli-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(vaultDir, { recursive: true });
  const setup = createEngine(vaultDir);
  await setup.initVault(TEST_PASSWORD);
  await setup.destroy();

  spies = spyCli();
});

afterEach(() => {
  spies.restore();
  rmSync(vaultDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("cert import / cert status — end to end", () => {
  it("creates an ACTIVE certificate secret and renders its status", async () => {
    await run(["import", "web", "--key", KEY_PATH, "--cert", CERT_PATH]);
    expect(spies.exitSpy).not.toHaveBeenCalled();

    const verify = await loadUnlockedEngine(vaultDir);
    try {
      const info = await verify.getSecretInfo("secret://web");
      expect(info.type).toBe(SecretType.CERTIFICATE);
      expect(info.status).toBe(SecretStatus.ACTIVE);
      // The fixture certificate expires 2036-08-13; the import carries that
      // into the ordinary secret-expiry machinery.
      expect(info.expiresAt).toBe(new Date("2036-08-13T19:46:24Z").getTime());
    } finally {
      await verify.destroy();
    }

    spies.logSpy.mockClear();
    await run(["status", "secret://web", "--json"]);
    const status = JSON.parse(spies.logSpy.mock.calls[0]?.[0] as string) as CertificateStatus;
    expect(status.subject).toBe("CN=fixture.example.com");
    expect(status.issuer).toBe("CN=fixture.example.com");
    expect(status.auto_renew).toBe(false);
    expect(status.renewal_status).toBe("ok");
    expect(status.not_after).toBe(new Date("2036-08-13T19:46:24Z").getTime());
  });

  it("the stored private key is not readable from the certificate status", async () => {
    await run(["import", "web", "--key", KEY_PATH, "--cert", CERT_PATH]);
    spies.logSpy.mockClear();
    spies.errorSpy.mockClear();

    await run(["status", "secret://web"]);

    const written = [...spies.logSpy.mock.calls, ...spies.errorSpy.mock.calls].flat().join("\n");
    expect(written).not.toContain("PRIVATE KEY");
  });

  it("a mismatched key/certificate pair is refused and leaves no secret behind", async () => {
    // The RSA fixture key against the EC fixture certificate.
    await expect(
      run(["import", "web", "--key", KEY_PATH, "--cert", join(FIXTURES, "ec-cert.pem")]),
    ).rejects.toThrow("process.exit");

    expect(spies.errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("CERT_PRIVATE_KEY_MISMATCH"),
    );

    const verify = await loadUnlockedEngine(vaultDir);
    try {
      await expectVaultError(
        () => verify.getSecretInfo("secret://web"),
        ErrorCode.SECRET_NOT_FOUND,
      );
    } finally {
      await verify.destroy();
    }
  });
});
