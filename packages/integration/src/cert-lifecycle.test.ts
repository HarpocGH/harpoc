import { generateKeyPairSync } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CertManager } from "@harpoc/cert-manager";
import { createMcpServer } from "@harpoc/mcp-server";
import { DirectClient, RestClient } from "@harpoc/sdk";
import { ErrorCode, SecretStatus, SecretType } from "@harpoc/shared";
import type { CertificateStatus } from "@harpoc/shared";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { startTestServer } from "./helpers/rest-helpers.js";
import type { TestServer } from "./helpers/rest-helpers.js";
import { callTool } from "./helpers/mcp-helpers.js";
import { KEY_PEM, CERT_PEM } from "./helpers/cert-fixtures.js";

/**
 * Certificate lifecycle across the wired surfaces (Phase 10): REST import →
 * status, the same status through both SDK clients, REST CSR generation, the
 * MCP renewal refusal on a non-ACME certificate, and the encrypted-key import
 * refusal on REST and in the SDK. Every status response is asserted over its
 * serialized form, because the invariant is about what reaches the wire: a
 * certificate secret holds a private key, and no status projection of it may
 * carry PEM material.
 *
 * One ordered lifecycle over a single vault and one REST server: later tests
 * read the secrets the earlier ones created, so the file runs as a whole.
 */

const PASSWORD = "cert-lifecycle-pw";
const PRINCIPAL = "cert-agent";
const IMPORTED_NAME = "web-cert";
const CSR_NAME = "csr-pending";
const CSR_SUBJECT = "csr.example.com";
const ENCRYPTED_REST_NAME = "enc-rest";
const ENCRYPTED_DIRECT_NAME = "enc-direct";

const FIXTURE_SUBJECT = "CN=fixture.example.com";
const FIXTURE_NOT_AFTER = new Date("2036-08-13T19:46:24Z").getTime();
const PEM_ARMOR = "-----BEGIN";

let vault: TestVault;
let rest: TestServer;
let token: string;
let importedStatus: CertificateStatus;

/**
 * A real passphrase-protected PKCS#8 key: the refusal is detected from the PEM
 * header, so a genuine `node:crypto` export is what proves the path rather
 * than a hand-typed marker.
 */
function encryptedEcPrivateKeyPem(): string {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return privateKey.export({
    type: "pkcs8",
    format: "pem",
    cipher: "aes-256-cbc",
    passphrase: "pw",
  }) as string;
}

function authHeaders(): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

function post(path: string, body: unknown): Promise<Response> {
  return fetch(`${rest.baseUrl}/api/v1/certificates${path}`, {
    method: "POST",
    headers: { ...authHeaders(), "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

/**
 * Every status read sweeps the whole serialized response, not just the fields
 * its caller goes on to assert: the secret this status describes holds a
 * private key, and neither it nor the certificate may ride along on the status
 * projection.
 */
async function getStatus(name: string): Promise<CertificateStatus> {
  const res = await fetch(`${rest.baseUrl}/api/v1/certificates/${name}/status`, {
    headers: authHeaders(),
  });
  expect(res.status).toBe(200);
  const raw = await res.text();
  expect(raw).not.toContain(PEM_ARMOR);
  return (JSON.parse(raw) as { data: CertificateStatus }).data;
}

beforeAll(async () => {
  vault = createTestVault();
  await vault.engine.initVault(PASSWORD);
  rest = startTestServer(vault.engine);
  token = vault.engine.createToken(PRINCIPAL, ["create", "read", "rotate"]);
});

afterAll(async () => {
  await rest.close();
  await destroyTestVault(vault).catch(() => {});
});

describe("certificate lifecycle across REST, SDK and MCP", () => {
  it("1. REST import answers 201 and its status carries the parsed metadata, no PEM", async () => {
    const res = await post("/import", {
      name: IMPORTED_NAME,
      private_key_pem: KEY_PEM,
      certificate_pem: CERT_PEM,
    });

    expect(res.status).toBe(201);
    const created = (await res.json()) as { data: { handle: string; secret_id: string } };
    // Wire names are snake_case: the route projects the manager's camelCase
    // `secretId` onto `secret_id`, the same field name the status route uses.
    expect(Object.keys(created.data).sort()).toEqual(["handle", "secret_id"]);
    expect(created.data.handle).toBe(`secret://${IMPORTED_NAME}`);
    expect(created.data.secret_id).toBe(await vault.engine.resolveSecretId(created.data.handle));

    const status = await getStatus(IMPORTED_NAME);
    importedStatus = status;
    expect(status.secret_id).toBe(created.data.secret_id);
    expect(status.subject).toBe(FIXTURE_SUBJECT);
    expect(status.issuer).toBe(FIXTURE_SUBJECT);
    expect(status.not_after).toBe(FIXTURE_NOT_AFTER);
    expect(status.not_before).toBeLessThan(status.not_after as number);
    expect(status.auto_renew).toBe(false);
    expect(status.renewal_status).toBe("ok");

    const info = await vault.engine.getSecretInfo(created.data.handle);
    expect(info.type).toBe(SecretType.CERTIFICATE);
    expect(info.status).toBe(SecretStatus.ACTIVE);
    expect(info.expiresAt).toBe(FIXTURE_NOT_AFTER);
  });

  it("2. both SDK clients report the same status REST does, and neither leaks PEM", async () => {
    const direct = new DirectClient(vault.engine);
    const directStatus = await direct.getCertificateStatus(`secret://${IMPORTED_NAME}`);
    expect(directStatus).toEqual(importedStatus);

    const restClient = new RestClient({ baseUrl: rest.baseUrl, token });
    const restClientStatus = await restClient.getCertificateStatus(`secret://${IMPORTED_NAME}`);
    expect(restClientStatus).toEqual(importedStatus);

    expect(JSON.stringify(directStatus)).not.toContain(PEM_ARMOR);
    expect(JSON.stringify(restClientStatus)).not.toContain(PEM_ARMOR);
  });

  it("3. REST CSR generation returns the request and leaves the secret PENDING", async () => {
    const res = await post("/csr", { name: CSR_NAME, subject: CSR_SUBJECT });

    expect(res.status).toBe(201);
    const created = (await res.json()) as { data: { handle: string; csr_pem: string } };
    // The response carries the handle and the request, and nothing else — the
    // key the CSR was built from stays in the vault.
    expect(Object.keys(created.data).sort()).toEqual(["csr_pem", "handle"]);
    expect(created.data.handle).toBe(`secret://${CSR_NAME}`);
    // The CSR is public material and is the one payload that legitimately
    // carries PEM armor — it exists to be handed to a CA.
    expect(created.data.csr_pem.startsWith("-----BEGIN CERTIFICATE REQUEST-----")).toBe(true);
    expect(created.data.csr_pem).toContain("-----END CERTIFICATE REQUEST-----");
    expect(created.data.csr_pem).not.toContain("PRIVATE KEY");

    // CSR-only: the subject comes from the request, and there is no validity
    // window until an issued certificate arrives.
    const status = await getStatus(CSR_NAME);
    expect(status.subject).toBe(`CN=${CSR_SUBJECT}`);
    expect(status.issuer).toBeNull();
    expect(status.not_before).toBeNull();
    expect(status.not_after).toBeNull();
    expect(status.renewal_status).toBe("no_certificate");

    const info = await vault.engine.getSecretInfo(`secret://${CSR_NAME}`);
    expect(info.type).toBe(SecretType.CERTIFICATE);
    expect(info.status).toBe(SecretStatus.PENDING);
    expect(info.expiresAt).toBeNull();
  });

  it("4. renewal of the imported certificate is refused — no ACME account to renew against", async () => {
    const mcpServer: McpServer = createMcpServer({
      engine: vault.engine,
      allowTokenless: true,
    });

    const result = await callTool(mcpServer, "renew_certificate", {
      handle: `secret://${IMPORTED_NAME}`,
    });

    expect(result.isError).toBe(true);
    const text = result.content[0]?.text ?? "";
    expect(text).toContain("ACME operation failed");
    expect(text).toContain("no ACME account for this certificate");

    // The tool result carries the message only, so the code is pinned where it
    // is observable: CERT_ACME_FAILED (not CERT_NOT_CONFIGURED) is what
    // CertManager.renewCertificate throws on the no-account path.
    await expect(
      new DirectClient(vault.engine).renewCertificate(`secret://${IMPORTED_NAME}`),
    ).rejects.toMatchObject({ code: ErrorCode.CERT_ACME_FAILED });

    const renewOverRest = await post(`/${IMPORTED_NAME}/renew`, {});
    expect(renewOverRest.status).toBe(502);
    const failure = (await renewOverRest.json()) as { error: string };
    expect(failure.error).toBe(ErrorCode.CERT_ACME_FAILED);

    // A refused renewal changes nothing about the certificate it was asked to
    // replace.
    const status = await getStatus(IMPORTED_NAME);
    expect(status).toEqual(importedStatus);
  });

  it("5. a passphrase-protected key is refused on both write paths, and nothing is created", async () => {
    const res = await post("/import", {
      name: ENCRYPTED_REST_NAME,
      private_key_pem: encryptedEcPrivateKeyPem(),
      certificate_pem: CERT_PEM,
    });

    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string; message: string };
    expect(body.error).toBe(ErrorCode.SCHEMA_VALIDATION_ERROR);
    expect(body.message).toContain("harpoc cert import");
    await expect(vault.engine.resolveSecretId(`secret://${ENCRYPTED_REST_NAME}`)).rejects.toThrow();

    // The SDK's own check, in front of its manager: injecting a real CertManager
    // is what makes "untouched" observable — the refusal must land before any
    // manager call, not be undone by one.
    const manager = new CertManager(vault.engine);
    const importSpy = vi.spyOn(manager, "importCertificate");
    const direct = new DirectClient(vault.engine, { certManager: manager });

    await expect(
      direct.importCertificate(ENCRYPTED_DIRECT_NAME, {
        private_key_pem: encryptedEcPrivateKeyPem(),
        certificate_pem: CERT_PEM,
      }),
    ).rejects.toMatchObject({ code: ErrorCode.SCHEMA_VALIDATION_ERROR });

    expect(importSpy).not.toHaveBeenCalled();
    await expect(
      vault.engine.resolveSecretId(`secret://${ENCRYPTED_DIRECT_NAME}`),
    ).rejects.toThrow();

    // The two refusals are the only writes attempted since test 3, so the
    // vault still holds exactly the imported and the pending secret.
    const names = (await vault.engine.listSecrets()).map((s) => s.name).sort();
    expect(names).toEqual([CSR_NAME, IMPORTED_NAME].sort());
  });
});
