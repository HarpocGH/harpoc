import { Hono } from "hono";
import {
  VaultError,
  callerFromToken,
  certificateImportSchema,
  generateCsrRequestSchema,
  renewCertificateRequestSchema,
  isEncryptedPrivateKeyPem,
  ENCRYPTED_KEY_IMPORT_REFUSAL,
} from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";
import { checkTokenScope, buildHandle, parseHandleParam } from "../middleware/scope.js";
import { readJsonBody } from "../utils/read-json-body.js";

export function createCertificateRoutes(): Hono<HarpocEnv> {
  const router = new Hono<HarpocEnv>();

  router.post("/import", async (c) => {
    const token = c.get("token");
    checkTokenScope(token, "create");
    const body = await readJsonBody(c);
    const parsed = certificateImportSchema.safeParse(body);
    if (!parsed.success) {
      throw VaultError.schemaValidation(parsed.error.issues.map((i) => i.message).join(", "));
    }
    checkTokenScope(token, "create", parsed.data.project, parsed.data.name);
    if (isEncryptedPrivateKeyPem(parsed.data.private_key_pem)) {
      throw VaultError.schemaValidation(ENCRYPTED_KEY_IMPORT_REFUSAL);
    }
    const ref = await c.get("certManager").importCertificate(parsed.data.name, {
      privateKeyPem: parsed.data.private_key_pem,
      certificatePem: parsed.data.certificate_pem,
      chainPem: parsed.data.chain_pem,
      project: parsed.data.project,
      autoRenew: parsed.data.auto_renew,
      renewBeforeDays: parsed.data.renew_before_days,
      caller: callerFromToken(token, "rest"),
    });
    return c.json({ data: { handle: ref.handle, secret_id: ref.secretId } }, 201);
  });

  router.post("/csr", async (c) => {
    const token = c.get("token");
    checkTokenScope(token, "create");
    const body = await readJsonBody(c);
    const parsed = generateCsrRequestSchema.safeParse(body);
    if (!parsed.success) {
      throw VaultError.schemaValidation(parsed.error.issues.map((i) => i.message).join(", "));
    }
    checkTokenScope(token, "create", parsed.data.project, parsed.data.name);
    const r = await c.get("certManager").generateCsr(parsed.data.name, {
      commonName: parsed.data.subject,
      sans: parsed.data.sans,
      algorithm: parsed.data.algorithm ?? "ec",
      modulusLength: parsed.data.bits,
      namedCurve: parsed.data.curve,
      project: parsed.data.project,
      caller: callerFromToken(token, "rest"),
    });
    return c.json({ data: { handle: r.handle, csr_pem: r.csrPem } }, 201);
  });

  router.post("/:handle/renew", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "rotate", project, name);
    const body = await readJsonBody(c);
    const parsed = renewCertificateRequestSchema.safeParse(body);
    if (!parsed.success) {
      throw VaultError.schemaValidation(parsed.error.issues.map((i) => i.message).join(", "));
    }
    const engine = c.get("engine");
    const secretId = await engine.resolveSecretId(buildHandle(c.req.param("handle")));
    c.get("limiter").checkSecret(secretId);
    const status = await c.get("certManager").renewCertificate(secretId, {
      httpPort: parsed.data.http_port,
      caller: callerFromToken(token, "rest"),
    });
    return c.json({ data: status });
  });

  router.get("/:handle/status", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "read", project, name);
    const engine = c.get("engine");
    const secretId = await engine.resolveSecretId(buildHandle(c.req.param("handle")));
    c.get("limiter").checkSecret(secretId);
    const status = engine.getCertificateStatus(secretId, callerFromToken(token, "rest"));
    return c.json({ data: status });
  });

  return router;
}
