import type { McpServer } from "@modelcontextprotocol/server";
import type { CertManager } from "@harpoc/cert-manager";
import type { VaultEngine } from "@harpoc/core";
import type { Permission } from "@harpoc/shared";
import { AuditEventType, parseHandle } from "@harpoc/shared";
import type { RateLimiter } from "../guards/rate-limiter.js";
import type { ScopeGuard } from "../guards/scope-guard.js";
import { RENEW_CERTIFICATE_TOOL } from "./definitions.js";

const PERMISSION: Permission = "rotate";

export function registerRenewCertificate(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
  rateLimiter: RateLimiter,
  certManager: CertManager,
): void {
  server.registerTool(RENEW_CERTIFICATE_TOOL.name, RENEW_CERTIFICATE_TOOL.config, async (args) => {
    const parsed = parseHandle(args.handle);
    scopeGuard.checkAccess(PERMISSION, parsed.project, parsed.name, "renew_certificate");
    rateLimiter.checkLimit(args.handle);
    const secretId = await engine.resolveSecretId(
      args.handle,
      scopeGuard.caller,
      AuditEventType.CERT_RENEW,
    );
    const status = await certManager.renewCertificate(secretId, {
      caller: scopeGuard.caller,
      handle: args.handle,
    });
    return { content: [{ type: "text" as const, text: JSON.stringify(status, null, 2) }] };
  });
}
