import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { CertManager } from "@harpoc/cert-manager";
import type { VaultEngine } from "@harpoc/core";
import type { Permission } from "@harpoc/shared";
import { parseHandle } from "@harpoc/shared";
import type { RateLimiter } from "../guards/rate-limiter.js";
import type { ScopeGuard } from "../guards/scope-guard.js";

const PERMISSION: Permission = "rotate";

export function registerRenewCertificate(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
  rateLimiter: RateLimiter,
  certManager: CertManager,
): void {
  server.tool(
    "renew_certificate",
    "Renew a certificate secret via ACME (http-01 only). Returns certificate metadata; never key material.",
    {
      handle: z.string().describe("Secret handle (secret://[project/]name)"),
      http_port: z
        .number()
        .int()
        .min(1)
        .max(65535)
        .optional()
        .describe("Port for the http-01 challenge responder (default 80)"),
    },
    async (args) => {
      const parsed = parseHandle(args.handle);
      scopeGuard.checkAccess(PERMISSION, parsed.project, parsed.name);
      const secretId = await engine.resolveSecretId(args.handle);
      rateLimiter.checkLimit(secretId);
      const status = await certManager.renewCertificate(secretId, {
        httpPort: args.http_port,
        caller: scopeGuard.caller,
      });
      return { content: [{ type: "text" as const, text: JSON.stringify(status, null, 2) }] };
    },
  );
}
