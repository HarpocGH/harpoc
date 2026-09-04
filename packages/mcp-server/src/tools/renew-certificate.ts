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
    "Renew a certificate secret via ACME (http-01 on the default port 80). Returns certificate metadata; never key material. The challenge responder's port is not selectable here — `harpoc cert renew --http-port` is the only path that selects one.",
    {
      handle: z.string().describe("Secret handle (secret://[project/]name)"),
    },
    async (args) => {
      const parsed = parseHandle(args.handle);
      scopeGuard.checkAccess(PERMISSION, parsed.project, parsed.name);
      rateLimiter.checkLimit(args.handle);
      const secretId = await engine.resolveSecretId(args.handle, scopeGuard.caller);
      const status = await certManager.renewCertificate(secretId, {
        caller: scopeGuard.caller,
        handle: args.handle,
      });
      return { content: [{ type: "text" as const, text: JSON.stringify(status, null, 2) }] };
    },
  );
}
