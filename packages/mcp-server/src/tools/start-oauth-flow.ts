import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { VaultEngine } from "@harpoc/core";
import type { Permission, StartOAuthFlowInput } from "@harpoc/shared";
import { oauthGrantTypeSchema, oauthProviderPresetSchema } from "@harpoc/shared";
import { providerConfigFromFlowInput } from "@harpoc/oauth-proxy";
import type { OAuthManager } from "@harpoc/oauth-proxy";
import { collectValueFromTty } from "../elicitation/tty-prompt.js";
import { collectValueViaUrlElicitation } from "../elicitation/value-collector.js";
import type { RateLimiter } from "../guards/rate-limiter.js";
import type { ScopeGuard } from "../guards/scope-guard.js";

const PERMISSION: Permission = "create";

function text(payload: unknown): { content: [{ type: "text"; text: string }] } {
  return { content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }] };
}

export function registerStartOauthFlow(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
  rateLimiter: RateLimiter,
  oauthManager: OAuthManager,
  enableTtyPrompt = false,
): void {
  server.tool(
    "start_oauth_flow",
    "Create an OAuth provider secret. No client secret is accepted or returned — a confidential client's secret is collected out-of-band, and the browser authorization leg is completed via the CLI. Tokens never pass through the LLM.",
    {
      name: z
        .string()
        .regex(/^[a-zA-Z0-9_-]+$/)
        .describe("Secret name"),
      provider: oauthProviderPresetSchema.describe("Provider preset (or custom)"),
      grant_type: oauthGrantTypeSchema.describe("OAuth grant type"),
      client_id: z.string().min(1).describe("OAuth client id (public metadata)"),
      token_endpoint_auth_method: z.enum(["client_secret_post", "client_secret_basic"]).optional(),
      scopes: z.array(z.string().min(1)).optional(),
      project: z
        .string()
        .regex(/^[a-zA-Z0-9_-]+$/)
        .optional(),
      auth_endpoint: z.string().url().optional(),
      token_endpoint: z.string().url().optional(),
      device_authorization_endpoint: z.string().url().optional(),
    },
    async (args) => {
      scopeGuard.checkAccess(PERMISSION, args.project, args.name);
      rateLimiter.checkLimit(`create:${args.project ?? ""}/${args.name}`);
      const input: StartOAuthFlowInput = { ...args };

      if (args.grant_type === "authorization_code") {
        const { config, project } = providerConfigFromFlowInput(input);
        const { handle } = await engine.createOAuthSecret(
          args.name,
          config,
          project,
          scopeGuard.caller,
        );
        return text({
          handle,
          status: "pending_authorization",
          message:
            `OAuth secret created (PENDING). Complete the browser authorization with: ` +
            `harpoc oauth connect ${args.name} --provider ${args.provider} --client-id ${args.client_id}`,
        });
      }

      if (args.grant_type === "device_code") {
        const { config, project } = providerConfigFromFlowInput(input);
        const device = await oauthManager.startDeviceCode(
          args.name,
          config,
          project,
          scopeGuard.caller,
        );
        // Never serialize `completion` (a Promise) into the result.
        return text({
          handle: device.handle,
          status: device.status,
          auth_url: device.auth_url,
          user_code: device.user_code,
          message: device.message,
        });
      }

      // client_credentials — config-then-collect: the PENDING secret exists either way.
      const { config, project } = providerConfigFromFlowInput(input);
      const { handle } = await engine.createOAuthSecret(
        args.name,
        config,
        project,
        scopeGuard.caller,
      );
      const subject = `${args.name} (OAuth client secret)`;
      let secretBytes = await collectValueViaUrlElicitation(server, {
        subject,
        operation: "create",
      });
      if (secretBytes === null && enableTtyPrompt) {
        secretBytes = await collectValueFromTty({ subject, operation: "create" });
      }
      if (!secretBytes) {
        return text({
          handle,
          status: "pending",
          message:
            `No out-of-band channel was available to collect the client secret. Complete with: ` +
            `harpoc oauth connect ${args.name} --client-credentials --provider ${args.provider} --client-id ${args.client_id}`,
        });
      }
      let clientSecret: string;
      try {
        clientSecret = Buffer.from(secretBytes).toString("utf8");
      } finally {
        secretBytes.fill(0);
      }
      const resolved = providerConfigFromFlowInput({ ...input, client_secret: clientSecret });
      const result = await oauthManager.startClientCredentials(
        args.name,
        resolved.config,
        resolved.project,
        scopeGuard.caller,
      );
      return text({ handle: result.handle, status: result.status, message: result.message });
    },
  );
}
