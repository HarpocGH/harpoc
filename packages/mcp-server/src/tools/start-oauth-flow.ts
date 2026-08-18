import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { VaultEngine } from "@harpoc/core";
import type { Permission, StartOAuthFlowInput } from "@harpoc/shared";
import { startOAuthFlowInputSchema } from "@harpoc/shared";
import { providerConfigFromFlowInput, startOAuthFlowResult } from "@harpoc/oauth-proxy";
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
      // The shared field schemas, so the advertised contract IS the enforced
      // one (name-length cap, HTTPS-or-loopback endpoints) — `client_secret`
      // is deliberately absent (D1: config-then-defer).
      name: startOAuthFlowInputSchema.shape.name.describe("Secret name"),
      provider: startOAuthFlowInputSchema.shape.provider.describe("Provider preset (or custom)"),
      grant_type: startOAuthFlowInputSchema.shape.grant_type.describe("OAuth grant type"),
      client_id: startOAuthFlowInputSchema.shape.client_id.describe(
        "OAuth client id (public metadata)",
      ),
      token_endpoint_auth_method: startOAuthFlowInputSchema.shape.token_endpoint_auth_method,
      scopes: startOAuthFlowInputSchema.shape.scopes,
      project: startOAuthFlowInputSchema.shape.project,
      auth_endpoint: startOAuthFlowInputSchema.shape.auth_endpoint,
      token_endpoint: startOAuthFlowInputSchema.shape.token_endpoint,
      device_authorization_endpoint: startOAuthFlowInputSchema.shape.device_authorization_endpoint,
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
        // Shared arm (oauth-proxy): the projection never serializes `completion`.
        return text(await startOAuthFlowResult(oauthManager, input, scopeGuard.caller));
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
      // Buffer.from(Uint8Array) copies — the copy holds the credential too.
      const decodeCopy = Buffer.from(secretBytes);
      try {
        clientSecret = decodeCopy.toString("utf8");
      } finally {
        decodeCopy.fill(0);
        secretBytes.fill(0);
      }
      // Shared arm (oauth-proxy): projects handle/status/message only.
      const result = await startOAuthFlowResult(
        oauthManager,
        { ...input, client_secret: clientSecret },
        scopeGuard.caller,
      );
      return text(result);
    },
  );
}
