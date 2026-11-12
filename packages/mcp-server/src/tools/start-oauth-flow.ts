import type { McpServer } from "@modelcontextprotocol/server";
import type { VaultEngine } from "@harpoc/core";
import type { Permission, StartOAuthFlowInput } from "@harpoc/shared";
import { providerConfigFromFlowInput, startOAuthFlowResult } from "@harpoc/oauth-proxy";
import type { OAuthManager } from "@harpoc/oauth-proxy";
import { collectValueFromTty } from "../elicitation/tty-prompt.js";
import { collectValueViaUrlElicitation } from "../elicitation/value-collector.js";
import type { RateLimiter } from "../guards/rate-limiter.js";
import type { ScopeGuard } from "../guards/scope-guard.js";
import { START_OAUTH_FLOW_TOOL, oauthConnectCommand } from "./definitions.js";

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
  server.registerTool(START_OAUTH_FLOW_TOOL.name, START_OAUTH_FLOW_TOOL.config, async (args) => {
    scopeGuard.checkAccess(PERMISSION, args.project, args.name, "start_oauth_flow");
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
          oauthConnectCommand(args),
      });
    }

    if (args.grant_type === "device_code") {
      // Shared arm (oauth-proxy): the projection never serializes `completion`.
      return text(await startOAuthFlowResult(oauthManager, input, scopeGuard.caller));
    }

    // client_credentials — collect-then-create: a declined collection creates nothing.
    providerConfigFromFlowInput(input);
    const subject = `${args.name} (OAuth client secret)`;
    let secretBytes = await collectValueViaUrlElicitation(server, {
      subject,
      operation: "create",
      principal: scopeGuard.principalBinding,
    });
    if (secretBytes === null && enableTtyPrompt) {
      secretBytes = await collectValueFromTty({ subject, operation: "create" });
    }
    if (!secretBytes) {
      return text({
        status: "not_created",
        message:
          `No out-of-band channel was available to collect the client secret, so nothing was created. Create it with: ` +
          oauthConnectCommand(args),
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
  });
}
