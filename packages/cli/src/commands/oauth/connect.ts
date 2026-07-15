import type { Command } from "commander";
import { OAuthGrantType } from "@harpoc/shared";
import type { OAuthFlowResult } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printJson, printSuccess } from "../../utils/output.js";
import { promptHidden } from "../../utils/prompt.js";
import { buildOAuthProviderConfig } from "../../utils/oauth-config.js";

function parseIntOption(value: string, label: string, min: number, max: number): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    console.error(`Error: Invalid ${label} "${value}". Must be ${min}-${max}.`);
    process.exit(1);
  }
  return parsed;
}

export function registerOAuthConnectCommand(oauth: Command): void {
  oauth
    .command("connect <name>")
    .description("Create an OAuth secret and run the provider flow (PENDING -> ACTIVE)")
    .option("--provider <preset>", "Provider preset (github | google | microsoft | slack | custom)")
    .option("--client-id <id>", "OAuth client ID")
    .option("--device", "Use the device-code flow (headless)")
    .option("--client-credentials", "Use the client-credentials flow (machine-to-machine)")
    .option("--scopes <list>", "Comma-separated scopes (presets supply defaults)")
    .option("--auth-endpoint <url>", "Authorization endpoint (custom provider)")
    .option("--token-endpoint <url>", "Token endpoint (custom provider)")
    .option("--device-endpoint <url>", "Device authorization endpoint (custom provider)")
    .option("--redirect-uri <url>", "Redirect URI override (default: loopback callback)")
    .option("--auth-method <method>", "Token endpoint auth (client_secret_post | client_secret_basic)")
    .option("-p, --project <project>", "Project scope for the new secret")
    .option("--callback-port <port>", "Loopback callback port (0 = OS-assigned)", "19876")
    .option("--timeout <seconds>", "Authorization wait timeout in seconds", "300")
    .option(
      "--open",
      "Also open the browser automatically (default: only print the authorization URL)",
    )
    .option("--json", "Output as JSON")
    .action(
      async (
        name: string,
        options: {
          provider?: string;
          clientId?: string;
          device?: boolean;
          clientCredentials?: boolean;
          scopes?: string;
          authEndpoint?: string;
          tokenEndpoint?: string;
          deviceEndpoint?: string;
          redirectUri?: string;
          authMethod?: string;
          project?: string;
          callbackPort: string;
          timeout: string;
          open?: boolean;
          json?: boolean;
        },
        cmd: Command,
      ) => {
        try {
          if (options.device && options.clientCredentials) {
            console.error("Error: --device and --client-credentials are mutually exclusive.");
            process.exit(1);
          }

          const callbackPort = parseIntOption(options.callbackPort, "callback port", 0, 65535);
          const timeoutSeconds = parseIntOption(options.timeout, "timeout", 1, 86400);

          const grantType: OAuthGrantType = options.device
            ? OAuthGrantType.DEVICE_CODE
            : options.clientCredentials
              ? OAuthGrantType.CLIENT_CREDENTIALS
              : OAuthGrantType.AUTHORIZATION_CODE;

          // The client secret never travels via argv: an ambient env var wins
          // (HARPOC_TOKEN precedent), otherwise a hidden prompt. Empty = public client.
          let clientSecret: string | undefined = process.env.HARPOC_OAUTH_CLIENT_SECRET;
          if (clientSecret === undefined) {
            clientSecret = await promptHidden("Client secret (leave empty for a public client): ");
          }
          if (clientSecret === "") clientSecret = undefined;
          if (grantType === OAuthGrantType.CLIENT_CREDENTIALS && clientSecret === undefined) {
            console.error(
              "Error: client_credentials requires a client secret. Set HARPOC_OAUTH_CLIENT_SECRET or enter it at the prompt.",
            );
            process.exit(1);
          }

          const { config, project } = buildOAuthProviderConfig(
            name,
            grantType,
            options,
            clientSecret,
          );

          const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
          const engine = await loadUnlockedEngine(vaultDir);
          let onSigint: (() => void) | undefined;
          try {
            const { OAuthManager, defaultOpenBrowser } = await import("@harpoc/oauth-proxy");
            const manager = new OAuthManager(engine, {
              callbackPort,
              callbackTimeoutMs: timeoutSeconds * 1000,
              openBrowser: async (url) => {
                console.error(`Open this URL in your browser to authorize:\n\n  ${url}\n`);
                console.error("Waiting for the authorization callback...");
                if (options.open) await defaultOpenBrowser(url);
              },
            });

            onSigint = (): void => {
              manager.cancelPendingFlows();
              console.error(
                "Cancelled. The secret remains pending - re-run 'oauth connect' or delete it.",
              );
              void engine.destroy().finally(() => process.exit(130));
            };
            process.once("SIGINT", onSigint);

            let result: OAuthFlowResult;
            if (grantType === OAuthGrantType.DEVICE_CODE) {
              const device = await manager.startDeviceCode(name, config, project);
              console.error(`To authorize, visit: ${device.auth_url ?? ""}`);
              console.error(`and enter code: ${device.user_code ?? ""}`);
              console.error("Waiting for authorization...");
              await device.completion;
              result = {
                handle: device.handle,
                status: "authorized",
                message: `OAuth flow completed successfully for ${config.provider}`,
              };
            } else if (grantType === OAuthGrantType.CLIENT_CREDENTIALS) {
              result = await manager.startClientCredentials(name, config, project);
            } else {
              result = await manager.startAuthorizationCode(name, config, project);
            }

            if (options.json) {
              printJson({ handle: result.handle, status: result.status, message: result.message });
            } else {
              printSuccess(`OAuth secret connected: ${result.handle}`);
            }
          } finally {
            if (onSigint) process.removeListener("SIGINT", onSigint);
            await engine.destroy();
          }
        } catch (err) {
          handleError(err, options.json);
        }
      },
    );
}
