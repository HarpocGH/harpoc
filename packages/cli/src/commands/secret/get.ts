import type { Command } from "commander";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printRecord, printJson, formatTimestamp } from "../../utils/output.js";
import { resolveTokenCallerForHandle, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";

export function registerSecretGetCommand(secret: Command): void {
  secret
    .command("get <handle>")
    .description("Get secret metadata or value")
    .option("--value", "Show the decrypted secret value")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output as JSON")
    .action(
      async (
        handle: string,
        options: { value?: boolean; token?: string; json?: boolean },
        cmd: Command,
      ) => {
        const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
        try {
          const engine = await loadUnlockedEngine(vaultDir);
          try {
            const resolved = resolveTokenCallerForHandle(
              engine,
              "read",
              handle,
              options.token ?? process.env.HARPOC_TOKEN,
            );
            if (options.value) {
              const value = await engine.getSecretValue(handle, resolved?.caller);
              const text = new TextDecoder().decode(value);
              if (options.json) {
                printJson({ handle, value: text });
              } else {
                // Output raw value to stdout for piping
                process.stdout.write(text);
                // Add newline only if stdout is a TTY
                if (process.stdout.isTTY) process.stdout.write("\n");
              }
            } else {
              const info = await engine.getSecretInfo(handle, resolved?.caller);
              if (options.json) {
                printJson(info);
              } else {
                printRecord({
                  Handle: info.handle,
                  Name: info.name,
                  Type: info.type,
                  Project: info.project ?? "-",
                  Status: info.status,
                  Version: info.version,
                  Created: formatTimestamp(info.createdAt),
                  Updated: formatTimestamp(info.updatedAt),
                  Expires: formatTimestamp(info.expiresAt),
                  Rotated: formatTimestamp(info.rotatedAt),
                });
              }
            }
          } finally {
            await engine.destroy();
          }
        } catch (err) {
          handleError(err, options.json);
        }
      },
    );
}
