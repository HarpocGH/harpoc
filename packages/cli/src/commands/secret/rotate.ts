import type { Command } from "commander";
import { wipeBuffer } from "@harpoc/core";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { resolveSecretValue } from "../../utils/secret-value.js";
import { handleError, printSuccess } from "../../utils/output.js";
import { resolveTokenCallerForHandle, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";

interface SecretRotateOptions {
  fromFile?: string;
  decrypt?: boolean;
  token?: string;
}

export function registerSecretRotateCommand(secret: Command): void {
  secret
    .command("rotate <handle>")
    .description("Rotate a secret value")
    .option("--from-file <path>", "Read the new secret value from a file instead of prompting")
    .option(
      "--no-decrypt",
      "Store encrypted private-key material verbatim instead of decrypting at import",
    )
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .action(async (handle: string, options: SecretRotateOptions, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        // Engine first: a sealed vault must fail before the user types a
        // value or key passphrase, and the resolved plaintext must never
        // exist outside a wiping finally.
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const resolved = resolveTokenCallerForHandle(
            engine,
            "rotate",
            handle,
            options.token ?? process.env.HARPOC_TOKEN,
          );
          const newValue = await resolveSecretValue({
            fromFile: options.fromFile,
            noDecrypt: options.decrypt === false,
            promptMessage: "New secret value: ",
          });
          try {
            await engine.rotateSecret(handle, newValue, resolved?.caller);
            printSuccess(`Secret rotated (${handle})`);
          } finally {
            wipeBuffer(newValue);
          }
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err);
      }
    });
}
