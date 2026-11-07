import type { Command } from "commander";
import { loadUnlockedEngine, resolveVaultDir } from "../../utils/vault-loader.js";
import { handleError, printJson, printRecord } from "../../utils/output.js";

export function registerUnlockKeyStatusCommand(unlockKey: Command): void {
  unlockKey
    .command("status")
    .description(
      "Show whether a machine-bound unlock key is enrolled, and since when (needs an unlocked vault; prints no key material)",
    )
    .option("--json", "Output as JSON")
    .action(async (options: { json?: boolean }, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const status = await engine.unlockKeyStatus();
          if (options.json) {
            printJson(status);
          } else {
            printRecord({
              Enrolled: status.enrolled ? "yes" : "no",
              "Enrolled at": status.enrolledAt,
            });
          }
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
