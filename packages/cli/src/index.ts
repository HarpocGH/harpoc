#!/usr/bin/env node
export { resolveVaultDir, createEngine, loadUnlockedEngine, resolveSecretId } from "./utils/vault-loader.js";
import { Command } from "commander";
import { registerInitCommand } from "./commands/init.js";
import { registerUnlockCommand } from "./commands/unlock.js";
import { registerLockCommand } from "./commands/lock.js";
import { registerSecretSetCommand } from "./commands/secret/set.js";
import { registerSecretGetCommand } from "./commands/secret/get.js";
import { registerSecretListCommand } from "./commands/secret/list.js";
import { registerSecretRotateCommand } from "./commands/secret/rotate.js";
import { registerSecretDeleteCommand } from "./commands/secret/delete.js";
import { registerAuditCommand } from "./commands/audit.js";
import { registerAuthTokenCommand } from "./commands/auth/token.js";
import { registerAuthRevokeCommand } from "./commands/auth/revoke.js";
import { registerPolicyGrantCommand } from "./commands/policy/grant.js";
import { registerPolicyRevokeCommand } from "./commands/policy/revoke.js";
import { registerPolicyListCommand } from "./commands/policy/list.js";
import { registerServerCommand } from "./commands/server.js";

const program = new Command();

program
  .name("harpoc")
  .description("Secret vault for AI agents")
  .version("0.0.0")
  .option("--vault-dir <path>", "Path to vault directory");

// Top-level commands
registerInitCommand(program);
registerUnlockCommand(program);
registerLockCommand(program);
registerAuditCommand(program);
registerServerCommand(program);

// secret subcommands
const secret = program.command("secret").description("Manage secrets");
registerSecretSetCommand(secret);
registerSecretGetCommand(secret);
registerSecretListCommand(secret);
registerSecretRotateCommand(secret);
registerSecretDeleteCommand(secret);

// auth subcommands
const auth = program.command("auth").description("Manage API tokens");
registerAuthTokenCommand(auth);
registerAuthRevokeCommand(auth);

// policy subcommands
const policy = program.command("policy").description("Manage access policies");
registerPolicyGrantCommand(policy);
registerPolicyRevokeCommand(policy);
registerPolicyListCommand(policy);

program.parse();
