#!/usr/bin/env node
export {
  resolveVaultDir,
  createEngine,
  loadUnlockedEngine,
  resolveSecretId,
} from "./utils/vault-loader.js";
import { Command } from "commander";
import { registerInitCommand } from "./commands/init.js";
import { registerUnlockCommand } from "./commands/unlock.js";
import { registerLockCommand } from "./commands/lock.js";
import { registerSecretSetCommand } from "./commands/secret/set.js";
import { registerSecretGetCommand } from "./commands/secret/get.js";
import { registerSecretListCommand } from "./commands/secret/list.js";
import { registerSecretRotateCommand } from "./commands/secret/rotate.js";
import { registerSecretDeleteCommand } from "./commands/secret/delete.js";
import { registerSecretUseCommand } from "./commands/secret/use.js";
import { registerSecretAllowCommand } from "./commands/secret/allow.js";
import { registerSecretMcpServerCommand } from "./commands/secret/mcp-server.js";
import { registerSecretConnectionCommand } from "./commands/secret/connection.js";
import { registerAuditCommand } from "./commands/audit.js";
import { registerAuthTokenCommand } from "./commands/auth/token.js";
import { registerAuthListCommand } from "./commands/auth/list.js";
import { registerAuthRevokeCommand } from "./commands/auth/revoke.js";
import { registerPolicyGrantCommand } from "./commands/policy/grant.js";
import { registerPolicyRevokeCommand } from "./commands/policy/revoke.js";
import { registerPolicyListCommand } from "./commands/policy/list.js";
import { registerAgentRegisterCommand } from "./commands/agent/register.js";
import { registerAgentListCommand } from "./commands/agent/list.js";
import { registerAgentShowCommand } from "./commands/agent/show.js";
import { registerAgentUpdateCommand } from "./commands/agent/update.js";
import { registerAgentDeactivateCommand } from "./commands/agent/deactivate.js";
import { registerAgentActivateCommand } from "./commands/agent/activate.js";
import { registerAgentDeleteCommand } from "./commands/agent/delete.js";
import { registerAgentPermissionsCommand } from "./commands/agent/permissions.js";
import { registerOAuthConnectCommand } from "./commands/oauth/connect.js";
import { registerOAuthStatusCommand } from "./commands/oauth/status.js";
import { registerOAuthRefreshCommand } from "./commands/oauth/refresh.js";
import { registerOAuthProvidersCommand } from "./commands/oauth/providers.js";
import { registerCertImportCommand } from "./commands/cert/import.js";
import { registerCertStatusCommand } from "./commands/cert/status.js";
import { registerCertCsrCommand } from "./commands/cert/csr.js";
import { registerCertIssueCommand } from "./commands/cert/issue.js";
import { registerCertRenewCommand } from "./commands/cert/renew.js";
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
registerSecretUseCommand(secret);
registerSecretAllowCommand(secret);
registerSecretMcpServerCommand(secret);
registerSecretConnectionCommand(secret);

// auth subcommands
const auth = program.command("auth").description("Manage API tokens");
registerAuthTokenCommand(auth);
registerAuthListCommand(auth);
registerAuthRevokeCommand(auth);

// policy subcommands
const policy = program.command("policy").description("Manage access policies");
registerPolicyGrantCommand(policy);
registerPolicyRevokeCommand(policy);
registerPolicyListCommand(policy);

// agent subcommands
const agent = program.command("agent").description("Manage registered agents");
registerAgentRegisterCommand(agent);
registerAgentListCommand(agent);
registerAgentShowCommand(agent);
registerAgentUpdateCommand(agent);
registerAgentDeactivateCommand(agent);
registerAgentActivateCommand(agent);
registerAgentDeleteCommand(agent);
registerAgentPermissionsCommand(agent);

// oauth subcommands
const oauth = program.command("oauth").description("Connect and manage OAuth provider secrets");
registerOAuthConnectCommand(oauth);
registerOAuthStatusCommand(oauth);
registerOAuthRefreshCommand(oauth);
registerOAuthProvidersCommand(oauth);

// cert subcommands
const cert = program.command("cert").description("Manage certificate secrets");
registerCertImportCommand(cert);
registerCertStatusCommand(cert);
registerCertCsrCommand(cert);
registerCertIssueCommand(cert);
registerCertRenewCommand(cert);

program.parse();
