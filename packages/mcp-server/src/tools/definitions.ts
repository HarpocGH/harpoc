import { z } from "zod";
import { secretTypeSchema, startOAuthFlowInputSchema, useSecretActionSchema } from "@harpoc/shared";

/**
 * The nine tools' advertised contract — name, description and input schema —
 * in one core-free module: the in-process server (`server.ts`) and the REST
 * bridge (`bridge.ts`) register from the same objects, so `tools/list` cannot
 * drift between them (B1; pinned in `bridge.test.ts`).
 */
export const LIST_SECRETS_TOOL = {
  name: "list_secrets",
  config: {
    description: "List all secrets in the vault (metadata only, never values)",
    inputSchema: z.object({
      project: z.string().optional().describe("Filter by project name"),
      type: z
        .string()
        .optional()
        .describe("Filter by secret type (api_key, oauth_token, certificate)"),
      status: z
        .string()
        .optional()
        .describe("Filter by status (active, pending, expired, revoked)"),
    }),
  },
};

export const GET_SECRET_INFO_TOOL = {
  name: "get_secret_info",
  config: {
    description: "Get metadata for a specific secret (never returns the value)",
    inputSchema: z.object({
      handle: z
        .string()
        .describe("Secret handle (e.g. secret://my-api-key or secret://project/name)"),
    }),
  },
};

export const USE_SECRET_TOOL = {
  name: "use_secret",
  config: {
    description:
      "Use a secret via a context-specific action — an HTTP request, a process execution, a proxied MCP tool call, a database query or command (PostgreSQL, MySQL, Redis or MongoDB), a Git operation, an SSH command, an SMTP send, an IMAP mailbox operation, a WebSocket exchange, an SFTP transfer, or a Docker registry pull/push. The secret value is injected at the execution layer and never exposed.",
    inputSchema: z.object({
      handle: z.string().describe("Secret handle (secret://name)"),
      action: useSecretActionSchema.describe(
        "Action specification. HTTP: {type:'http', method, url, injection, headers?, body?, follow_redirects?, response_mode?}. Process: {type:'process', command, args?, env_var, working_directory?}. MCP: {type:'mcp', server, tool, arguments?}. Database: {type:'database', engine:'postgresql'|'mysql', host, database, query, params?} for SQL, or {type:'database', engine:'redis'|'mongodb', host, database, command} for the key-value/document engines (SQL takes query, redis takes a string-array command, mongodb takes a document command). Git: {type:'git', operation:'clone'|'pull'|'push'|'fetch'|'ls-remote', repository, refspecs?, args?, working_directory?} (refspecs on a fetch only; ls-remote returns the remote's refs). SSH: {type:'ssh', host, user, command, port?}. SMTP: {type:'smtp', host, from, to, subject, text?|html?, cc?, bcc?, headers?, attachments?, security?, port?}. IMAP: {type:'imap', host, mailbox?, operation:{kind:'search'|'fetch'|'store'|'move'|'copy'|'expunge', ...}, port?}. WebSocket: {type:'websocket', url, injection, message?, subprotocols?, collect?, response_mode?}. SFTP: {type:'sftp', host, user, operation:'upload'|'download'|'list', remote_path, local_path?, port?}. Docker registry: {type:'docker_registry', operation:'pull'|'push', image}. HTTP response_mode ('full'|'filtered'|'status_only') may only equal or tighten the secret's policy mode; 'status_only' returns the status code without a body. Target allowlists, the response-mode policy, TLS/host-key pinning, recipient allowlists, read-only mode, strict tree exit and downstream config are set out-of-band via the trusted admin path (CLI/REST), never here.",
      ),
    }),
  },
};

export const CREATE_SECRET_TOOL = {
  name: "create_secret",
  config: {
    description:
      "Create a new secret. The value is collected out-of-band — via a one-time browser form (URL-mode elicitation) when the client supports it, otherwise set separately via CLI. Secret values never pass through the LLM.",
    inputSchema: z.object({
      name: z
        .string()
        .regex(/^[a-zA-Z0-9_-]+$/)
        .describe("Secret name (alphanumeric, hyphens, underscores)"),
      type: secretTypeSchema.describe("Secret type"),
      project: z
        .string()
        .regex(/^[a-zA-Z0-9_-]+$/)
        .optional()
        .describe("Project namespace"),
    }),
  },
};

export const ROTATE_SECRET_TOOL = {
  name: "rotate_secret",
  config: {
    description:
      "Rotate a secret's value. The new value is collected out-of-band — via a one-time browser form (URL-mode elicitation) when the client supports it, otherwise set separately via CLI. Secret values never pass through the LLM.",
    inputSchema: z.object({
      handle: z.string().describe("Secret handle to rotate"),
    }),
  },
};

export const REVOKE_SECRET_TOOL = {
  name: "revoke_secret",
  config: {
    description: "Permanently revoke a secret (cannot be undone)",
    inputSchema: z.object({
      handle: z.string().describe("Secret handle to revoke"),
    }),
  },
};

export const CHECK_SECRET_HEALTH_TOOL = {
  name: "check_secret_health",
  config: {
    description: "Check vault and secret health status",
    inputSchema: z.object({
      handle: z.string().optional().describe("Optional: check a specific secret (omit for all)"),
    }),
  },
};

export const START_OAUTH_FLOW_TOOL = {
  name: "start_oauth_flow",
  config: {
    description:
      "Create an OAuth provider secret. No client secret is accepted or returned — a confidential client's secret is collected out-of-band, and the browser authorization leg is completed via the CLI. Tokens never pass through the LLM.",
    inputSchema: z.object({
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
    }),
  },
};

export const RENEW_CERTIFICATE_TOOL = {
  name: "renew_certificate",
  config: {
    description:
      "Renew a certificate secret via ACME (http-01 on the default port 80). Returns certificate metadata; never key material. The challenge responder's port is not selectable here — `harpoc cert renew --http-port` is the only path that selects one.",
    inputSchema: z.object({
      handle: z.string().describe("Secret handle (secret://[project/]name)"),
    }),
  },
};
