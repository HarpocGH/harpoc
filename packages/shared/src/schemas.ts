import { z } from "zod";

import { MAX_NAME_LENGTH, MAX_PROCESS_ARGS } from "./constants.js";
import { isValidHandle } from "./handle.js";
import {
  ActionType,
  AuditEventType,
  DatabaseEngine,
  FollowRedirects,
  GitOperation,
  InjectionType,
  McpTransport,
  OAuthGrantType,
  OAuthProviderPreset,
  Permission,
  PrincipalType,
  ResponseMode,
  SecretStatus,
  SecretType,
  VaultState,
} from "./types.js";

// ---------------------------------------------------------------------------
// Single source of truth: every externally-supplied shape (REST bodies, MCP
// tool inputs, CLI args, files read from disk) is validated against a schema
// below, and its TypeScript type is derived from that schema via z.infer —
// the validator and the type cannot drift apart. Enum value sets come from
// the const objects in types.ts, which the z.enum schemas are built from.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Enum schemas (derived from const objects in types.ts)
// ---------------------------------------------------------------------------

const secretTypeValues = Object.values(SecretType) as [SecretType, ...SecretType[]];
export const secretTypeSchema = z.enum(secretTypeValues);

const secretStatusValues = Object.values(SecretStatus) as [SecretStatus, ...SecretStatus[]];
export const secretStatusSchema = z.enum(secretStatusValues);

const permissionValues = Object.values(Permission) as [Permission, ...Permission[]];
export const permissionSchema = z.enum(permissionValues);

const auditEventTypeValues = Object.values(AuditEventType) as [AuditEventType, ...AuditEventType[]];
export const auditEventTypeSchema = z.enum(auditEventTypeValues);

const principalTypeValues = Object.values(PrincipalType) as [PrincipalType, ...PrincipalType[]];
export const principalTypeSchema = z.enum(principalTypeValues);

const injectionTypeValues = Object.values(InjectionType) as [InjectionType, ...InjectionType[]];
export const injectionTypeSchema = z.enum(injectionTypeValues);

const followRedirectsValues = Object.values(FollowRedirects) as [
  FollowRedirects,
  ...FollowRedirects[],
];
export const followRedirectsSchema = z.enum(followRedirectsValues);

const responseModeValues = Object.values(ResponseMode) as [ResponseMode, ...ResponseMode[]];
export const responseModeSchema = z.enum(responseModeValues);

const vaultStateValues = Object.values(VaultState) as [VaultState, ...VaultState[]];
export const vaultStateSchema = z.enum(vaultStateValues);

// ---------------------------------------------------------------------------
// Handle schema
// ---------------------------------------------------------------------------

export const handleSchema = z.string().refine(isValidHandle, { message: "Invalid secret handle" });

// ---------------------------------------------------------------------------
// Injection config schema
// ---------------------------------------------------------------------------

export const injectionConfigSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal(InjectionType.BEARER) }),
  z.object({ type: z.literal(InjectionType.BASIC_AUTH) }),
  z.object({
    type: z.literal(InjectionType.HEADER),
    header_name: z
      .string()
      .min(1)
      .regex(/^[a-zA-Z0-9\-_]+$/, "Invalid header name characters"),
  }),
  z.object({
    type: z.literal(InjectionType.QUERY),
    query_param: z.string().min(1),
  }),
]);

/** How a secret value is injected into an HTTP request. */
export type InjectionConfig = z.infer<typeof injectionConfigSchema>;

// ---------------------------------------------------------------------------
// Input validation schemas (API boundaries: REST bodies, MCP inputs, CLI args)
// ---------------------------------------------------------------------------

const namePattern = z
  .string()
  .regex(/^[a-zA-Z0-9_-]+$/, "Invalid name format")
  .max(MAX_NAME_LENGTH);

export const createSecretInputSchema = z.object({
  name: namePattern,
  type: secretTypeSchema,
  project: namePattern.optional(),
  value: z.string().base64().optional(),
  expires_at: z.number().int().positive().optional(),
});

/**
 * Create-secret request body (wire shape): the binary secret value travels
 * base64-encoded; `expires_at` is epoch milliseconds.
 */
export type CreateSecretRequest = z.infer<typeof createSecretInputSchema>;

export const httpMethodSchema = z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]);

export type HttpMethod = z.infer<typeof httpMethodSchema>;

// ---------------------------------------------------------------------------
// use_secret action schemas (thesis §4.5: two-mechanism injection taxonomy)
// ---------------------------------------------------------------------------

/**
 * URL whose scheme must be http(s). Not https-only at the schema layer:
 * core's validateUrl legitimately allows loopback HTTP and the schema must
 * never be stricter than the enforcement layer it fronts — but javascript:,
 * file:, ftp: et al. are rejected at the boundary instead of one layer down.
 */
const httpishUrlSchema = z
  .string()
  .url()
  .refine((value) => /^https?:\/\//i.test(value), {
    message: "URL scheme must be http or https",
  });

const MAX_HTTP_HEADER_COUNT = 64;
const MAX_HTTP_HEADER_VALUE_LENGTH = 8192;

/**
 * Caller-supplied HTTP headers: names share the injection header_name charset,
 * values are capped and must not smuggle CR/LF/NUL (header-injection defense
 * at the boundary, even though undici also refuses them).
 */
const httpHeadersSchema = z
  .record(
    z
      .string()
      .min(1)
      .max(256)
      .regex(/^[a-zA-Z0-9\-_]+$/, "Invalid header name characters"),
    z
      .string()
      .max(MAX_HTTP_HEADER_VALUE_LENGTH)
      .refine((value) => !/[\r\n\0]/.test(value), {
        message: "Header value must not contain CR, LF or NUL",
      }),
  )
  .refine((headers) => Object.keys(headers).length <= MAX_HTTP_HEADER_COUNT, {
    message: `At most ${MAX_HTTP_HEADER_COUNT} headers are allowed`,
  });

/**
 * HTTP action — request-mediated injection. The vault assembles an outbound
 * HTTP request with the credential placed in a structured field.
 */
export const httpActionSchema = z.object({
  type: z.literal(ActionType.HTTP),
  method: httpMethodSchema,
  url: httpishUrlSchema,
  headers: httpHeadersSchema.optional(),
  body: z.string().optional(),
  injection: injectionConfigSchema,
  follow_redirects: followRedirectsSchema.optional(),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
  response_mode: responseModeSchema.optional(),
});

export type HttpAction = z.infer<typeof httpActionSchema>;

/**
 * Process action — process-mediated injection. The vault spawns a subprocess
 * with the credential placed in its environment under `env_var`. The command
 * and args are passed as data; no shell interpretation is performed.
 */
export const processActionSchema = z.object({
  type: z.literal(ActionType.PROCESS),
  command: z.string().min(1).max(4096),
  args: z.array(z.string().max(4096)).max(MAX_PROCESS_ARGS).optional(),
  working_directory: z.string().min(1).max(4096).optional(),
  env_var: z
    .string()
    .min(1)
    .regex(/^[A-Za-z_][A-Za-z0-9_]*$/, "Invalid environment variable name"),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
});

export type ProcessAction = z.infer<typeof processActionSchema>;

/**
 * MCP action — the vault acts as a transparent MCP proxy, forwarding a single
 * tool call to the downstream MCP server named by `server`. The transport and
 * launch/endpoint configuration come from the secret's McpServerConfig (trusted
 * admin path), never from the action.
 */
export const mcpActionSchema = z.object({
  type: z.literal(ActionType.MCP),
  server: z
    .string()
    .regex(/^[a-zA-Z0-9_-]+$/, "Invalid server name format")
    .max(MAX_NAME_LENGTH),
  tool: z.string().min(1).max(MAX_NAME_LENGTH),
  arguments: z.record(z.unknown()).optional(),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
});

export type McpAction = z.infer<typeof mcpActionSchema>;

const databaseEngineValues = Object.values(DatabaseEngine) as [DatabaseEngine, ...DatabaseEngine[]];
export const databaseEngineSchema = z.enum(databaseEngineValues);

const gitOperationValues = Object.values(GitOperation) as [GitOperation, ...GitOperation[]];
export const gitOperationSchema = z.enum(gitOperationValues);

/** Host or host:port (no scheme). IPv6 literals are out of scope — use a hostname. */
const hostPattern = z
  .string()
  .min(1)
  .max(2048)
  .regex(/^[a-zA-Z0-9._-]+(:\d{1,5})?$/, "Invalid host format")
  .refine(
    (value) => {
      const colon = value.lastIndexOf(":");
      if (colon < 0) return true;
      const port = parseInt(value.slice(colon + 1), 10);
      return port >= 1 && port <= 65_535;
    },
    { message: "Port must be between 1 and 65535" },
  );

/**
 * Database action — request-mediated injection. The vault assembles the
 * connection string in-process (the credential is the secret, `user:password`),
 * connects with TLS by default, executes the query and returns the result set.
 * `host` may embed a port (`host:port`); an explicit `port` overrides it.
 */
export const databaseActionSchema = z.object({
  type: z.literal(ActionType.DATABASE),
  engine: databaseEngineSchema,
  host: hostPattern,
  port: z.number().int().positive().max(65_535).optional(),
  database: z
    .string()
    .min(1)
    .max(255)
    .regex(/^[a-zA-Z0-9_.$-]+$/, "Invalid database name"),
  query: z.string().min(1).max(1_000_000),
  params: z.array(z.unknown()).max(1_000).optional(),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
});

export type DatabaseAction = z.infer<typeof databaseActionSchema>;

/**
 * Git action — request-mediated over HTTPS (credential helper) or process-mediated
 * over SSH (ephemeral ssh-agent), selected by the `repository` transport. The
 * credential never appears in the command output or the agent's context.
 */
export const gitActionSchema = z.object({
  type: z.literal(ActionType.GIT),
  operation: gitOperationSchema,
  repository: z.string().min(1).max(2048),
  args: z.array(z.string().max(4096)).max(MAX_PROCESS_ARGS).optional(),
  working_directory: z.string().min(1).max(4096).optional(),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
});

export type GitAction = z.infer<typeof gitActionSchema>;

/**
 * SSH action — process-mediated injection. The vault spawns `ssh` with the
 * private key served through an ephemeral ssh-agent (signatures only, key never
 * on disk) and strict host-key verification against the pinned known_hosts.
 */
export const sshActionSchema = z.object({
  type: z.literal(ActionType.SSH),
  host: z
    .string()
    .min(1)
    .max(255)
    .regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/, "Invalid host format"),
  user: z
    .string()
    .min(1)
    .max(255)
    .regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/, "Invalid user format"),
  command: z.string().min(1).max(65_536),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
});

export type SshAction = z.infer<typeof sshActionSchema>;

/** Discriminated union over the execution context. */
export const useSecretActionSchema = z.discriminatedUnion("type", [
  httpActionSchema,
  processActionSchema,
  mcpActionSchema,
  databaseActionSchema,
  gitActionSchema,
  sshActionSchema,
]);

/** Discriminated union of context-specific use_secret action specifications. */
export type UseSecretAction = z.infer<typeof useSecretActionSchema>;

export const useSecretRequestSchema = z.object({
  handle: handleSchema,
  action: useSecretActionSchema,
});

/** Request to use a secret via a context-specific action. */
export type UseSecretRequest = z.infer<typeof useSecretRequestSchema>;

/** Per-secret injection policy input (URL + host + command + env allowlists + HTTP response mode). */
export const injectionPolicyInputSchema = z.object({
  url_allowlist: z.array(z.string().min(1).max(2048)).max(100).optional().default([]),
  command_allowlist: z.array(z.string().min(1).max(4096)).max(100).optional().default([]),
  env_allowlist: z
    .array(z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/, "Invalid environment variable name"))
    .max(100)
    .optional()
    .default([]),
  host_allowlist: z.array(z.string().min(1).max(2048)).max(100).optional().default([]),
  response_mode: responseModeSchema.optional().default(ResponseMode.FILTERED),
  response_header_allowlist: z
    .array(
      z
        .string()
        .min(1)
        .max(256)
        .regex(/^[a-zA-Z0-9\-_]+$/, "Invalid header name characters"),
    )
    .max(100)
    .optional()
    .default([]),
});

/**
 * Per-secret injection policy: allowlists constraining where a credential may
 * be used (thesis §4.7 target allowlisting). `url_allowlist` bounds URL targets
 * (HTTP, Git-over-HTTPS, MCP-over-HTTP); `host_allowlist` bounds host and
 * host:port targets (SSH, Git-over-SSH, database); `command_allowlist` bounds
 * process-mediated binaries; `env_allowlist` names additional environment
 * variables passed through to a spawned subprocess. `response_mode` is the
 * HTTP response shaping floor (default `filtered`; per-invocation overrides
 * may only tighten it, thesis §4.5.2); `response_header_allowlist` names the
 * headers still returned under `status_only`. The schema's output type: all
 * defaults applied, every field present — the shape the vault loads and
 * returns.
 */
export type InjectionPolicy = z.output<typeof injectionPolicyInputSchema>;

/**
 * The policy as callers may supply it: every field optional; the vault (or
 * the schema's defaults) fills in empty allowlists and `filtered` mode.
 */
export type InjectionPolicyInput = z.input<typeof injectionPolicyInputSchema>;

/**
 * PUT injection-policy request body: the policy plus the per-operation
 * interpreter acknowledgement flag (thesis §4.5.3). The flag is a request
 * field, never stored on the policy.
 */
export const setInjectionPolicyRequestSchema = injectionPolicyInputSchema.extend({
  acknowledge_interpreters: z.boolean().optional().default(false),
});

/**
 * Database endpoint-authentication config. TLS is required by default; `disable`
 * is the audited per-secret opt-out for trusted local sockets (thesis §4.5.5).
 */
export const databaseConnectionConfigSchema = z.object({
  tls_mode: z.enum(["require", "disable"]).optional(),
  ca_pem: z.string().min(1).max(65_536).optional(),
  servername: z
    .string()
    .min(1)
    .max(255)
    .regex(/^[a-zA-Z0-9._-]+$/, "Invalid servername")
    .optional(),
});

export type DatabaseConnectionConfig = z.infer<typeof databaseConnectionConfigSchema>;

/** SSH endpoint-authentication config: host keys pinned at secret creation. */
export const sshConnectionConfigSchema = z.object({
  known_hosts: z.array(z.string().min(1).max(4096)).min(1).max(50),
});

export type SshConnectionConfig = z.infer<typeof sshConnectionConfigSchema>;

/**
 * Per-secret endpoint-authentication pins (KEK-encrypted at rest), the §4.7
 * "authenticated target connections" counterpart to the target allowlist. Set
 * only via the trusted admin path (CLI/REST) — never via an MCP tool. `ssh` is
 * shared by the SSH and Git-over-SSH contexts. At least one of `database` /
 * `ssh` must be present.
 */
export const connectionConfigSchema = z
  .object({
    database: databaseConnectionConfigSchema.optional(),
    ssh: sshConnectionConfigSchema.optional(),
  })
  .superRefine((data, ctx) => {
    if (!data.database && !data.ssh) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "connection config must set at least one of database or ssh",
        path: [],
      });
    }
  });

export type ConnectionConfig = z.infer<typeof connectionConfigSchema>;

const mcpTransportValues = Object.values(McpTransport) as [McpTransport, ...McpTransport[]];
export const mcpTransportSchema = z.enum(mcpTransportValues);

/**
 * Per-secret downstream MCP server configuration (trusted admin path only).
 * stdio requires `command` + `env_var`; http requires `url`.
 */
export const mcpServerConfigSchema = z
  .object({
    server_name: z
      .string()
      .regex(/^[a-zA-Z0-9_-]+$/, "Invalid server name format")
      .max(MAX_NAME_LENGTH),
    transport: mcpTransportSchema,
    command: z.string().min(1).max(4096).optional(),
    args: z.array(z.string().max(4096)).max(MAX_PROCESS_ARGS).optional(),
    env_var: z
      .string()
      .regex(/^[A-Za-z_][A-Za-z0-9_]*$/, "Invalid environment variable name")
      .optional(),
    working_directory: z.string().min(1).max(4096).optional(),
    url: httpishUrlSchema.optional(),
  })
  .superRefine((data, ctx) => {
    if (data.transport === McpTransport.STDIO) {
      if (!data.command) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "command is required for stdio transport",
          path: ["command"],
        });
      }
      if (!data.env_var) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "env_var is required for stdio transport",
          path: ["env_var"],
        });
      }
    }
    if (data.transport === McpTransport.HTTP && !data.url) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "url is required for http transport",
        path: ["url"],
      });
    }
  });

/**
 * Per-secret downstream MCP server configuration (KEK-encrypted at rest).
 * Set only via the trusted admin path (CLI/REST) — never via an MCP tool.
 * stdio: `command` + `env_var` required; the launch command is validated
 * against the secret's command allowlist (fail-safe deny) at every use.
 * http: `url` required; validated against the URL allowlist and SSRF checks.
 */
export type McpServerConfig = z.infer<typeof mcpServerConfigSchema>;

export const accessPolicyInputSchema = z.object({
  principal_type: principalTypeSchema,
  principal_id: z.string().min(1),
  permissions: z.array(permissionSchema).min(1),
  expires_at: z.number().int().positive().optional(),
});

/** Access-policy grant request body (principal + permissions). */
export type AccessPolicyInput = z.infer<typeof accessPolicyInputSchema>;

export const auditQuerySchema = z.object({
  secret_id: z.string().uuid().optional(),
  event_type: auditEventTypeSchema.optional(),
  since: z.number().int().nonnegative().optional(),
  until: z.number().int().nonnegative().optional(),
  limit: z.number().int().positive().max(1000).optional(),
});

export const healthResponseSchema = z.object({
  state: vaultStateSchema,
  version: z.string().min(1),
});

/** GET /health response (also the SDK VaultClient.getHealth result). */
export type HealthResponse = z.infer<typeof healthResponseSchema>;

// ---------------------------------------------------------------------------
// Session file schema (for deserializing session.json)
// ---------------------------------------------------------------------------

const base64Pattern = z.string().min(1).base64();

/** How the session file's `session_key` is protected at rest (thesis §4.6 off-host hardening). */
export const sessionKeyProtectionSchemeSchema = z.enum([
  "none",
  "dpapi",
  "keychain",
  "secret-service",
  "keyring",
]);

export type SessionKeyProtectionScheme = z.infer<typeof sessionKeyProtectionSchemeSchema>;

export const sessionFileSchema = z.object({
  version: z.literal(1),
  session_id: z.string().min(1),
  vault_id: z.string().min(1),
  created_at: z.number().int().positive(),
  expires_at: z.number().int().positive(),
  max_expires_at: z.number().int().positive(),
  /** Scheme wrapping `session_key`; absent means "none" (files written before this field existed). */
  key_protection: sessionKeyProtectionSchemeSchema.optional(),
  session_key: base64Pattern,
  wrapped_kek: base64Pattern,
  wrapped_kek_iv: base64Pattern,
  wrapped_kek_tag: base64Pattern,
  wrapped_jwt_key: base64Pattern,
  wrapped_jwt_key_iv: base64Pattern,
  wrapped_jwt_key_tag: base64Pattern,
  wrapped_audit_key: base64Pattern,
  wrapped_audit_key_iv: base64Pattern,
  wrapped_audit_key_tag: base64Pattern,
});

/** Session file persisted at ~/.harpoc/session.json (all binary values base64-encoded). */
export type SessionFile = z.infer<typeof sessionFileSchema>;

// ---------------------------------------------------------------------------
// Audit-chain anchor
// ---------------------------------------------------------------------------

export const AUDIT_CHAIN_ANCHOR_FORMAT = "harpoc-audit-anchor/1";

/**
 * Exportable audit-chain tail link. Comparing a stored anchor against the
 * live chain detects tail truncation and database rollback — attacks the
 * chain HMACs alone cannot see, since a shorter chain is still valid.
 * The anchor holds no sensitive material (`row_hmac` is stored in plaintext
 * in the database); its value comes entirely from being stored OFF-HOST.
 */
export const auditChainAnchorSchema = z
  .object({
    format: z.literal(AUDIT_CHAIN_ANCHOR_FORMAT),
    vault_id: z.string().min(1),
    last_id: z.number().int().positive(),
    /** Informational — the row's chain HMAC already covers its timestamp; verification compares only `row_hmac`. */
    timestamp: z.number().int().positive(),
    row_hmac: z.string().regex(/^[0-9a-f]{64}$/, "must be 64 lowercase hex characters"),
  })
  .strict();

export type AuditChainAnchor = z.infer<typeof auditChainAnchorSchema>;

// ---------------------------------------------------------------------------
// OAuth schemas (v1.1)
// ---------------------------------------------------------------------------

const oauthGrantTypeValues = Object.values(OAuthGrantType) as [OAuthGrantType, ...OAuthGrantType[]];
export const oauthGrantTypeSchema = z.enum(oauthGrantTypeValues);

const oauthProviderPresetValues = Object.values(OAuthProviderPreset) as [
  OAuthProviderPreset,
  ...OAuthProviderPreset[],
];
export const oauthProviderPresetSchema = z.enum(oauthProviderPresetValues);

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

// Mirrors core's validateUrl SSRF policy: HTTPS anywhere, plain HTTP for loopback only.
const oauthEndpointUrlSchema = z
  .string()
  .url()
  .refine((value) => {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      return false;
    }
    return (
      url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname))
    );
  }, "URL must use HTTPS (plain HTTP is allowed for loopback only)");

export const oauthProviderConfigSchema = z
  .object({
    provider: oauthProviderPresetSchema,
    grant_type: oauthGrantTypeSchema,
    token_endpoint: oauthEndpointUrlSchema,
    auth_endpoint: oauthEndpointUrlSchema.optional(),
    device_authorization_endpoint: oauthEndpointUrlSchema.optional(),
    client_id: z.string().min(1),
    client_secret: z.string().min(1).optional(),
    token_endpoint_auth_method: z.enum(["client_secret_post", "client_secret_basic"]).optional(),
    scopes: z.array(z.string().min(1)).optional(),
    redirect_uri: z.string().url().optional(),
    pkce_method: z.literal("S256").optional(),
  })
  .superRefine((data, ctx) => {
    if (data.grant_type === OAuthGrantType.AUTHORIZATION_CODE && !data.auth_endpoint) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "auth_endpoint is required for authorization_code grant type",
        path: ["auth_endpoint"],
      });
    }
    if (data.grant_type === OAuthGrantType.DEVICE_CODE && !data.device_authorization_endpoint) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "device_authorization_endpoint is required for device_code grant type",
        path: ["device_authorization_endpoint"],
      });
    }
  });

/** OAuth provider configuration (stored alongside secret). */
export type OAuthProviderConfig = z.infer<typeof oauthProviderConfigSchema>;

export const startOAuthFlowInputSchema = z.object({
  name: namePattern,
  provider: oauthProviderPresetSchema,
  grant_type: oauthGrantTypeSchema,
  client_id: z.string().min(1),
  client_secret: z.string().min(1).optional(),
  token_endpoint_auth_method: z.enum(["client_secret_post", "client_secret_basic"]).optional(),
  scopes: z.array(z.string().min(1)).optional(),
  project: namePattern.optional(),
  auth_endpoint: oauthEndpointUrlSchema.optional(),
  token_endpoint: oauthEndpointUrlSchema.optional(),
  device_authorization_endpoint: oauthEndpointUrlSchema.optional(),
});

// ---------------------------------------------------------------------------
// Certificate schemas (v1.1)
// ---------------------------------------------------------------------------

const pemPattern = z
  .string()
  .min(1)
  .refine((s) => s.startsWith("-----BEGIN "), "Value must be PEM-encoded");

export const certificateImportSchema = z.object({
  name: namePattern,
  private_key_pem: pemPattern,
  certificate_pem: pemPattern.optional(),
  chain_pem: pemPattern.optional(),
  project: namePattern.optional(),
  auto_renew: z.boolean().optional().default(false),
  renew_before_days: z.number().int().positive().max(365).optional().default(30),
});
