import { z } from "zod";

import { MAX_NAME_LENGTH, MAX_PROCESS_ARGS } from "./constants.js";
import { isValidHandle } from "./handle.js";
import {
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
} from "./types.js";

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
  injection: injectionConfigSchema.optional(),
});

export const httpMethodSchema = z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]);

// ---------------------------------------------------------------------------
// use_secret action schemas (thesis §4.5: two-mechanism injection taxonomy)
// ---------------------------------------------------------------------------

/** HTTP action — request-mediated injection. */
export const httpActionSchema = z.object({
  type: z.literal("http"),
  method: httpMethodSchema,
  url: z.string().url(),
  headers: z.record(z.string()).optional(),
  body: z.string().optional(),
  injection: injectionConfigSchema,
  follow_redirects: followRedirectsSchema.optional(),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
  response_mode: responseModeSchema.optional(),
});

/** Process action — process-mediated injection. `command`/`args` are data, never shell-interpreted. */
export const processActionSchema = z.object({
  type: z.literal("process"),
  command: z.string().min(1).max(4096),
  args: z.array(z.string().max(4096)).max(MAX_PROCESS_ARGS).optional(),
  working_directory: z.string().min(1).max(4096).optional(),
  env_var: z
    .string()
    .min(1)
    .regex(/^[A-Za-z_][A-Za-z0-9_]*$/, "Invalid environment variable name"),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
});

/**
 * MCP action — the vault forwards one tool call to the downstream MCP server
 * named by `server`; transport configuration comes from the secret's
 * McpServerConfig, never from the action.
 */
export const mcpActionSchema = z.object({
  type: z.literal("mcp"),
  server: z
    .string()
    .regex(/^[a-zA-Z0-9_-]+$/, "Invalid server name format")
    .max(MAX_NAME_LENGTH),
  tool: z.string().min(1).max(MAX_NAME_LENGTH),
  arguments: z.record(z.unknown()).optional(),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
});

const databaseEngineValues = Object.values(DatabaseEngine) as [DatabaseEngine, ...DatabaseEngine[]];
export const databaseEngineSchema = z.enum(databaseEngineValues);

const gitOperationValues = Object.values(GitOperation) as [GitOperation, ...GitOperation[]];
export const gitOperationSchema = z.enum(gitOperationValues);

/** Host or host:port (no scheme). IPv6 literals are out of scope — use a hostname. */
const hostPattern = z
  .string()
  .min(1)
  .max(2048)
  .regex(/^[a-zA-Z0-9._-]+(:\d{1,5})?$/, "Invalid host format");

/** Database action — request-mediated injection; connection assembled in-vault. */
export const databaseActionSchema = z.object({
  type: z.literal("database"),
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

/** Git action — transport (HTTPS vs SSH) is derived from `repository` in the injector. */
export const gitActionSchema = z.object({
  type: z.literal("git"),
  operation: gitOperationSchema,
  repository: z.string().min(1).max(2048),
  args: z.array(z.string().max(4096)).max(MAX_PROCESS_ARGS).optional(),
  working_directory: z.string().min(1).max(4096).optional(),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
});

/** SSH action — process-mediated injection via an ephemeral ssh-agent. */
export const sshActionSchema = z.object({
  type: z.literal("ssh"),
  host: z
    .string()
    .min(1)
    .max(255)
    .regex(/^[a-zA-Z0-9._-]+$/, "Invalid host format"),
  user: z
    .string()
    .min(1)
    .max(255)
    .regex(/^[a-zA-Z0-9._-]+$/, "Invalid user format"),
  command: z.string().min(1).max(65_536),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
});

/** Discriminated union over the execution context. */
export const useSecretActionSchema = z.discriminatedUnion("type", [
  httpActionSchema,
  processActionSchema,
  mcpActionSchema,
  databaseActionSchema,
  gitActionSchema,
  sshActionSchema,
]);

export const useSecretRequestSchema = z.object({
  handle: handleSchema,
  action: useSecretActionSchema,
});

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
 * Per-secret endpoint-authentication config input (trusted admin path only).
 * At least one of `database` / `ssh` must be present.
 */
export const connectionConfigSchema = z
  .object({
    database: z
      .object({
        tls_mode: z.enum(["require", "disable"]).optional(),
        ca_pem: z.string().min(1).max(65_536).optional(),
        servername: z
          .string()
          .min(1)
          .max(255)
          .regex(/^[a-zA-Z0-9._-]+$/, "Invalid servername")
          .optional(),
      })
      .optional(),
    ssh: z
      .object({
        known_hosts: z.array(z.string().min(1).max(4096)).min(1).max(50),
      })
      .optional(),
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
    url: z.string().url().optional(),
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

export const accessPolicyInputSchema = z.object({
  principal_type: principalTypeSchema,
  principal_id: z.string().min(1),
  permissions: z.array(permissionSchema).min(1),
  expires_at: z.number().int().positive().optional(),
});

export const auditQuerySchema = z.object({
  secret_id: z.string().uuid().optional(),
  event_type: auditEventTypeSchema.optional(),
  since: z.number().int().nonnegative().optional(),
  until: z.number().int().nonnegative().optional(),
  limit: z.number().int().positive().max(1000).optional(),
});

// ---------------------------------------------------------------------------
// Session file schema (for deserializing session.json)
// ---------------------------------------------------------------------------

const base64Pattern = z.string().min(1).base64();

export const sessionFileSchema = z.object({
  version: z.literal(1),
  session_id: z.string().min(1),
  vault_id: z.string().min(1),
  created_at: z.number().int().positive(),
  expires_at: z.number().int().positive(),
  max_expires_at: z.number().int().positive(),
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

const httpsUrlSchema = z.string().url().startsWith("https://", "URL must use HTTPS");

export const oauthProviderConfigSchema = z
  .object({
    provider: oauthProviderPresetSchema,
    grant_type: oauthGrantTypeSchema,
    token_endpoint: httpsUrlSchema,
    auth_endpoint: httpsUrlSchema.optional(),
    device_authorization_endpoint: httpsUrlSchema.optional(),
    client_id: z.string().min(1),
    client_secret: z.string().min(1).optional(),
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

export const startOAuthFlowInputSchema = z.object({
  name: namePattern,
  provider: oauthProviderPresetSchema,
  grant_type: oauthGrantTypeSchema,
  client_id: z.string().min(1),
  client_secret: z.string().min(1).optional(),
  scopes: z.array(z.string().min(1)).optional(),
  project: namePattern.optional(),
  auth_endpoint: httpsUrlSchema.optional(),
  token_endpoint: httpsUrlSchema.optional(),
  device_authorization_endpoint: httpsUrlSchema.optional(),
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
