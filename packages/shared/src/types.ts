// ---------------------------------------------------------------------------
// Domain enums (as const objects — idiomatic with Zod, works with verbatimModuleSyntax)
// ---------------------------------------------------------------------------

export const SecretType = {
  API_KEY: "api_key",
  OAUTH_TOKEN: "oauth_token",
  CERTIFICATE: "certificate",
} as const;
export type SecretType = (typeof SecretType)[keyof typeof SecretType];

export const SecretStatus = {
  ACTIVE: "active",
  PENDING: "pending",
  EXPIRED: "expired",
  REVOKED: "revoked",
} as const;
export type SecretStatus = (typeof SecretStatus)[keyof typeof SecretStatus];

export const Permission = {
  LIST: "list",
  READ: "read",
  USE: "use",
  CREATE: "create",
  ROTATE: "rotate",
  REVOKE: "revoke",
  ADMIN: "admin",
} as const;
export type Permission = (typeof Permission)[keyof typeof Permission];

export const AuditEventType = {
  VAULT_UNLOCK: "vault.unlock",
  VAULT_LOCK: "vault.lock",
  VAULT_PASSWORD_CHANGE: "vault.password_change",
  SECRET_CREATE: "secret.create",
  SECRET_READ: "secret.read",
  SECRET_USE: "secret.use",
  SECRET_ROTATE: "secret.rotate",
  SECRET_EXPIRE: "secret.expire",
  SECRET_REVOKE: "secret.revoke",
  SECRET_DELETE: "secret.delete",
  POLICY_GRANT: "policy.grant",
  POLICY_REVOKE: "policy.revoke",
  POLICY_INTERPRETER_REFUSED: "policy.interpreter_refused",
  POLICY_INTERPRETER_ACKNOWLEDGED: "policy.interpreter_acknowledged",
  OAUTH_AUTHORIZE: "oauth.authorize",
  OAUTH_CALLBACK: "oauth.callback",
  OAUTH_REFRESH: "oauth.refresh",
  CERT_ISSUE: "cert.issue",
  CERT_RENEW: "cert.renew",
  CERT_REVOKE: "cert.revoke",
  TOKEN_CREATE: "token.create",
  TOKEN_REVOKE: "token.revoke",
  SYNC_PUSH: "sync.push",
  SYNC_PULL: "sync.pull",
  SYNC_CONFLICT: "sync.conflict",
  ACCESS_DENIED: "access.denied",
  MCP_SPAWN: "mcp.spawn",
  MCP_CRASH: "mcp.crash",
  MCP_TERMINATE: "mcp.terminate",
} as const;
export type AuditEventType = (typeof AuditEventType)[keyof typeof AuditEventType];

export const PrincipalType = {
  AGENT: "agent",
  TOOL: "tool",
  PROJECT: "project",
  USER: "user",
} as const;
export type PrincipalType = (typeof PrincipalType)[keyof typeof PrincipalType];

/**
 * Principal types a token can be issued to (thesis §4.6 access control).
 * `project` is deliberately absent: a project principal is derived from the
 * token's `project` claim, never issued as an identity of its own.
 */
export const TokenPrincipalType = {
  AGENT: "agent",
  TOOL: "tool",
  USER: "user",
} as const;
export type TokenPrincipalType = (typeof TokenPrincipalType)[keyof typeof TokenPrincipalType];

export const InjectionType = {
  HEADER: "header",
  QUERY: "query",
  BASIC_AUTH: "basic_auth",
  BEARER: "bearer",
} as const;
export type InjectionType = (typeof InjectionType)[keyof typeof InjectionType];

export const FollowRedirects = {
  SAME_ORIGIN: "same-origin",
  NONE: "none",
  ANY: "any",
} as const;
export type FollowRedirects = (typeof FollowRedirects)[keyof typeof FollowRedirects];

/**
 * HTTP response shaping mode (thesis §4.5.2). `status_only` removes the
 * response body structurally — the echo channel is absent, not filtered.
 */
export const ResponseMode = {
  FULL: "full",
  FILTERED: "filtered",
  STATUS_ONLY: "status_only",
} as const;
export type ResponseMode = (typeof ResponseMode)[keyof typeof ResponseMode];

/** Execution context selected by a use_secret action's discriminant. */
export const ActionType = {
  HTTP: "http",
  PROCESS: "process",
  MCP: "mcp",
  DATABASE: "database",
  GIT: "git",
  SSH: "ssh",
} as const;
export type ActionType = (typeof ActionType)[keyof typeof ActionType];

/** Transport of a downstream MCP server: spawned stdio child or Streamable HTTP endpoint. */
export const McpTransport = {
  STDIO: "stdio",
  HTTP: "http",
} as const;
export type McpTransport = (typeof McpTransport)[keyof typeof McpTransport];

/** SQL engine of a database action. The `engine` field keeps the taxonomy open. */
export const DatabaseEngine = {
  POSTGRESQL: "postgresql",
  MYSQL: "mysql",
} as const;
export type DatabaseEngine = (typeof DatabaseEngine)[keyof typeof DatabaseEngine];

/** Git operation forwarded to the spawned git binary. */
export const GitOperation = {
  CLONE: "clone",
  PULL: "pull",
  PUSH: "push",
} as const;
export type GitOperation = (typeof GitOperation)[keyof typeof GitOperation];

export const VaultState = {
  SEALED: "sealed",
  UNLOCKED: "unlocked",
} as const;
export type VaultState = (typeof VaultState)[keyof typeof VaultState];

// ---------------------------------------------------------------------------
// OAuth & Certificate enums (v1.1)
// ---------------------------------------------------------------------------

/** OAuth grant types supported by the proxy. */
export const OAuthGrantType = {
  AUTHORIZATION_CODE: "authorization_code",
  CLIENT_CREDENTIALS: "client_credentials",
  DEVICE_CODE: "device_code",
} as const;
export type OAuthGrantType = (typeof OAuthGrantType)[keyof typeof OAuthGrantType];

/** Provider preset names. */
export const OAuthProviderPreset = {
  GITHUB: "github",
  GOOGLE: "google",
  MICROSOFT: "microsoft",
  SLACK: "slack",
  CUSTOM: "custom",
} as const;
export type OAuthProviderPreset = (typeof OAuthProviderPreset)[keyof typeof OAuthProviderPreset];

// ---------------------------------------------------------------------------
// Domain interfaces (v1.0 scope)
// ---------------------------------------------------------------------------

/** Encrypted secret record — maps to the `secrets` SQLite table. */
export interface Secret {
  id: string;
  name_encrypted: Uint8Array;
  name_iv: Uint8Array;
  name_tag: Uint8Array;
  type: SecretType;
  project: string | null;
  wrapped_dek: Uint8Array;
  dek_iv: Uint8Array;
  dek_tag: Uint8Array;
  ciphertext: Uint8Array;
  ct_iv: Uint8Array;
  ct_tag: Uint8Array;
  metadata_encrypted: Uint8Array | null;
  metadata_iv: Uint8Array | null;
  metadata_tag: Uint8Array | null;
  created_at: number;
  updated_at: number;
  expires_at: number | null;
  rotated_at: number | null;
  version: number;
  status: SecretStatus;
  sync_version: number;
  name_hmac: string | null;
}

/** Per-secret access control — maps to the `access_policies` SQLite table. */
export interface AccessPolicy {
  id: string;
  secret_id: string;
  principal_type: PrincipalType;
  principal_id: string;
  permissions: Permission[];
  created_at: number;
  expires_at: number | null;
  created_by: string;
}

/** Audit log entry — maps to the `audit_log` SQLite table. */
export interface AuditEvent {
  id: number;
  timestamp: number;
  event_type: AuditEventType;
  secret_id: string | null;
  principal_type: PrincipalType | null;
  principal_id: string | null;
  detail_encrypted: Uint8Array | null;
  detail_iv: Uint8Array | null;
  detail_tag: Uint8Array | null;
  ip_address: string | null;
  session_id: string | null;
  success: boolean;
}

/** JWT claims for vault API tokens. */
export interface VaultApiToken {
  sub: string;
  vault_id: string;
  scope: Permission[];
  iat: number;
  exp: number;
  jti: string;
  project?: string;
  /** Secret-name patterns (`*` wildcards, thesis §4.7); absent = unrestricted. */
  secrets?: string[];
  /** Principal type for per-secret policy matching; absent = "agent". */
  principal_type?: TokenPrincipalType;
}

/**
 * Access interface a token-authenticated request arrived through — the
 * "through which interface" dimension of the audit trail (thesis §4.3.4).
 * Forensic attribution only; never consulted by policy matching.
 */
export type AccessInterface = "rest" | "mcp" | "mcp-http";

/**
 * Token-derived caller identity threaded from an interface layer into the
 * engine for per-secret access-policy enforcement (thesis §4.6). An absent
 * caller marks the trusted local path (CLI, in-process SDK) — administrative
 * access that is not subject to per-secret policies (thesis §4.7 split).
 */
export interface CallerContext {
  principal_type: TokenPrincipalType;
  principal_id: string;
  /** Token project claim; derives an additional (project, <claim>) principal. */
  project?: string;
  /** Interface the request arrived through; audit attribution only. */
  interface?: AccessInterface;
}

/** Result of a request-mediated (HTTP) use_secret invocation. */
export interface HttpResult {
  type: typeof ActionType.HTTP;
  status: number | null;
  headers?: Record<string, string>;
  body?: string;
  error?: string;
  redirect_warning?: string;
}

/** Result of a process-mediated use_secret invocation. */
export interface ProcessResult {
  type: typeof ActionType.PROCESS;
  exit_code: number | null;
  stdout: string;
  stderr: string;
  timed_out?: boolean;
  truncated?: boolean;
  signal?: string;
  error?: string;
}

/** Result of an MCP-proxied use_secret invocation (sanitized downstream tool result). */
export interface McpResult {
  type: typeof ActionType.MCP;
  content: unknown[];
  structured_content?: Record<string, unknown>;
  is_error?: boolean;
  truncated?: boolean;
}

/** Result of a request-mediated (database) use_secret invocation. */
export interface DatabaseResult {
  type: typeof ActionType.DATABASE;
  row_count: number;
  rows: unknown[];
  fields?: { name: string }[];
  command?: string;
  truncated?: boolean;
  error?: string;
}

/** Result of a Git use_secret invocation (captured, sanitized git output). */
export interface GitResult {
  type: typeof ActionType.GIT;
  operation: GitOperation;
  exit_code: number | null;
  stdout: string;
  stderr: string;
  timed_out?: boolean;
  truncated?: boolean;
  signal?: string;
  error?: string;
}

/** Result of an SSH use_secret invocation (captured, sanitized remote output). */
export interface SshResult {
  type: typeof ActionType.SSH;
  exit_code: number | null;
  stdout: string;
  stderr: string;
  timed_out?: boolean;
  truncated?: boolean;
  signal?: string;
  error?: string;
}

/** Response from use_secret — discriminated by execution mechanism. */
export type UseSecretResponse =
  | HttpResult
  | ProcessResult
  | McpResult
  | DatabaseResult
  | GitResult
  | SshResult;

/**
 * Options for the trusted-admin injection-policy set path.
 * `acknowledge_interpreters` is the thesis §4.5.3 acknowledgement flag: adding
 * a known interpreter binary to `command_allowlist` collapses the L2/L3
 * capability-ladder split for that secret, so the vault refuses the addition
 * without it and audits both outcomes. A per-operation flag — never stored on
 * the policy.
 */
export interface SetInjectionPolicyOptions {
  acknowledge_interpreters?: boolean;
}

/** Argon2id key derivation parameters — stored in vault header. */
export interface KeyDerivationParams {
  algorithm: "argon2id";
  version: number;
  memory_cost: number;
  time_cost: number;
  parallelism: number;
  salt: Uint8Array;
  hash_length: number;
}

/** Wildcard-capable access scope for policies. */
export interface AccessScope {
  projects: string[] | "*";
  agents: string[] | "*";
  tools: string[] | "*";
  permissions: Permission[];
}

/** Result of parsing a secret handle. */
export interface ParsedHandle {
  name: string;
  project?: string;
}

/** Response after creating a secret. */
export interface CreateSecretResponse {
  handle: string;
  status: "created" | "pending";
  message: string;
}

// ---------------------------------------------------------------------------
// OAuth & Certificate interfaces (v1.1)
// ---------------------------------------------------------------------------

/** OAuth token state stored in vault (encrypted). */
export interface OAuthTokenRecord {
  secret_id: string;
  provider: OAuthProviderPreset;
  grant_type: OAuthGrantType;
  token_endpoint: string;
  auth_endpoint: string | null;
  scopes: string | null;
  access_token_expires_at: number | null;
  redirect_uri: string | null;
  pkce_method: string;
}

/** Certificate record stored in vault. */
export interface CertificateRecord {
  secret_id: string;
  subject: string;
  issuer: string | null;
  serial_number: string | null;
  not_before: number | null;
  not_after: number | null;
  certificate_pem: string | null;
  chain_pem: string | null;
  csr_pem: string | null;
  auto_renew: boolean;
  renew_before_days: number;
}

/** Status of an OAuth token (for health checks and UI). */
export interface OAuthTokenStatus {
  secret_id: string;
  provider: OAuthProviderPreset;
  has_access_token: boolean;
  access_token_expires_at: number | null;
  has_refresh_token: boolean;
  last_refreshed_at: number | null;
  refresh_status: "ok" | "expiring_soon" | "expired" | "no_refresh_token";
  /** Client auth at the token endpoint; null = legacy row, refreshes as client_secret_post. */
  token_endpoint_auth_method: "client_secret_post" | "client_secret_basic" | null;
}

/** Status of a certificate (for health checks and UI). */
export interface CertificateStatus {
  secret_id: string;
  subject: string;
  issuer: string | null;
  not_before: number | null;
  not_after: number | null;
  auto_renew: boolean;
  renewal_status: "ok" | "expiring_soon" | "expired" | "no_certificate";
}

/** start_oauth_flow response. */
export interface OAuthFlowResult {
  handle: string;
  status: "authorized" | "pending_authorization";
  auth_url?: string;
  user_code?: string;
  message: string;
}
