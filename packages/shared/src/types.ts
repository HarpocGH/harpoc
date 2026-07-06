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

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD";

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

/** Session file persisted at ~/.harpoc/session.json (all binary values base64-encoded). */
export interface SessionFile {
  version: 1;
  session_id: string;
  vault_id: string;
  created_at: number;
  expires_at: number;
  max_expires_at: number;
  session_key: string;
  wrapped_kek: string;
  wrapped_kek_iv: string;
  wrapped_kek_tag: string;
  wrapped_jwt_key: string;
  wrapped_jwt_key_iv: string;
  wrapped_jwt_key_tag: string;
  wrapped_audit_key: string;
  wrapped_audit_key_iv: string;
  wrapped_audit_key_tag: string;
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
}

/** How a secret value is injected into an HTTP request. */
export interface InjectionConfig {
  type: InjectionType;
  header_name?: string;
  query_param?: string;
}

/**
 * HTTP action — request-mediated injection. The vault assembles an outbound
 * HTTP request with the credential placed in a structured field.
 */
export interface HttpAction {
  type: typeof ActionType.HTTP;
  method: HttpMethod;
  url: string;
  headers?: Record<string, string>;
  body?: string;
  injection: InjectionConfig;
  follow_redirects?: FollowRedirects;
  timeout_ms?: number;
  response_mode?: ResponseMode;
}

/**
 * Process action — process-mediated injection. The vault spawns a subprocess
 * with the credential placed in its environment under `env_var`. The command
 * and args are passed as data; no shell interpretation is performed.
 */
export interface ProcessAction {
  type: typeof ActionType.PROCESS;
  command: string;
  args?: string[];
  working_directory?: string;
  env_var: string;
  timeout_ms?: number;
}

/**
 * MCP action — the vault acts as a transparent MCP proxy, forwarding a single
 * tool call to the downstream MCP server named by `server`. The transport and
 * launch/endpoint configuration come from the secret's McpServerConfig (trusted
 * admin path), never from the action.
 */
export interface McpAction {
  type: typeof ActionType.MCP;
  server: string;
  tool: string;
  arguments?: Record<string, unknown>;
  timeout_ms?: number;
}

/**
 * Database action — request-mediated injection. The vault assembles the
 * connection string in-process (the credential is the secret, `user:password`),
 * connects with TLS by default, executes the query and returns the result set.
 * `host` may embed a port (`host:port`); an explicit `port` overrides it.
 */
export interface DatabaseAction {
  type: typeof ActionType.DATABASE;
  engine: DatabaseEngine;
  host: string;
  port?: number;
  database: string;
  query: string;
  params?: unknown[];
  timeout_ms?: number;
}

/**
 * Git action — request-mediated over HTTPS (credential helper) or process-mediated
 * over SSH (ephemeral ssh-agent), selected by the `repository` transport. The
 * credential never appears in the command output or the agent's context.
 */
export interface GitAction {
  type: typeof ActionType.GIT;
  operation: GitOperation;
  repository: string;
  args?: string[];
  working_directory?: string;
  timeout_ms?: number;
}

/**
 * SSH action — process-mediated injection. The vault spawns `ssh` with the
 * private key served through an ephemeral ssh-agent (signatures only, key never
 * on disk) and strict host-key verification against the pinned known_hosts.
 */
export interface SshAction {
  type: typeof ActionType.SSH;
  host: string;
  user: string;
  command: string;
  timeout_ms?: number;
}

/** Discriminated union of context-specific use_secret action specifications. */
export type UseSecretAction =
  | HttpAction
  | ProcessAction
  | McpAction
  | DatabaseAction
  | GitAction
  | SshAction;

/** Request to use a secret via a context-specific action. */
export interface UseSecretRequest {
  handle: string;
  action: UseSecretAction;
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
 * Per-secret injection policy: allowlists constraining where a credential may
 * be used (thesis §4.7 target allowlisting). `url_allowlist` bounds URL targets
 * (HTTP, Git-over-HTTPS, MCP-over-HTTP); `host_allowlist` bounds host and
 * host:port targets (SSH, Git-over-SSH, database); `command_allowlist` bounds
 * process-mediated binaries; `env_allowlist` names additional environment
 * variables passed through to a spawned subprocess. `response_mode` is the
 * HTTP response shaping floor (default `filtered`; per-invocation overrides
 * may only tighten it, thesis §4.5.2); `response_header_allowlist` names the
 * headers still returned under `status_only`. Both are optional — absent on
 * older policy blobs — and defaulted by the loader.
 */
export interface InjectionPolicy {
  url_allowlist: string[];
  command_allowlist: string[];
  env_allowlist: string[];
  host_allowlist: string[];
  response_mode?: ResponseMode;
  response_header_allowlist?: string[];
}

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

/**
 * Database endpoint-authentication config. TLS is required by default; `disable`
 * is the audited per-secret opt-out for trusted local sockets (thesis §4.5.5).
 */
export interface DatabaseConnectionConfig {
  tls_mode?: "require" | "disable";
  ca_pem?: string;
  servername?: string;
}

/** SSH endpoint-authentication config: host keys pinned at secret creation. */
export interface SshConnectionConfig {
  known_hosts: string[];
}

/**
 * Per-secret endpoint-authentication pins (KEK-encrypted at rest), the §4.7
 * "authenticated target connections" counterpart to the target allowlist. Set
 * only via the trusted admin path (CLI/REST) — never via an MCP tool. `ssh` is
 * shared by the SSH and Git-over-SSH contexts.
 */
export interface ConnectionConfig {
  database?: DatabaseConnectionConfig;
  ssh?: SshConnectionConfig;
}

/**
 * Per-secret downstream MCP server configuration (KEK-encrypted at rest).
 * Set only via the trusted admin path (CLI/REST) — never via an MCP tool.
 * stdio: `command` + `env_var` required; the launch command is validated
 * against the secret's command allowlist (fail-safe deny) at every use.
 * http: `url` required; validated against the URL allowlist and SSRF checks.
 */
export interface McpServerConfig {
  server_name: string;
  transport: McpTransport;
  command?: string;
  args?: string[];
  env_var?: string;
  working_directory?: string;
  url?: string;
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

/** OAuth provider configuration (stored alongside secret). */
export interface OAuthProviderConfig {
  provider: OAuthProviderPreset;
  grant_type: OAuthGrantType;
  token_endpoint: string;
  auth_endpoint?: string;
  device_authorization_endpoint?: string;
  client_id: string;
  client_secret?: string;
  scopes?: string[];
  redirect_uri?: string;
  pkce_method?: "S256";
}

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
