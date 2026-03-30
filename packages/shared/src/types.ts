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
  secrets?: string[];
}

/** Request to execute an HTTP call with an injected secret. */
export interface UseSecretRequest {
  handle: string;
  request: {
    method: HttpMethod;
    url: string;
    headers?: Record<string, string>;
    body?: string;
    timeout_ms?: number;
  };
  injection: InjectionConfig;
  follow_redirects?: FollowRedirects;
}

/** Response from use_secret — either an HTTP response or a transport error. */
export interface UseSecretResponse {
  status: number | null;
  headers?: Record<string, string>;
  body?: string;
  error?: string;
  redirect_warning?: string;
}

/** How a secret value is injected into an HTTP request. */
export interface InjectionConfig {
  type: InjectionType;
  header_name?: string;
  query_param?: string;
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
