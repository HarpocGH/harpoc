import { isTextPart, isVaultText, num, renderVaultText, token, vaultText } from "./error-text.js";
import type { EchoSource, TextPart, VaultText } from "./error-text.js";

// ---------------------------------------------------------------------------
// Error codes and VaultError class
// ---------------------------------------------------------------------------

export enum ErrorCode {
  // Vault state
  VAULT_LOCKED = "VAULT_LOCKED",
  VAULT_NOT_FOUND = "VAULT_NOT_FOUND",
  VAULT_ALREADY_EXISTS = "VAULT_ALREADY_EXISTS",
  VAULT_CORRUPTED = "VAULT_CORRUPTED",

  // Auth
  INVALID_PASSWORD = "INVALID_PASSWORD",
  WEAK_PASSWORD = "WEAK_PASSWORD",
  INVALID_TOKEN = "INVALID_TOKEN",
  TOKEN_EXPIRED = "TOKEN_EXPIRED",
  TOKEN_REVOKED = "TOKEN_REVOKED",
  TOKEN_REQUIRED = "TOKEN_REQUIRED",
  ACCESS_DENIED = "ACCESS_DENIED",
  LOCKOUT_ACTIVE = "LOCKOUT_ACTIVE",

  // Secrets
  SECRET_NOT_FOUND = "SECRET_NOT_FOUND",
  AMBIGUOUS_HANDLE = "AMBIGUOUS_HANDLE",
  DUPLICATE_SECRET = "DUPLICATE_SECRET",
  SECRET_EXPIRED = "SECRET_EXPIRED",
  SECRET_REVOKED = "SECRET_REVOKED",
  INVALID_SECRET_TYPE = "INVALID_SECRET_TYPE",
  SECRET_VALUE_REQUIRED = "SECRET_VALUE_REQUIRED",

  // HTTP injection
  URL_INVALID = "URL_INVALID",
  URL_HTTPS_REQUIRED = "URL_HTTPS_REQUIRED",
  SSRF_BLOCKED = "SSRF_BLOCKED",
  TLS_ERROR = "TLS_ERROR",
  DNS_RESOLUTION_FAILED = "DNS_RESOLUTION_FAILED",
  CONNECTION_REFUSED = "CONNECTION_REFUSED",
  TIMEOUT = "TIMEOUT",
  REDIRECT_POLICY_VIOLATION = "REDIRECT_POLICY_VIOLATION",
  INVALID_INJECTION_CONFIG = "INVALID_INJECTION_CONFIG",
  URL_NOT_ALLOWED = "URL_NOT_ALLOWED",
  RESPONSE_MODE_NOT_ALLOWED = "RESPONSE_MODE_NOT_ALLOWED",
  RESPONSE_TOO_LARGE = "RESPONSE_TOO_LARGE",

  // Process execution
  COMMAND_NOT_ALLOWED = "COMMAND_NOT_ALLOWED",
  PROCESS_SPAWN_FAILED = "PROCESS_SPAWN_FAILED",
  PROCESS_TIMEOUT = "PROCESS_TIMEOUT",
  PROCESS_OUTPUT_LIMIT = "PROCESS_OUTPUT_LIMIT",
  INVALID_PROCESS_CONFIG = "INVALID_PROCESS_CONFIG",
  INTERPRETER_NOT_ACKNOWLEDGED = "INTERPRETER_NOT_ACKNOWLEDGED",
  NETWORK_ISOLATION_UNAVAILABLE = "NETWORK_ISOLATION_UNAVAILABLE",
  FS_ISOLATION_UNAVAILABLE = "FS_ISOLATION_UNAVAILABLE",
  STRICT_TREE_EXIT_UNAVAILABLE = "STRICT_TREE_EXIT_UNAVAILABLE",

  // MCP proxy
  MCP_SERVER_NOT_CONFIGURED = "MCP_SERVER_NOT_CONFIGURED",
  MCP_SERVER_MISMATCH = "MCP_SERVER_MISMATCH",
  MCP_CONNECT_FAILED = "MCP_CONNECT_FAILED",
  MCP_SERVER_CRASHED = "MCP_SERVER_CRASHED",
  MCP_PROTOCOL_ERROR = "MCP_PROTOCOL_ERROR",
  MCP_TIMEOUT = "MCP_TIMEOUT",

  // Database / Git / SSH contexts
  HOST_NOT_ALLOWED = "HOST_NOT_ALLOWED",
  DB_CONNECTION_FAILED = "DB_CONNECTION_FAILED",
  DB_QUERY_FAILED = "DB_QUERY_FAILED",
  DB_TLS_REQUIRED = "DB_TLS_REQUIRED",
  UNSUPPORTED_DB_ENGINE = "UNSUPPORTED_DB_ENGINE",
  INVALID_DATABASE_CONFIG = "INVALID_DATABASE_CONFIG",
  SSH_CONNECT_FAILED = "SSH_CONNECT_FAILED",
  SSH_HOST_KEY_MISMATCH = "SSH_HOST_KEY_MISMATCH",
  SSH_AGENT_FAILED = "SSH_AGENT_FAILED",
  SSH_NOT_CONFIGURED = "SSH_NOT_CONFIGURED",
  INVALID_SSH_CONFIG = "INVALID_SSH_CONFIG",
  SSH_CLIENT_UNSUPPORTED = "SSH_CLIENT_UNSUPPORTED",
  SSH_BOOTSTRAP_NOT_ALLOWED = "SSH_BOOTSTRAP_NOT_ALLOWED",
  SSH_PASSWORD_NOT_OFFERED = "SSH_PASSWORD_NOT_OFFERED",
  SSH_PASSWORD_REFUSED = "SSH_PASSWORD_REFUSED",
  SSH_BOOTSTRAP_STEP_FAILED = "SSH_BOOTSTRAP_STEP_FAILED",
  SSH_BOOTSTRAP_UNCONFIRMED = "SSH_BOOTSTRAP_UNCONFIRMED",
  SSH_BOOTSTRAP_IN_FLIGHT = "SSH_BOOTSTRAP_IN_FLIGHT",
  GIT_OPERATION_FAILED = "GIT_OPERATION_FAILED",
  GIT_UNSUPPORTED_TRANSPORT = "GIT_UNSUPPORTED_TRANSPORT",
  INVALID_GIT_CONFIG = "INVALID_GIT_CONFIG",
  KEY_PASSPHRASE_INVALID = "KEY_PASSPHRASE_INVALID",
  ENCRYPTED_KEY_UNSUPPORTED = "ENCRYPTED_KEY_UNSUPPORTED",
  KEY_BUNDLE_UNSUPPORTED = "KEY_BUNDLE_UNSUPPORTED",
  DEDICATED_CONTEXT_REQUIRED = "DEDICATED_CONTEXT_REQUIRED",

  // Validation
  INVALID_INPUT = "INVALID_INPUT",
  INVALID_HANDLE = "INVALID_HANDLE",
  INVALID_PROJECT_NAME = "INVALID_PROJECT_NAME",
  INVALID_SECRET_NAME = "INVALID_SECRET_NAME",
  SCHEMA_VALIDATION_ERROR = "SCHEMA_VALIDATION_ERROR",

  // Policy
  POLICY_NOT_FOUND = "POLICY_NOT_FOUND",
  POLICY_CONFLICT = "POLICY_CONFLICT",
  PRINCIPAL_NOT_FOUND = "PRINCIPAL_NOT_FOUND",

  // OAuth
  OAUTH_FLOW_FAILED = "OAUTH_FLOW_FAILED",
  OAUTH_CALLBACK_TIMEOUT = "OAUTH_CALLBACK_TIMEOUT",
  OAUTH_INVALID_STATE = "OAUTH_INVALID_STATE",
  OAUTH_TOKEN_EXCHANGE_FAILED = "OAUTH_TOKEN_EXCHANGE_FAILED",
  OAUTH_REFRESH_FAILED = "OAUTH_REFRESH_FAILED",
  OAUTH_PROVIDER_NOT_FOUND = "OAUTH_PROVIDER_NOT_FOUND",
  OAUTH_NOT_CONFIGURED = "OAUTH_NOT_CONFIGURED",

  // Certificates
  CERT_INVALID = "CERT_INVALID",
  CERT_EXPIRED = "CERT_EXPIRED",
  CERT_PRIVATE_KEY_MISMATCH = "CERT_PRIVATE_KEY_MISMATCH",
  CERT_ACME_FAILED = "CERT_ACME_FAILED",
  CERT_CSR_FAILED = "CERT_CSR_FAILED",
  CERT_NOT_CONFIGURED = "CERT_NOT_CONFIGURED",
  CERT_VALUE_UNSUPPORTED = "CERT_VALUE_UNSUPPORTED",

  // Email / WebSocket / SFTP / Docker contexts (v1.3)
  RECIPIENT_NOT_ALLOWED = "RECIPIENT_NOT_ALLOWED",
  ATTACHMENT_POLICY_REQUIRED = "ATTACHMENT_POLICY_REQUIRED",
  ATTACHMENT_REJECTED = "ATTACHMENT_REJECTED",
  IMAP_MUTATION_NOT_ALLOWED = "IMAP_MUTATION_NOT_ALLOWED",
  SMTP_STARTTLS_UNAVAILABLE = "SMTP_STARTTLS_UNAVAILABLE",
  SMTP_DELIVERY_FAILED = "SMTP_DELIVERY_FAILED",
  IMAP_OPERATION_FAILED = "IMAP_OPERATION_FAILED",
  WEBSOCKET_CONNECT_FAILED = "WEBSOCKET_CONNECT_FAILED",
  SFTP_OPERATION_FAILED = "SFTP_OPERATION_FAILED",
  RENDER_ENTRY_NOT_FOUND = "RENDER_ENTRY_NOT_FOUND",
  RENDER_IN_FLIGHT = "RENDER_IN_FLIGHT",
  RENDER_SLOT_REFUSED = "RENDER_SLOT_REFUSED",
  RENDER_SLOT_UNSUPPORTED = "RENDER_SLOT_UNSUPPORTED",
  RENDER_NOT_APPROVED = "RENDER_NOT_APPROVED",
  RENDER_VALUE_UNSUPPORTED = "RENDER_VALUE_UNSUPPORTED",
  RENDER_ONLY_KEY = "RENDER_ONLY_KEY",
  RENDER_FAILED = "RENDER_FAILED",
  LOCAL_PATH_NOT_ALLOWED = "LOCAL_PATH_NOT_ALLOWED",
  DOCKER_OPERATION_FAILED = "DOCKER_OPERATION_FAILED",

  // Agent governance (v1.4)
  AGENT_NOT_FOUND = "AGENT_NOT_FOUND",
  AGENT_INACTIVE = "AGENT_INACTIVE",
  AGENT_EXISTS = "AGENT_EXISTS",

  // Optional dependencies
  MISSING_DEPENDENCY = "MISSING_DEPENDENCY",

  // Rate limiting
  RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED",

  // Listener host allowlist (D61)
  MISDIRECTED_REQUEST = "MISDIRECTED_REQUEST",

  // Deployment model B
  REST_MODE_UNSUPPORTED = "REST_MODE_UNSUPPORTED",
  SESSION_MODE_CONFLICT = "SESSION_MODE_CONFLICT",
  PROXY_PLACEHOLDER_DENIED = "PROXY_PLACEHOLDER_DENIED",
  PROXY_UPSTREAM_FAILED = "PROXY_UPSTREAM_FAILED",
  SSH_AGENT_UNBOUND = "SSH_AGENT_UNBOUND",
  INVALID_UNLOCK_KEY = "INVALID_UNLOCK_KEY",
  UNLOCK_KEY_NOT_ENROLLED = "UNLOCK_KEY_NOT_ENROLLED",
  UNLOCK_KEY_SOURCE_UNSAFE = "UNLOCK_KEY_SOURCE_UNSAFE",
  UNLOCK_KEY_PASSWORD_REQUIRED = "UNLOCK_KEY_PASSWORD_REQUIRED",
  PROXY_CONNECT_DENIED = "PROXY_CONNECT_DENIED",

  // System
  INTERNAL_ERROR = "INTERNAL_ERROR",
  DATABASE_ERROR = "DATABASE_ERROR",
  ENCRYPTION_ERROR = "ENCRYPTION_ERROR",
  KEY_DERIVATION_ERROR = "KEY_DERIVATION_ERROR",
  FILE_IO_ERROR = "FILE_IO_ERROR",
  SESSION_FILE_ERROR = "SESSION_FILE_ERROR",
  SESSION_KEYSTORE_UNAVAILABLE = "SESSION_KEYSTORE_UNAVAILABLE",
}

const STATUS_MAP: Record<ErrorCode, number> = {
  // Vault state
  [ErrorCode.VAULT_LOCKED]: 423,
  [ErrorCode.VAULT_NOT_FOUND]: 404,
  [ErrorCode.VAULT_ALREADY_EXISTS]: 409,
  [ErrorCode.VAULT_CORRUPTED]: 500,

  // Auth
  [ErrorCode.INVALID_PASSWORD]: 401,
  [ErrorCode.WEAK_PASSWORD]: 400,
  [ErrorCode.INVALID_TOKEN]: 401,
  [ErrorCode.TOKEN_EXPIRED]: 401,
  [ErrorCode.TOKEN_REVOKED]: 401,
  [ErrorCode.TOKEN_REQUIRED]: 401,
  [ErrorCode.ACCESS_DENIED]: 403,
  [ErrorCode.LOCKOUT_ACTIVE]: 429,

  // Secrets
  [ErrorCode.SECRET_NOT_FOUND]: 404,
  [ErrorCode.AMBIGUOUS_HANDLE]: 409,
  [ErrorCode.DUPLICATE_SECRET]: 409,
  [ErrorCode.SECRET_EXPIRED]: 410,
  [ErrorCode.SECRET_REVOKED]: 410,
  [ErrorCode.INVALID_SECRET_TYPE]: 400,
  [ErrorCode.SECRET_VALUE_REQUIRED]: 400,

  // HTTP injection
  [ErrorCode.URL_INVALID]: 400,
  [ErrorCode.URL_HTTPS_REQUIRED]: 400,
  [ErrorCode.SSRF_BLOCKED]: 403,
  [ErrorCode.TLS_ERROR]: 502,
  [ErrorCode.DNS_RESOLUTION_FAILED]: 502,
  [ErrorCode.CONNECTION_REFUSED]: 502,
  [ErrorCode.TIMEOUT]: 504,
  [ErrorCode.REDIRECT_POLICY_VIOLATION]: 502,
  [ErrorCode.INVALID_INJECTION_CONFIG]: 400,
  [ErrorCode.URL_NOT_ALLOWED]: 403,
  [ErrorCode.RESPONSE_MODE_NOT_ALLOWED]: 403,
  [ErrorCode.RESPONSE_TOO_LARGE]: 502,

  // Process execution
  [ErrorCode.COMMAND_NOT_ALLOWED]: 403,
  [ErrorCode.PROCESS_SPAWN_FAILED]: 500,
  [ErrorCode.PROCESS_TIMEOUT]: 504,
  [ErrorCode.PROCESS_OUTPUT_LIMIT]: 413,
  [ErrorCode.INVALID_PROCESS_CONFIG]: 400,
  [ErrorCode.INTERPRETER_NOT_ACKNOWLEDGED]: 400,
  [ErrorCode.NETWORK_ISOLATION_UNAVAILABLE]: 501,
  [ErrorCode.FS_ISOLATION_UNAVAILABLE]: 501,
  [ErrorCode.STRICT_TREE_EXIT_UNAVAILABLE]: 501,

  // MCP proxy
  [ErrorCode.MCP_SERVER_NOT_CONFIGURED]: 400,
  [ErrorCode.MCP_SERVER_MISMATCH]: 400,
  [ErrorCode.MCP_CONNECT_FAILED]: 502,
  [ErrorCode.MCP_SERVER_CRASHED]: 502,
  [ErrorCode.MCP_PROTOCOL_ERROR]: 502,
  [ErrorCode.MCP_TIMEOUT]: 504,

  // Database / Git / SSH contexts
  [ErrorCode.HOST_NOT_ALLOWED]: 403,
  [ErrorCode.DB_CONNECTION_FAILED]: 502,
  [ErrorCode.DB_QUERY_FAILED]: 400,
  [ErrorCode.DB_TLS_REQUIRED]: 400,
  [ErrorCode.UNSUPPORTED_DB_ENGINE]: 400,
  [ErrorCode.INVALID_DATABASE_CONFIG]: 400,
  [ErrorCode.SSH_CONNECT_FAILED]: 502,
  [ErrorCode.SSH_HOST_KEY_MISMATCH]: 502,
  [ErrorCode.SSH_AGENT_FAILED]: 500,
  [ErrorCode.SSH_NOT_CONFIGURED]: 400,
  [ErrorCode.INVALID_SSH_CONFIG]: 400,
  [ErrorCode.SSH_CLIENT_UNSUPPORTED]: 501,
  [ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED]: 403,
  [ErrorCode.SSH_PASSWORD_NOT_OFFERED]: 502,
  [ErrorCode.SSH_PASSWORD_REFUSED]: 502,
  [ErrorCode.SSH_BOOTSTRAP_STEP_FAILED]: 502,
  [ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED]: 502,
  [ErrorCode.SSH_BOOTSTRAP_IN_FLIGHT]: 409,
  [ErrorCode.GIT_OPERATION_FAILED]: 502,
  [ErrorCode.GIT_UNSUPPORTED_TRANSPORT]: 400,
  [ErrorCode.INVALID_GIT_CONFIG]: 400,
  [ErrorCode.KEY_PASSPHRASE_INVALID]: 400,
  [ErrorCode.ENCRYPTED_KEY_UNSUPPORTED]: 400,
  [ErrorCode.KEY_BUNDLE_UNSUPPORTED]: 400,
  [ErrorCode.DEDICATED_CONTEXT_REQUIRED]: 403,

  // Validation
  [ErrorCode.INVALID_INPUT]: 400,
  [ErrorCode.INVALID_HANDLE]: 400,
  [ErrorCode.INVALID_PROJECT_NAME]: 400,
  [ErrorCode.INVALID_SECRET_NAME]: 400,
  [ErrorCode.SCHEMA_VALIDATION_ERROR]: 400,

  // Policy
  [ErrorCode.POLICY_NOT_FOUND]: 404,
  [ErrorCode.POLICY_CONFLICT]: 409,
  [ErrorCode.PRINCIPAL_NOT_FOUND]: 404,

  // OAuth
  [ErrorCode.OAUTH_FLOW_FAILED]: 502,
  [ErrorCode.OAUTH_CALLBACK_TIMEOUT]: 504,
  [ErrorCode.OAUTH_INVALID_STATE]: 400,
  [ErrorCode.OAUTH_TOKEN_EXCHANGE_FAILED]: 502,
  [ErrorCode.OAUTH_REFRESH_FAILED]: 502,
  [ErrorCode.OAUTH_PROVIDER_NOT_FOUND]: 404,
  [ErrorCode.OAUTH_NOT_CONFIGURED]: 400,

  // Certificates
  [ErrorCode.CERT_INVALID]: 400,
  [ErrorCode.CERT_EXPIRED]: 410,
  [ErrorCode.CERT_PRIVATE_KEY_MISMATCH]: 400,
  [ErrorCode.CERT_ACME_FAILED]: 502,
  [ErrorCode.CERT_CSR_FAILED]: 500,
  [ErrorCode.CERT_NOT_CONFIGURED]: 400,
  [ErrorCode.CERT_VALUE_UNSUPPORTED]: 400,

  // Email / WebSocket / SFTP / Docker contexts (v1.3)
  [ErrorCode.RECIPIENT_NOT_ALLOWED]: 403,
  [ErrorCode.ATTACHMENT_POLICY_REQUIRED]: 403,
  [ErrorCode.ATTACHMENT_REJECTED]: 400,
  [ErrorCode.IMAP_MUTATION_NOT_ALLOWED]: 403,
  [ErrorCode.SMTP_STARTTLS_UNAVAILABLE]: 502,
  [ErrorCode.SMTP_DELIVERY_FAILED]: 502,
  [ErrorCode.IMAP_OPERATION_FAILED]: 502,
  [ErrorCode.WEBSOCKET_CONNECT_FAILED]: 502,
  [ErrorCode.SFTP_OPERATION_FAILED]: 502,
  [ErrorCode.RENDER_ENTRY_NOT_FOUND]: 404,
  [ErrorCode.RENDER_IN_FLIGHT]: 409,
  [ErrorCode.RENDER_SLOT_REFUSED]: 403,
  [ErrorCode.RENDER_SLOT_UNSUPPORTED]: 400,
  [ErrorCode.RENDER_NOT_APPROVED]: 403,
  [ErrorCode.RENDER_VALUE_UNSUPPORTED]: 400,
  [ErrorCode.RENDER_ONLY_KEY]: 403,
  [ErrorCode.RENDER_FAILED]: 502,
  [ErrorCode.LOCAL_PATH_NOT_ALLOWED]: 403,
  [ErrorCode.DOCKER_OPERATION_FAILED]: 502,

  // Agent governance (v1.4)
  [ErrorCode.AGENT_NOT_FOUND]: 404,
  [ErrorCode.AGENT_INACTIVE]: 403,
  [ErrorCode.AGENT_EXISTS]: 409,

  // Optional dependencies
  [ErrorCode.MISSING_DEPENDENCY]: 501,

  // Rate limiting
  [ErrorCode.RATE_LIMIT_EXCEEDED]: 429,

  // Listener host allowlist (D61)
  [ErrorCode.MISDIRECTED_REQUEST]: 421,

  // Deployment model B
  [ErrorCode.REST_MODE_UNSUPPORTED]: 501,
  [ErrorCode.SESSION_MODE_CONFLICT]: 400,
  [ErrorCode.PROXY_PLACEHOLDER_DENIED]: 403,
  [ErrorCode.PROXY_UPSTREAM_FAILED]: 502,
  [ErrorCode.SSH_AGENT_UNBOUND]: 403,
  [ErrorCode.INVALID_UNLOCK_KEY]: 401,
  [ErrorCode.UNLOCK_KEY_NOT_ENROLLED]: 400,
  [ErrorCode.UNLOCK_KEY_SOURCE_UNSAFE]: 400,
  [ErrorCode.UNLOCK_KEY_PASSWORD_REQUIRED]: 403,
  [ErrorCode.PROXY_CONNECT_DENIED]: 403,

  // System
  [ErrorCode.INTERNAL_ERROR]: 500,
  [ErrorCode.DATABASE_ERROR]: 500,
  [ErrorCode.ENCRYPTION_ERROR]: 500,
  [ErrorCode.KEY_DERIVATION_ERROR]: 500,
  [ErrorCode.FILE_IO_ERROR]: 500,
  [ErrorCode.SESSION_FILE_ERROR]: 500,
  [ErrorCode.SESSION_KEYSTORE_UNAVAILABLE]: 501,
};

/** The closed set of upstream-failure classes the egress proxy may name — never an upstream error's text (hard rule 4). */
export type ProxyUpstreamFailureReason = "refused" | "timeout" | "tls";

/**
 * Why a consumer's ssh-agent socket refused a signature on its connection's
 * session binding or on the data to sign (deployment model B, M5) — a closed
 * vocabulary, never a host key, a session identifier or the data to sign
 * (hard rule 4).
 */
export type SshAgentUnboundReason =
  "unbound" | "forwarding" | "not_userauth" | "session_mismatch" | "host_unpinned";

const SSH_AGENT_UNBOUND_TEXT: Record<SshAgentUnboundReason, string> = {
  unbound: "the connection is not bound to a host (session-bind@openssh.com)",
  forwarding: "the connection was bound for agent forwarding, which the socket does not serve",
  not_userauth: "the data to sign is not a user authentication request for the key",
  session_mismatch: "the user authentication request is not for the bound session",
  host_unpinned: "the bound host key matches no pinned known_hosts line of the secret",
};

/**
 * Why a source of the unlock key was refused before the vault opened
 * (deployment model B, M1) — a closed vocabulary, never a byte of the key
 * (hard rule 4).
 */
export type UnlockKeySourceUnsafeReason = "symlink" | "owner" | "mode" | "acl" | "acl_unverified";

const UNLOCK_KEY_SOURCE_UNSAFE_TEXT: Record<UnlockKeySourceUnsafeReason, string> = {
  symlink: "is a symbolic link; name the file itself",
  owner: "is owned by another account",
  mode: "has permission bits that grant access beyond its owner",
  acl: "grants access to an account other than this process's account, SYSTEM and Administrators",
  acl_unverified: "has an access list that could not be read",
};

/** Why a use was refused by a secret's bootstrap block (design 4b B2, B3) — a closed vocabulary, never a host, user, port or key (hard rule 4, H1 E-2). */
export type SshBootstrapRefusalReason =
  "no_block" | "target" | "key" | "sudoers" | "bootstrap_only";

const SSH_BOOTSTRAP_NOT_ALLOWED_TEXT: Record<SshBootstrapRefusalReason, string> = {
  no_block: "SSH bootstrap not allowed: the secret's injection policy holds no bootstrap block",
  target: "SSH bootstrap not allowed: host, user or port is not the bootstrap block's",
  key: "SSH bootstrap not allowed: the public key is not one the bootstrap block lists",
  sudoers: "SSH bootstrap not allowed: the bootstrap block does not allow the sudoers rule",
  bootstrap_only:
    "Use refused: the secret holds an ssh bootstrap block and serves the ssh bootstrap alone",
};

/** What an ssh client is resolved for: the ssh bootstrap's password login or the sftp render. */
export type SshClientUse = "bootstrap" | "render";

/** What the remote script says became of the sudoers drop-in, as the vault reads its status line. */
export type SshBootstrapDropInWord =
  "written" | "present" | "not_asked" | "not_attempted" | "refused";

export type RecordedDetails = Readonly<Record<string, TextPart>>;

type ErrorRecord = { readonly message: VaultText; readonly details?: RecordedDetails };

type Quoted = string | TextPart | VaultText;

const RECORDS = new WeakMap<VaultError, ErrorRecord>();

const NULL_WORD = token(null, [], "null");

function recordable(
  details: Record<string, unknown> | undefined,
): details is RecordedDetails | undefined {
  return details === undefined || Object.values(details).every(isTextPart);
}

export function renderRecordedDetails(
  details: RecordedDetails,
  call?: EchoSource,
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(details).map(([key, part]) => {
      const text = renderVaultText(vaultText`${part}`, call);
      if (!isTextPart(part)) return [key, text];
      if (part.kind === "number") return [key, Number(text)];
      return [key, part.kind === "words" && text === "null" ? null : text];
    }),
  );
}

function asText(value: unknown): VaultText | undefined {
  if (isVaultText(value)) return value;
  return isTextPart(value) ? vaultText`${value}` : undefined;
}

function plain(value: unknown): string {
  const text = asText(value);
  return text === undefined ? String(value) : renderVaultText(text);
}

function loose(value: unknown): unknown {
  const text = asText(value);
  return text === undefined ? value : renderVaultText(text);
}

function shows(value: unknown): boolean {
  const text = asText(value);
  return text === undefined ? Boolean(value) : renderVaultText(text) !== "";
}

function bare(value: unknown, text: string | VaultText): string | VaultText {
  return value === undefined || asText(value) !== undefined || typeof text === "string"
    ? text
    : renderVaultText(text);
}

function say(strings: TemplateStringsArray, ...values: readonly unknown[]): string | VaultText {
  const parts: VaultText[] = [];
  for (const value of values) {
    const text = asText(value);
    if (text === undefined) {
      return values.reduce<string>(
        (out, v, i) => `${out}${plain(v)}${strings[i + 1] ?? ""}`,
        strings[0] ?? "",
      );
    }
    parts.push(text);
  }
  return vaultText(strings, ...parts);
}

function serverDetails(
  server: string | TextPart,
  message: string | VaultText,
): Record<string, unknown> {
  return { server: typeof message === "string" ? loose(server) : server };
}

export class VaultError extends Error {
  readonly code: ErrorCode;
  readonly statusCode: number;
  readonly details?: Record<string, unknown>;

  constructor(
    code: ErrorCode,
    message: string | VaultText,
    details?: Record<string, unknown> | RecordedDetails,
  ) {
    const text = isVaultText(message) ? message : undefined;
    super(text === undefined ? (message as string) : renderVaultText(text));
    this.name = "VaultError";
    this.code = code;
    this.statusCode = STATUS_MAP[code];
    if (text !== undefined && recordable(details)) {
      const recorded = details === undefined ? undefined : Object.freeze({ ...details });
      RECORDS.set(
        this,
        Object.freeze(
          recorded === undefined ? { message: text } : { message: text, details: recorded },
        ),
      );
      this.details = recorded === undefined ? undefined : renderRecordedDetails(recorded);
    } else {
      this.details = details;
    }
  }

  static vaultLocked(): VaultError {
    return new VaultError(ErrorCode.VAULT_LOCKED, vaultText`Vault is locked`);
  }

  static vaultNotFound(): VaultError {
    return new VaultError(ErrorCode.VAULT_NOT_FOUND, vaultText`Vault not found`);
  }

  static vaultAlreadyExists(): VaultError {
    return new VaultError(
      ErrorCode.VAULT_ALREADY_EXISTS,
      vaultText`A vault already exists at this location; use unlock instead`,
    );
  }

  static secretNotFound(handle?: string): VaultError {
    const msg = handle ? `Secret not found: ${handle}` : bare(handle, vaultText`Secret not found`);
    return new VaultError(ErrorCode.SECRET_NOT_FOUND, msg);
  }

  static accessDenied(detail?: string): VaultError {
    const msg = detail ? `Access denied: ${detail}` : bare(detail, vaultText`Access denied`);
    return new VaultError(ErrorCode.ACCESS_DENIED, msg);
  }

  static misdirectedRequest(header: "Host" | "Origin", hostname: string | null): VaultError {
    const subject =
      hostname === null
        ? `the ${header} header is missing or unparsable`
        : `the ${header} header names ${hostname}, which this listener does not serve`;
    return new VaultError(
      ErrorCode.MISDIRECTED_REQUEST,
      `Misdirected request: ${subject} — start the server with --allowed-host <name> for every name clients use to reach it`,
    );
  }

  static invalidInput(message: string | VaultText): VaultError {
    return new VaultError(ErrorCode.INVALID_INPUT, message);
  }

  static invalidHandle(handle: string): VaultError {
    return new VaultError(ErrorCode.INVALID_HANDLE, `Invalid handle: ${handle}`);
  }

  static invalidPassword(): VaultError {
    return new VaultError(ErrorCode.INVALID_PASSWORD, vaultText`Invalid password`);
  }

  static duplicateSecret(name: string): VaultError {
    return new VaultError(ErrorCode.DUPLICATE_SECRET, `Secret already exists: ${name}`);
  }

  static lockoutActive(retryAfterMs: number): VaultError {
    return new VaultError(ErrorCode.LOCKOUT_ACTIVE, "Too many failed attempts", {
      retry_after_ms: retryAfterMs,
    });
  }

  static schemaValidation(message: string): VaultError {
    return new VaultError(ErrorCode.SCHEMA_VALIDATION_ERROR, message);
  }

  static internalError(message: string | VaultText): VaultError {
    return new VaultError(ErrorCode.INTERNAL_ERROR, message);
  }

  static vaultCorrupted(detail?: Quoted): VaultError {
    const msg = shows(detail)
      ? say`Vault corrupted: ${detail}`
      : bare(detail, vaultText`Vault corrupted`);
    return new VaultError(ErrorCode.VAULT_CORRUPTED, msg);
  }

  static encryptionError(detail?: Quoted): VaultError {
    const msg = shows(detail)
      ? say`Encryption error: ${detail}`
      : bare(detail, vaultText`Encryption error`);
    return new VaultError(ErrorCode.ENCRYPTION_ERROR, msg);
  }

  static databaseError(detail?: string): VaultError {
    const msg = detail ? `Database error: ${detail}` : bare(detail, vaultText`Database error`);
    return new VaultError(ErrorCode.DATABASE_ERROR, msg);
  }

  static secretExpired(handle?: Quoted): VaultError {
    const msg = shows(handle)
      ? say`Secret expired: ${handle}`
      : bare(handle, vaultText`Secret expired`);
    return new VaultError(ErrorCode.SECRET_EXPIRED, msg);
  }

  static secretRevoked(handle?: Quoted): VaultError {
    const msg = shows(handle)
      ? say`Secret revoked: ${handle}`
      : bare(handle, vaultText`Secret revoked`);
    return new VaultError(ErrorCode.SECRET_REVOKED, msg);
  }

  static tokenExpired(): VaultError {
    return new VaultError(ErrorCode.TOKEN_EXPIRED, vaultText`Token expired`);
  }

  static tokenRevoked(): VaultError {
    return new VaultError(ErrorCode.TOKEN_REVOKED, vaultText`Token revoked`);
  }

  static tokenRequired(): VaultError {
    return new VaultError(
      ErrorCode.TOKEN_REQUIRED,
      vaultText`A launch token is required: issue one with \`harpoc auth token\` and pass it via the HARPOC_TOKEN environment variable (or --token-file <path>), or start with --allow-tokenless to explicitly accept unrestricted local full access`,
    );
  }

  static sessionFileError(detail?: string): VaultError {
    const msg = detail
      ? `Session file error: ${detail}`
      : bare(detail, vaultText`Session file error`);
    return new VaultError(ErrorCode.SESSION_FILE_ERROR, msg);
  }

  static sessionKeystoreUnavailable(scheme: string, cause: string): VaultError {
    return new VaultError(
      ErrorCode.SESSION_KEYSTORE_UNAVAILABLE,
      `Session keystore unavailable: the ${scheme} keystore could not protect the session key (${cause}). Repair the keystore and unlock again, or set HARPOC_SESSION_KEYSTORE=off to keep the session under file permissions only`,
    );
  }

  static weakPassword(minLength: number): VaultError {
    return new VaultError(
      ErrorCode.WEAK_PASSWORD,
      `Password must be at least ${minLength} characters`,
    );
  }

  static urlNotAllowed(url?: Quoted): VaultError {
    const msg = shows(url)
      ? say`URL not in secret allowlist: ${url}`
      : bare(url, vaultText`URL not in secret allowlist`);
    return new VaultError(ErrorCode.URL_NOT_ALLOWED, msg);
  }

  static responseModeNotAllowed(requested: Quoted, allowed: Quoted): VaultError {
    return new VaultError(
      ErrorCode.RESPONSE_MODE_NOT_ALLOWED,
      say`Response mode "${requested}" not allowed: secret policy is "${allowed}" and overrides may only tighten`,
    );
  }

  static commandNotAllowed(command?: Quoted): VaultError {
    const msg = shows(command)
      ? say`Command not in secret allowlist: ${command}`
      : bare(command, vaultText`Command not in secret allowlist`);
    return new VaultError(ErrorCode.COMMAND_NOT_ALLOWED, msg);
  }

  static networkIsolationUnavailable(reason: Quoted): VaultError {
    return new VaultError(
      ErrorCode.NETWORK_ISOLATION_UNAVAILABLE,
      say`Network isolation is required by this secret's policy but unavailable: ${reason}. Linux needs unprivileged user namespaces (unshare, or bubblewrap's bwrap as the second tier, both under the same userns grant); macOS needs sandbox-exec; Windows is unsupported by design. Remove the requirement via the admin path: secret allow <handle> --no-network-isolation`,
    );
  }

  static fsIsolationUnavailable(reason: Quoted): VaultError {
    return new VaultError(
      ErrorCode.FS_ISOLATION_UNAVAILABLE,
      say`Filesystem isolation was demanded by policy but cannot be delivered: ${reason}. Linux needs setpriv with Landlock support (util-linux >= 2.40) on a Landlock-enabled kernel, or bubblewrap's bwrap as the second tier (a read-only root bind, under the userns grant); macOS needs /usr/bin/sandbox-exec; Windows is unsupported by design. Lift the demand via: secret allow <handle> --no-fs-isolation`,
    );
  }

  static strictTreeExitUnavailable(reason: Quoted): VaultError {
    return new VaultError(
      ErrorCode.STRICT_TREE_EXIT_UNAVAILABLE,
      say`Strict tree exit is required by this secret's policy but the Windows job wrapper is unavailable: ${reason}. The wrapper is compiled by the .NET Framework compiler every Windows with PowerShell 5.1 carries; lift the demand via the admin path: secret allow <handle> --no-strict-tree-exit`,
    );
  }

  static interpreterNotAcknowledged(interpreters: string[], wrappers: string[] = []): VaultError {
    const tiers = [
      ...(interpreters.length > 0 ? [`known interpreter(s): ${interpreters.join(", ")}`] : []),
      ...(wrappers.length > 0 ? [`exec wrapper(s): ${wrappers.join(", ")}`] : []),
    ];
    return new VaultError(
      ErrorCode.INTERPRETER_NOT_ACKNOWLEDGED,
      `Refusing to allowlist ${tiers.join(" and ")} — allowlisting an interpreter or exec wrapper collapses the capability ladder for this secret; pass the explicit acknowledgement (--acknowledge-interpreter / acknowledge_interpreters) to proceed`,
    );
  }

  static processSpawnFailed(detail?: string): VaultError {
    const msg = detail
      ? `Process spawn failed: ${detail}`
      : bare(detail, vaultText`Process spawn failed`);
    return new VaultError(ErrorCode.PROCESS_SPAWN_FAILED, msg);
  }

  static processTimeout(): VaultError {
    return new VaultError(ErrorCode.PROCESS_TIMEOUT, vaultText`Process timed out`);
  }

  static processOutputLimit(): VaultError {
    return new VaultError(ErrorCode.PROCESS_OUTPUT_LIMIT, vaultText`Process output exceeded limit`);
  }

  static invalidProcessConfig(message: string | VaultText): VaultError {
    return new VaultError(ErrorCode.INVALID_PROCESS_CONFIG, message);
  }

  static mcpServerNotConfigured(handle?: Quoted): VaultError {
    const msg = shows(handle)
      ? say`MCP server not configured for secret: ${handle}`
      : bare(handle, vaultText`MCP server not configured for secret`);
    return new VaultError(ErrorCode.MCP_SERVER_NOT_CONFIGURED, msg);
  }

  static mcpServerMismatch(requested: Quoted, configured: Quoted): VaultError {
    return new VaultError(
      ErrorCode.MCP_SERVER_MISMATCH,
      say`MCP server '${requested}' does not match configured server '${configured}'`,
    );
  }

  static mcpConnectFailed(server: string | TextPart, detail?: Quoted): VaultError {
    const msg = shows(detail)
      ? say`Failed to connect to MCP server '${server}': ${detail}`
      : bare(detail, say`Failed to connect to MCP server '${server}'`);
    return new VaultError(ErrorCode.MCP_CONNECT_FAILED, msg, serverDetails(server, msg));
  }

  static mcpServerCrashed(
    server: string | TextPart,
    exitCode: number | null,
    signal: string | null | TextPart,
  ): VaultError {
    if (isTextPart(server) && (signal === null || isTextPart(signal))) {
      return new VaultError(
        ErrorCode.MCP_SERVER_CRASHED,
        vaultText`MCP server '${server}' exited unexpectedly`,
        {
          server,
          exit_code: exitCode === null ? NULL_WORD : num(exitCode),
          signal: signal ?? NULL_WORD,
        },
      );
    }
    return new VaultError(
      ErrorCode.MCP_SERVER_CRASHED,
      `MCP server '${plain(server)}' exited unexpectedly`,
      { server: loose(server), exit_code: exitCode, signal: loose(signal) },
    );
  }

  static mcpProtocolError(server: string | TextPart, detail?: Quoted): VaultError {
    const msg = shows(detail)
      ? say`MCP protocol error from server '${server}': ${detail}`
      : bare(detail, say`MCP protocol error from server '${server}'`);
    return new VaultError(ErrorCode.MCP_PROTOCOL_ERROR, msg, serverDetails(server, msg));
  }

  static mcpTimeout(server: string | TextPart): VaultError {
    const msg = say`MCP tool call to server '${server}' timed out`;
    return new VaultError(ErrorCode.MCP_TIMEOUT, msg, serverDetails(server, msg));
  }

  static oauthFlowFailed(detail?: string): VaultError {
    const msg = detail
      ? `OAuth flow failed: ${detail}`
      : bare(detail, vaultText`OAuth flow failed`);
    return new VaultError(ErrorCode.OAUTH_FLOW_FAILED, msg);
  }

  static oauthCallbackTimeout(): VaultError {
    return new VaultError(ErrorCode.OAUTH_CALLBACK_TIMEOUT, vaultText`OAuth callback timed out`);
  }

  static oauthInvalidState(): VaultError {
    return new VaultError(ErrorCode.OAUTH_INVALID_STATE, vaultText`OAuth state parameter mismatch`);
  }

  static oauthTokenExchangeFailed(detail?: string): VaultError {
    const msg = detail
      ? `OAuth token exchange failed: ${detail}`
      : bare(detail, vaultText`OAuth token exchange failed`);
    return new VaultError(ErrorCode.OAUTH_TOKEN_EXCHANGE_FAILED, msg);
  }

  static oauthRefreshFailed(detail?: Quoted): VaultError {
    const msg = shows(detail)
      ? say`OAuth token refresh failed: ${detail}`
      : bare(detail, vaultText`OAuth token refresh failed`);
    return new VaultError(ErrorCode.OAUTH_REFRESH_FAILED, msg);
  }

  static oauthProviderNotFound(provider: string): VaultError {
    return new VaultError(
      ErrorCode.OAUTH_PROVIDER_NOT_FOUND,
      `OAuth provider not found: ${provider}`,
    );
  }

  static oauthNotConfigured(handle?: string): VaultError {
    const msg = handle
      ? `OAuth not configured for secret: ${handle}`
      : bare(handle, vaultText`OAuth not configured for secret`);
    return new VaultError(ErrorCode.OAUTH_NOT_CONFIGURED, msg);
  }

  static certInvalid(detail?: string): VaultError {
    const msg = detail
      ? `Certificate invalid: ${detail}`
      : bare(detail, vaultText`Certificate invalid`);
    return new VaultError(ErrorCode.CERT_INVALID, msg);
  }

  static certExpired(subject?: string): VaultError {
    const msg = subject
      ? `Certificate expired: ${subject}`
      : bare(subject, vaultText`Certificate expired`);
    return new VaultError(ErrorCode.CERT_EXPIRED, msg);
  }

  static certPrivateKeyMismatch(): VaultError {
    return new VaultError(
      ErrorCode.CERT_PRIVATE_KEY_MISMATCH,
      vaultText`Private key does not match certificate`,
    );
  }

  static certAcmeFailed(detail?: string): VaultError {
    const msg = detail
      ? `ACME operation failed: ${detail}`
      : bare(detail, vaultText`ACME operation failed`);
    return new VaultError(ErrorCode.CERT_ACME_FAILED, msg);
  }

  static certCsrFailed(detail?: string): VaultError {
    const msg = detail
      ? `CSR generation failed: ${detail}`
      : bare(detail, vaultText`CSR generation failed`);
    return new VaultError(ErrorCode.CERT_CSR_FAILED, msg);
  }

  static certNotConfigured(handle?: string): VaultError {
    const msg = handle
      ? `Certificate not configured for secret: ${handle}`
      : bare(handle, vaultText`Certificate not configured for secret`);
    return new VaultError(ErrorCode.CERT_NOT_CONFIGURED, msg);
  }

  /**
   * A certificate secret carries no raw payload — its private key lives in the
   * `certificates` table, so the generic value paths would inject an empty
   * credential. They refuse instead; the certificate accessors are the way in.
   */
  static certValueUnsupported(handle?: string): VaultError {
    const msg = handle
      ? `Certificate secrets cannot be used as a raw value: ${handle}`
      : bare(handle, vaultText`Certificate secrets cannot be used as a raw value`);
    return new VaultError(ErrorCode.CERT_VALUE_UNSUPPORTED, msg);
  }

  static hostNotAllowed(host?: Quoted): VaultError {
    const msg = shows(host)
      ? say`Host not in secret allowlist: ${host}`
      : bare(host, vaultText`Host not in secret allowlist`);
    return new VaultError(ErrorCode.HOST_NOT_ALLOWED, msg);
  }

  static dbConnectionFailed(detail?: Quoted): VaultError {
    const msg = shows(detail)
      ? say`Database connection failed: ${detail}`
      : bare(detail, vaultText`Database connection failed`);
    return new VaultError(ErrorCode.DB_CONNECTION_FAILED, msg);
  }

  static dbQueryFailed(detail?: Quoted): VaultError {
    const msg = shows(detail)
      ? say`Database query failed: ${detail}`
      : bare(detail, vaultText`Database query failed`);
    return new VaultError(ErrorCode.DB_QUERY_FAILED, msg);
  }

  static dbTlsRequired(): VaultError {
    return new VaultError(
      ErrorCode.DB_TLS_REQUIRED,
      vaultText`TLS is required for this database connection; set tls_mode 'disable' to opt out`,
    );
  }

  static unsupportedDbEngine(engine: Quoted): VaultError {
    return new VaultError(
      ErrorCode.UNSUPPORTED_DB_ENGINE,
      say`Unsupported database engine: ${engine}`,
    );
  }

  static invalidDatabaseConfig(message: string | VaultText): VaultError {
    return new VaultError(ErrorCode.INVALID_DATABASE_CONFIG, message);
  }

  static sshConnectFailed(detail?: Quoted): VaultError {
    const msg = shows(detail)
      ? say`SSH connection failed: ${detail}`
      : bare(detail, vaultText`SSH connection failed`);
    return new VaultError(ErrorCode.SSH_CONNECT_FAILED, msg);
  }

  static sshHostKeyMismatch(host?: Quoted): VaultError {
    const msg = shows(host)
      ? say`SSH host key does not match the pinned key for: ${host}`
      : bare(host, vaultText`SSH host key does not match the pinned key`);
    return new VaultError(ErrorCode.SSH_HOST_KEY_MISMATCH, msg);
  }

  static sshAgentFailed(detail?: Quoted): VaultError {
    const msg = shows(detail)
      ? say`Ephemeral ssh-agent failed: ${detail}`
      : bare(detail, vaultText`Ephemeral ssh-agent failed`);
    return new VaultError(ErrorCode.SSH_AGENT_FAILED, msg);
  }

  static sshNotConfigured(handle?: string): VaultError {
    const msg = handle
      ? `SSH host keys not pinned for secret: ${handle}`
      : bare(handle, vaultText`SSH host keys not pinned for secret`);
    return new VaultError(ErrorCode.SSH_NOT_CONFIGURED, msg);
  }

  static sshClientUnsupported(directory: Quoted): VaultError {
    return new VaultError(
      ErrorCode.SSH_CLIENT_UNSUPPORTED,
      say`Unsupported ssh client: the binary resolved under ${directory} is an MSYS/Cygwin build (msys-2.0.dll or cygwin1.dll beside it), which cannot reach the vault's named-pipe ssh-agent; allowlist the native Win32-OpenSSH client (C:\\Windows\\System32\\OpenSSH\\ssh.exe) and put its directory ahead of Git's usr\\bin on PATH`,
    );
  }

  static invalidSshConfig(message: string | VaultText): VaultError {
    return new VaultError(ErrorCode.INVALID_SSH_CONFIG, message);
  }

  static sshBootstrapNotAllowed(reason: SshBootstrapRefusalReason): VaultError {
    return new VaultError(
      ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED,
      SSH_BOOTSTRAP_NOT_ALLOWED_TEXT[reason],
    );
  }

  static sshPasswordNotOffered(): VaultError {
    return new VaultError(
      ErrorCode.SSH_PASSWORD_NOT_OFFERED,
      vaultText`SSH bootstrap refused: the server does not offer password login`,
    );
  }

  static sshPasswordRefused(): VaultError {
    return new VaultError(
      ErrorCode.SSH_PASSWORD_REFUSED,
      vaultText`SSH bootstrap refused: the server refused the stored password; repeating the bootstrap can lock the vault host out of the server`,
    );
  }

  static sshBootstrapStepFailed(
    dropIn: SshBootstrapDropInWord | TextPart,
    key: "not_attempted" | "failed" | TextPart,
  ): VaultError {
    return new VaultError(
      ErrorCode.SSH_BOOTSTRAP_STEP_FAILED,
      say`SSH bootstrap failed: no key was installed (sudoers: ${dropIn}, key: ${key})`,
    );
  }

  static sshBootstrapUnconfirmed(): VaultError {
    return new VaultError(
      ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED,
      vaultText`SSH bootstrap unconfirmed: a bootstrap of this secret has no confirmed outcome, so the secret was ended; a key and a sudoers drop-in may be installed on the host`,
    );
  }

  static sshBootstrapInFlight(): VaultError {
    return new VaultError(
      ErrorCode.SSH_BOOTSTRAP_IN_FLIGHT,
      vaultText`SSH bootstrap in flight: another bootstrap of this secret is running`,
    );
  }

  static sshBootstrapOnWindows(): VaultError {
    return new VaultError(
      ErrorCode.SSH_CLIENT_UNSUPPORTED,
      vaultText`Unsupported ssh client: the ssh bootstrap is not served on a Windows vault host`,
    );
  }

  static sshClientBelowFloor(
    found: string | null,
    floor: string,
    use: SshClientUse = "bootstrap",
  ): VaultError {
    const needs = use === "render" ? "an sftp render" : "an ssh bootstrap";
    return new VaultError(
      ErrorCode.SSH_CLIENT_UNSUPPORTED,
      found === null
        ? `Unsupported ssh client: its version could not be read; ${needs} needs OpenSSH ${floor} or later`
        : `Unsupported ssh client: OpenSSH ${found} is older than ${floor}, which ${needs} needs`,
    );
  }

  static gitOperationFailed(detail?: Quoted): VaultError {
    const msg = shows(detail)
      ? say`Git operation failed: ${detail}`
      : bare(detail, vaultText`Git operation failed`);
    return new VaultError(ErrorCode.GIT_OPERATION_FAILED, msg);
  }

  static gitUnsupportedTransport(repository?: Quoted): VaultError {
    const msg = shows(repository)
      ? say`Unsupported git transport for repository: ${repository}`
      : bare(repository, vaultText`Unsupported git transport`);
    return new VaultError(ErrorCode.GIT_UNSUPPORTED_TRANSPORT, msg);
  }

  static invalidGitConfig(message: string | VaultText): VaultError {
    return new VaultError(ErrorCode.INVALID_GIT_CONFIG, message);
  }

  static keyPassphraseInvalid(): VaultError {
    return new VaultError(
      ErrorCode.KEY_PASSPHRASE_INVALID,
      vaultText`Could not decrypt the private key: wrong passphrase or corrupted key material`,
    );
  }

  static encryptedKeyUnsupported(message?: string): VaultError {
    return new VaultError(
      ErrorCode.ENCRYPTED_KEY_UNSUPPORTED,
      message ??
        vaultText`Encrypted OpenSSH-format keys are not supported (bcrypt-pbkdf is outside node:crypto). RSA/ECDSA: convert in place with \`ssh-keygen -p -f <keyfile> -m PKCS8\` (the passphrase is kept), then re-import — the vault decrypts at import. Ed25519: ssh-keygen cannot write PKCS#8 — strip the passphrase with \`ssh-keygen -p -f <keyfile> -N ''\` and re-import (the vault stores the key under its own encryption either way)`,
    );
  }

  static dedicatedContextRequired(binary: Quoted, context: Quoted): VaultError {
    return new VaultError(
      ErrorCode.DEDICATED_CONTEXT_REQUIRED,
      say`'${binary}' has a dedicated injection context and cannot be run through the process context: its command allowlist entry exists so the '${context}' context can spawn it under vault-authored arguments. Use action.type '${context}' instead`,
    );
  }

  static keyBundleUnsupported(): VaultError {
    return new VaultError(
      ErrorCode.KEY_BUNDLE_UNSUPPORTED,
      vaultText`The file contains additional PEM blocks alongside an encrypted private key (a certificate bundle). Decrypt-at-import would silently drop everything but the key — import the key alone, or use --no-decrypt to store the bundle verbatim (the key then stays encrypted and is unusable for SSH until re-imported on its own)`,
    );
  }

  static recipientNotAllowed(recipient: Quoted): VaultError {
    return new VaultError(
      ErrorCode.RECIPIENT_NOT_ALLOWED,
      say`Recipient not in secret allowlist: ${recipient}`,
    );
  }

  static attachmentPolicyRequired(): VaultError {
    return new VaultError(
      ErrorCode.ATTACHMENT_POLICY_REQUIRED,
      vaultText`Attachments require an explicit recipient allowlist before they can be sent: configure one via secret allow <handle> --recipient`,
    );
  }

  static attachmentRejected(reason: Quoted): VaultError {
    return new VaultError(ErrorCode.ATTACHMENT_REJECTED, say`Attachment rejected: ${reason}`);
  }

  static imapMutationNotAllowed(operation: Quoted): VaultError {
    return new VaultError(
      ErrorCode.IMAP_MUTATION_NOT_ALLOWED,
      say`IMAP mutation '${operation}' is not allowed: this secret's IMAP policy is read-only`,
    );
  }

  static smtpStarttlsUnavailable(host: Quoted): VaultError {
    return new VaultError(
      ErrorCode.SMTP_STARTTLS_UNAVAILABLE,
      say`SMTP STARTTLS is required but not available on ${host}`,
    );
  }

  static smtpDeliveryFailed(origin: Quoted): VaultError {
    return new VaultError(ErrorCode.SMTP_DELIVERY_FAILED, say`SMTP delivery failed: ${origin}`);
  }

  static imapOperationFailed(origin: Quoted, operation: Quoted): VaultError {
    return new VaultError(
      ErrorCode.IMAP_OPERATION_FAILED,
      say`IMAP operation '${operation}' failed: ${origin}`,
    );
  }

  static imapMoveUnsupported(origin: Quoted): VaultError {
    return new VaultError(
      ErrorCode.IMAP_OPERATION_FAILED,
      say`IMAP operation 'move' refused: ${origin} advertises neither MOVE (RFC 6851) nor UIDPLUS (RFC 4315), so a move could only complete with a mailbox-wide EXPUNGE; use 'copy', then 'store' (\\Deleted) and 'expunge' explicitly if that is acceptable`,
    );
  }

  static websocketConnectFailed(origin: Quoted): VaultError {
    return new VaultError(
      ErrorCode.WEBSOCKET_CONNECT_FAILED,
      say`WebSocket connection failed: ${origin}`,
    );
  }

  static sftpOperationFailed(exitCode: number): VaultError {
    return new VaultError(
      ErrorCode.SFTP_OPERATION_FAILED,
      say`SFTP operation failed (exit code ${num(exitCode)})`,
    );
  }

  static localPathNotAllowed(): VaultError {
    return new VaultError(
      ErrorCode.LOCAL_PATH_NOT_ALLOWED,
      vaultText`sftp local path is not inside a directory the secret's policy lists`,
    );
  }

  static renderEntryNotFound(): VaultError {
    return new VaultError(
      ErrorCode.RENDER_ENTRY_NOT_FOUND,
      vaultText`SFTP render refused: the secret's injection policy holds no render entry of that name`,
    );
  }

  static renderInFlight(): VaultError {
    return new VaultError(
      ErrorCode.RENDER_IN_FLIGHT,
      vaultText`SFTP render in flight: another render to the same host, port and path is running`,
    );
  }

  static renderSlotRefused(): VaultError {
    return new VaultError(
      ErrorCode.RENDER_SLOT_REFUSED,
      vaultText`SFTP render refused: a slot of the entry's template cannot be served to this call`,
    );
  }

  static renderSlotUnsupported(): VaultError {
    return new VaultError(
      ErrorCode.RENDER_SLOT_UNSUPPORTED,
      vaultText`SFTP render refused: a slot's secret is one a render does not serve`,
    );
  }

  static renderNotApproved(): VaultError {
    return new VaultError(
      ErrorCode.RENDER_NOT_APPROVED,
      vaultText`SFTP render refused: a slot's secret has not approved the entry as it stands`,
    );
  }

  static renderValueUnsupported(): VaultError {
    return new VaultError(
      ErrorCode.RENDER_VALUE_UNSUPPORTED,
      vaultText`SFTP render refused: a value does not fit the template: every value is UTF-8 text without a NUL, 1 to 65536 bytes, and beside other text only of A-Z, a-z, 0-9 and . _ ~ + / = : @ % -`,
    );
  }

  static renderOnlyKey(): VaultError {
    return new VaultError(
      ErrorCode.RENDER_ONLY_KEY,
      vaultText`Use refused: the secret holds a render entry and serves the sftp render alone`,
    );
  }

  static renderFailed(): VaultError {
    return new VaultError(
      ErrorCode.RENDER_FAILED,
      vaultText`SFTP render failed: the file is not confirmed written; the key's audit row holds the reason`,
    );
  }

  static localPathProtected(): VaultError {
    return new VaultError(
      ErrorCode.LOCAL_PATH_NOT_ALLOWED,
      vaultText`git working directory is inside a directory the vault protects`,
    );
  }

  static workTreeHoldsProtectedPath(): VaultError {
    return new VaultError(
      ErrorCode.LOCAL_PATH_NOT_ALLOWED,
      vaultText`git work tree holds a path the vault protects`,
    );
  }

  static dockerOperationFailed(exitCode: number): VaultError {
    return new VaultError(
      ErrorCode.DOCKER_OPERATION_FAILED,
      say`Docker operation failed (exit code ${num(exitCode)})`,
    );
  }

  static agentNotFound(name: string): VaultError {
    return new VaultError(
      ErrorCode.AGENT_NOT_FOUND,
      `Agent not registered: "${name}". Register it with: harpoc agent register ${name}`,
    );
  }

  static agentInactive(name: string): VaultError {
    return new VaultError(
      ErrorCode.AGENT_INACTIVE,
      `Agent "${name}" is deactivated. Reactivate it with: harpoc agent activate ${name}`,
    );
  }

  static agentExists(name: string): VaultError {
    return new VaultError(ErrorCode.AGENT_EXISTS, `Agent already registered: "${name}"`);
  }

  static missingDependency(specifier: string): VaultError {
    return new VaultError(
      ErrorCode.MISSING_DEPENDENCY,
      `Optional dependency "${specifier}" is not installed. Install it to use this feature.`,
    );
  }

  static restModeUnsupported(what: string): VaultError {
    return new VaultError(
      ErrorCode.REST_MODE_UNSUPPORTED,
      `${what} has no REST mode; run it on the vault host`,
    );
  }

  static sessionModeConflict(flag: string): VaultError {
    return new VaultError(
      ErrorCode.SESSION_MODE_CONFLICT,
      `${flag} requires --session memory: on a session file the daemon would seal when the session expires or an administrator unlocks the vault`,
    );
  }

  static proxyPlaceholderDenied(origin: string): VaultError {
    return new VaultError(
      ErrorCode.PROXY_PLACEHOLDER_DENIED,
      `Placeholder refused for ${origin}: the secret is not enabled for the egress proxy (harpoc secret allow --proxy)`,
    );
  }

  static proxyMultiplePlaceholders(origin: string): VaultError {
    return new VaultError(
      ErrorCode.PROXY_PLACEHOLDER_DENIED,
      `Placeholder refused for ${origin}: one placeholder per request`,
    );
  }

  static proxyUpstreamFailed(origin: string, reason?: ProxyUpstreamFailureReason): VaultError {
    return new VaultError(
      ErrorCode.PROXY_UPSTREAM_FAILED,
      reason === undefined
        ? `Egress proxy upstream request failed: ${origin}`
        : `Egress proxy upstream request failed (${reason}): ${origin}`,
    );
  }

  /**
   * A CONNECT to a host outside the proxy CA's host list (deployment model B, M4(ii); RX-B8-15):
   * the host and port only, an IPv6 literal bracketed.
   */
  static proxyConnectDenied(host: string, port: number): VaultError {
    const authority = host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
    return new VaultError(
      ErrorCode.PROXY_CONNECT_DENIED,
      `CONNECT to ${authority}:${String(port)} is outside the proxy CA's name constraints (harpoc proxy ca init --name-constraints <host>…)`,
    );
  }

  static proxyCaExists(): VaultError {
    return new VaultError(
      ErrorCode.DUPLICATE_SECRET,
      vaultText`The Harpoc CA already exists (secret://harpoc-ca); harpoc proxy ca init --force replaces it`,
    );
  }

  static proxyCaNotConfigured(): VaultError {
    return new VaultError(
      ErrorCode.CERT_NOT_CONFIGURED,
      vaultText`No Harpoc CA in this vault (secret://harpoc-ca); harpoc proxy ca init creates one`,
    );
  }

  static proxyCaExpired(notAfter: string): VaultError {
    return new VaultError(
      ErrorCode.CERT_EXPIRED,
      `The Harpoc CA (secret://harpoc-ca) expired at ${notAfter}; harpoc proxy ca init --force issues a new one`,
    );
  }

  static sshAgentUnbound(reason: SshAgentUnboundReason): VaultError {
    return new VaultError(
      ErrorCode.SSH_AGENT_UNBOUND,
      `Agent socket signature refused: ${SSH_AGENT_UNBOUND_TEXT[reason]}`,
      { reason },
    );
  }

  static invalidUnlockKey(detail?: string): VaultError {
    return new VaultError(
      ErrorCode.INVALID_UNLOCK_KEY,
      detail === undefined ? vaultText`Invalid unlock key` : `Invalid unlock key: ${detail}`,
    );
  }

  static unlockKeyNotEnrolled(): VaultError {
    return new VaultError(
      ErrorCode.UNLOCK_KEY_NOT_ENROLLED,
      vaultText`No unlock key is enrolled for this vault (harpoc unlock-key enroll)`,
    );
  }

  static unlockKeySourceUnsafe(
    path: string,
    reason: UnlockKeySourceUnsafeReason,
    observed?: string,
  ): VaultError {
    return new VaultError(
      ErrorCode.UNLOCK_KEY_SOURCE_UNSAFE,
      `Unlock key source refused: ${path} ${UNLOCK_KEY_SOURCE_UNSAFE_TEXT[reason]}${observed === undefined ? "" : ` (${observed})`}`,
      { reason },
    );
  }

  static unlockKeyPasswordRequired(): VaultError {
    return new VaultError(
      ErrorCode.UNLOCK_KEY_PASSWORD_REQUIRED,
      vaultText`Enrolling or revoking an unlock key requires an unlock by password in this process`,
    );
  }

  static responseTooLarge(origin: Quoted, maxBytes: number): VaultError {
    const text = asText(origin);
    return new VaultError(
      ErrorCode.RESPONSE_TOO_LARGE,
      text === undefined
        ? `Response body from ${plain(origin)} exceeds the ${maxBytes}-byte limit`
        : vaultText`Response body from ${text} exceeds the ${num(maxBytes)}-byte limit`,
    );
  }
}

export function recordOf(err: unknown): ErrorRecord | undefined {
  return err instanceof VaultError ? RECORDS.get(err) : undefined;
}
