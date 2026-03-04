// ---------------------------------------------------------------------------
// Error codes and VaultError class
// ---------------------------------------------------------------------------

export enum ErrorCode {
  // Vault state
  VAULT_LOCKED = "VAULT_LOCKED",
  VAULT_NOT_FOUND = "VAULT_NOT_FOUND",
  VAULT_CORRUPTED = "VAULT_CORRUPTED",

  // Auth
  INVALID_PASSWORD = "INVALID_PASSWORD",
  WEAK_PASSWORD = "WEAK_PASSWORD",
  INVALID_TOKEN = "INVALID_TOKEN",
  TOKEN_EXPIRED = "TOKEN_EXPIRED",
  TOKEN_REVOKED = "TOKEN_REVOKED",
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

  // System
  INTERNAL_ERROR = "INTERNAL_ERROR",
  DATABASE_ERROR = "DATABASE_ERROR",
  ENCRYPTION_ERROR = "ENCRYPTION_ERROR",
  KEY_DERIVATION_ERROR = "KEY_DERIVATION_ERROR",
  FILE_IO_ERROR = "FILE_IO_ERROR",
  SESSION_FILE_ERROR = "SESSION_FILE_ERROR",
}

const STATUS_MAP: Record<ErrorCode, number> = {
  // Vault state
  [ErrorCode.VAULT_LOCKED]: 423,
  [ErrorCode.VAULT_NOT_FOUND]: 404,
  [ErrorCode.VAULT_CORRUPTED]: 500,

  // Auth
  [ErrorCode.INVALID_PASSWORD]: 401,
  [ErrorCode.WEAK_PASSWORD]: 400,
  [ErrorCode.INVALID_TOKEN]: 401,
  [ErrorCode.TOKEN_EXPIRED]: 401,
  [ErrorCode.TOKEN_REVOKED]: 401,
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

  // System
  [ErrorCode.INTERNAL_ERROR]: 500,
  [ErrorCode.DATABASE_ERROR]: 500,
  [ErrorCode.ENCRYPTION_ERROR]: 500,
  [ErrorCode.KEY_DERIVATION_ERROR]: 500,
  [ErrorCode.FILE_IO_ERROR]: 500,
  [ErrorCode.SESSION_FILE_ERROR]: 500,
};

export class VaultError extends Error {
  readonly code: ErrorCode;
  readonly statusCode: number;
  readonly details?: Record<string, unknown>;

  constructor(code: ErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = "VaultError";
    this.code = code;
    this.statusCode = STATUS_MAP[code];
    this.details = details;
  }

  static vaultLocked(): VaultError {
    return new VaultError(ErrorCode.VAULT_LOCKED, "Vault is locked");
  }

  static vaultNotFound(): VaultError {
    return new VaultError(ErrorCode.VAULT_NOT_FOUND, "Vault not found");
  }

  static secretNotFound(handle?: string): VaultError {
    const msg = handle ? `Secret not found: ${handle}` : "Secret not found";
    return new VaultError(ErrorCode.SECRET_NOT_FOUND, msg);
  }

  static accessDenied(detail?: string): VaultError {
    const msg = detail ? `Access denied: ${detail}` : "Access denied";
    return new VaultError(ErrorCode.ACCESS_DENIED, msg);
  }

  static invalidInput(message: string): VaultError {
    return new VaultError(ErrorCode.INVALID_INPUT, message);
  }

  static invalidHandle(handle: string): VaultError {
    return new VaultError(ErrorCode.INVALID_HANDLE, `Invalid handle: ${handle}`);
  }

  static invalidPassword(): VaultError {
    return new VaultError(ErrorCode.INVALID_PASSWORD, "Invalid password");
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

  static internalError(message: string): VaultError {
    return new VaultError(ErrorCode.INTERNAL_ERROR, message);
  }

  static vaultCorrupted(detail?: string): VaultError {
    const msg = detail ? `Vault corrupted: ${detail}` : "Vault corrupted";
    return new VaultError(ErrorCode.VAULT_CORRUPTED, msg);
  }

  static encryptionError(detail?: string): VaultError {
    const msg = detail ? `Encryption error: ${detail}` : "Encryption error";
    return new VaultError(ErrorCode.ENCRYPTION_ERROR, msg);
  }

  static databaseError(detail?: string): VaultError {
    const msg = detail ? `Database error: ${detail}` : "Database error";
    return new VaultError(ErrorCode.DATABASE_ERROR, msg);
  }

  static secretExpired(handle?: string): VaultError {
    const msg = handle ? `Secret expired: ${handle}` : "Secret expired";
    return new VaultError(ErrorCode.SECRET_EXPIRED, msg);
  }

  static secretRevoked(handle?: string): VaultError {
    const msg = handle ? `Secret revoked: ${handle}` : "Secret revoked";
    return new VaultError(ErrorCode.SECRET_REVOKED, msg);
  }

  static tokenExpired(): VaultError {
    return new VaultError(ErrorCode.TOKEN_EXPIRED, "Token expired");
  }

  static tokenRevoked(): VaultError {
    return new VaultError(ErrorCode.TOKEN_REVOKED, "Token revoked");
  }

  static sessionFileError(detail?: string): VaultError {
    const msg = detail ? `Session file error: ${detail}` : "Session file error";
    return new VaultError(ErrorCode.SESSION_FILE_ERROR, msg);
  }

  static weakPassword(minLength: number): VaultError {
    return new VaultError(
      ErrorCode.WEAK_PASSWORD,
      `Password must be at least ${minLength} characters`,
    );
  }
}
