import { describe, expect, it } from "vitest";

import { ErrorCode, VaultError } from "./errors.js";

describe("VaultError", () => {
  it("is an instance of Error", () => {
    const err = new VaultError(ErrorCode.INTERNAL_ERROR, "test");
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(VaultError);
  });

  it("preserves code, message, and statusCode", () => {
    const err = new VaultError(ErrorCode.SECRET_NOT_FOUND, "gone");
    expect(err.code).toBe(ErrorCode.SECRET_NOT_FOUND);
    expect(err.message).toBe("gone");
    expect(err.statusCode).toBe(404);
    expect(err.name).toBe("VaultError");
  });

  it("preserves details", () => {
    const details = { key: "value" };
    const err = new VaultError(ErrorCode.INTERNAL_ERROR, "oops", details);
    expect(err.details).toEqual({ key: "value" });
  });

  it("has undefined details when not provided", () => {
    const err = new VaultError(ErrorCode.INTERNAL_ERROR, "oops");
    expect(err.details).toBeUndefined();
  });
});

describe("HTTP status mapping", () => {
  it.each([
    // Vault state
    [ErrorCode.VAULT_LOCKED, 423],
    [ErrorCode.VAULT_NOT_FOUND, 404],
    [ErrorCode.VAULT_CORRUPTED, 500],
    // Auth
    [ErrorCode.INVALID_PASSWORD, 401],
    [ErrorCode.INVALID_TOKEN, 401],
    [ErrorCode.TOKEN_EXPIRED, 401],
    [ErrorCode.TOKEN_REVOKED, 401],
    [ErrorCode.ACCESS_DENIED, 403],
    [ErrorCode.LOCKOUT_ACTIVE, 429],
    // Secrets
    [ErrorCode.SECRET_NOT_FOUND, 404],
    [ErrorCode.AMBIGUOUS_HANDLE, 409],
    [ErrorCode.DUPLICATE_SECRET, 409],
    [ErrorCode.SECRET_EXPIRED, 410],
    [ErrorCode.SECRET_REVOKED, 410],
    [ErrorCode.INVALID_SECRET_TYPE, 400],
    [ErrorCode.SECRET_VALUE_REQUIRED, 400],
    // HTTP injection
    [ErrorCode.URL_INVALID, 400],
    [ErrorCode.URL_HTTPS_REQUIRED, 400],
    [ErrorCode.SSRF_BLOCKED, 403],
    [ErrorCode.TLS_ERROR, 502],
    [ErrorCode.DNS_RESOLUTION_FAILED, 502],
    [ErrorCode.CONNECTION_REFUSED, 502],
    [ErrorCode.TIMEOUT, 504],
    [ErrorCode.REDIRECT_POLICY_VIOLATION, 502],
    [ErrorCode.INVALID_INJECTION_CONFIG, 400],
    // Validation
    [ErrorCode.WEAK_PASSWORD, 400],
    [ErrorCode.INVALID_INPUT, 400],
    [ErrorCode.INVALID_HANDLE, 400],
    [ErrorCode.INVALID_PROJECT_NAME, 400],
    [ErrorCode.INVALID_SECRET_NAME, 400],
    [ErrorCode.SCHEMA_VALIDATION_ERROR, 400],
    // Policy
    [ErrorCode.POLICY_NOT_FOUND, 404],
    [ErrorCode.POLICY_CONFLICT, 409],
    [ErrorCode.PRINCIPAL_NOT_FOUND, 404],
    // OAuth
    [ErrorCode.OAUTH_FLOW_FAILED, 502],
    [ErrorCode.OAUTH_CALLBACK_TIMEOUT, 504],
    [ErrorCode.OAUTH_INVALID_STATE, 400],
    [ErrorCode.OAUTH_TOKEN_EXCHANGE_FAILED, 502],
    [ErrorCode.OAUTH_REFRESH_FAILED, 502],
    [ErrorCode.OAUTH_PROVIDER_NOT_FOUND, 404],
    [ErrorCode.OAUTH_NOT_CONFIGURED, 400],
    // Certificates
    [ErrorCode.CERT_INVALID, 400],
    [ErrorCode.CERT_EXPIRED, 410],
    [ErrorCode.CERT_PRIVATE_KEY_MISMATCH, 400],
    [ErrorCode.CERT_ACME_FAILED, 502],
    [ErrorCode.CERT_CSR_FAILED, 500],
    [ErrorCode.CERT_NOT_CONFIGURED, 400],
    // System
    [ErrorCode.INTERNAL_ERROR, 500],
    [ErrorCode.DATABASE_ERROR, 500],
    [ErrorCode.ENCRYPTION_ERROR, 500],
    [ErrorCode.KEY_DERIVATION_ERROR, 500],
    [ErrorCode.FILE_IO_ERROR, 500],
    [ErrorCode.SESSION_FILE_ERROR, 500],
  ] as const)("%s → %d", (code, expected) => {
    const err = new VaultError(code, "test");
    expect(err.statusCode).toBe(expected);
  });

  it("covers all ErrorCode members", () => {
    const members = Object.values(ErrorCode).filter((v) => typeof v === "string");
    expect(members).toHaveLength(54);
  });
});

describe("factory methods", () => {
  it("vaultLocked()", () => {
    const err = VaultError.vaultLocked();
    expect(err.code).toBe(ErrorCode.VAULT_LOCKED);
    expect(err.statusCode).toBe(423);
  });

  it("secretNotFound() without handle", () => {
    const err = VaultError.secretNotFound();
    expect(err.code).toBe(ErrorCode.SECRET_NOT_FOUND);
    expect(err.message).toBe("Secret not found");
  });

  it("secretNotFound() with handle", () => {
    const err = VaultError.secretNotFound("secret://my-key");
    expect(err.message).toBe("Secret not found: secret://my-key");
  });

  it("accessDenied() with detail", () => {
    const err = VaultError.accessDenied("no use permission");
    expect(err.code).toBe(ErrorCode.ACCESS_DENIED);
    expect(err.statusCode).toBe(403);
    expect(err.message).toBe("Access denied: no use permission");
  });

  it("invalidInput()", () => {
    const err = VaultError.invalidInput("bad data");
    expect(err.code).toBe(ErrorCode.INVALID_INPUT);
    expect(err.statusCode).toBe(400);
  });

  it("invalidHandle()", () => {
    const err = VaultError.invalidHandle("nope");
    expect(err.code).toBe(ErrorCode.INVALID_HANDLE);
    expect(err.message).toBe("Invalid handle: nope");
  });

  it("lockoutActive() includes retry_after_ms", () => {
    const err = VaultError.lockoutActive(30_000);
    expect(err.code).toBe(ErrorCode.LOCKOUT_ACTIVE);
    expect(err.details).toEqual({ retry_after_ms: 30_000 });
  });

  it("duplicateSecret()", () => {
    const err = VaultError.duplicateSecret("my-key");
    expect(err.code).toBe(ErrorCode.DUPLICATE_SECRET);
    expect(err.statusCode).toBe(409);
  });

  it("vaultNotFound()", () => {
    const err = VaultError.vaultNotFound();
    expect(err.code).toBe(ErrorCode.VAULT_NOT_FOUND);
    expect(err.statusCode).toBe(404);
    expect(err.message).toBe("Vault not found");
  });

  it("invalidPassword()", () => {
    const err = VaultError.invalidPassword();
    expect(err.code).toBe(ErrorCode.INVALID_PASSWORD);
    expect(err.statusCode).toBe(401);
    expect(err.message).toBe("Invalid password");
  });

  it("schemaValidation()", () => {
    const err = VaultError.schemaValidation("field X is required");
    expect(err.code).toBe(ErrorCode.SCHEMA_VALIDATION_ERROR);
    expect(err.statusCode).toBe(400);
    expect(err.message).toBe("field X is required");
  });

  it("internalError()", () => {
    const err = VaultError.internalError("unexpected failure");
    expect(err.code).toBe(ErrorCode.INTERNAL_ERROR);
    expect(err.statusCode).toBe(500);
    expect(err.message).toBe("unexpected failure");
  });

  it("accessDenied() without argument", () => {
    const err = VaultError.accessDenied();
    expect(err.code).toBe(ErrorCode.ACCESS_DENIED);
    expect(err.message).toBe("Access denied");
  });

  it("vaultCorrupted() without detail", () => {
    const err = VaultError.vaultCorrupted();
    expect(err.code).toBe(ErrorCode.VAULT_CORRUPTED);
    expect(err.statusCode).toBe(500);
    expect(err.message).toBe("Vault corrupted");
  });

  it("vaultCorrupted() with detail", () => {
    const err = VaultError.vaultCorrupted("bad header checksum");
    expect(err.code).toBe(ErrorCode.VAULT_CORRUPTED);
    expect(err.message).toBe("Vault corrupted: bad header checksum");
  });

  it("encryptionError() without detail", () => {
    const err = VaultError.encryptionError();
    expect(err.code).toBe(ErrorCode.ENCRYPTION_ERROR);
    expect(err.statusCode).toBe(500);
    expect(err.message).toBe("Encryption error");
  });

  it("encryptionError() with detail", () => {
    const err = VaultError.encryptionError("GCM tag mismatch");
    expect(err.message).toBe("Encryption error: GCM tag mismatch");
  });

  it("databaseError() without detail", () => {
    const err = VaultError.databaseError();
    expect(err.code).toBe(ErrorCode.DATABASE_ERROR);
    expect(err.statusCode).toBe(500);
    expect(err.message).toBe("Database error");
  });

  it("databaseError() with detail", () => {
    const err = VaultError.databaseError("table locked");
    expect(err.message).toBe("Database error: table locked");
  });

  it("secretExpired() without handle", () => {
    const err = VaultError.secretExpired();
    expect(err.code).toBe(ErrorCode.SECRET_EXPIRED);
    expect(err.statusCode).toBe(410);
    expect(err.message).toBe("Secret expired");
  });

  it("secretExpired() with handle", () => {
    const err = VaultError.secretExpired("secret://my-key");
    expect(err.message).toBe("Secret expired: secret://my-key");
  });

  it("secretRevoked() without handle", () => {
    const err = VaultError.secretRevoked();
    expect(err.code).toBe(ErrorCode.SECRET_REVOKED);
    expect(err.statusCode).toBe(410);
    expect(err.message).toBe("Secret revoked");
  });

  it("secretRevoked() with handle", () => {
    const err = VaultError.secretRevoked("secret://old-key");
    expect(err.message).toBe("Secret revoked: secret://old-key");
  });

  it("tokenExpired()", () => {
    const err = VaultError.tokenExpired();
    expect(err.code).toBe(ErrorCode.TOKEN_EXPIRED);
    expect(err.statusCode).toBe(401);
    expect(err.message).toBe("Token expired");
  });

  it("tokenRevoked()", () => {
    const err = VaultError.tokenRevoked();
    expect(err.code).toBe(ErrorCode.TOKEN_REVOKED);
    expect(err.statusCode).toBe(401);
    expect(err.message).toBe("Token revoked");
  });

  it("sessionFileError() without detail", () => {
    const err = VaultError.sessionFileError();
    expect(err.code).toBe(ErrorCode.SESSION_FILE_ERROR);
    expect(err.statusCode).toBe(500);
    expect(err.message).toBe("Session file error");
  });

  it("sessionFileError() with detail", () => {
    const err = VaultError.sessionFileError("parse failed");
    expect(err.message).toBe("Session file error: parse failed");
  });

  it("weakPassword()", () => {
    const err = VaultError.weakPassword(8);
    expect(err.code).toBe(ErrorCode.WEAK_PASSWORD);
    expect(err.statusCode).toBe(400);
    expect(err.message).toBe("Password must be at least 8 characters");
  });

  it("oauthFlowFailed() without detail", () => {
    const err = VaultError.oauthFlowFailed();
    expect(err.code).toBe(ErrorCode.OAUTH_FLOW_FAILED);
    expect(err.statusCode).toBe(502);
    expect(err.message).toBe("OAuth flow failed");
  });

  it("oauthFlowFailed() with detail", () => {
    const err = VaultError.oauthFlowFailed("provider unreachable");
    expect(err.message).toBe("OAuth flow failed: provider unreachable");
  });

  it("oauthCallbackTimeout()", () => {
    const err = VaultError.oauthCallbackTimeout();
    expect(err.code).toBe(ErrorCode.OAUTH_CALLBACK_TIMEOUT);
    expect(err.statusCode).toBe(504);
  });

  it("oauthInvalidState()", () => {
    const err = VaultError.oauthInvalidState();
    expect(err.code).toBe(ErrorCode.OAUTH_INVALID_STATE);
    expect(err.statusCode).toBe(400);
  });

  it("oauthTokenExchangeFailed() without detail", () => {
    const err = VaultError.oauthTokenExchangeFailed();
    expect(err.code).toBe(ErrorCode.OAUTH_TOKEN_EXCHANGE_FAILED);
    expect(err.statusCode).toBe(502);
    expect(err.message).toBe("OAuth token exchange failed");
  });

  it("oauthTokenExchangeFailed() with detail", () => {
    const err = VaultError.oauthTokenExchangeFailed("invalid grant");
    expect(err.message).toBe("OAuth token exchange failed: invalid grant");
  });

  it("oauthRefreshFailed() without detail", () => {
    const err = VaultError.oauthRefreshFailed();
    expect(err.code).toBe(ErrorCode.OAUTH_REFRESH_FAILED);
    expect(err.statusCode).toBe(502);
    expect(err.message).toBe("OAuth token refresh failed");
  });

  it("oauthRefreshFailed() with detail", () => {
    const err = VaultError.oauthRefreshFailed("refresh token revoked");
    expect(err.message).toBe("OAuth token refresh failed: refresh token revoked");
  });

  it("oauthProviderNotFound()", () => {
    const err = VaultError.oauthProviderNotFound("unknown-provider");
    expect(err.code).toBe(ErrorCode.OAUTH_PROVIDER_NOT_FOUND);
    expect(err.statusCode).toBe(404);
    expect(err.message).toBe("OAuth provider not found: unknown-provider");
  });

  it("oauthNotConfigured() without handle", () => {
    const err = VaultError.oauthNotConfigured();
    expect(err.code).toBe(ErrorCode.OAUTH_NOT_CONFIGURED);
    expect(err.statusCode).toBe(400);
    expect(err.message).toBe("OAuth not configured for secret");
  });

  it("oauthNotConfigured() with handle", () => {
    const err = VaultError.oauthNotConfigured("secret://my-key");
    expect(err.message).toBe("OAuth not configured for secret: secret://my-key");
  });

  it("certInvalid() without detail", () => {
    const err = VaultError.certInvalid();
    expect(err.code).toBe(ErrorCode.CERT_INVALID);
    expect(err.statusCode).toBe(400);
    expect(err.message).toBe("Certificate invalid");
  });

  it("certInvalid() with detail", () => {
    const err = VaultError.certInvalid("malformed PEM");
    expect(err.message).toBe("Certificate invalid: malformed PEM");
  });

  it("certExpired() without subject", () => {
    const err = VaultError.certExpired();
    expect(err.code).toBe(ErrorCode.CERT_EXPIRED);
    expect(err.statusCode).toBe(410);
    expect(err.message).toBe("Certificate expired");
  });

  it("certExpired() with subject", () => {
    const err = VaultError.certExpired("CN=example.com");
    expect(err.message).toBe("Certificate expired: CN=example.com");
  });

  it("certPrivateKeyMismatch()", () => {
    const err = VaultError.certPrivateKeyMismatch();
    expect(err.code).toBe(ErrorCode.CERT_PRIVATE_KEY_MISMATCH);
    expect(err.statusCode).toBe(400);
  });

  it("certAcmeFailed() without detail", () => {
    const err = VaultError.certAcmeFailed();
    expect(err.code).toBe(ErrorCode.CERT_ACME_FAILED);
    expect(err.statusCode).toBe(502);
    expect(err.message).toBe("ACME operation failed");
  });

  it("certAcmeFailed() with detail", () => {
    const err = VaultError.certAcmeFailed("challenge failed");
    expect(err.message).toBe("ACME operation failed: challenge failed");
  });

  it("certCsrFailed() without detail", () => {
    const err = VaultError.certCsrFailed();
    expect(err.code).toBe(ErrorCode.CERT_CSR_FAILED);
    expect(err.statusCode).toBe(500);
    expect(err.message).toBe("CSR generation failed");
  });

  it("certCsrFailed() with detail", () => {
    const err = VaultError.certCsrFailed("invalid subject");
    expect(err.message).toBe("CSR generation failed: invalid subject");
  });

  it("certNotConfigured() without handle", () => {
    const err = VaultError.certNotConfigured();
    expect(err.code).toBe(ErrorCode.CERT_NOT_CONFIGURED);
    expect(err.statusCode).toBe(400);
    expect(err.message).toBe("Certificate not configured for secret");
  });

  it("certNotConfigured() with handle", () => {
    const err = VaultError.certNotConfigured("secret://my-cert");
    expect(err.message).toBe("Certificate not configured for secret: secret://my-cert");
  });
});
