import { createHmac, timingSafeEqual } from "node:crypto";
import type {
  AccessPolicy,
  CreateSecretResponse,
  FollowRedirects,
  HttpMethod,
  InjectionConfig,
  OAuthProviderConfig,
  OAuthTokenStatus,
  Permission,
  UseSecretResponse,
  VaultApiToken,
} from "@harpoc/shared";
import {
  AAD_OAUTH_ACCESS_TOKEN,
  AAD_OAUTH_CLIENT_ID,
  AAD_OAUTH_CLIENT_SECRET,
  AAD_OAUTH_REFRESH_TOKEN,
  AAD_SESSION_AUDIT,
  AAD_SESSION_JWT,
  AAD_SESSION_KEK,
  AAD_WRAPPED_AUDIT_KEY,
  AAD_WRAPPED_JWT_KEY,
  AES_KEY_LENGTH,
  AuditEventType,
  ErrorCode,
  LOCKOUT_DURATIONS_MS,
  LOCKOUT_MAX_ATTEMPTS,
  MAX_TOKEN_TTL_MS,
  MIN_PASSWORD_LENGTH,
  OAuthProviderPreset,
  SecretStatus,
  SecretType,
  SESSION_CLEANUP_INTERVAL_MS,
  VaultError,
  VaultState,
  VAULT_VERSION,
} from "@harpoc/shared";
import { PolicyEngine } from "./access/policy-engine.js";
import type { GrantPolicyInput } from "./access/policy-engine.js";
import { AuditLogger } from "./audit/audit-logger.js";
import { AuditQuery } from "./audit/audit-query.js";
import type { AuditQueryOptions, DecryptedAuditEvent } from "./audit/audit-query.js";
import { decrypt, encrypt } from "./crypto/aes-gcm.js";
import type { WrappedKey } from "./crypto/key-hierarchy.js";
import {
  changePassword,
  createVaultKeys,
  unlockVault,
  wrapKeyWithKek,
} from "./crypto/key-hierarchy.js";
import { generateRandomBytes, generateUUIDv7, wipeBuffer } from "./crypto/random.js";
import { HttpInjector } from "./injection/http-injector.js";
import { validateUrl } from "./injection/url-validator.js";
import type { SecretInfo } from "./secrets/secret-manager.js";
import { SecretManager } from "./secrets/secret-manager.js";
import { SessionManager } from "./session/session-manager.js";
import { SqliteStore } from "./storage/sqlite-store.js";
import type { OAuthTokenRow } from "./storage/sqlite-store.js";

export interface VaultEngineOptions {
  dbPath: string;
  sessionPath: string;
}

interface UnlockedState {
  store: SqliteStore;
  kek: Uint8Array;
  jwtKey: Uint8Array;
  auditKey: Uint8Array;
  vaultId: string;
  secretManager: SecretManager;
  policyEngine: PolicyEngine;
  auditLogger: AuditLogger;
  auditQuery: AuditQuery;
  httpInjector: HttpInjector;
}

/**
 * Central orchestrator for the vault. Manages lifecycle, secrets, policies, audit, and JWT auth.
 */
export class VaultEngine {
  private state: VaultState = VaultState.SEALED;
  private store: SqliteStore | null = null;
  private kek: Uint8Array | null = null;
  private jwtKey: Uint8Array | null = null;
  private auditKey: Uint8Array | null = null;
  private vaultId: string | null = null;
  private sessionId: string | null = null;

  private secretManager: SecretManager | null = null;
  private policyEngine: PolicyEngine | null = null;
  private auditLogger: AuditLogger | null = null;
  private auditQuery: AuditQuery | null = null;
  private httpInjector: HttpInjector | null = null;
  private sessionManager: SessionManager;
  private sessionMonitorInterval: ReturnType<typeof setInterval> | null = null;

  constructor(private readonly options: VaultEngineOptions) {
    this.sessionManager = new SessionManager(options.sessionPath);
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  /**
   * Initialize a new vault: generate keys, create database, write session.
   */
  async initVault(password: string): Promise<{ vaultId: string }> {
    this.validatePassword(password);

    const keys = await createVaultKeys(password);

    const store = new SqliteStore(this.options.dbPath);
    store.setMeta("vault_id", keys.vaultId);
    store.setMeta("vault_version", VAULT_VERSION);

    // Store wrapped KEK
    store.setMeta("kdf_salt", Buffer.from(keys.salt).toString("base64"));
    store.setMeta("wrapped_kek", Buffer.from(keys.wrappedKek).toString("base64"));
    store.setMeta("wrapped_kek_iv", Buffer.from(keys.wrappedKekIv).toString("base64"));
    store.setMeta("wrapped_kek_tag", Buffer.from(keys.wrappedKekTag).toString("base64"));

    // Store wrapped JWT and audit keys in vault_meta
    this.storeWrappedKey(store, "wrapped_jwt_key", keys.wrappedJwtKey);
    this.storeWrappedKey(store, "wrapped_audit_key", keys.wrappedAuditKey);

    // Set internal state
    this.store = store;
    this.vaultId = keys.vaultId;
    this.kek = keys.kek;
    this.jwtKey = keys.jwtKey;
    this.auditKey = keys.auditKey;
    this.state = VaultState.UNLOCKED;

    this.initManagers();

    // Write session
    await this.writeNewSession();

    const logger = this.auditLogger as AuditLogger;
    logger.log({
      eventType: AuditEventType.VAULT_UNLOCK,
      sessionId: this.sessionId ?? undefined,
    });

    return { vaultId: keys.vaultId };
  }

  /**
   * Unlock an existing vault with a password.
   */
  async unlock(password: string): Promise<void> {
    const isNewStore = this.store === null;
    const store = this.store ?? new SqliteStore(this.options.dbPath);

    const vaultId = store.getMeta("vault_id");
    if (!vaultId) {
      store.close();
      throw VaultError.vaultNotFound();
    }

    // Version check
    const vaultVersion = store.getMeta("vault_version");
    if (vaultVersion && vaultVersion > VAULT_VERSION) {
      store.close();
      throw VaultError.vaultCorrupted(
        `Vault version ${vaultVersion} is newer than supported ${VAULT_VERSION}`,
      );
    }

    // Check lockout
    this.checkLockout(store);

    const salt = this.loadBase64Meta(store, "kdf_salt");
    const wrappedKek = this.loadBase64Meta(store, "wrapped_kek");
    const wrappedKekIv = this.loadBase64Meta(store, "wrapped_kek_iv");
    const wrappedKekTag = this.loadBase64Meta(store, "wrapped_kek_tag");

    // Load optional wrapped JWT/audit keys from vault_meta
    const wrappedJwtKey = this.loadOptionalWrappedKey(store, "wrapped_jwt_key");
    const wrappedAuditKey = this.loadOptionalWrappedKey(store, "wrapped_audit_key");

    try {
      const keys = await unlockVault(
        password,
        salt,
        wrappedKek,
        wrappedKekIv,
        wrappedKekTag,
        vaultId,
        wrappedJwtKey,
        wrappedAuditKey,
      );

      this.store = store;
      this.vaultId = vaultId;
      this.kek = keys.kek;
      this.jwtKey = keys.jwtKey;
      this.auditKey = keys.auditKey;
      this.state = VaultState.UNLOCKED;

      // One-time migration: if no wrapped keys in meta, generate and store them
      if (!wrappedJwtKey || !wrappedAuditKey) {
        const wJwt = wrapKeyWithKek(keys.kek, keys.jwtKey, AAD_WRAPPED_JWT_KEY);
        const wAudit = wrapKeyWithKek(keys.kek, keys.auditKey, AAD_WRAPPED_AUDIT_KEY);
        this.storeWrappedKey(store, "wrapped_jwt_key", wJwt);
        this.storeWrappedKey(store, "wrapped_audit_key", wAudit);
      }

      // Reset lockout on success
      store.setMeta("failed_attempts", "0");

      this.initManagers();
      await this.writeNewSession();

      const logger = this.auditLogger as AuditLogger;
      logger.log({
        eventType: AuditEventType.VAULT_UNLOCK,
        sessionId: this.sessionId ?? undefined,
      });
    } catch (err) {
      if (err instanceof VaultError && err.code === ErrorCode.ENCRYPTION_ERROR) {
        // Wrong password — increment lockout counter
        this.incrementLockout(store);
        throw VaultError.invalidPassword();
      }
      // Non-password error: close store if we opened it in this call
      if (isNewStore) store.close();
      throw err;
    }
  }

  /**
   * Load session from file (for long-lived processes like MCP server).
   */
  async loadSession(): Promise<boolean> {
    const session = await this.sessionManager.readSession();
    if (!session) return false;

    const isNewStore = this.store === null;
    const store = this.store ?? new SqliteStore(this.options.dbPath);
    const vaultId = store.getMeta("vault_id");
    if (!vaultId || vaultId !== session.vault_id) {
      if (isNewStore) store.close();
      return false;
    }

    // Unwrap KEK and JWT key from session
    const sessionKeyBytes = new Uint8Array(Buffer.from(session.session_key, "base64"));

    try {
      const kek = decrypt(
        sessionKeyBytes,
        new Uint8Array(Buffer.from(session.wrapped_kek, "base64")),
        new Uint8Array(Buffer.from(session.wrapped_kek_iv, "base64")),
        new Uint8Array(Buffer.from(session.wrapped_kek_tag, "base64")),
        AAD_SESSION_KEK,
      );

      const jwtKey = decrypt(
        sessionKeyBytes,
        new Uint8Array(Buffer.from(session.wrapped_jwt_key, "base64")),
        new Uint8Array(Buffer.from(session.wrapped_jwt_key_iv, "base64")),
        new Uint8Array(Buffer.from(session.wrapped_jwt_key_tag, "base64")),
        AAD_SESSION_JWT,
      );

      const auditKey = decrypt(
        sessionKeyBytes,
        new Uint8Array(Buffer.from(session.wrapped_audit_key, "base64")),
        new Uint8Array(Buffer.from(session.wrapped_audit_key_iv, "base64")),
        new Uint8Array(Buffer.from(session.wrapped_audit_key_tag, "base64")),
        AAD_SESSION_AUDIT,
      );

      this.store = store;
      this.vaultId = vaultId;
      this.kek = kek;
      this.jwtKey = jwtKey;
      this.auditKey = auditKey;
      this.sessionId = session.session_id;
      this.state = VaultState.UNLOCKED;

      this.initManagers();
      this.startSessionMonitor();

      return true;
    } catch {
      if (isNewStore) store.close();
      return false;
    }
  }

  /**
   * Lock the vault: wipe keys, erase session.
   */
  async lock(): Promise<void> {
    this.auditLogger?.log({
      eventType: AuditEventType.VAULT_LOCK,
      sessionId: this.sessionId ?? undefined,
    });

    this.wipeKeys();
    await this.sessionManager.eraseSession();
    this.state = VaultState.SEALED;
    this.stopSessionMonitor();
  }

  /**
   * Destroy and close everything. Does NOT erase the database.
   */
  async destroy(): Promise<void> {
    this.wipeKeys();
    this.stopSessionMonitor();
    this.store?.close();
    this.store = null;
    this.state = VaultState.SEALED;
  }

  getState(): VaultState {
    return this.state;
  }

  // ---------------------------------------------------------------------------
  // Secrets
  // ---------------------------------------------------------------------------

  async createSecret(input: {
    name: string;
    type: SecretType;
    project?: string;
    value?: Uint8Array;
    injection?: InjectionConfig;
    expiresAt?: number;
  }): Promise<CreateSecretResponse> {
    const s = this.assertUnlocked();
    const result = await s.secretManager.createSecret(input);

    s.auditLogger.log({
      eventType: AuditEventType.SECRET_CREATE,
      detail: { handle: result.handle, status: result.status },
      sessionId: this.sessionId ?? undefined,
    });

    return result;
  }

  async getSecretInfo(handle: string): Promise<SecretInfo> {
    const s = this.assertUnlocked();
    const info = await s.secretManager.getSecretInfo(handle);

    s.auditLogger.log({
      eventType: AuditEventType.SECRET_READ,
      detail: { handle },
      sessionId: this.sessionId ?? undefined,
    });

    return info;
  }

  async getSecretValue(handle: string): Promise<Uint8Array> {
    const s = this.assertUnlocked();
    const value = await s.secretManager.getSecretValue(handle);

    s.auditLogger.log({
      eventType: AuditEventType.SECRET_READ,
      detail: { handle, action: "get_value" },
      sessionId: this.sessionId ?? undefined,
    });

    return value;
  }

  listSecrets(project?: string): SecretInfo[] {
    const s = this.assertUnlocked();
    return s.secretManager.listSecrets(project);
  }

  async setSecretValue(handle: string, value: Uint8Array): Promise<void> {
    const s = this.assertUnlocked();
    await s.secretManager.setSecretValue(handle, value);

    s.auditLogger.log({
      eventType: AuditEventType.SECRET_CREATE,
      detail: { handle, action: "set_value" },
      sessionId: this.sessionId ?? undefined,
    });
  }

  async rotateSecret(handle: string, newValue: Uint8Array): Promise<void> {
    const s = this.assertUnlocked();
    await s.secretManager.rotateSecret(handle, newValue);

    s.auditLogger.log({
      eventType: AuditEventType.SECRET_ROTATE,
      detail: { handle },
      sessionId: this.sessionId ?? undefined,
    });
  }

  async revokeSecret(handle: string): Promise<void> {
    const s = this.assertUnlocked();
    await s.secretManager.revokeSecret(handle);

    s.auditLogger.log({
      eventType: AuditEventType.SECRET_REVOKE,
      detail: { handle },
      sessionId: this.sessionId ?? undefined,
    });
  }

  /**
   * Execute an HTTP request with an injected secret (use_secret).
   */
  async useSecret(
    handle: string,
    request: {
      method: HttpMethod;
      url: string;
      headers?: Record<string, string>;
      body?: string;
      timeoutMs?: number;
    },
    injection: InjectionConfig,
    followRedirects?: FollowRedirects,
  ): Promise<UseSecretResponse> {
    const s = this.assertUnlocked();

    const secret = await s.secretManager.resolveHandle(handle);

    let value: Uint8Array;
    if (secret.type === SecretType.OAUTH_TOKEN) {
      const accessToken = await this.getOAuthAccessToken(secret.id);
      value = new Uint8Array(Buffer.from(accessToken, "utf8"));
    } else {
      value = await s.secretManager.getSecretValue(handle);
    }

    try {
      const response = await s.httpInjector.executeWithSecret(
        request,
        value,
        injection,
        followRedirects,
        secret.id,
      );

      // Exact-match redaction: scrub the actual secret value from the response
      const valueStr = Buffer.from(value).toString("utf8");
      if (valueStr.length > 0) {
        this.redactValue(response, valueStr);
        // Also redact base64 form (used in basic_auth injection)
        const valueB64 = Buffer.from(valueStr).toString("base64");
        if (valueB64 !== valueStr) {
          this.redactValue(response, valueB64);
        }
      }

      return response;
    } finally {
      wipeBuffer(value);
    }
  }

  private redactValue(response: UseSecretResponse, needle: string): void {
    if (response.body?.includes(needle)) {
      response.body = response.body.replaceAll(needle, "[REDACTED]");
    }
    if (response.error?.includes(needle)) {
      response.error = response.error.replaceAll(needle, "[REDACTED]");
    }
    if (response.headers) {
      for (const [key, val] of Object.entries(response.headers)) {
        if (val.includes(needle)) {
          response.headers[key] = val.replaceAll(needle, "[REDACTED]");
        }
      }
    }
  }

  // ---------------------------------------------------------------------------
  // OAuth
  // ---------------------------------------------------------------------------

  /**
   * Create an OAuth secret with provider configuration.
   * Status is PENDING until completeOAuthFlow is called.
   */
  async createOAuthSecret(
    name: string,
    providerConfig: OAuthProviderConfig,
    project?: string,
  ): Promise<{ handle: string; secretId: string }> {
    const s = this.assertUnlocked();

    const result = await s.secretManager.createSecret({
      name,
      type: SecretType.OAUTH_TOKEN,
      project,
    });

    const secret = await s.secretManager.resolveHandle(result.handle);

    // Encrypt client_id with KEK
    const clientIdBytes = new Uint8Array(Buffer.from(providerConfig.client_id, "utf8"));
    const clientIdEnc = encrypt(s.kek, clientIdBytes, AAD_OAUTH_CLIENT_ID(secret.id));

    // Encrypt client_secret with KEK (if provided)
    let clientSecretEnc: { ciphertext: Uint8Array; iv: Uint8Array; tag: Uint8Array } | null = null;
    if (providerConfig.client_secret) {
      const clientSecretBytes = new Uint8Array(
        Buffer.from(providerConfig.client_secret, "utf8"),
      );
      clientSecretEnc = encrypt(s.kek, clientSecretBytes, AAD_OAUTH_CLIENT_SECRET(secret.id));
    }

    s.store.insertOAuthToken({
      secret_id: secret.id,
      provider: providerConfig.provider,
      grant_type: providerConfig.grant_type,
      token_endpoint: providerConfig.token_endpoint,
      auth_endpoint: providerConfig.auth_endpoint ?? null,
      client_id_encrypted: clientIdEnc.ciphertext,
      client_id_iv: clientIdEnc.iv,
      client_id_tag: clientIdEnc.tag,
      client_secret_encrypted: clientSecretEnc?.ciphertext ?? null,
      client_secret_iv: clientSecretEnc?.iv ?? null,
      client_secret_tag: clientSecretEnc?.tag ?? null,
      scopes: providerConfig.scopes ? JSON.stringify(providerConfig.scopes) : null,
      refresh_token_encrypted: null,
      refresh_token_iv: null,
      refresh_token_tag: null,
      access_token_encrypted: null,
      access_token_iv: null,
      access_token_tag: null,
      access_token_expires_at: null,
      redirect_uri: providerConfig.redirect_uri ?? null,
      pkce_method: providerConfig.pkce_method ?? "S256",
    });

    s.auditLogger.log({
      eventType: AuditEventType.OAUTH_AUTHORIZE,
      secretId: secret.id,
      detail: {
        handle: result.handle,
        provider: providerConfig.provider,
        grant_type: providerConfig.grant_type,
      },
      sessionId: this.sessionId ?? undefined,
    });

    return { handle: result.handle, secretId: secret.id };
  }

  /**
   * Complete an OAuth flow: encrypt and store tokens, transition secret to ACTIVE.
   */
  async completeOAuthFlow(
    secretId: string,
    accessToken: string,
    refreshToken?: string,
    expiresAt?: number,
  ): Promise<void> {
    const s = this.assertUnlocked();

    const secret = s.store.getSecret(secretId);
    if (!secret) throw VaultError.secretNotFound();
    if (secret.type !== SecretType.OAUTH_TOKEN) {
      throw VaultError.oauthNotConfigured();
    }

    const oauthRow = s.store.getOAuthToken(secretId);
    if (!oauthRow) throw VaultError.oauthNotConfigured();

    // Encrypt access token with KEK
    const accessTokenBytes = new Uint8Array(Buffer.from(accessToken, "utf8"));
    const accessTokenEnc = encrypt(s.kek, accessTokenBytes, AAD_OAUTH_ACCESS_TOKEN(secretId));

    const accessUpdate = {
      access_token_encrypted: accessTokenEnc.ciphertext,
      access_token_iv: accessTokenEnc.iv,
      access_token_tag: accessTokenEnc.tag,
      access_token_expires_at: expiresAt ?? null,
    };

    if (refreshToken) {
      const refreshTokenBytes = new Uint8Array(Buffer.from(refreshToken, "utf8"));
      const refreshTokenEnc = encrypt(
        s.kek,
        refreshTokenBytes,
        AAD_OAUTH_REFRESH_TOKEN(secretId),
      );
      s.store.updateOAuthToken(secretId, {
        ...accessUpdate,
        refresh_token_encrypted: refreshTokenEnc.ciphertext,
        refresh_token_iv: refreshTokenEnc.iv,
        refresh_token_tag: refreshTokenEnc.tag,
      });
    } else {
      s.store.updateOAuthToken(secretId, accessUpdate);
    }

    // Transition secret to ACTIVE
    s.store.updateSecret(secretId, {
      status: SecretStatus.ACTIVE,
      updated_at: Date.now(),
    });

    s.auditLogger.log({
      eventType: AuditEventType.OAUTH_CALLBACK,
      secretId,
      detail: { has_refresh_token: !!refreshToken, expires_at: expiresAt ?? null },
      sessionId: this.sessionId ?? undefined,
      success: true,
    });
  }

  /**
   * Refresh an OAuth token: decrypt refresh_token, call token endpoint, encrypt new tokens.
   * Returns the new access_token expiry timestamp (or null if no expires_in in response).
   */
  async refreshOAuthToken(secretId: string): Promise<number | null> {
    const s = this.assertUnlocked();

    const oauthRow = s.store.getOAuthToken(secretId);
    if (!oauthRow) throw VaultError.oauthNotConfigured();

    if (
      !oauthRow.refresh_token_encrypted ||
      !oauthRow.refresh_token_iv ||
      !oauthRow.refresh_token_tag
    ) {
      throw VaultError.oauthRefreshFailed("No refresh token available");
    }

    // Decrypt refresh token
    const refreshToken = Buffer.from(
      decrypt(
        s.kek,
        oauthRow.refresh_token_encrypted,
        oauthRow.refresh_token_iv,
        oauthRow.refresh_token_tag,
        AAD_OAUTH_REFRESH_TOKEN(secretId),
      ),
    ).toString("utf8");

    // Decrypt client_id
    const clientId = Buffer.from(
      decrypt(
        s.kek,
        oauthRow.client_id_encrypted,
        oauthRow.client_id_iv,
        oauthRow.client_id_tag,
        AAD_OAUTH_CLIENT_ID(secretId),
      ),
    ).toString("utf8");

    // Decrypt client_secret (optional)
    let clientSecret: string | undefined;
    if (
      oauthRow.client_secret_encrypted &&
      oauthRow.client_secret_iv &&
      oauthRow.client_secret_tag
    ) {
      clientSecret = Buffer.from(
        decrypt(
          s.kek,
          oauthRow.client_secret_encrypted,
          oauthRow.client_secret_iv,
          oauthRow.client_secret_tag,
          AAD_OAUTH_CLIENT_SECRET(secretId),
        ),
      ).toString("utf8");
    }

    // Validate token endpoint (SSRF protection)
    await validateUrl(oauthRow.token_endpoint);

    // POST to token endpoint
    const params = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: clientId,
    });
    if (clientSecret) {
      params.set("client_secret", clientSecret);
    }

    let response: Response;
    try {
      response = await fetch(oauthRow.token_endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: params.toString(),
        signal: AbortSignal.timeout(30_000),
      });
    } catch (err) {
      throw VaultError.oauthRefreshFailed(
        err instanceof Error ? err.message : "Network error",
      );
    }

    if (!response.ok) {
      throw VaultError.oauthRefreshFailed(
        `Token endpoint returned HTTP ${response.status}`,
      );
    }

    let tokenResponse: {
      access_token?: string;
      refresh_token?: string;
      expires_in?: number;
    };
    try {
      tokenResponse = (await response.json()) as typeof tokenResponse;
    } catch {
      throw VaultError.oauthRefreshFailed("Invalid JSON response from token endpoint");
    }

    if (!tokenResponse.access_token) {
      throw VaultError.oauthRefreshFailed("No access_token in response");
    }

    // Encrypt new access token
    const newAccessTokenBytes = new Uint8Array(
      Buffer.from(tokenResponse.access_token, "utf8"),
    );
    const newAccessTokenEnc = encrypt(
      s.kek,
      newAccessTokenBytes,
      AAD_OAUTH_ACCESS_TOKEN(secretId),
    );

    const newExpiresAt = tokenResponse.expires_in
      ? Date.now() + tokenResponse.expires_in * 1000
      : null;

    const accessUpdate = {
      access_token_encrypted: newAccessTokenEnc.ciphertext,
      access_token_iv: newAccessTokenEnc.iv,
      access_token_tag: newAccessTokenEnc.tag,
      access_token_expires_at: newExpiresAt,
    };

    if (tokenResponse.refresh_token) {
      const newRefreshBytes = new Uint8Array(
        Buffer.from(tokenResponse.refresh_token, "utf8"),
      );
      const newRefreshEnc = encrypt(
        s.kek,
        newRefreshBytes,
        AAD_OAUTH_REFRESH_TOKEN(secretId),
      );
      s.store.updateOAuthToken(secretId, {
        ...accessUpdate,
        refresh_token_encrypted: newRefreshEnc.ciphertext,
        refresh_token_iv: newRefreshEnc.iv,
        refresh_token_tag: newRefreshEnc.tag,
      });
    } else {
      s.store.updateOAuthToken(secretId, accessUpdate);
    }

    s.store.updateSecret(secretId, { updated_at: Date.now() });

    s.auditLogger.log({
      eventType: AuditEventType.OAUTH_REFRESH,
      secretId,
      detail: { new_expires_at: newExpiresAt },
      sessionId: this.sessionId ?? undefined,
      success: true,
    });

    return newExpiresAt;
  }

  /**
   * Get OAuth token status without decrypting sensitive fields.
   */
  getOAuthTokenStatus(secretId: string): OAuthTokenStatus {
    const s = this.assertUnlocked();

    const oauthRow = s.store.getOAuthToken(secretId);
    if (!oauthRow) throw VaultError.oauthNotConfigured();

    const secret = s.store.getSecret(secretId);

    const hasAccessToken = oauthRow.access_token_encrypted !== null;
    const hasRefreshToken = oauthRow.refresh_token_encrypted !== null;
    const expiresAt = oauthRow.access_token_expires_at;

    let refreshStatus: OAuthTokenStatus["refresh_status"];
    if (!hasRefreshToken) {
      refreshStatus = "no_refresh_token";
    } else if (!hasAccessToken || (expiresAt !== null && expiresAt <= Date.now())) {
      refreshStatus = "expired";
    } else if (expiresAt !== null && expiresAt <= Date.now() + 5 * 60 * 1000) {
      refreshStatus = "expiring_soon";
    } else {
      refreshStatus = "ok";
    }

    return {
      secret_id: secretId,
      provider: oauthRow.provider as OAuthProviderPreset,
      has_access_token: hasAccessToken,
      access_token_expires_at: expiresAt,
      has_refresh_token: hasRefreshToken,
      last_refreshed_at: secret?.updated_at ?? null,
      refresh_status: refreshStatus,
    };
  }

  /**
   * Get the decrypted OAuth access token. Auto-refreshes if expired or within 60s of expiry.
   * NEVER return this to the LLM — only use within the injection pipeline.
   */
  async getOAuthAccessToken(secretId: string): Promise<string> {
    const s = this.assertUnlocked();

    const secret = s.store.getSecret(secretId);
    if (!secret) throw VaultError.secretNotFound();
    if (secret.type !== SecretType.OAUTH_TOKEN) {
      throw VaultError.oauthNotConfigured();
    }

    // Lazy expiry check
    if (
      secret.status !== SecretStatus.EXPIRED &&
      secret.expires_at !== null &&
      secret.expires_at <= Date.now()
    ) {
      s.store.updateSecret(secretId, {
        status: SecretStatus.EXPIRED,
        updated_at: Date.now(),
      });
      throw VaultError.secretExpired();
    }
    if (secret.status === SecretStatus.EXPIRED) throw VaultError.secretExpired();
    if (secret.status === SecretStatus.REVOKED) throw VaultError.secretRevoked();
    if (secret.status === SecretStatus.PENDING) {
      throw VaultError.oauthNotConfigured("OAuth flow not completed");
    }

    const oauthRow = s.store.getOAuthToken(secretId);
    if (!oauthRow) throw VaultError.oauthNotConfigured();

    // Auto-refresh if expired or within 60s of expiry
    const AUTO_REFRESH_BUFFER_MS = 60_000;
    if (
      oauthRow.access_token_expires_at !== null &&
      oauthRow.access_token_expires_at <= Date.now() + AUTO_REFRESH_BUFFER_MS
    ) {
      if (oauthRow.refresh_token_encrypted) {
        try {
          await this.refreshOAuthToken(secretId);
          const refreshed = s.store.getOAuthToken(secretId);
          if (
            refreshed?.access_token_encrypted &&
            refreshed.access_token_iv &&
            refreshed.access_token_tag
          ) {
            return Buffer.from(
              decrypt(
                s.kek,
                refreshed.access_token_encrypted,
                refreshed.access_token_iv,
                refreshed.access_token_tag,
                AAD_OAUTH_ACCESS_TOKEN(secretId),
              ),
            ).toString("utf8");
          }
        } catch (err) {
          if (oauthRow.access_token_expires_at <= Date.now()) {
            throw err instanceof VaultError
              ? err
              : VaultError.oauthRefreshFailed("Refresh failed");
          }
          // Token not yet expired — fall through to return current token
        }
      } else if (oauthRow.access_token_expires_at <= Date.now()) {
        throw VaultError.oauthRefreshFailed(
          "Access token expired and no refresh token available",
        );
      }
    }

    if (
      !oauthRow.access_token_encrypted ||
      !oauthRow.access_token_iv ||
      !oauthRow.access_token_tag
    ) {
      throw VaultError.oauthNotConfigured("No access token stored");
    }

    return Buffer.from(
      decrypt(
        s.kek,
        oauthRow.access_token_encrypted,
        oauthRow.access_token_iv,
        oauthRow.access_token_tag,
        AAD_OAUTH_ACCESS_TOKEN(secretId),
      ),
    ).toString("utf8");
  }

  /**
   * Get OAuth tokens expiring within the given time window.
   */
  getExpiringOAuthTokens(withinMs: number): OAuthTokenRow[] {
    const s = this.assertUnlocked();
    return s.store.getExpiringOAuthTokens(withinMs);
  }

  // ---------------------------------------------------------------------------
  // Policies
  // ---------------------------------------------------------------------------

  grantPolicy(input: Omit<GrantPolicyInput, "createdBy">, createdBy: string): AccessPolicy {
    const s = this.assertUnlocked();
    const policy = s.policyEngine.grantPolicy({ ...input, createdBy });

    s.auditLogger.log({
      eventType: AuditEventType.POLICY_GRANT,
      secretId: input.secretId,
      detail: {
        policy_id: policy.id,
        principal: `${input.principalType}:${input.principalId}`,
      },
      sessionId: this.sessionId ?? undefined,
    });

    return policy;
  }

  revokePolicy(policyId: string): void {
    const s = this.assertUnlocked();
    s.policyEngine.revokePolicy(policyId);

    s.auditLogger.log({
      eventType: AuditEventType.POLICY_REVOKE,
      detail: { policy_id: policyId },
      sessionId: this.sessionId ?? undefined,
    });
  }

  listPolicies(secretId?: string): AccessPolicy[] {
    const s = this.assertUnlocked();
    return s.policyEngine.listPolicies(secretId);
  }

  // ---------------------------------------------------------------------------
  // Audit
  // ---------------------------------------------------------------------------

  queryAudit(options?: AuditQueryOptions): DecryptedAuditEvent[] {
    const s = this.assertUnlocked();
    return s.auditQuery.query(options);
  }

  // ---------------------------------------------------------------------------
  // JWT Auth
  // ---------------------------------------------------------------------------

  /**
   * Create a scoped JWT API token. HMAC-SHA256 signed.
   */
  createToken(
    subject: string,
    scope: Permission[],
    ttlMs: number = 3600_000,
    options?: { project?: string; secrets?: string[] },
  ): string {
    const s = this.assertUnlocked();

    const effectiveTtl = Math.min(Math.max(ttlMs, 0), MAX_TOKEN_TTL_MS);
    const now = Math.floor(Date.now() / 1000);
    const payload: VaultApiToken = {
      sub: subject,
      vault_id: s.vaultId,
      scope,
      iat: now,
      exp: now + Math.floor(effectiveTtl / 1000),
      jti: generateUUIDv7(),
    };

    if (options?.project) payload.project = options.project;
    if (options?.secrets?.length) payload.secrets = options.secrets;

    const token = this.signJwt(payload);

    s.auditLogger.log({
      eventType: AuditEventType.TOKEN_CREATE,
      detail: { subject, jti: payload.jti, scope, project: options?.project },
      sessionId: this.sessionId ?? undefined,
    });

    return token;
  }

  /**
   * Verify and decode a JWT token.
   */
  verifyToken(token: string): VaultApiToken {
    const s = this.assertUnlocked();

    // Opportunistic cleanup of expired revocation entries
    s.store.pruneExpiredTokens();

    const payload = this.verifyJwt(token);

    if (payload.vault_id !== s.vaultId) {
      throw new VaultError(ErrorCode.INVALID_TOKEN, "Token vault_id mismatch");
    }

    if (s.store.isTokenRevoked(payload.jti)) {
      throw VaultError.tokenRevoked();
    }

    const now = Math.floor(Date.now() / 1000);
    if (payload.exp <= now) {
      throw VaultError.tokenExpired();
    }

    return payload;
  }

  /**
   * Revoke a JWT token by JTI.
   */
  revokeToken(jti: string, expiresAt?: number): void {
    const s = this.assertUnlocked();
    // Fallback: MAX_TOKEN_TTL_MS from now ensures the revocation entry always
    // outlives any token (since createToken caps TTL at MAX_TOKEN_TTL_MS).
    const fallback = Math.floor(Date.now() / 1000) + Math.floor(MAX_TOKEN_TTL_MS / 1000);
    s.store.insertRevokedToken(jti, expiresAt ?? fallback);

    s.auditLogger.log({
      eventType: AuditEventType.TOKEN_REVOKE,
      detail: { jti },
      sessionId: this.sessionId ?? undefined,
    });
  }

  // ---------------------------------------------------------------------------
  // Password change
  // ---------------------------------------------------------------------------

  async changePassword(oldPassword: string, newPassword: string): Promise<void> {
    this.validatePassword(newPassword);

    const s = this.assertUnlocked();

    const salt = this.loadBase64Meta(s.store, "kdf_salt");
    const wrappedKek = this.loadBase64Meta(s.store, "wrapped_kek");
    const wrappedKekIv = this.loadBase64Meta(s.store, "wrapped_kek_iv");
    const wrappedKekTag = this.loadBase64Meta(s.store, "wrapped_kek_tag");

    const result = await changePassword(
      oldPassword,
      newPassword,
      salt,
      wrappedKek,
      wrappedKekIv,
      wrappedKekTag,
    );

    s.store.setMeta("kdf_salt", Buffer.from(result.newSalt).toString("base64"));
    s.store.setMeta("wrapped_kek", Buffer.from(result.newWrappedKek).toString("base64"));
    s.store.setMeta("wrapped_kek_iv", Buffer.from(result.newWrappedKekIv).toString("base64"));
    s.store.setMeta("wrapped_kek_tag", Buffer.from(result.newWrappedKekTag).toString("base64"));

    // JWT and audit keys are unchanged — they're wrapped with KEK, not derived from master key

    s.auditLogger.log({
      eventType: AuditEventType.VAULT_PASSWORD_CHANGE,
      sessionId: this.sessionId ?? undefined,
    });

    // Write new session with updated keys
    await this.writeNewSession();
  }

  /**
   * Resolve a secret handle to its internal UUID.
   */
  async resolveSecretId(handle: string): Promise<string> {
    const s = this.assertUnlocked();
    const secret = await s.secretManager.resolveHandle(handle);
    return secret.id;
  }

  // ---------------------------------------------------------------------------
  // Private: state management
  // ---------------------------------------------------------------------------

  private assertUnlocked(): UnlockedState {
    if (this.state !== VaultState.UNLOCKED) {
      throw VaultError.vaultLocked();
    }
    return {
      store: this.store as SqliteStore,
      kek: this.kek as Uint8Array,
      jwtKey: this.jwtKey as Uint8Array,
      auditKey: this.auditKey as Uint8Array,
      vaultId: this.vaultId as string,
      secretManager: this.secretManager as SecretManager,
      policyEngine: this.policyEngine as PolicyEngine,
      auditLogger: this.auditLogger as AuditLogger,
      auditQuery: this.auditQuery as AuditQuery,
      httpInjector: this.httpInjector as HttpInjector,
    };
  }

  private initManagers(): void {
    const store = this.store as SqliteStore;
    const kek = this.kek as Uint8Array;
    const auditKey = this.auditKey as Uint8Array;

    this.secretManager = new SecretManager(store, kek);
    this.policyEngine = new PolicyEngine(store);
    this.auditLogger = new AuditLogger(store, auditKey);
    this.auditQuery = new AuditQuery(store, auditKey);
    this.httpInjector = new HttpInjector(this.auditLogger);
  }

  private wipeKeys(): void {
    if (this.kek) {
      wipeBuffer(this.kek);
      this.kek = null;
    }
    if (this.jwtKey) {
      wipeBuffer(this.jwtKey);
      this.jwtKey = null;
    }
    if (this.auditKey) {
      wipeBuffer(this.auditKey);
      this.auditKey = null;
    }

    this.secretManager = null;
    this.policyEngine = null;
    this.auditLogger = null;
    this.auditQuery = null;
    this.httpInjector = null;
    this.sessionId = null;
    this.vaultId = null;
  }

  // ---------------------------------------------------------------------------
  // Private: session
  // ---------------------------------------------------------------------------

  private async writeNewSession(): Promise<void> {
    const kek = this.kek as Uint8Array;
    const jwtKey = this.jwtKey as Uint8Array;
    const auditKey = this.auditKey as Uint8Array;
    const vaultId = this.vaultId as string;

    const sessionKey = generateRandomBytes(AES_KEY_LENGTH);
    try {
      const sessionIdVal = generateUUIDv7();
      this.sessionId = sessionIdVal;

      // Wrap KEK, JWT key, and audit key with session key
      const wrappedKek = encrypt(sessionKey, kek, AAD_SESSION_KEK);
      const wrappedJwt = encrypt(sessionKey, jwtKey, AAD_SESSION_JWT);
      const wrappedAudit = encrypt(sessionKey, auditKey, AAD_SESSION_AUDIT);

      const session = SessionManager.createSessionData(
        sessionIdVal,
        vaultId,
        Buffer.from(sessionKey).toString("base64"),
        Buffer.from(wrappedKek.ciphertext).toString("base64"),
        Buffer.from(wrappedKek.iv).toString("base64"),
        Buffer.from(wrappedKek.tag).toString("base64"),
        Buffer.from(wrappedJwt.ciphertext).toString("base64"),
        Buffer.from(wrappedJwt.iv).toString("base64"),
        Buffer.from(wrappedJwt.tag).toString("base64"),
        Buffer.from(wrappedAudit.ciphertext).toString("base64"),
        Buffer.from(wrappedAudit.iv).toString("base64"),
        Buffer.from(wrappedAudit.tag).toString("base64"),
      );

      await this.sessionManager.writeSession(session);
    } finally {
      wipeBuffer(sessionKey);
    }
  }

  private startSessionMonitor(): void {
    this.stopSessionMonitor();
    this.sessionMonitorInterval = setInterval(async () => {
      const session = await this.sessionManager.extendSession();
      if (!session) {
        // Session expired or removed — close store and seal
        this.wipeKeys();
        this.store?.close();
        this.store = null;
        this.state = VaultState.SEALED;
        this.stopSessionMonitor();
      }
    }, SESSION_CLEANUP_INTERVAL_MS);

    // Don't block Node.js exit
    if (this.sessionMonitorInterval.unref) {
      this.sessionMonitorInterval.unref();
    }
  }

  private stopSessionMonitor(): void {
    if (this.sessionMonitorInterval) {
      clearInterval(this.sessionMonitorInterval);
      this.sessionMonitorInterval = null;
    }
  }

  // ---------------------------------------------------------------------------
  // Private: lockout
  // ---------------------------------------------------------------------------

  private checkLockout(store: SqliteStore): void {
    const lockoutUntil = store.getMeta("lockout_until");
    if (lockoutUntil) {
      const until = parseInt(lockoutUntil, 10);
      if (Date.now() < until) {
        throw VaultError.lockoutActive(until - Date.now());
      }
    }
  }

  private incrementLockout(store: SqliteStore): void {
    const attempts = parseInt(store.getMeta("failed_attempts") ?? "0", 10) + 1;
    store.setMeta("failed_attempts", String(attempts));

    if (attempts >= LOCKOUT_MAX_ATTEMPTS) {
      const lockoutIndex = Math.min(
        Math.floor((attempts - LOCKOUT_MAX_ATTEMPTS) / LOCKOUT_MAX_ATTEMPTS),
        LOCKOUT_DURATIONS_MS.length - 1,
      );
      const duration =
        LOCKOUT_DURATIONS_MS[lockoutIndex] ??
        LOCKOUT_DURATIONS_MS[LOCKOUT_DURATIONS_MS.length - 1] ??
        1800_000;
      store.setMeta("lockout_until", String(Date.now() + duration));
    }
  }

  // ---------------------------------------------------------------------------
  // Private: JWT (HMAC-SHA256, no external deps)
  // ---------------------------------------------------------------------------

  private signJwt(payload: VaultApiToken): string {
    const jwtKey = this.jwtKey as Uint8Array;
    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const signature = createHmac("sha256", jwtKey).update(`${header}.${body}`).digest("base64url");

    return `${header}.${body}.${signature}`;
  }

  private verifyJwt(token: string): VaultApiToken {
    const jwtKey = this.jwtKey as Uint8Array;
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new VaultError(ErrorCode.INVALID_TOKEN, "Invalid token format");
    }

    const [header, body, signature] = parts as [string, string, string];

    // Verify signature using timing-safe comparison
    const expectedSig = createHmac("sha256", jwtKey).update(`${header}.${body}`).digest();

    const actualSig = Buffer.from(signature, "base64url");

    if (expectedSig.length !== actualSig.length || !timingSafeEqual(expectedSig, actualSig)) {
      throw new VaultError(ErrorCode.INVALID_TOKEN, "Invalid token signature");
    }

    try {
      return JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as VaultApiToken;
    } catch {
      throw new VaultError(ErrorCode.INVALID_TOKEN, "Invalid token payload");
    }
  }

  // ---------------------------------------------------------------------------
  // Private: helpers
  // ---------------------------------------------------------------------------

  private validatePassword(password: string): void {
    if (password.length < MIN_PASSWORD_LENGTH) {
      throw VaultError.weakPassword(MIN_PASSWORD_LENGTH);
    }
  }

  private loadOptionalWrappedKey(store: SqliteStore, prefix: string): WrappedKey | undefined {
    const ct = store.getMeta(`${prefix}`);
    const iv = store.getMeta(`${prefix}_iv`);
    const tag = store.getMeta(`${prefix}_tag`);
    if (!ct || !iv || !tag) return undefined;
    return {
      ciphertext: new Uint8Array(Buffer.from(ct, "base64")),
      iv: new Uint8Array(Buffer.from(iv, "base64")),
      tag: new Uint8Array(Buffer.from(tag, "base64")),
    };
  }

  private storeWrappedKey(store: SqliteStore, prefix: string, key: WrappedKey): void {
    store.setMeta(`${prefix}`, Buffer.from(key.ciphertext).toString("base64"));
    store.setMeta(`${prefix}_iv`, Buffer.from(key.iv).toString("base64"));
    store.setMeta(`${prefix}_tag`, Buffer.from(key.tag).toString("base64"));
  }

  private loadBase64Meta(store: SqliteStore, key: string): Uint8Array {
    const value = store.getMeta(key);
    if (!value) {
      throw VaultError.vaultCorrupted(`Missing ${key}`);
    }
    return new Uint8Array(Buffer.from(value, "base64"));
  }
}
