import { createHmac, timingSafeEqual } from "node:crypto";
import type {
  AccessPolicy,
  ConnectionConfig,
  CreateSecretResponse,
  HttpResult,
  InjectionConfig,
  InjectionPolicy,
  McpServerConfig,
  OAuthProviderConfig,
  OAuthTokenStatus,
  Permission,
  SetInjectionPolicyOptions,
  UseSecretAction,
  UseSecretResponse,
  VaultApiToken,
} from "@harpoc/shared";
import {
  AAD_CONNECTION_CONFIG,
  AAD_INJECTION_POLICY,
  AAD_MCP_SERVER_CONFIG,
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
  findKnownInterpreters,
  isValidSecretNamePattern,
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
import { matchesUrlAllowlist } from "./injection/allowlist.js";
import { DatabaseInjector } from "./injection/database-injector.js";
import { GitInjector } from "./injection/git-injector.js";
import { HttpInjector } from "./injection/http-injector.js";
import { McpInjector } from "./injection/mcp-injector.js";
import { McpConnectionRegistry } from "./injection/mcp-registry.js";
import { redactSecretEncodings } from "./injection/output-sanitizer.js";
import { ProcessInjector } from "./injection/process-injector.js";
import { isResponseModeAllowed } from "./injection/response-mode.js";
import { SshInjector } from "./injection/ssh-injector.js";
import { validateUrl } from "./injection/url-validator.js";
import type { SecretInfo } from "./secrets/secret-manager.js";
import { SecretManager } from "./secrets/secret-manager.js";
import { SessionManager } from "./session/session-manager.js";
import type { SessionKeyProtector } from "./session/session-key-protector.js";
import { SqliteStore } from "./storage/sqlite-store.js";
import type { OAuthTokenRow } from "./storage/sqlite-store.js";

export interface VaultEngineOptions {
  dbPath: string;
  sessionPath: string;
  /** Override the session-key protector (default: platform keystore — DPAPI on Windows, none elsewhere). */
  sessionKeyProtector?: SessionKeyProtector;
  /** Surface session-key keystore fallback events (default: silent — core never logs). */
  onSessionKeyProtectionFallback?: (error: Error) => void;
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
  processInjector: ProcessInjector;
  mcpInjector: McpInjector;
  mcpRegistry: McpConnectionRegistry;
  databaseInjector: DatabaseInjector;
  sshInjector: SshInjector;
  gitInjector: GitInjector;
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
  private processInjector: ProcessInjector | null = null;
  private mcpInjector: McpInjector | null = null;
  private mcpRegistry: McpConnectionRegistry | null = null;
  private databaseInjector: DatabaseInjector | null = null;
  private sshInjector: SshInjector | null = null;
  private gitInjector: GitInjector | null = null;
  private sessionManager: SessionManager;
  private sessionMonitorInterval: ReturnType<typeof setInterval> | null = null;

  constructor(private readonly options: VaultEngineOptions) {
    this.sessionManager = new SessionManager(options.sessionPath, {
      protector: options.sessionKeyProtector,
      onProtectionFallback: options.onSessionKeyProtectionFallback,
    });
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
    } finally {
      wipeBuffer(sessionKeyBytes);
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

    // Graceful downstream MCP teardown while the audit logger is still alive;
    // wipeKeys() below hard-kills anything that survived the budget.
    await this.mcpRegistry?.closeAll("vault_lock");

    this.wipeKeys();
    await this.sessionManager.eraseSession();
    this.state = VaultState.SEALED;
    this.stopSessionMonitor();
  }

  /**
   * Destroy and close everything. Does NOT erase the database.
   */
  async destroy(): Promise<void> {
    await this.mcpRegistry?.closeAll("engine_destroy");
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
   * Use a secret via a context-specific action (use_secret). Dispatches to the
   * request-mediated (HTTP), process-mediated (process) or MCP proxy injector.
   * The secret plaintext is resolved inside the vault, injected, and wiped
   * before return; it never crosses the vault-to-agent boundary.
   */
  async useSecret(handle: string, action: UseSecretAction): Promise<UseSecretResponse> {
    const s = this.assertUnlocked();

    const secret = await s.secretManager.resolveHandle(handle);
    const policy = this.loadInjectionPolicy(s, secret.id);

    let value: Uint8Array;
    if (secret.type === SecretType.OAUTH_TOKEN) {
      const accessToken = await this.getOAuthAccessToken(secret.id);
      value = new Uint8Array(Buffer.from(accessToken, "utf8"));
    } else {
      value = await s.secretManager.getSecretValue(handle);
    }

    try {
      if (action.type === "process") {
        return await s.processInjector.executeWithSecret(action, value, policy, secret.id);
      }

      if (action.type === "mcp") {
        const config = this.loadMcpServerConfig(s, secret.id);
        if (!config) {
          throw VaultError.mcpServerNotConfigured(handle);
        }
        return await s.mcpInjector.executeWithSecret(action, value, policy, config, secret.id);
      }

      if (action.type === "http") {
        // Request-mediated (HTTP): enforce the per-secret URL allowlist before injection.
        if (!matchesUrlAllowlist(action.url, policy.url_allowlist)) {
          s.auditLogger.log({
            eventType: AuditEventType.SECRET_USE,
            secretId: secret.id,
            detail: { context: "http", url: action.url, error: ErrorCode.URL_NOT_ALLOWED },
            success: false,
            sessionId: this.sessionId ?? undefined,
          });
          throw VaultError.urlNotAllowed(action.url);
        }

        // Tighten-only response-mode override (thesis §4.5.2): a loosening
        // override would reopen the echo channel — rejected before the
        // request executes.
        const policyMode = policy.response_mode ?? "filtered";
        if (action.response_mode && !isResponseModeAllowed(policyMode, action.response_mode)) {
          s.auditLogger.log({
            eventType: AuditEventType.SECRET_USE,
            secretId: secret.id,
            detail: {
              context: "http",
              url: action.url,
              requested_mode: action.response_mode,
              policy_mode: policyMode,
              error: ErrorCode.RESPONSE_MODE_NOT_ALLOWED,
            },
            success: false,
            sessionId: this.sessionId ?? undefined,
          });
          throw VaultError.responseModeNotAllowed(action.response_mode, policyMode);
        }
        const responseMode = action.response_mode ?? policyMode;

        const response = await s.httpInjector.executeWithSecret(
          {
            method: action.method,
            url: action.url,
            headers: action.headers,
            body: action.body,
            timeoutMs: action.timeout_ms,
            responseMode,
            responseHeaderAllowlist: policy.response_header_allowlist ?? [],
            urlAllowlist: policy.url_allowlist,
          },
          value,
          action.injection,
          action.follow_redirects,
          secret.id,
        );

        // Value + encodings redaction (I2a) — skipped only under the
        // policy-gated `full` opt-out.
        if (responseMode !== "full") {
          const valueStr = Buffer.from(value).toString("utf8");
          if (valueStr.length > 0) {
            this.redactHttpResult(response, valueStr);
          }
        }

        return response;
      }

      if (action.type === "database") {
        const config = this.loadConnectionConfig(s, secret.id);
        return await s.databaseInjector.executeWithSecret(action, value, policy, config, secret.id);
      }

      if (action.type === "ssh") {
        const config = this.loadConnectionConfig(s, secret.id);
        return await s.sshInjector.executeWithSecret(action, value, policy, config, secret.id);
      }

      if (action.type === "git") {
        const config = this.loadConnectionConfig(s, secret.id);
        return await s.gitInjector.executeWithSecret(action, value, policy, config, secret.id);
      }

      throw VaultError.invalidInput(
        `Unsupported action type: ${(action as { type: string }).type}`,
      );
    } finally {
      wipeBuffer(value);
    }
  }

  /** Scrub the secret value and its common encodings from an HTTP result (I2a). */
  private redactHttpResult(response: HttpResult, valueStr: string): void {
    if (response.body) {
      response.body = redactSecretEncodings(response.body, valueStr);
    }
    if (response.error) {
      response.error = redactSecretEncodings(response.error, valueStr);
    }
    if (response.headers) {
      for (const [key, val] of Object.entries(response.headers)) {
        response.headers[key] = redactSecretEncodings(val, valueStr);
      }
    }
  }

  /**
   * Load a secret's injection policy, decrypting the allowlists. Returns empty
   * allowlists when no policy is set (URL allowlisting is then not enforced;
   * command allowlisting denies by default — see ProcessInjector).
   */
  private loadInjectionPolicy(s: UnlockedState, secretId: string): InjectionPolicy {
    const row = s.store.getInjectionPolicy(secretId);
    if (!row) {
      return {
        url_allowlist: [],
        command_allowlist: [],
        env_allowlist: [],
        host_allowlist: [],
        response_mode: "filtered",
        response_header_allowlist: [],
      };
    }
    const bytes = decrypt(
      s.kek,
      row.policy_encrypted,
      row.policy_iv,
      row.policy_tag,
      AAD_INJECTION_POLICY(secretId),
    );
    const parsed = JSON.parse(Buffer.from(bytes).toString("utf8")) as Partial<InjectionPolicy>;
    return {
      url_allowlist: parsed.url_allowlist ?? [],
      command_allowlist: parsed.command_allowlist ?? [],
      env_allowlist: parsed.env_allowlist ?? [],
      host_allowlist: parsed.host_allowlist ?? [],
      response_mode: parsed.response_mode ?? "filtered",
      response_header_allowlist: parsed.response_header_allowlist ?? [],
    };
  }

  /**
   * Set (or replace) a secret's injection policy. Trusted administrative
   * operation — the allowlists are encrypted under the KEK.
   *
   * Command-allowlist entries naming a known interpreter (thesis §4.5.3)
   * collapse the L2/L3 capability-ladder split for this secret, so a newly
   * added interpreter entry is refused unless the caller passes
   * `options.acknowledge_interpreters`; the refusal and any acknowledged
   * addition are both audited. Entries already on the stored allowlist are
   * not re-gated — re-asserting them is not an addition.
   */
  async setInjectionPolicy(
    handle: string,
    policy: InjectionPolicy,
    options?: SetInjectionPolicyOptions,
  ): Promise<void> {
    const s = this.assertUnlocked();
    const secret = await s.secretManager.resolveHandle(handle);

    const stored = new Set(this.loadInjectionPolicy(s, secret.id).command_allowlist);
    const addedInterpreters = findKnownInterpreters(
      (policy.command_allowlist ?? []).filter((entry) => !stored.has(entry)),
    );
    if (addedInterpreters.length > 0 && options?.acknowledge_interpreters !== true) {
      s.auditLogger.log({
        eventType: AuditEventType.POLICY_INTERPRETER_REFUSED,
        secretId: secret.id,
        detail: { policy: "injection", interpreters: addedInterpreters },
        sessionId: this.sessionId ?? undefined,
      });
      throw VaultError.interpreterNotAcknowledged(addedInterpreters);
    }

    const json = JSON.stringify({
      url_allowlist: policy.url_allowlist ?? [],
      command_allowlist: policy.command_allowlist ?? [],
      env_allowlist: policy.env_allowlist ?? [],
      host_allowlist: policy.host_allowlist ?? [],
      response_mode: policy.response_mode ?? "filtered",
      response_header_allowlist: policy.response_header_allowlist ?? [],
    });
    const enc = encrypt(
      s.kek,
      new Uint8Array(Buffer.from(json, "utf8")),
      AAD_INJECTION_POLICY(secret.id),
    );
    const now = Date.now();
    s.store.upsertInjectionPolicy({
      secret_id: secret.id,
      policy_encrypted: enc.ciphertext,
      policy_iv: enc.iv,
      policy_tag: enc.tag,
      created_at: now,
      updated_at: now,
    });

    s.auditLogger.log({
      eventType: AuditEventType.POLICY_GRANT,
      secretId: secret.id,
      detail: {
        policy: "injection",
        url_count: policy.url_allowlist?.length ?? 0,
        command_count: policy.command_allowlist?.length ?? 0,
        env_count: policy.env_allowlist?.length ?? 0,
        host_count: policy.host_allowlist?.length ?? 0,
        response_mode: policy.response_mode ?? "filtered",
        response_header_count: policy.response_header_allowlist?.length ?? 0,
      },
      sessionId: this.sessionId ?? undefined,
    });

    if (addedInterpreters.length > 0) {
      s.auditLogger.log({
        eventType: AuditEventType.POLICY_INTERPRETER_ACKNOWLEDGED,
        secretId: secret.id,
        detail: { policy: "injection", interpreters: addedInterpreters },
        sessionId: this.sessionId ?? undefined,
      });
    }
  }

  /** Read a secret's injection policy (empty allowlists when unset). */
  async getInjectionPolicy(handle: string): Promise<InjectionPolicy> {
    const s = this.assertUnlocked();
    const secret = await s.secretManager.resolveHandle(handle);
    return this.loadInjectionPolicy(s, secret.id);
  }

  /** Load a secret's downstream MCP server config, or undefined when unset. */
  private loadMcpServerConfig(s: UnlockedState, secretId: string): McpServerConfig | undefined {
    const row = s.store.getMcpServer(secretId);
    if (!row) return undefined;
    const bytes = decrypt(
      s.kek,
      row.config_encrypted,
      row.config_iv,
      row.config_tag,
      AAD_MCP_SERVER_CONFIG(secretId),
    );
    return JSON.parse(Buffer.from(bytes).toString("utf8")) as McpServerConfig;
  }

  /**
   * Set (or replace) a secret's downstream MCP server config. Trusted
   * administrative operation (CLI/REST only — never an MCP tool); the config
   * is encrypted under the KEK. A live downstream connection for this secret
   * is terminated so the next invocation connects with the new config.
   */
  async setMcpServerConfig(handle: string, config: McpServerConfig): Promise<void> {
    const s = this.assertUnlocked();
    const secret = await s.secretManager.resolveHandle(handle);

    const json = JSON.stringify(config);
    const enc = encrypt(
      s.kek,
      new Uint8Array(Buffer.from(json, "utf8")),
      AAD_MCP_SERVER_CONFIG(secret.id),
    );
    const now = Date.now();
    s.store.upsertMcpServer({
      secret_id: secret.id,
      config_encrypted: enc.ciphertext,
      config_iv: enc.iv,
      config_tag: enc.tag,
      created_at: now,
      updated_at: now,
    });

    s.auditLogger.log({
      eventType: AuditEventType.POLICY_GRANT,
      secretId: secret.id,
      detail: {
        policy: "mcp_server",
        server_name: config.server_name,
        transport: config.transport,
      },
      sessionId: this.sessionId ?? undefined,
    });

    await s.mcpRegistry.terminate(secret.id, "config_changed");
  }

  /** Read a secret's downstream MCP server config (undefined when unset). */
  async getMcpServerConfig(handle: string): Promise<McpServerConfig | undefined> {
    const s = this.assertUnlocked();
    const secret = await s.secretManager.resolveHandle(handle);
    return this.loadMcpServerConfig(s, secret.id);
  }

  /** Remove a secret's downstream MCP server config, terminating any live connection. */
  async deleteMcpServerConfig(handle: string): Promise<boolean> {
    const s = this.assertUnlocked();
    const secret = await s.secretManager.resolveHandle(handle);
    await s.mcpRegistry.terminate(secret.id, "config_removed");
    const deleted = s.store.deleteMcpServer(secret.id);
    if (deleted) {
      s.auditLogger.log({
        eventType: AuditEventType.POLICY_REVOKE,
        secretId: secret.id,
        detail: { policy: "mcp_server" },
        sessionId: this.sessionId ?? undefined,
      });
    }
    return deleted;
  }

  // ---------------------------------------------------------------------------
  // Connection config (database TLS policy / SSH pinned host keys)
  // ---------------------------------------------------------------------------

  /** Load a secret's endpoint-authentication config, or undefined when unset. */
  private loadConnectionConfig(s: UnlockedState, secretId: string): ConnectionConfig | undefined {
    const row = s.store.getConnectionConfig(secretId);
    if (!row) return undefined;
    const bytes = decrypt(
      s.kek,
      row.config_encrypted,
      row.config_iv,
      row.config_tag,
      AAD_CONNECTION_CONFIG(secretId),
    );
    return JSON.parse(Buffer.from(bytes).toString("utf8")) as ConnectionConfig;
  }

  /**
   * Set (or replace) a secret's endpoint-authentication config (database TLS
   * policy / SSH pinned host keys). Trusted administrative operation (CLI/REST
   * only — never an MCP tool); encrypted under the KEK.
   */
  async setConnectionConfig(handle: string, config: ConnectionConfig): Promise<void> {
    const s = this.assertUnlocked();
    const secret = await s.secretManager.resolveHandle(handle);

    const json = JSON.stringify(config);
    const enc = encrypt(
      s.kek,
      new Uint8Array(Buffer.from(json, "utf8")),
      AAD_CONNECTION_CONFIG(secret.id),
    );
    const now = Date.now();
    s.store.upsertConnectionConfig({
      secret_id: secret.id,
      config_encrypted: enc.ciphertext,
      config_iv: enc.iv,
      config_tag: enc.tag,
      created_at: now,
      updated_at: now,
    });

    s.auditLogger.log({
      eventType: AuditEventType.POLICY_GRANT,
      secretId: secret.id,
      detail: {
        policy: "connection",
        has_database: config.database !== undefined,
        has_ssh: config.ssh !== undefined,
        database_tls: config.database?.tls_mode,
        known_hosts_count: config.ssh?.known_hosts.length ?? 0,
      },
      sessionId: this.sessionId ?? undefined,
    });
  }

  /** Read a secret's endpoint-authentication config (undefined when unset). */
  async getConnectionConfig(handle: string): Promise<ConnectionConfig | undefined> {
    const s = this.assertUnlocked();
    const secret = await s.secretManager.resolveHandle(handle);
    return this.loadConnectionConfig(s, secret.id);
  }

  /** Remove a secret's endpoint-authentication config. */
  async deleteConnectionConfig(handle: string): Promise<boolean> {
    const s = this.assertUnlocked();
    const secret = await s.secretManager.resolveHandle(handle);
    const deleted = s.store.deleteConnectionConfig(secret.id);
    if (deleted) {
      s.auditLogger.log({
        eventType: AuditEventType.POLICY_REVOKE,
        secretId: secret.id,
        detail: { policy: "connection" },
        sessionId: this.sessionId ?? undefined,
      });
    }
    return deleted;
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
   *
   * `options.secrets` entries are secret-name patterns (thesis §4.7): literal
   * names or `*` wildcards (`db-*`). Each entry is validated against the
   * pattern grammar — name characters plus `*`, no other meta-characters.
   */
  createToken(
    subject: string,
    scope: Permission[],
    ttlMs: number = 3600_000,
    options?: { project?: string; secrets?: string[] },
  ): string {
    const s = this.assertUnlocked();

    for (const pattern of options?.secrets ?? []) {
      if (!isValidSecretNamePattern(pattern)) {
        throw new VaultError(
          ErrorCode.INVALID_SECRET_NAME,
          `Invalid secret name pattern: "${pattern}" — letters, digits, "_", "-" and "*" wildcards only`,
        );
      }
    }

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
      processInjector: this.processInjector as ProcessInjector,
      mcpInjector: this.mcpInjector as McpInjector,
      mcpRegistry: this.mcpRegistry as McpConnectionRegistry,
      databaseInjector: this.databaseInjector as DatabaseInjector,
      sshInjector: this.sshInjector as SshInjector,
      gitInjector: this.gitInjector as GitInjector,
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
    this.processInjector = new ProcessInjector(this.auditLogger);
    this.mcpRegistry = new McpConnectionRegistry(this.auditLogger);
    this.mcpInjector = new McpInjector(this.auditLogger, this.mcpRegistry);
    this.databaseInjector = new DatabaseInjector(this.auditLogger);
    this.sshInjector = new SshInjector(this.auditLogger);
    this.gitInjector = new GitInjector(this.auditLogger);
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

    // Every seal path funnels through here: no downstream MCP child may
    // outlive the keys that authorized it.
    this.mcpRegistry?.killAllSync();

    this.secretManager = null;
    this.policyEngine = null;
    this.auditLogger = null;
    this.auditQuery = null;
    this.httpInjector = null;
    this.processInjector = null;
    this.mcpInjector = null;
    this.mcpRegistry = null;
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
        await this.mcpRegistry?.closeAll("session_expired");
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
