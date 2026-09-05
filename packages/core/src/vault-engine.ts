import { createHmac, createPrivateKey, timingSafeEqual, X509Certificate } from "node:crypto";
import type {
  AccessPolicy,
  Agent,
  AgentPolicy,
  AuditChainAnchor,
  AuditVisibilityScope,
  CallerContext,
  CertificateStatus,
  ConnectionConfig,
  CreateSecretResponse,
  ExpiringCertificateInfo,
  ExpiringOAuthTokenInfo,
  ImportCertificateOptions,
  InjectionPolicy,
  InjectionPolicyInput,
  IssuedToken,
  IssuedTokenStatusFilter,
  McpServerConfig,
  OAuthProviderConfig,
  OAuthTokenStatus,
  Permission,
  RegisterAgentInput,
  Secret,
  SessionFile,
  SetAgentPermissionsResult,
  SetInjectionPolicyOptions,
  SmtpAction,
  TokenPrincipalType,
  UpdateAgentInput,
  UseSecretAction,
  UseSecretResponse,
  VaultApiToken,
} from "@harpoc/shared";
import {
  AAD_CERT_ACME_ACCOUNT,
  AAD_CERT_PRIVATE_KEY,
  AAD_CONNECTION_CONFIG,
  AAD_INJECTION_POLICY,
  AAD_MCP_SERVER_CONFIG,
  applyTokenEndpointAuth,
  AUDIT_CHAIN_ANCHOR_FORMAT,
  AAD_OAUTH_ACCESS_TOKEN,
  AAD_OAUTH_CLIENT_ID,
  AAD_OAUTH_CLIENT_SECRET,
  AAD_OAUTH_REFRESH_TOKEN,
  AAD_SESSION_AUDIT,
  AAD_SESSION_JWT,
  AAD_SESSION_KEK,
  AES_KEY_LENGTH,
  AgentStatus,
  AuditEventType,
  DEFAULT_SESSION_TTL_MS,
  ErrorCode,
  formatHandle,
  injectionPolicyInputSchema,
  injectionPolicySchema,
  isAdminUserCaller,
  isValidSecretNamePattern,
  isVaultVersionSupported,
  IssuedTokenStatus,
  execWrapperName,
  knownInterpreterName,
  LOCKOUT_DURATIONS_MS,
  LOCKOUT_MAX_ATTEMPTS,
  matchesSecretNameScope,
  MAX_SESSION_TTL_MS,
  MAX_TOKEN_TTL_MS,
  meetsVaultVersionFloor,
  MIN_PASSWORD_LENGTH,
  OAuthProviderPreset,
  PrincipalType,
  SecretStatus,
  SecretType,
  SESSION_CLEANUP_INTERVAL_MS,
  TokenPrincipalType as TokenPrincipalTypeValues,
  SESSION_SLIDE_INTERVAL_MS,
  TOKEN_LABEL_MAX_LENGTH,
  VaultError,
  VaultState,
  VAULT_VERSION,
  VAULT_VERSION_FLOOR,
} from "@harpoc/shared";
import { AgentRegistry } from "./access/agent-registry.js";
import { PolicyEngine } from "./access/policy-engine.js";
import type { GrantPolicyInput, PolicyPrincipal } from "./access/policy-engine.js";
import type { AuditAttribution } from "./audit/attribution.js";
import {
  attributionFromCaller,
  callerColumns,
  callerInterfaceDetail,
  withAttribution,
} from "./audit/attribution.js";
import { AuditLogger } from "./audit/audit-logger.js";
import { AuditQuery } from "./audit/audit-query.js";
import type {
  AuditChainVerification,
  AuditQueryOptions,
  DecryptedAuditEvent,
} from "./audit/audit-query.js";
import { decrypt, encrypt } from "./crypto/aes-gcm.js";
import type { WrappedKey } from "./crypto/key-hierarchy.js";
import { changePassword, createVaultKeys, unlockVault } from "./crypto/key-hierarchy.js";
import { assertNever } from "./assert-never.js";
import { generateRandomBytes, generateUUIDv7, wipeBuffer } from "./crypto/random.js";
import {
  controlledPathDirs,
  matchesUrlAllowlist,
  resolveExecutable,
} from "./injection/allowlist.js";
import { DatabaseInjector } from "./injection/database-injector.js";
import type { DockerExecution } from "./injection/docker/docker-injector.js";
import {
  buildDockerAuditDetails,
  executeDockerRegistryAction,
} from "./injection/docker/docker-injector.js";
import { GitInjector } from "./injection/git-injector.js";
import { HttpInjector } from "./injection/http-injector.js";
import type { ImapOAuth } from "./injection/imap-injector.js";
import { buildImapAuditDetails, ImapInjector } from "./injection/imap-injector.js";
import { McpInjector } from "./injection/mcp-injector.js";
import { McpConnectionRegistry } from "./injection/mcp-registry.js";
import { redactErrorMessage } from "./injection/output-sanitizer.js";
import { ProcessInjector } from "./injection/process-injector.js";
import { isResponseModeAllowed } from "./injection/response-mode.js";
import type { SftpExecution } from "./injection/sftp-injector.js";
import { buildSftpAuditDetails, executeSftpAction } from "./injection/sftp-injector.js";
import type { SmtpOAuth, SmtpResolvedAttachment } from "./injection/smtp-injector.js";
import { buildSmtpAuditDetails, SmtpInjector } from "./injection/smtp-injector.js";
import { SshInjector } from "./injection/ssh-injector.js";
import { validateUrl } from "./injection/url-validator.js";
import { buildWsAuditDetails, executeWebsocketAction } from "./injection/websocket-injector.js";
import type { SecretInfo } from "./secrets/secret-manager.js";
import { SecretManager } from "./secrets/secret-manager.js";
import { SessionManager } from "./session/session-manager.js";
import type { SessionKeyProtector } from "./session/session-key-protector.js";
import { SqliteStore } from "./storage/sqlite-store.js";
import type { CertificateRow, OAuthTokenRow } from "./storage/sqlite-store.js";

export interface VaultEngineOptions {
  dbPath: string;
  sessionPath: string;
  /** Override the session-key protector (default: platform keystore — DPAPI on Windows, none elsewhere). */
  sessionKeyProtector?: SessionKeyProtector;
  /**
   * Surface a failed owner-only permission repair on the session file — the
   * POSIX chmod or the Windows icacls step (default: silent — core never
   * logs). A keystore failure is not reported here: it fails the unlock with
   * `SESSION_KEYSTORE_UNAVAILABLE` (R8/D54).
   */
  onSessionFilePermissionRepairFailure?: (error: Error) => void;
  /** Sliding session TTL in ms (default DEFAULT_SESSION_TTL_MS, capped at MAX_SESSION_TTL_MS). Operator knob / test seam. */
  sessionTtlMs?: number;
}

/** Chain verification plus the current tail (for printing/comparison and re-anchoring). */
export interface AuditChainVerificationReport extends AuditChainVerification {
  tail: AuditChainAnchor | null;
}

/**
 * The v1.3 mail/WebSocket dispatch seams. Unlike the older injectors these
 * write no audit row of their own — they hand the engine a metadata-only
 * projection and the engine writes the `secret.use` row — so the engine holds
 * them behind the narrowest structural type that its dispatch needs. The real
 * injectors satisfy them as-is, and an engine test can substitute a plain
 * object (the `ImapClientLike` pattern the IMAP injector uses for its client).
 */
export type SmtpRunner = Pick<SmtpInjector, "run">;
export type ImapRunner = Pick<ImapInjector, "run">;
export type WebsocketExecutor = typeof executeWebsocketAction;
export type SftpExecutor = typeof executeSftpAction;
export type DockerExecutor = typeof executeDockerRegistryAction;

interface UnlockedState {
  store: SqliteStore;
  kek: Uint8Array;
  jwtKey: Uint8Array;
  auditKey: Uint8Array;
  vaultId: string;
  secretManager: SecretManager;
  policyEngine: PolicyEngine;
  agentRegistry: AgentRegistry;
  auditLogger: AuditLogger;
  auditQuery: AuditQuery;
  httpInjector: HttpInjector;
  processInjector: ProcessInjector;
  mcpInjector: McpInjector;
  mcpRegistry: McpConnectionRegistry;
  databaseInjector: DatabaseInjector;
  sshInjector: SshInjector;
  gitInjector: GitInjector;
  smtpInjector: SmtpRunner;
  imapInjector: ImapRunner;
  websocketExecutor: WebsocketExecutor;
  sftpExecutor: SftpExecutor;
  dockerExecutor: DockerExecutor;
}

const DAY_MS = 86_400_000;

type ServerTransport = "stdio" | "http" | "rest";
type ServerStopTrigger = "SIGINT" | "SIGTERM" | "transport_closed";

/**
 * Engine-enforced ceiling for `renew_before_days`, matching the REST schema's
 * cap (certificateImportSchema): every import path — REST, SDK, CLI,
 * cert-manager issuance — funnels through `doImportCertificate`, so no stored
 * row can exceed it.
 */
const MAX_RENEW_BEFORE_DAYS = 365;

/**
 * The renewal scheduler's wide net (renewal-scheduler.ts): one leap year,
 * strictly greater than {@link MAX_RENEW_BEFORE_DAYS}, so no row can carry a
 * `renew_before_days` wide enough to fall outside the query it is then
 * filtered against.
 */
const EXPIRING_CERT_QUERY_DAYS = 366;

/**
 * The `create` refusal shared by `grantPolicy` and `setAgentPermissions`: both
 * write the same policy row, so the two paths must refuse it with one message.
 */
const CREATE_NOT_GRANTABLE_MESSAGE =
  "'create' cannot be granted per secret: a policy attaches to an existing secret. Use token scope (harpoc auth token --permissions create) instead";

/**
 * The refresh state of an OAuth row, derived from the stored expiry alone.
 * Shared by the per-secret status accessor and the expiring-token projection:
 * two derivations would eventually disagree about what `expiring_soon` means.
 */
function computeOAuthRefreshStatus(row: OAuthTokenRow): OAuthTokenStatus["refresh_status"] {
  const hasAccessToken = row.access_token_encrypted !== null;
  const hasRefreshToken = row.refresh_token_encrypted !== null;
  const expiresAt = row.access_token_expires_at;

  if (!hasRefreshToken) return "no_refresh_token";
  if (!hasAccessToken || (expiresAt !== null && expiresAt <= Date.now())) return "expired";
  if (expiresAt !== null && expiresAt <= Date.now() + 5 * 60 * 1000) return "expiring_soon";
  return "ok";
}

/**
 * The attachments an SMTP action asked for, with unknown sizes. A failed
 * `secret.use` row is built from these: the injector returns its resolved
 * (read) attachment list on success only, and a refusal may have happened
 * before the first `stat`. Naming the attempted paths keeps the
 * exfiltration-relevant fact — which local files the caller tried to send — in
 * the trail; `attachment_total_bytes` stays 0 because nothing was read.
 */
function attemptedAttachments(action: SmtpAction): SmtpResolvedAttachment[] {
  return (action.attachments ?? []).map((spec) => ({ path: spec.path, bytes: 0 }));
}

/**
 * Every throw out of the SMTP injector is already a redacted `VaultError`
 * except a raw `node:fs` error from the attachment `stat`/`readFile` pair,
 * whose message carries the filesystem path. Remapped path-free here so no raw
 * error message reaches an interface boundary (design §7.1 reuses
 * `FILE_IO_ERROR` for an unreadable attachment).
 */
function mapSmtpThrow(err: unknown): VaultError {
  if (err instanceof VaultError) return err;
  return new VaultError(ErrorCode.FILE_IO_ERROR, "an attachment could not be read");
}

/**
 * Coerce any throw out of a v1.3 injector into a redacted `VaultError` so the
 * dispatch arm can audit-then-throw unconditionally. Every injector provably
 * throws only `VaultError`, so the fallback is the honest "shouldn't happen"
 * path: a non-`VaultError` becomes a generic, value-free `INTERNAL_ERROR` — the
 * failed `secret.use` row is still written (audit-every-denial made structural,
 * not reachability-dependent) and no raw error message crosses an interface
 * boundary. Kept distinct from {@link mapSmtpThrow}, whose `FILE_IO_ERROR`
 * mapping is specific to the SMTP attachment `stat`/`readFile` pair.
 */
function toVaultError(err: unknown): VaultError {
  if (err instanceof VaultError) return err;
  return VaultError.internalError("the injection context failed unexpectedly");
}

/** The certificate counterpart of {@link computeOAuthRefreshStatus}. */
function computeCertificateRenewalStatus(row: CertificateRow): CertificateStatus["renewal_status"] {
  if (!row.certificate_pem || row.not_after === null) return "no_certificate";
  if (row.not_after <= Date.now()) return "expired";
  if (row.not_after <= Date.now() + row.renew_before_days * DAY_MS) return "expiring_soon";
  return "ok";
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
  private agentRegistry: AgentRegistry | null = null;
  private auditLogger: AuditLogger | null = null;
  private auditQuery: AuditQuery | null = null;
  private httpInjector: HttpInjector | null = null;
  private processInjector: ProcessInjector | null = null;
  private mcpInjector: McpInjector | null = null;
  private mcpRegistry: McpConnectionRegistry | null = null;
  private databaseInjector: DatabaseInjector | null = null;
  private sshInjector: SshInjector | null = null;
  private gitInjector: GitInjector | null = null;
  private smtpInjector: SmtpRunner | null = null;
  private imapInjector: ImapRunner | null = null;
  private websocketExecutor: WebsocketExecutor = executeWebsocketAction;
  private sftpExecutor: SftpExecutor = executeSftpAction;
  private dockerExecutor: DockerExecutor = executeDockerRegistryAction;
  private sessionManager: SessionManager;
  private sessionMonitorInterval: ReturnType<typeof setInterval> | null = null;
  private lastSessionSlideAt = 0;
  private sessionSlide: Promise<void> | null = null;
  // In-memory mirror of the session file's expiry, so every authenticated
  // operation enforces the TTL synchronously — the monitor (loadSession only,
  // ≤30 s granularity) is the backstop, not the sole enforcer.
  private sessionExpiresAt: number | null = null;
  private readonly sessionTtlMs: number;
  private readonly oauthRefreshInFlight = new Map<string, Promise<number | null>>();

  constructor(private readonly options: VaultEngineOptions) {
    this.sessionManager = new SessionManager(options.sessionPath, {
      protector: options.sessionKeyProtector,
      onPermissionRepairFailure: options.onSessionFilePermissionRepairFailure,
    });
    this.sessionTtlMs = Math.min(
      options.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS,
      MAX_SESSION_TTL_MS,
    );
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  /**
   * Initialize a new vault: generate keys, create database, write session.
   */
  async initVault(password: string): Promise<{ vaultId: string }> {
    this.validatePassword(password);

    const store = this.store ?? new SqliteStore(this.options.dbPath);
    let keys: Awaited<ReturnType<typeof createVaultKeys>>;
    try {
      // Re-initializing rewraps the KEK; every existing secret's DEK would
      // become permanently undecryptable. Refuse instead of destroying data.
      if (store.getMeta("vault_id") !== undefined) {
        throw VaultError.vaultAlreadyExists();
      }
      keys = await createVaultKeys(password);
    } catch (err) {
      if (this.store === null) {
        store.close();
      }
      throw err;
    }

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

    // Write session — fail closed (R8/D54): the vault exists on disk, but an
    // engine whose session could not be written protected does not stay
    // unlocked in memory on the keys it just installed.
    try {
      await this.writeNewSession();
    } catch (err) {
      this.sealAfterFailedSessionWrite();
      throw err;
    }
    // Enforce the session TTL for long-lived engines too (SDK direct mode),
    // not only loadSession-created ones.
    this.startSessionMonitor();

    const logger = this.auditLogger as AuditLogger;
    logger.log({
      eventType: AuditEventType.VAULT_UNLOCK,
      sessionId: this.sessionId ?? undefined,
    });

    return { vaultId: keys.vaultId };
  }

  /**
   * The fail-closed version guard every entry path shares: a missing stamp,
   * one newer than this binary supports, or one below the v1.5 floor (R2 —
   * the 1.0–1.4 line cannot be upgraded) all refuse as VAULT_CORRUPTED.
   * Numeric per-component compare: a lexicographic string compare orders
   * "1.10.0" before "1.2.0" and defeats the guard.
   */
  private assertVaultVersionOpenable(store: SqliteStore, closeOnFailure: boolean): void {
    const vaultVersion = store.getMeta("vault_version");
    let message: string | null = null;
    if (!vaultVersion) {
      message = "vault_version row is missing";
    } else if (!isVaultVersionSupported(vaultVersion, VAULT_VERSION)) {
      message = `Vault version ${vaultVersion} is newer than supported ${VAULT_VERSION}`;
    } else if (!meetsVaultVersionFloor(vaultVersion, VAULT_VERSION_FLOOR)) {
      message = `Vault version ${vaultVersion} predates the supported minimum ${VAULT_VERSION_FLOOR} and cannot be upgraded — move or delete the vault directory and run harpoc init`;
    }
    if (message !== null) {
      if (closeOnFailure) store.close();
      throw VaultError.vaultCorrupted(message);
    }
  }

  /**
   * Unlock an existing vault with a password.
   */
  async unlock(password: string): Promise<void> {
    const isNewStore = this.store === null;
    const store = this.store ?? new SqliteStore(this.options.dbPath);

    const vaultId = store.getMeta("vault_id");
    if (!vaultId) {
      if (isNewStore) store.close();
      throw VaultError.vaultNotFound();
    }

    this.assertVaultVersionOpenable(store, isNewStore);

    let sealedOnFailedWrite = false;

    try {
      // Lockout and meta reads live inside the try so any throw (lockout
      // active, corrupted meta) closes the store we opened in this call.
      this.checkLockout(store);

      const salt = this.loadBase64Meta(store, "kdf_salt");
      const wrappedKek = this.loadBase64Meta(store, "wrapped_kek");
      const wrappedKekIv = this.loadBase64Meta(store, "wrapped_kek_iv");
      const wrappedKekTag = this.loadBase64Meta(store, "wrapped_kek_tag");

      // Wrapped JWT/audit keys are mandatory — the key hierarchy has exactly
      // one instantiation (random keys wrapped with the KEK); a vault without
      // them is corrupted, never a candidate for a derivation fallback.
      const wrappedJwtKey = this.loadWrappedKey(store, "wrapped_jwt_key");
      const wrappedAuditKey = this.loadWrappedKey(store, "wrapped_audit_key");

      const keys = await unlockVault(
        password,
        salt,
        wrappedKek,
        wrappedKekIv,
        wrappedKekTag,
        wrappedJwtKey,
        wrappedAuditKey,
      );

      // Re-unlock over a live engine: wipe the old key buffers before they
      // are overwritten. Success-path only — a failed re-unlock must not
      // seal a working engine.
      if (this.state === VaultState.UNLOCKED) {
        this.wipeKeys();
        this.stopSessionMonitor();
      }

      this.store = store;
      this.vaultId = vaultId;
      this.kek = keys.kek;
      this.jwtKey = keys.jwtKey;
      this.auditKey = keys.auditKey;
      this.state = VaultState.UNLOCKED;

      // Reset lockout on success
      store.setMeta("failed_attempts", "0");

      this.initManagers();
      try {
        await this.writeNewSession();
      } catch (err) {
        // Fail closed (R8/D54): no protected session file, no unlocked engine.
        // The seal closes the store this call holds; the catch below must not
        // close it a second time.
        this.sealAfterFailedSessionWrite();
        sealedOnFailedWrite = true;
        throw err;
      }
      // Enforce the session TTL for long-lived engines too (SDK direct mode),
      // not only loadSession-created ones.
      this.startSessionMonitor();

      const logger = this.auditLogger as AuditLogger;
      logger.log({
        eventType: AuditEventType.VAULT_UNLOCK,
        sessionId: this.sessionId ?? undefined,
      });
    } catch (err) {
      if (err instanceof VaultError && err.code === ErrorCode.ENCRYPTION_ERROR) {
        // Wrong password — increment lockout counter (persisted synchronously)
        // before closing the store we opened in this call.
        this.incrementLockout(store);
        if (isNewStore) store.close();
        throw VaultError.invalidPassword();
      }
      // Non-password error: close store if we opened it in this call
      if (isNewStore && !sealedOnFailedWrite) store.close();
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

    // The same fail-closed guard `unlock` enforces. Without it, every entry
    // path that reuses a session file — i.e. all of them except init/unlock —
    // let an older binary open and write a newer-format vault (L5). Thrown
    // rather than reported as "no session": falling through would prompt for a
    // password and then raise this very error from `unlock`.
    this.assertVaultVersionOpenable(store, isNewStore);

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

      // Session load over a live engine: wipe the old key buffers before
      // they are overwritten. Success-path only — a failed load must not
      // seal a working engine.
      if (this.state === VaultState.UNLOCKED) {
        this.wipeKeys();
        this.stopSessionMonitor();
      }

      this.store = store;
      this.vaultId = vaultId;
      this.kek = kek;
      this.jwtKey = jwtKey;
      this.auditKey = auditKey;
      this.sessionId = session.session_id;
      this.sessionExpiresAt = session.expires_at;
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

    // Seal first so no further use-driven slide can start, then settle any
    // in-flight slide — its atomic rename racing the secure erase below could
    // otherwise resurrect the session file after the unlink.
    this.state = VaultState.SEALED;
    await this.settleSessionSlide();

    // Graceful downstream MCP teardown while the audit logger is still alive;
    // wipeKeys() below hard-kills anything that survived the budget.
    await this.mcpRegistry?.closeAll("vault_lock");

    this.wipeKeys();
    await this.sessionManager.eraseSession();
    this.stopSessionMonitor();
  }

  /**
   * Destroy and close everything. Does NOT erase the database.
   */
  async destroy(): Promise<void> {
    this.state = VaultState.SEALED;
    await this.settleSessionSlide();
    await this.mcpRegistry?.closeAll("engine_destroy");
    this.wipeKeys();
    this.stopSessionMonitor();
    this.store?.close();
    this.store = null;
  }

  getState(): VaultState {
    return this.state;
  }

  // ---------------------------------------------------------------------------
  // Secrets
  // ---------------------------------------------------------------------------

  /**
   * Create a secret. `caller` is attribution only — `create` is not grantable
   * per secret (there is no secret to carry the row yet, W2), so token scope
   * governs it; without the caller every REST/MCP create wrote a NULL-principal
   * row, which is the documented marker for the *trusted local path* (L3).
   */
  async createSecret(
    input: {
      name: string;
      type: SecretType;
      project?: string;
      value?: Uint8Array;
      expiresAt?: number;
    },
    caller?: CallerContext,
  ): Promise<CreateSecretResponse> {
    const s = this.assertUnlocked();
    // Audit row committed in the same transaction as the secret row (NM3):
    // a crash cannot yield a created-but-unaudited secret, and an unwritable
    // audit log rolls the create back.
    return s.secretManager.createSecret(input, (result, secretId) => {
      s.auditLogger.log({
        eventType: AuditEventType.SECRET_CREATE,
        secretId,
        ...callerColumns(caller),
        detail: { handle: result.handle, status: result.status, ...callerInterfaceDetail(caller) },
        sessionId: this.sessionId ?? undefined,
      });
    });
  }

  async getSecretInfo(handle: string, caller?: CallerContext): Promise<SecretInfo> {
    const s = this.assertUnlocked();
    await this.enforceCallerPolicy(s, handle, caller, "read", AuditEventType.SECRET_READ, {
      handle,
    });
    // The resolved id, reported by the manager's read hook: without it the
    // success rows left `audit_log.secret_id` NULL, so `audit --secret <id>`
    // omitted exactly the successful reads of that secret (L4).
    //
    // On the catch arm it is still undefined in every reachable case — the
    // manager's getSecretInfo throws only out of handle resolution, which runs
    // before the hook fires (a throw after it would mean the name decrypt
    // failed, i.e. a corrupted vault). It is passed anyway so this arm stays
    // identical in shape to getSecretValue's, where the id genuinely is set by
    // the time the throw happens: the cert-value refusal and the usability check
    // both sit after the hook there (secret-manager.ts:303-328).
    let secretId: string | undefined;
    let info: SecretInfo;
    try {
      info = await s.secretManager.getSecretInfo(handle, (id) => (secretId = id));
    } catch (err) {
      this.auditDenied(s, AuditEventType.SECRET_READ, err, { handle }, secretId, caller);
      throw await this.concealHandleError(s, err, handle, caller);
    }

    s.auditLogger.log({
      eventType: AuditEventType.SECRET_READ,
      secretId,
      ...callerColumns(caller),
      detail: { handle, ...callerInterfaceDetail(caller) },
      sessionId: this.sessionId ?? undefined,
    });

    return info;
  }

  async getSecretValue(handle: string, caller?: CallerContext): Promise<Uint8Array> {
    const s = this.assertUnlocked();
    await this.enforceCallerPolicy(s, handle, caller, "read", AuditEventType.SECRET_READ, {
      handle,
      action: "get_value",
    });
    let secretId: string | undefined;
    let value: Uint8Array;
    try {
      value = await s.secretManager.getSecretValue(handle, (id) => (secretId = id));
    } catch (err) {
      this.auditDenied(
        s,
        AuditEventType.SECRET_READ,
        err,
        { handle, action: "get_value" },
        secretId,
        caller,
      );
      throw await this.concealHandleError(s, err, handle, caller);
    }

    s.auditLogger.log({
      eventType: AuditEventType.SECRET_READ,
      secretId,
      ...callerColumns(caller),
      detail: { handle, action: "get_value", ...callerInterfaceDetail(caller) },
      sessionId: this.sessionId ?? undefined,
    });

    return value;
  }

  /**
   * List secrets (metadata only). A token-derived caller sees only what its
   * principals may enumerate (thesis §4.6 `list`): a secret is listed only
   * when a grant to one of the caller's principals carries `list` or `admin`
   * (R1, 2026-09-01: a secret with no rows is listed to no token caller), so a
   * read-gated secret's metadata row cannot be recovered from the listing. Filtering is silent —
   * enumeration writes no audit row, here as before. An absent caller is the
   * trusted local path (CLI, in-process SDK) and sees everything; so does an
   * admin-scoped user-type token since R7 (v1.4.1), the one caller class the
   * per-secret gate exempts — a gated secret must not vanish from the
   * operator's own listing while they may still address it.
   */
  listSecrets(project?: string, caller?: CallerContext): SecretInfo[] {
    const s = this.assertUnlocked();
    if (!caller || isAdminUserCaller(caller)) return s.secretManager.listSecrets(project);

    const entries = s.secretManager.listSecretsWithIds(project);
    const permitted = s.policyEngine.filterPermitted(
      entries.map((entry) => entry.id),
      this.callerPrincipals(caller),
      "list",
    );
    return entries.filter((entry) => permitted.has(entry.id)).map((entry) => entry.info);
  }

  async setSecretValue(handle: string, value: Uint8Array, caller?: CallerContext): Promise<void> {
    const s = this.assertUnlocked();
    await this.enforceCallerPolicy(s, handle, caller, "rotate", AuditEventType.SECRET_CREATE, {
      handle,
      action: "set_value",
    });
    let resolvedId: string | undefined;
    try {
      await s.secretManager.setSecretValue(
        handle,
        value,
        (secretId) => {
          s.auditLogger.log({
            eventType: AuditEventType.SECRET_CREATE,
            secretId,
            ...callerColumns(caller),
            detail: { handle, action: "set_value", ...callerInterfaceDetail(caller) },
            sessionId: this.sessionId ?? undefined,
          });
        },
        (id) => (resolvedId = id),
      );
    } catch (err) {
      this.auditDenied(
        s,
        AuditEventType.SECRET_CREATE,
        err,
        { handle, action: "set_value" },
        resolvedId,
        caller,
      );
      throw await this.concealHandleError(s, err, handle, caller);
    }
  }

  async rotateSecret(handle: string, newValue: Uint8Array, caller?: CallerContext): Promise<void> {
    const s = this.assertUnlocked();
    await this.enforceCallerPolicy(s, handle, caller, "rotate", AuditEventType.SECRET_ROTATE, {
      handle,
    });
    let resolvedId: string | undefined;
    try {
      await s.secretManager.rotateSecret(
        handle,
        newValue,
        (secretId) => {
          s.auditLogger.log({
            eventType: AuditEventType.SECRET_ROTATE,
            secretId,
            ...callerColumns(caller),
            detail: { handle, ...callerInterfaceDetail(caller) },
            sessionId: this.sessionId ?? undefined,
          });
        },
        (id) => (resolvedId = id),
      );
    } catch (err) {
      this.auditDenied(s, AuditEventType.SECRET_ROTATE, err, { handle }, resolvedId, caller);
      throw await this.concealHandleError(s, err, handle, caller);
    }
  }

  async revokeSecret(handle: string, caller?: CallerContext): Promise<void> {
    const s = this.assertUnlocked();
    await this.enforceCallerPolicy(s, handle, caller, "revoke", AuditEventType.SECRET_REVOKE, {
      handle,
    });
    let revokedId: string | undefined;
    try {
      await s.secretManager.revokeSecret(handle, (secretId) => {
        revokedId = secretId;
        s.auditLogger.log({
          eventType: AuditEventType.SECRET_REVOKE,
          secretId,
          ...callerColumns(caller),
          detail: { handle, ...callerInterfaceDetail(caller) },
          sessionId: this.sessionId ?? undefined,
        });
      });
    } catch (err) {
      this.auditDenied(s, AuditEventType.SECRET_REVOKE, err, { handle }, undefined, caller);
      throw await this.concealHandleError(s, err, handle, caller);
    }

    // A downstream stdio MCP child spawned with this credential outlives the
    // revocation otherwise — it keeps running with the revoked plaintext in its
    // environment until lock/destroy/TTL-seal, and use-driven slides push that
    // out indefinitely (L2). Terminated after the revoke commits, so a failed
    // teardown cannot roll the revocation back.
    if (revokedId) {
      await s.mcpRegistry.terminate(
        revokedId,
        "secret_revoked",
        attributionFromCaller(caller, this.sessionId),
      );
    }
  }

  /**
   * Use a secret via a context-specific action (use_secret). Dispatches to the
   * request-mediated (HTTP), process-mediated (process) or MCP proxy injector.
   * The secret plaintext is resolved inside the vault, injected, and wiped
   * before return; it never crosses the vault-to-agent boundary.
   */
  async useSecret(
    handle: string,
    action: UseSecretAction,
    caller?: CallerContext,
  ): Promise<UseSecretResponse> {
    try {
      return await this.useSecretInner(handle, action, caller);
    } finally {
      // Completion slide (throttled): a long-running action ends with a fresh
      // idle window instead of one aged by the action's own runtime.
      this.touchSession();
    }
  }

  private async useSecretInner(
    handle: string,
    action: UseSecretAction,
    caller?: CallerContext,
  ): Promise<UseSecretResponse> {
    const s = this.assertUnlocked();

    let secret: Secret;
    try {
      secret = await s.secretManager.resolveHandle(handle);
    } catch (err) {
      this.auditDenied(
        s,
        AuditEventType.SECRET_USE,
        err,
        { handle, context: action.type },
        undefined,
        caller,
      );
      throw await this.concealHandleError(s, err, handle, caller);
    }

    // Per-secret policy enforcement (thesis §4.6) — before the injection
    // policy is read, any OAuth refresh runs, or the value is decrypted. A
    // refusal also ends this secret's live downstream child (E73): the grant
    // it was spawned under no longer covers the caller, so the credential in
    // its environment must not outlive the refusal.
    try {
      this.checkResolvedCallerPolicy(
        s,
        secret.id,
        caller,
        "use",
        AuditEventType.SECRET_USE,
        { handle, context: action.type },
        handle,
      );
    } catch (err) {
      await s.mcpRegistry.terminate(
        secret.id,
        "use_denied",
        attributionFromCaller(caller, this.sessionId),
      );
      throw err;
    }

    // Attribution for the injector-written audit rows ("by whom" / "through
    // which interface", thesis §4.3.4) — per invocation, never injector state.
    const attribution = attributionFromCaller(caller, this.sessionId);

    const policy = this.loadInjectionPolicy(s, secret.id);

    // Status before the architectural guards below (B21): an expired, revoked
    // or pending secret reports its own status — and the lazy EXPIRED
    // transition runs — instead of the INVALID_INPUT a guard would raise
    // first. Same failure semantics as the value block: the denial row, then
    // the registry backstop. The vault-managed-certificate refusal keeps its
    // place ahead of the status ladder — as it has on both value paths — because
    // the renewal census keys on the persisted status, so letting the lazy
    // transition run here would drop the expired certificate out of the very
    // set `server start --cert-renew` retries.
    try {
      if (secret.type === SecretType.CERTIFICATE && s.store.getCertificate(secret.id)) {
        throw VaultError.certValueUnsupported(handle);
      }

      s.secretManager.assertUsable(secret, handle, {
        pending:
          secret.type === SecretType.OAUTH_TOKEN
            ? () => VaultError.oauthNotConfigured("OAuth flow not completed")
            : undefined,
      });
    } catch (err) {
      this.auditDenied(
        s,
        AuditEventType.SECRET_USE,
        err,
        { handle, context: action.type },
        secret.id,
        caller,
      );
      await s.mcpRegistry.terminate(secret.id, "secret_unusable", attribution);
      throw err;
    }

    // Docker × isolation (design §5.4) — fail closed BEFORE the dispatch arm,
    // before any spawn, and before the credential is even decrypted. The
    // spawned `docker` CLI is a thin client: the daemon the vault never
    // spawned performs the registry egress and writes the layers, and its Unix
    // socket survives `unshare -rn`, so wrapping the CLI would isolate the
    // messenger, not the actor. Documenting-and-allowing would make the audit
    // row assert an isolation that was never enforced. Same fail-closed answer
    // an isolation-incapable host gives, and network keeps precedence on the
    // terminate reason there too — though the composer answers with the
    // filesystem code when both flags are demanded; here the network code
    // keeps precedence, matching that terminate reason.
    this.assertDockerIsolationAllowed(s, action, policy, secret.id, caller);

    // SMTP STARTTLS × the mail TLS opt-out — the same pre-dispatch,
    // pre-credential placement: the opt-out cannot be honored on this leg, so
    // producing the credential for it is pure exposure.
    this.assertSmtpUsageAllowed(s, action, secret, attribution);

    // IMAP × (mail TLS opt-out | OAuth secret) — the same pre-dispatch,
    // pre-credential placement, for the same reason: both are architectural
    // refusals that no credential can satisfy, so producing the credential
    // first is pure exposure. An OAuth-typed secret would otherwise run a live
    // token refresh (a refresh_token POST plus a persisted rotation) for a use
    // that is refused a few lines later, and a `tls: false` secret would be
    // decrypted for it. The loaded connection config is handed back so the
    // imap arm reads it once; every other action type returns without touching
    // the config store.
    const imapConnection = this.assertImapUsageAllowed(s, action, secret, attribution);

    let value: Uint8Array;
    try {
      if (secret.type === SecretType.OAUTH_TOKEN) {
        const accessToken = await this.getOAuthAccessToken(secret.id);
        value = new Uint8Array(Buffer.from(accessToken, "utf8"));
      } else {
        value = await s.secretManager.getSecretValue(handle);
      }
    } catch (err) {
      this.auditDenied(
        s,
        AuditEventType.SECRET_USE,
        err,
        { handle, context: action.type },
        secret.id,
        caller,
      );
      // Backstop for the out-of-process case (L2): a CLI `secret revoke`, or a
      // lazy expiry detected in another process, cannot reach this process's
      // registry. The credential is no longer usable here, so any downstream
      // child still holding it is torn down before the refusal returns.
      await s.mcpRegistry.terminate(secret.id, "secret_unusable", attribution);
      throw err;
    }

    try {
      // Exhaustive dispatch over the action union (thesis §5.3.1): every
      // context has an explicit arm and the default funnels into the
      // never-typed assertNever — a seventh action type without an arm is a
      // compile error, not a runtime fall-through.
      switch (action.type) {
        case "process":
          return await s.processInjector.executeWithSecret(
            action,
            value,
            policy,
            secret.id,
            attribution,
          );

        case "mcp": {
          const config = this.loadMcpServerConfig(s, secret.id);
          if (!config) {
            throw VaultError.mcpServerNotConfigured(handle);
          }
          return await s.mcpInjector.executeWithSecret(
            action,
            value,
            policy,
            config,
            secret.id,
            attribution,
          );
        }

        case "http": {
          // Request-mediated (HTTP): enforce the per-secret URL allowlist before injection.
          if (!matchesUrlAllowlist(action.url, policy.url_allowlist)) {
            s.auditLogger.log({
              eventType: AuditEventType.SECRET_USE,
              secretId: secret.id,
              ...callerColumns(caller),
              detail: {
                context: "http",
                url: action.url,
                error: ErrorCode.URL_NOT_ALLOWED,
                ...callerInterfaceDetail(caller),
              },
              success: false,
              sessionId: this.sessionId ?? undefined,
            });
            throw VaultError.urlNotAllowed(action.url);
          }

          // Tighten-only response-mode override (thesis §4.5.2): a loosening
          // override would reopen the echo channel — rejected before the
          // request executes.
          const policyMode = policy.response_mode;
          if (action.response_mode && !isResponseModeAllowed(policyMode, action.response_mode)) {
            s.auditLogger.log({
              eventType: AuditEventType.SECRET_USE,
              secretId: secret.id,
              ...callerColumns(caller),
              detail: {
                context: "http",
                url: action.url,
                requested_mode: action.response_mode,
                policy_mode: policyMode,
                error: ErrorCode.RESPONSE_MODE_NOT_ALLOWED,
                ...callerInterfaceDetail(caller),
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
              responseHeaderAllowlist: policy.response_header_allowlist,
              urlAllowlist: policy.url_allowlist,
            },
            value,
            action.injection,
            action.follow_redirects,
            secret.id,
            attribution,
          );

          return response;
        }

        case "database": {
          const config = this.loadConnectionConfig(s, secret.id);
          return await s.databaseInjector.executeWithSecret(
            action,
            value,
            policy,
            config,
            secret.id,
            attribution,
          );
        }

        case "ssh": {
          const config = this.loadConnectionConfig(s, secret.id);
          return await s.sshInjector.executeWithSecret(
            action,
            value,
            policy,
            config,
            secret.id,
            attribution,
          );
        }

        case "git": {
          const config = this.loadConnectionConfig(s, secret.id);
          return await s.gitInjector.executeWithSecret(
            action,
            value,
            policy,
            config,
            secret.id,
            attribution,
          );
        }

        case "smtp": {
          const mail = this.loadConnectionConfig(s, secret.id)?.mail;
          // `tls: false` is the audited plaintext opt-out on the implicit-TLS
          // leg — the one mail case the vault honors, mirroring the database
          // `tls_mode: "disable"` opt-out (which is audited on the config-set
          // row; the use row records it per invocation as well). Stamped only
          // when that leg was actually skipped: the STARTTLS leg cannot honor
          // the opt-out, and `assertSmtpUsageAllowed` has already refused that
          // combination above.
          const tlsOptOut = action.security === "tls" && mail?.tls === false;
          const secretValue = Buffer.from(value).toString("utf8");
          const oauth: SmtpOAuth | undefined =
            secret.type === SecretType.OAUTH_TOKEN
              ? // XOAUTH2 authenticates the envelope sender's mailbox; the
                // OAuth row stores no account identity of its own.
                { accessToken: secretValue, username: action.from }
              : undefined;

          let execution;
          try {
            execution = await s.smtpInjector.run(action, secretValue, policy, mail, oauth);
          } catch (err) {
            const mapped = mapSmtpThrow(err);
            this.auditUse(
              s,
              secret.id,
              {
                context: "smtp",
                ...buildSmtpAuditDetails(action, attemptedAttachments(action)),
                ...(tlsOptOut ? { tls_opt_out: true } : {}),
                error: mapped.code,
              },
              false,
              attribution,
            );
            throw mapped;
          }

          this.auditUse(
            s,
            secret.id,
            {
              context: "smtp",
              ...execution.auditDetails,
              ...(tlsOptOut ? { tls_opt_out: true } : {}),
            },
            true,
            attribution,
          );
          return execution.result;
        }

        case "imap": {
          // Loaded once by `assertImapUsageAllowed` above, which needed it for
          // the TLS refusal — re-reading it here would decrypt the same row a
          // second time.
          const mail = imapConnection?.mail;

          // A failed row's details describe the attempt with the
          // result-derived counter at zero: `uid_count` is "what was touched"
          // (Task 8's decided semantic), and a refusal touched nothing.
          const failedDetail = {
            context: "imap",
            ...buildImapAuditDetails(action, { affected: 0 }),
          };

          const imapSecretValue = Buffer.from(value).toString("utf8");
          const imapOAuth: ImapOAuth | undefined =
            secret.type === SecretType.OAUTH_TOKEN
              ? // `assertImapUsageAllowed` guarantees `account` is present on
                // this arm; XOAUTH2 authenticates that mailbox, mirroring how
                // the SMTP arm reads the identity off the envelope sender.
                { accessToken: imapSecretValue, username: action.account as string }
              : undefined;

          let execution;
          try {
            execution = await s.imapInjector.run(action, imapSecretValue, policy, mail, imapOAuth);
          } catch (err) {
            const mapped = toVaultError(err);
            this.auditUse(
              s,
              secret.id,
              { ...failedDetail, error: mapped.code },
              false,
              attribution,
            );
            throw mapped;
          }

          this.auditUse(
            s,
            secret.id,
            {
              context: "imap",
              ...execution.auditDetails,
              ...(execution.sanitized ? { sanitized: true } : {}),
            },
            true,
            attribution,
          );
          return execution.result;
        }

        case "websocket": {
          // A failed row keeps `sent` as the attempt (a message was supplied)
          // and the result-derived `received` at zero — the same
          // attempt-plus-zero-counter shape the smtp/imap failures use.
          const failedDetail = {
            context: "websocket",
            ...buildWsAuditDetails(action, { messages: [], close_code: null }),
          };

          let execution;
          try {
            execution = await s.websocketExecutor(action, value, policy);
          } catch (err) {
            const mapped = toVaultError(err);
            this.auditUse(
              s,
              secret.id,
              { ...failedDetail, error: mapped.code },
              false,
              attribution,
            );
            throw mapped;
          }

          const result = execution.result;
          this.auditUse(
            s,
            secret.id,
            {
              context: "websocket",
              ...buildWsAuditDetails(action, result),
              ...(execution.sanitized ? { sanitized: true } : {}),
            },
            true,
            attribution,
          );
          return result;
        }

        case "sftp": {
          const config = this.loadConnectionConfig(s, secret.id);
          // Every SftpAuditDetails field the builder writes is request-derived
          // (design §7.2: host, operation, remote/local paths — no result-derived
          // counter to zero on a denial), so the same projection covers the
          // attempt and the outcome (Task 12's rule, applied where nothing needs
          // zeroing). `sanitized` is the one result-derived key, folded in below
          // onto whichever row the spawn produced — a success, or a graceful
          // non-throwing failure such as PROCESS_TIMEOUT; a refusal row (the
          // catch arm, which never reached a spawn) is never flagged.
          const auditDetail = { context: "sftp", ...buildSftpAuditDetails(action) };

          let execution: SftpExecution;
          try {
            execution = await s.sftpExecutor(action, value, policy, config);
          } catch (err) {
            const mapped = toVaultError(err);
            this.auditUse(s, secret.id, { ...auditDetail, error: mapped.code }, false, attribution);
            throw mapped;
          }
          const result = execution.result;
          const spawnedDetail = execution.sanitized
            ? { ...auditDetail, sanitized: true }
            : auditDetail;

          // A process-shaped result can carry a graceful, non-throwing
          // failure (e.g. PROCESS_TIMEOUT) in `error` — mirrors the ssh arm's
          // own `error === undefined` success test.
          this.auditUse(
            s,
            secret.id,
            result.error ? { ...spawnedDetail, error: result.error } : spawnedDetail,
            result.error === undefined,
            attribution,
          );
          return result;
        }

        case "docker_registry": {
          // Reached only after `assertDockerIsolationAllowed` above cleared the
          // action — a docker × isolation secret is refused before this arm.
          // Every DockerAuditDetails field the builder writes is request-derived
          // (the registry is parsed from the image, plus image + operation — no
          // result-derived counter to zero on a denial), so the same projection
          // covers the attempt and the outcome, exactly like the sftp arm.
          // `sanitized` is the one result-derived key, folded in below onto
          // whichever row the spawn produced — a success, or a graceful
          // non-throwing failure such as PROCESS_TIMEOUT; a refusal row (the
          // catch arm, which never reached a spawn) is never flagged.
          const auditDetail = { context: "docker_registry", ...buildDockerAuditDetails(action) };

          let execution: DockerExecution;
          try {
            execution = await s.dockerExecutor(action, value, policy);
          } catch (err) {
            const mapped = toVaultError(err);
            this.auditUse(s, secret.id, { ...auditDetail, error: mapped.code }, false, attribution);
            throw mapped;
          }
          const result = execution.result;
          const spawnedDetail = execution.sanitized
            ? { ...auditDetail, sanitized: true }
            : auditDetail;

          // A process-shaped result can carry a graceful, non-throwing failure
          // (a PROCESS_TIMEOUT) in `error`; a non-zero docker exit throws
          // DOCKER_OPERATION_FAILED and is handled on the catch arm above.
          this.auditUse(
            s,
            secret.id,
            result.error ? { ...spawnedDetail, error: result.error } : spawnedDetail,
            result.error === undefined,
            attribution,
          );
          return result;
        }

        default:
          return assertNever(action, "action type");
      }
    } catch (err) {
      // The choke point (E69): every thrown error leaves this method as a
      // VaultError with the credential stripped from message and details. The
      // injector-authored arms audit the VaultErrors they throw; a raw throw
      // provably had no row, so it gets the engine's (N16).
      if (!(err instanceof VaultError)) {
        this.auditUse(
          s,
          secret.id,
          { handle, context: action.type, error: ErrorCode.INTERNAL_ERROR },
          false,
          attribution,
        );
      }
      throw redactErrorMessage(toVaultError(err), Buffer.from(value).toString("utf8"));
    } finally {
      wipeBuffer(value);
    }
  }

  /**
   * Refuse a `docker_registry` action on a secret demanding process isolation
   * (design §5.4). Engine-level and pre-dispatch: unlike the platform-capability
   * refusals, this one is architectural — the Docker daemon, not the spawned
   * CLI, performs the registry egress and writes the layers, and the daemon
   * socket survives `unshare -rn`. Fail closed, audited like every denial.
   * Network takes precedence when both flags are set, matching the terminate
   * reason in setInjectionPolicy.
   */
  private assertDockerIsolationAllowed(
    s: UnlockedState,
    action: UseSecretAction,
    policy: InjectionPolicy,
    secretId: string,
    caller?: CallerContext,
  ): void {
    if (action.type !== "docker_registry") return;
    const wantsNetwork = policy.network_isolation === true;
    if (!wantsNetwork && policy.fs_isolation !== true) return;

    const err = wantsNetwork
      ? VaultError.networkIsolationUnavailable(
          "network isolation cannot be enforced across the Docker daemon boundary — the daemon, " +
            "not the spawned CLI, performs registry egress; remove the requirement via: " +
            "secret allow <handle> --no-network-isolation",
        )
      : VaultError.fsIsolationUnavailable(
          "filesystem isolation cannot be enforced across the Docker daemon boundary — the " +
            "daemon, not the spawned CLI, writes the image layers; remove the requirement via: " +
            "secret allow <handle> --no-fs-isolation",
        );

    this.auditDenied(
      s,
      AuditEventType.SECRET_USE,
      err,
      {
        context: "docker_registry",
        image: action.image,
        operation: action.operation,
        ...(wantsNetwork ? { network_isolation: true } : { fs_isolation: true }),
      },
      secretId,
      caller,
    );
    throw err;
  }

  /**
   * Refuse an `smtp` action whose STARTTLS leg cannot honor the mail
   * connection config's `tls: false` opt-out (N4). The opt-out is an
   * implicit-TLS-mode instruction — the SMTP client ignores it for STARTTLS,
   * which upgrades before authenticating regardless — so honoring it here was
   * never possible; the arm below merely stamped `tls_opt_out: true` on a row
   * whose leg had run encrypted, making the trail assert a plaintext send that
   * never happened. Dead config is refused, not dropped (the imap `account`
   * precedent), and like the docker and imap guards this runs before the
   * dispatch arm, so no credential is produced for a use that is refused.
   *
   * Audited through `auditUse`, not `auditDenied`, for the imap guard's
   * reason: the failed row keeps the smtp contexts' own shape, with
   * `attachment_total_bytes` at zero because nothing was read. It carries no
   * `tls_opt_out`: nothing was sent in the clear, so nothing may claim it was.
   *
   * Runs after `useSecret`'s status check (B21), so an expired, revoked or
   * pending secret has already reported its own status by the time this
   * architectural refusal is reached.
   */
  private assertSmtpUsageAllowed(
    s: UnlockedState,
    action: UseSecretAction,
    secret: Secret,
    attribution: AuditAttribution | undefined,
  ): void {
    if (action.type !== "smtp" || action.security !== "starttls") return;
    const mail = this.loadConnectionConfig(s, secret.id)?.mail;
    if (mail?.tls !== false) return;

    const err = VaultError.invalidInput(
      "SMTP STARTTLS cannot honor the mail connection config's TLS opt-out (tls: false): " +
        "the STARTTLS leg upgrades before authenticating. Use security: tls to keep the " +
        "opt-out meaningful on the implicit-TLS leg, or remove the mail TLS opt-out from " +
        "this secret's connection config.",
    );
    this.auditUse(
      s,
      secret.id,
      {
        context: "smtp",
        ...buildSmtpAuditDetails(action, attemptedAttachments(action)),
        error: err.code,
      },
      false,
      attribution,
    );
    throw err;
  }

  /**
   * Refuse an `imap` action the vault can never serve, and hand the imap arm
   * the connection config it loaded on the way. Two refusals, in this order:
   *
   * - Ruling 3: the IMAP client is implicit-TLS-only (design §4.2), so a mail
   *   `tls: false` opt-out cannot be honored on this leg.
   * - Ruling 4 (narrowed 2026-08-20): XOAUTH2 needs the mailbox account name,
   *   which the OAuth row does not store — the imap action's `account` field
   *   carries it now, so only an OAuth secret *without* that field refuses.
   *   The mirror image refuses too: `account` on a username:password secret
   *   would be silently dead (that arm's username lives in the value), and
   *   dead config is refused, not dropped (the tls:false precedent above).
   *
   * Both are architectural — no credential can satisfy either — so, like
   * `assertDockerIsolationAllowed`, they belong before the value block rather
   * than inside the dispatch arm. That placement is the point: producing the
   * credential first would run a live token refresh (a refresh_token POST plus
   * a persisted rotation and its `oauth.refresh` row) for the OAuth case, and
   * decrypt the value for the TLS case, both for a use that is then refused.
   *
   * Runs after `useSecret`'s status check (B21), so an expired, revoked or
   * pending secret has already reported its own status by the time this
   * architectural refusal is reached.
   *
   * Unlike the docker guard this audits through `auditUse`, not `auditDenied`:
   * the failed-row shape (`context: "imap"` plus the zeroed
   * `buildImapAuditDetails` projection) is the mail contexts' own, and moving
   * the refusal must not change what an operator reads off the trail.
   */
  private assertImapUsageAllowed(
    s: UnlockedState,
    action: UseSecretAction,
    secret: Secret,
    attribution: AuditAttribution | undefined,
  ): ConnectionConfig | undefined {
    if (action.type !== "imap") return undefined;

    const connection = this.loadConnectionConfig(s, secret.id);
    const mail = connection?.mail;

    // A failed row's details describe the attempt with the result-derived
    // counter at zero: `uid_count` is "what was touched" (Task 8's decided
    // semantic), and a refusal touched nothing.
    const failedDetail = {
      context: "imap",
      ...buildImapAuditDetails(action, { affected: 0 }),
    };

    // Ruling 3: refused before any socket rather than silently ignored — a
    // silent no-op would leave the admin believing an opt-out is live, with no
    // trail.
    if (mail?.tls === false) {
      const err = VaultError.invalidInput(
        "IMAP is implicit-TLS-only: the mail connection config's TLS opt-out (tls: false) " +
          "cannot be honored for imap actions. Remove the mail TLS opt-out from this " +
          "secret's connection config, or split the plaintext SMTP leg and the IMAP leg " +
          "onto two secrets.",
      );
      this.auditUse(s, secret.id, { ...failedDetail, error: err.code }, false, attribution);
      throw err;
    }

    // Ruling 4 (narrowed): the SMTP context reads the account name off the
    // envelope sender; the imap action's `account` field is its counterpart.
    // Without it the access token has no user to bind to — refused rather
    // than falling through to the password arm, which would put the access
    // token on the wire as an IMAP password.
    if (secret.type === SecretType.OAUTH_TOKEN && action.account === undefined) {
      const err = VaultError.invalidInput(
        "an OAuth-type secret cannot authenticate an imap action without the mailbox " +
          "account name: XOAUTH2 binds the access token to an account. Set the imap " +
          "action's 'account' field to the mailbox address.",
      );
      this.auditUse(s, secret.id, { ...failedDetail, error: err.code }, false, attribution);
      throw err;
    }

    // The mirror image: on the username:password arm the wire username comes
    // from the secret value, so a supplied `account` would be silently dead —
    // refused, not dropped.
    if (secret.type !== SecretType.OAUTH_TOKEN && action.account !== undefined) {
      const err = VaultError.invalidInput(
        "the imap action's 'account' field names the XOAUTH2 identity and is only " +
          "meaningful for an OAuth-type secret: the username:password arm reads its " +
          "username from the secret value. Remove the field or use an OAuth-type secret.",
      );
      this.auditUse(s, secret.id, { ...failedDetail, error: err.code }, false, attribution);
      throw err;
    }

    return connection;
  }

  /**
   * Write the `secret.use` row for a context whose injector returns a
   * metadata-only projection instead of logging its own row (the v1.3
   * mail/WebSocket contexts, design §7.2). Same envelope the injector-written
   * rows use, so attribution and the encrypted detail stay identical.
   */
  private auditUse(
    s: UnlockedState,
    secretId: string,
    detail: Record<string, unknown>,
    success: boolean,
    attribution: AuditAttribution | undefined,
  ): void {
    s.auditLogger.log(
      withAttribution(
        { eventType: AuditEventType.SECRET_USE, secretId, detail, success },
        attribution,
      ),
    );
  }

  /**
   * Load a secret's injection policy, decrypting the allowlists. Returns empty
   * allowlists when no policy is set — and every allowlist denies by default
   * (R1, 2026-09-01), so an unconfigured secret is usable in no target context
   * until an administrator writes its policy. A stored blob is parsed strictly
   * (R2/C43): the writer always emits all ten fields, so a miss or an extra
   * key is corruption.
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
        network_isolation: false,
        fs_isolation: false,
        smtp_recipient_allowlist: [],
        imap_read_only: false,
      };
    }
    const bytes = decrypt(
      s.kek,
      row.policy_encrypted,
      row.policy_iv,
      row.policy_tag,
      AAD_INJECTION_POLICY(secretId),
    );
    let raw: unknown;
    try {
      raw = JSON.parse(Buffer.from(bytes).toString("utf8"));
    } catch {
      throw VaultError.vaultCorrupted(`injection policy for secret ${secretId} is not JSON`);
    }
    const parsed = injectionPolicySchema.safeParse(raw);
    if (!parsed.success) {
      const paths = parsed.error.issues.map((issue) => issue.path.join(".") || "<root>");
      throw VaultError.vaultCorrupted(
        `injection policy for secret ${secretId} is malformed (${paths.join(", ")})`,
      );
    }
    return parsed.data;
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
   *
   * An entry is gated on its own name and on the binary it resolves to on
   * this host's controlled PATH (a symlink to `sh` is `sh`), which is the
   * parity the use-time gate already has; a resolution failure is ignored —
   * such an entry cannot spawn.
   */
  async setInjectionPolicy(
    handle: string,
    policy: InjectionPolicyInput,
    options?: SetInjectionPolicyOptions,
    caller?: CallerContext,
  ): Promise<void> {
    const validated = injectionPolicyInputSchema.safeParse(policy);
    if (!validated.success) {
      const issues = validated.error.issues.map(
        (issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`,
      );
      throw VaultError.schemaValidation(`Invalid injection policy: ${issues.join("; ")}`);
    }

    const s = this.assertUnlocked();
    let secret: Secret;
    try {
      secret = await s.secretManager.resolveHandle(handle);
    } catch (err) {
      this.auditDenied(
        s,
        AuditEventType.POLICY_GRANT,
        err,
        { policy: "injection", handle },
        undefined,
        caller,
      );
      throw await this.concealHandleError(s, err, handle, caller);
    }
    // Configuration of a secret is itself gated (W1) and the injection policy
    // is the widening half of it (R1): the allowlists bound where the
    // credential may go, so loosening them needs the same grant as writing a
    // policy row — `admin`, at the interface and per secret. Before the stored
    // policy is decrypted, before the interpreter gate, before any registry
    // terminate.
    this.checkResolvedCallerPolicy(
      s,
      secret.id,
      caller,
      "admin",
      AuditEventType.POLICY_GRANT,
      { policy: "injection", handle },
      handle,
    );

    const stored = new Set(this.loadInjectionPolicy(s, secret.id).command_allowlist);
    const pathDirs = controlledPathDirs();
    const added = [
      ...new Set((policy.command_allowlist ?? []).filter((entry) => !stored.has(entry))),
    ];
    // Two tiers, one flag (R6(ii)): the raw name first, then the entry
    // resolved on the controlled PATH (a symlink to `sh` is `sh`, E71i). An
    // entry is counted in exactly one tier.
    const tierOf = (entry: string): "interpreter" | "wrapper" | null => {
      if (knownInterpreterName(entry) !== null) return "interpreter";
      if (execWrapperName(entry) !== null) return "wrapper";
      const resolved = resolveExecutable(entry, pathDirs);
      if (resolved === null) return null;
      if (knownInterpreterName(resolved) !== null) return "interpreter";
      return execWrapperName(resolved) !== null ? "wrapper" : null;
    };
    const tiers = new Map(added.map((entry) => [entry, tierOf(entry)] as const));
    const addedInterpreters = added.filter((entry) => tiers.get(entry) === "interpreter");
    const addedWrappers = added.filter((entry) => tiers.get(entry) === "wrapper");
    const gated = addedInterpreters.length > 0 || addedWrappers.length > 0;
    if (gated && options?.acknowledge_interpreters !== true) {
      s.auditLogger.log({
        eventType: AuditEventType.POLICY_INTERPRETER_REFUSED,
        secretId: secret.id,
        ...callerColumns(caller),
        detail: {
          policy: "injection",
          interpreters: addedInterpreters,
          exec_wrappers: addedWrappers,
          ...callerInterfaceDetail(caller),
        },
        sessionId: this.sessionId ?? undefined,
      });
      throw VaultError.interpreterNotAcknowledged(addedInterpreters, addedWrappers);
    }

    const json = JSON.stringify({
      url_allowlist: policy.url_allowlist ?? [],
      command_allowlist: policy.command_allowlist ?? [],
      env_allowlist: policy.env_allowlist ?? [],
      host_allowlist: policy.host_allowlist ?? [],
      response_mode: policy.response_mode ?? "filtered",
      response_header_allowlist: policy.response_header_allowlist ?? [],
      network_isolation: policy.network_isolation ?? false,
      fs_isolation: policy.fs_isolation ?? false,
      smtp_recipient_allowlist: policy.smtp_recipient_allowlist ?? [],
      imap_read_only: policy.imap_read_only ?? false,
    });
    const enc = encrypt(
      s.kek,
      new Uint8Array(Buffer.from(json, "utf8")),
      AAD_INJECTION_POLICY(secret.id),
    );
    const now = Date.now();
    // Policy write + audit row(s) in one transaction (NM3): the acknowledged-
    // interpreter row commits with the grant it acknowledges.
    s.store.transaction(() => {
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
        ...callerColumns(caller),
        detail: {
          policy: "injection",
          url_count: policy.url_allowlist?.length ?? 0,
          command_count: policy.command_allowlist?.length ?? 0,
          env_count: policy.env_allowlist?.length ?? 0,
          host_count: policy.host_allowlist?.length ?? 0,
          response_mode: policy.response_mode ?? "filtered",
          response_header_count: policy.response_header_allowlist?.length ?? 0,
          network_isolation: policy.network_isolation ?? false,
          fs_isolation: policy.fs_isolation ?? false,
          recipient_count: policy.smtp_recipient_allowlist?.length ?? 0,
          imap_read_only: policy.imap_read_only ?? false,
          ...callerInterfaceDetail(caller),
        },
        sessionId: this.sessionId ?? undefined,
      });

      if (gated) {
        s.auditLogger.log({
          eventType: AuditEventType.POLICY_INTERPRETER_ACKNOWLEDGED,
          secretId: secret.id,
          ...callerColumns(caller),
          detail: {
            policy: "injection",
            interpreters: addedInterpreters,
            exec_wrappers: addedWrappers,
            ...callerInterfaceDetail(caller),
          },
          sessionId: this.sessionId ?? undefined,
        });
      }
    });

    // Thesis §4.5.3 layer 4: a live stdio downstream child predates the
    // isolation demand and holds the credential with full egress (and with
    // write access to the filesystem) — leaving it to the next invocation
    // would keep it running until then. Idempotent no-op when nothing is
    // live; the next use respawns the child wrapped (D51), and the posture
    // recorded on the registry entry is McpInjector's backstop for a policy
    // tightened from a separate process, whose engine cannot reach this
    // registry. One terminate covers both demands; the network reason keeps
    // precedence.
    if (policy.network_isolation === true || policy.fs_isolation === true) {
      await s.mcpRegistry.terminate(
        secret.id,
        policy.network_isolation === true ? "network_isolation_enabled" : "fs_isolation_enabled",
        attributionFromCaller(caller, this.sessionId),
      );
    }
  }

  /** Read a secret's injection policy (empty allowlists when unset). */
  async getInjectionPolicy(handle: string, caller?: CallerContext): Promise<InjectionPolicy> {
    const s = this.assertUnlocked();
    let secret: Secret;
    try {
      secret = await s.secretManager.resolveHandle(handle);
    } catch (err) {
      this.auditDenied(
        s,
        AuditEventType.SECRET_READ,
        err,
        { handle, config: "injection" },
        undefined,
        caller,
      );
      throw await this.concealHandleError(s, err, handle, caller);
    }
    this.checkResolvedCallerPolicy(
      s,
      secret.id,
      caller,
      "read",
      AuditEventType.SECRET_READ,
      { handle, config: "injection" },
      handle,
    );
    const policy = this.loadInjectionPolicy(s, secret.id);
    this.auditConfigRead(s, secret.id, caller, { handle, config: "injection" });
    return policy;
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
  async setMcpServerConfig(
    handle: string,
    config: McpServerConfig,
    caller?: CallerContext,
  ): Promise<void> {
    const s = this.assertUnlocked();
    let secret: Secret;
    try {
      secret = await s.secretManager.resolveHandle(handle);
    } catch (err) {
      this.auditDenied(
        s,
        AuditEventType.POLICY_GRANT,
        err,
        { policy: "mcp_server", handle },
        undefined,
        caller,
      );
      throw await this.concealHandleError(s, err, handle, caller);
    }
    // Before the terminate below: a denied caller must not be able to kill
    // another principal's live downstream child by calling this repeatedly.
    this.checkResolvedCallerPolicy(
      s,
      secret.id,
      caller,
      "rotate",
      AuditEventType.POLICY_GRANT,
      { policy: "mcp_server", handle },
      handle,
    );

    const json = JSON.stringify(config);
    const enc = encrypt(
      s.kek,
      new Uint8Array(Buffer.from(json, "utf8")),
      AAD_MCP_SERVER_CONFIG(secret.id),
    );
    const now = Date.now();
    s.store.transaction(() => {
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
        ...callerColumns(caller),
        detail: {
          policy: "mcp_server",
          server_name: config.server_name,
          transport: config.transport,
          ...callerInterfaceDetail(caller),
        },
        sessionId: this.sessionId ?? undefined,
      });
    });

    await s.mcpRegistry.terminate(
      secret.id,
      "config_changed",
      attributionFromCaller(caller, this.sessionId),
    );
  }

  /** Read a secret's downstream MCP server config (undefined when unset). */
  async getMcpServerConfig(
    handle: string,
    caller?: CallerContext,
  ): Promise<McpServerConfig | undefined> {
    const s = this.assertUnlocked();
    let secret: Secret;
    try {
      secret = await s.secretManager.resolveHandle(handle);
    } catch (err) {
      this.auditDenied(
        s,
        AuditEventType.SECRET_READ,
        err,
        { handle, config: "mcp_server" },
        undefined,
        caller,
      );
      throw await this.concealHandleError(s, err, handle, caller);
    }
    this.checkResolvedCallerPolicy(
      s,
      secret.id,
      caller,
      "read",
      AuditEventType.SECRET_READ,
      { handle, config: "mcp_server" },
      handle,
    );
    const config = this.loadMcpServerConfig(s, secret.id);
    this.auditConfigRead(s, secret.id, caller, { handle, config: "mcp_server" });
    return config;
  }

  /** Remove a secret's downstream MCP server config, terminating any live connection. */
  async deleteMcpServerConfig(handle: string, caller?: CallerContext): Promise<boolean> {
    const s = this.assertUnlocked();
    let secret: Secret;
    try {
      secret = await s.secretManager.resolveHandle(handle);
    } catch (err) {
      this.auditDenied(
        s,
        AuditEventType.POLICY_REVOKE,
        err,
        { policy: "mcp_server", handle },
        undefined,
        caller,
      );
      throw await this.concealHandleError(s, err, handle, caller);
    }
    // Before the terminate: a denied caller must not reach the registry.
    this.checkResolvedCallerPolicy(
      s,
      secret.id,
      caller,
      "rotate",
      AuditEventType.POLICY_REVOKE,
      { policy: "mcp_server", handle },
      handle,
    );
    await s.mcpRegistry.terminate(
      secret.id,
      "config_removed",
      attributionFromCaller(caller, this.sessionId),
    );
    return s.store.transaction(() => {
      const deleted = s.store.deleteMcpServer(secret.id);
      if (deleted) {
        s.auditLogger.log({
          eventType: AuditEventType.POLICY_REVOKE,
          secretId: secret.id,
          ...callerColumns(caller),
          detail: { policy: "mcp_server", ...callerInterfaceDetail(caller) },
          sessionId: this.sessionId ?? undefined,
        });
      }
      return deleted;
    });
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
  async setConnectionConfig(
    handle: string,
    config: ConnectionConfig,
    caller?: CallerContext,
  ): Promise<void> {
    const s = this.assertUnlocked();
    let secret: Secret;
    try {
      secret = await s.secretManager.resolveHandle(handle);
    } catch (err) {
      this.auditDenied(
        s,
        AuditEventType.POLICY_GRANT,
        err,
        { policy: "connection", handle },
        undefined,
        caller,
      );
      throw await this.concealHandleError(s, err, handle, caller);
    }
    // Endpoint-authentication pins (DB TLS/CA, SSH host keys) bound the
    // allowlist decision — dropping them is a rotate-class change.
    this.checkResolvedCallerPolicy(
      s,
      secret.id,
      caller,
      "rotate",
      AuditEventType.POLICY_GRANT,
      { policy: "connection", handle },
      handle,
    );

    const json = JSON.stringify(config);
    const enc = encrypt(
      s.kek,
      new Uint8Array(Buffer.from(json, "utf8")),
      AAD_CONNECTION_CONFIG(secret.id),
    );
    const now = Date.now();
    s.store.transaction(() => {
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
        ...callerColumns(caller),
        detail: {
          policy: "connection",
          has_database: config.database !== undefined,
          has_ssh: config.ssh !== undefined,
          has_mail: config.mail !== undefined,
          has_git: config.git !== undefined,
          database_tls: config.database?.tls_mode,
          // The mail group carries the TLS decision as a value, not a mode —
          // projected onto the database group's require/disable vocabulary so
          // one audit reader covers both TLS opt-outs.
          mail_tls:
            config.mail === undefined
              ? undefined
              : config.mail.tls === false
                ? "disable"
                : "require",
          known_hosts_count: config.ssh?.known_hosts.length ?? 0,
          ...callerInterfaceDetail(caller),
        },
        sessionId: this.sessionId ?? undefined,
      });
    });
  }

  /** Read a secret's endpoint-authentication config (undefined when unset). */
  async getConnectionConfig(
    handle: string,
    caller?: CallerContext,
  ): Promise<ConnectionConfig | undefined> {
    const s = this.assertUnlocked();
    let secret: Secret;
    try {
      secret = await s.secretManager.resolveHandle(handle);
    } catch (err) {
      this.auditDenied(
        s,
        AuditEventType.SECRET_READ,
        err,
        { handle, config: "connection" },
        undefined,
        caller,
      );
      throw await this.concealHandleError(s, err, handle, caller);
    }
    this.checkResolvedCallerPolicy(
      s,
      secret.id,
      caller,
      "read",
      AuditEventType.SECRET_READ,
      { handle, config: "connection" },
      handle,
    );
    const config = this.loadConnectionConfig(s, secret.id);
    this.auditConfigRead(s, secret.id, caller, { handle, config: "connection" });
    return config;
  }

  /** Remove a secret's endpoint-authentication config. */
  async deleteConnectionConfig(handle: string, caller?: CallerContext): Promise<boolean> {
    const s = this.assertUnlocked();
    let secret: Secret;
    try {
      secret = await s.secretManager.resolveHandle(handle);
    } catch (err) {
      this.auditDenied(
        s,
        AuditEventType.POLICY_REVOKE,
        err,
        { policy: "connection", handle },
        undefined,
        caller,
      );
      throw await this.concealHandleError(s, err, handle, caller);
    }
    this.checkResolvedCallerPolicy(
      s,
      secret.id,
      caller,
      "rotate",
      AuditEventType.POLICY_REVOKE,
      { policy: "connection", handle },
      handle,
    );
    return s.store.transaction(() => {
      const deleted = s.store.deleteConnectionConfig(secret.id);
      if (deleted) {
        s.auditLogger.log({
          eventType: AuditEventType.POLICY_REVOKE,
          secretId: secret.id,
          ...callerColumns(caller),
          detail: { policy: "connection", ...callerInterfaceDetail(caller) },
          sessionId: this.sessionId ?? undefined,
        });
      }
      return deleted;
    });
  }

  // ---------------------------------------------------------------------------
  // OAuth
  // ---------------------------------------------------------------------------

  /**
   * Create an OAuth secret with provider configuration.
   * Status is PENDING until completeOAuthFlow is called.
   *
   * A name collision with an existing PENDING OAuth secret resumes it: the
   * aborted flow's provider row is replaced wholesale with the fresh config
   * and the same secretId proceeds — so re-running `oauth connect` after a
   * cancelled/failed flow works. ACTIVE or non-OAuth collisions stay
   * DUPLICATE_SECRET.
   *
   * `caller` is attribution only, exactly as on `createSecret`: `create` is not
   * grantable per secret (W2), so token scope governs it — but without the
   * caller a token-bearing connect wrote NULL-principal rows, which is the
   * documented marker for the *trusted local path* (L3), so a REST/MCP/CLI-token
   * connect was indistinguishable from a local one in the trail (V2 attribution
   * parity). `oauth.authorize` is this operation's own row and carries the
   * attribution on both the fresh-create and the resume path; refusals are
   * audited as a failed `oauth.authorize`, like `refreshOAuthToken` audits its
   * own.
   */
  async createOAuthSecret(
    name: string,
    providerConfig: OAuthProviderConfig,
    project?: string,
    caller?: CallerContext,
  ): Promise<{ handle: string; secretId: string }> {
    const s = this.assertUnlocked();
    let secretId: string | undefined;
    try {
      return await this.doCreateOAuthSecret(
        s,
        name,
        providerConfig,
        (id) => (secretId = id),
        project,
        caller,
      );
    } catch (err) {
      this.auditDenied(
        s,
        AuditEventType.OAUTH_AUTHORIZE,
        err,
        { name, provider: providerConfig.provider, grant_type: providerConfig.grant_type },
        secretId,
        caller,
      );
      throw err;
    }
  }

  private async doCreateOAuthSecret(
    s: UnlockedState,
    name: string,
    providerConfig: OAuthProviderConfig,
    onResolved: (secretId: string) => void,
    project?: string,
    caller?: CallerContext,
  ): Promise<{ handle: string; secretId: string }> {
    // Base row, OAuth row and the `oauth.authorize` row commit together (NM3,
    // N10) — a crash cannot leave a PENDING secret without its provider row.
    // Runs inside the caller's transaction: `createSecret`'s own on the fresh
    // path, the replace transaction on the resume path.
    const commitOAuthRow = (secretId: string, handle: string, resumed: boolean): void => {
      const clientIdBytes = new Uint8Array(Buffer.from(providerConfig.client_id, "utf8"));
      const clientIdEnc = encrypt(s.kek, clientIdBytes, AAD_OAUTH_CLIENT_ID(secretId));

      let clientSecretEnc: { ciphertext: Uint8Array; iv: Uint8Array; tag: Uint8Array } | null =
        null;
      if (providerConfig.client_secret) {
        const clientSecretBytes = new Uint8Array(Buffer.from(providerConfig.client_secret, "utf8"));
        clientSecretEnc = encrypt(s.kek, clientSecretBytes, AAD_OAUTH_CLIENT_SECRET(secretId));
      }

      s.store.insertOAuthToken({
        secret_id: secretId,
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
        token_endpoint_auth_method:
          providerConfig.token_endpoint_auth_method ?? "client_secret_post",
      });

      s.auditLogger.log({
        eventType: AuditEventType.OAUTH_AUTHORIZE,
        secretId,
        ...callerColumns(caller),
        detail: {
          handle,
          provider: providerConfig.provider,
          grant_type: providerConfig.grant_type,
          ...(resumed ? { resumed: true } : {}),
          ...callerInterfaceDetail(caller),
        },
        sessionId: this.sessionId ?? undefined,
      });
    };

    let createdId = "";
    try {
      const result = await s.secretManager.createSecret(
        { name, type: SecretType.OAUTH_TOKEN, project },
        (response, id) => {
          createdId = id;
          commitOAuthRow(id, response.handle, false);
        },
      );
      return { handle: result.handle, secretId: createdId };
    } catch (createErr) {
      if (!(createErr instanceof VaultError) || createErr.code !== ErrorCode.DUPLICATE_SECRET) {
        throw createErr;
      }
      const handle = formatHandle(name, project);
      let existing: Awaited<ReturnType<typeof s.secretManager.resolveHandle>>;
      try {
        existing = await s.secretManager.resolveHandle(handle);
      } catch {
        throw createErr;
      }
      if (existing.type !== SecretType.OAUTH_TOKEN || existing.status !== SecretStatus.PENDING) {
        throw createErr;
      }

      // Only the resume path has a secret that outlives a rollback, so it is
      // the only one that can attribute a denial row to a secret id.
      const existingId = existing.id;
      onResolved(existingId);
      s.store.transaction(() => {
        s.store.deleteOAuthToken(existingId);
        commitOAuthRow(existingId, handle, true);
      });
      return { handle, secretId: existingId };
    }
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

    let tokenUpdate: Parameters<typeof s.store.updateOAuthToken>[1] = accessUpdate;
    if (refreshToken) {
      const refreshTokenBytes = new Uint8Array(Buffer.from(refreshToken, "utf8"));
      const refreshTokenEnc = encrypt(s.kek, refreshTokenBytes, AAD_OAUTH_REFRESH_TOKEN(secretId));
      tokenUpdate = {
        ...accessUpdate,
        refresh_token_encrypted: refreshTokenEnc.ciphertext,
        refresh_token_iv: refreshTokenEnc.iv,
        refresh_token_tag: refreshTokenEnc.tag,
      };
    }

    // Token write, ACTIVE transition and audit row in one transaction (NM3) —
    // previously a crash between them could leave tokens on a PENDING secret.
    s.store.transaction(() => {
      s.store.updateOAuthToken(secretId, tokenUpdate);

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
    });
  }

  /**
   * The token-endpoint client authentication a stored OAuth row prescribes.
   * The column is checked at the table (R2), so anything but the two methods
   * is corruption, not a degradation target: silently POSTing the client
   * secret to a provider that expects something else is a credential
   * disclosure, so it fails closed.
   */
  private storedAuthMethod(row: OAuthTokenRow): "client_secret_post" | "client_secret_basic" {
    const method = row.token_endpoint_auth_method;
    if (method === "client_secret_post" || method === "client_secret_basic") return method;
    throw VaultError.vaultCorrupted(`unknown token_endpoint_auth_method "${method}"`);
  }

  /**
   * Refresh an OAuth token: decrypt refresh_token, call token endpoint, encrypt new tokens.
   * Returns the new access_token expiry timestamp (or null if no expires_in in response).
   *
   * Concurrent callers for the same secret coalesce onto one in-flight refresh:
   * the refresh_token must be POSTed exactly once — providers with refresh-token
   * rotation treat a replay as theft and revoke the whole token family.
   *
   * `handle` is the string the interface resolved the id from — it lets a
   * concealed refusal read exactly like an unknown handle (R5); absent, the
   * refusal reads "Secret not found".
   */
  async refreshOAuthToken(
    secretId: string,
    caller?: CallerContext,
    handle?: string,
  ): Promise<number | null> {
    const s = this.assertUnlocked();
    // Deny before joining an in-flight refresh: a denied caller must neither
    // trigger a refresh_token POST nor await another principal's result.
    this.checkResolvedCallerPolicy(
      s,
      secretId,
      caller,
      "rotate",
      AuditEventType.OAUTH_REFRESH,
      { action: "refresh" },
      handle,
    );
    const existing = this.oauthRefreshInFlight.get(secretId);
    if (existing) return existing;

    const refresh = this.doRefreshOAuthToken(secretId, caller);
    this.oauthRefreshInFlight.set(secretId, refresh);
    try {
      return await refresh;
    } finally {
      this.oauthRefreshInFlight.delete(secretId);
    }
  }

  private async doRefreshOAuthToken(
    secretId: string,
    caller?: CallerContext,
  ): Promise<number | null> {
    const s = this.assertUnlocked();
    try {
      return await this.doRefreshOAuthTokenInner(s, secretId, caller);
    } catch (err) {
      this.auditDenied(
        s,
        AuditEventType.OAUTH_REFRESH,
        err,
        { action: "refresh" },
        secretId,
        caller,
      );
      throw err;
    }
  }

  private async doRefreshOAuthTokenInner(
    s: UnlockedState,
    secretId: string,
    caller?: CallerContext,
  ): Promise<number | null> {
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

    // POST to token endpoint. Client authentication follows the stored method; an unknown value is corruption (fail closed).
    const authMethod = this.storedAuthMethod(oauthRow);
    const params = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    });
    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
    };
    applyTokenEndpointAuth(
      { client_id: clientId, client_secret: clientSecret, token_endpoint_auth_method: authMethod },
      params,
      headers,
    );

    let response: Response;
    try {
      response = await fetch(oauthRow.token_endpoint, {
        method: "POST",
        headers,
        body: params.toString(),
        signal: AbortSignal.timeout(30_000),
      });
    } catch (err) {
      throw VaultError.oauthRefreshFailed(err instanceof Error ? err.message : "Network error");
    }

    if (!response.ok) {
      throw VaultError.oauthRefreshFailed(`Token endpoint returned HTTP ${response.status}`);
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
    const newAccessTokenBytes = new Uint8Array(Buffer.from(tokenResponse.access_token, "utf8"));
    const newAccessTokenEnc = encrypt(s.kek, newAccessTokenBytes, AAD_OAUTH_ACCESS_TOKEN(secretId));

    const newExpiresAt = tokenResponse.expires_in
      ? Date.now() + tokenResponse.expires_in * 1000
      : null;

    const accessUpdate = {
      access_token_encrypted: newAccessTokenEnc.ciphertext,
      access_token_iv: newAccessTokenEnc.iv,
      access_token_tag: newAccessTokenEnc.tag,
      access_token_expires_at: newExpiresAt,
    };

    let tokenUpdate: Parameters<typeof s.store.updateOAuthToken>[1] = accessUpdate;
    if (tokenResponse.refresh_token) {
      const newRefreshBytes = new Uint8Array(Buffer.from(tokenResponse.refresh_token, "utf8"));
      const newRefreshEnc = encrypt(s.kek, newRefreshBytes, AAD_OAUTH_REFRESH_TOKEN(secretId));
      tokenUpdate = {
        ...accessUpdate,
        refresh_token_encrypted: newRefreshEnc.ciphertext,
        refresh_token_iv: newRefreshEnc.iv,
        refresh_token_tag: newRefreshEnc.tag,
      };
    }

    // Rotated tokens and their audit row commit together (NM3): a possibly
    // rotated-away refresh_token is never stored unaudited.
    s.store.transaction(() => {
      s.store.updateOAuthToken(secretId, tokenUpdate);

      s.store.updateSecret(secretId, { updated_at: Date.now() });

      s.auditLogger.log({
        eventType: AuditEventType.OAUTH_REFRESH,
        secretId,
        ...callerColumns(caller),
        detail: { new_expires_at: newExpiresAt, ...callerInterfaceDetail(caller) },
        sessionId: this.sessionId ?? undefined,
        success: true,
      });
    });

    return newExpiresAt;
  }

  /**
   * Get OAuth token status without decrypting sensitive fields.
   *
   * `handle` is the string the interface resolved the id from — it lets a
   * concealed refusal read exactly like an unknown handle (R5); absent, the
   * refusal reads "Secret not found".
   */
  getOAuthTokenStatus(secretId: string, caller?: CallerContext, handle?: string): OAuthTokenStatus {
    const s = this.assertUnlocked();
    this.checkResolvedCallerPolicy(
      s,
      secretId,
      caller,
      "read",
      AuditEventType.SECRET_READ,
      { config: "oauth_status" },
      handle,
    );

    const oauthRow = s.store.getOAuthToken(secretId);
    if (!oauthRow) throw VaultError.oauthNotConfigured();

    const secret = s.store.getSecret(secretId);

    const status: OAuthTokenStatus = {
      secret_id: secretId,
      provider: oauthRow.provider as OAuthProviderPreset,
      has_access_token: oauthRow.access_token_encrypted !== null,
      access_token_expires_at: oauthRow.access_token_expires_at,
      has_refresh_token: oauthRow.refresh_token_encrypted !== null,
      last_refreshed_at: secret?.updated_at ?? null,
      refresh_status: computeOAuthRefreshStatus(oauthRow),
      token_endpoint_auth_method: this.storedAuthMethod(oauthRow),
    };
    this.auditConfigRead(s, secretId, caller, { config: "oauth_status" });
    return status;
  }

  /**
   * Get the decrypted OAuth access token. Auto-refreshes if expired or within 60s of expiry.
   * NEVER return this to the LLM — only use within the injection pipeline.
   */
  async getOAuthAccessToken(secretId: string): Promise<string> {
    const s = this.assertUnlocked();

    // No denial row here: the only caller is `useSecret`, whose own catch
    // writes the attributed `secret.use` refusal — a second, unattributed
    // `secret.read` row would double-count one refused use (E75h).
    const secret = s.store.getSecret(secretId);
    if (!secret) throw VaultError.secretNotFound();
    if (secret.type !== SecretType.OAUTH_TOKEN) {
      throw VaultError.oauthNotConfigured();
    }

    // Lazy expiry check — status write + audit row in one transaction (NM3)
    if (
      secret.status !== SecretStatus.EXPIRED &&
      secret.expires_at !== null &&
      secret.expires_at <= Date.now()
    ) {
      s.store.transaction(() => {
        s.store.updateSecret(secretId, {
          status: SecretStatus.EXPIRED,
          updated_at: Date.now(),
        });
        s.auditLogger.log({
          eventType: AuditEventType.SECRET_EXPIRE,
          secretId,
          sessionId: this.sessionId ?? undefined,
        });
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
            throw err instanceof VaultError ? err : VaultError.oauthRefreshFailed("Refresh failed");
          }
          // Token not yet expired — fall through to return current token
        }
      } else if (oauthRow.access_token_expires_at <= Date.now()) {
        throw VaultError.oauthRefreshFailed("Access token expired and no refresh token available");
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

  /**
   * Metadata-only projection of the expiring OAuth rows (D5): the row shape
   * carries the encrypted client/token columns, so no interface outside core
   * may see it — health surfaces get handle/name/project plus the derived
   * refresh state and nothing else.
   *
   * Policy-filtered like `listSecrets` (W2) and silent for the same reason: a
   * gated secret must not be recoverable from an expiry census, and enumeration
   * writes no audit row. An absent caller is the trusted local path.
   */
  getExpiringOAuthTokenStatuses(
    withinMs: number,
    caller?: CallerContext,
  ): ExpiringOAuthTokenInfo[] {
    const s = this.assertUnlocked();
    // The metadata join is built only once a row needs it: `secretInfoById`
    // KEK-decrypts every secret name in the vault, and a health census with
    // nothing expiring is the common case.
    const rows = s.store.getExpiringOAuthTokens(withinMs);
    if (rows.length === 0) return [];

    const infoById = this.secretInfoById(s, caller);
    const out: ExpiringOAuthTokenInfo[] = [];
    for (const row of rows) {
      const info = infoById.get(row.secret_id);
      if (!info) continue;
      out.push({
        handle: info.handle,
        name: info.name,
        project: info.project,
        provider: row.provider as OAuthProviderPreset,
        access_token_expires_at: row.access_token_expires_at,
        has_refresh_token: row.refresh_token_encrypted !== null,
        refresh_status: computeOAuthRefreshStatus(row),
      });
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // Certificates
  // ---------------------------------------------------------------------------

  /**
   * Import a certificate: the private key is stored KEK-encrypted, the public
   * material (cert/chain/CSR) verbatim. With a certificate the key/cert pair is
   * verified before anything is written and the parsed notAfter becomes the
   * secret's expiry, so the ordinary expiry machinery covers certificates too;
   * a CSR-only import (ACME order placed, not yet issued) stays PENDING with no
   * expiry until the issued certificate arrives.
   *
   * Every refusal is audited as a failed `cert.issue`, like `refreshOAuthToken`
   * audits its own: the pre-write validation is where a mismatched pair or an
   * unparseable PEM is caught, and those attempts are exactly what a trail
   * needs to show. The row carries the secret id only once one exists.
   *
   * `caller` is attribution only, exactly as on `createSecret`: `create` is not
   * grantable per secret (there is no secret to carry the row yet, W2), so
   * token scope governs it — but without the caller a token-bearing import
   * wrote NULL-principal rows, which is the documented marker for the *trusted
   * local path* (L3), so a REST/MCP/CLI-token import was indistinguishable from
   * a local one in the trail (V2 attribution parity).
   */
  async importCertificate(
    name: string,
    privateKeyPem: string,
    opts?: ImportCertificateOptions,
    project?: string,
    caller?: CallerContext,
  ): Promise<{ handle: string; secretId: string }> {
    const s = this.assertUnlocked();
    let secretId: string | undefined;
    try {
      return await this.doImportCertificate(
        s,
        name,
        privateKeyPem,
        (id) => (secretId = id),
        opts,
        project,
        caller,
      );
    } catch (err) {
      this.auditDenied(
        s,
        AuditEventType.CERT_ISSUE,
        err,
        { name, action: "import_certificate" },
        secretId,
        caller,
      );
      throw err;
    }
  }

  private async doImportCertificate(
    s: UnlockedState,
    name: string,
    privateKeyPem: string,
    onResolved: (secretId: string) => void,
    opts?: ImportCertificateOptions,
    project?: string,
    caller?: CallerContext,
  ): Promise<{ handle: string; secretId: string }> {
    const o = opts ?? {};

    if (
      o.renewBeforeDays !== undefined &&
      (!Number.isInteger(o.renewBeforeDays) ||
        o.renewBeforeDays < 1 ||
        o.renewBeforeDays > MAX_RENEW_BEFORE_DAYS)
    ) {
      throw VaultError.invalidInput(
        `renewBeforeDays must be an integer between 1 and ${MAX_RENEW_BEFORE_DAYS}`,
      );
    }

    if (o.autoRenew === true && o.acmeIssued !== true) {
      throw VaultError.invalidInput(
        "auto_renew requires an ACME-issued certificate (harpoc cert issue)",
      );
    }

    if (o.acmeAccountJson !== undefined && o.acmeIssued !== true) {
      throw VaultError.invalidInput("acmeAccountJson requires acmeIssued (an ACME issuance)");
    }

    let keyObj: ReturnType<typeof createPrivateKey>;
    try {
      keyObj = createPrivateKey(privateKeyPem);
    } catch {
      throw VaultError.certInvalid("private key PEM is not parseable");
    }

    let subject: string;
    let issuer: string | null = null;
    let serial: string | null = null;
    let notBefore: number | null = null;
    let notAfter: number | null = null;

    if (o.certificatePem) {
      let cert: X509Certificate;
      try {
        cert = new X509Certificate(o.certificatePem);
      } catch {
        throw VaultError.certInvalid("certificate PEM is not parseable");
      }
      if (!cert.checkPrivateKey(keyObj)) throw VaultError.certPrivateKeyMismatch();
      subject = cert.subject;
      issuer = cert.issuer;
      serial = cert.serialNumber;
      notBefore = new Date(cert.validFrom).getTime();
      notAfter = new Date(cert.validTo).getTime();
    } else if (o.csrPem && o.subject) {
      subject = o.subject;
    } else {
      throw VaultError.certInvalid("either certificatePem or csrPem+subject is required");
    }

    // The secret row and its secret.create audit row commit together (NM3),
    // like every other create path.
    const { handle } = await s.secretManager.createSecret(
      {
        name,
        type: SecretType.CERTIFICATE,
        project,
        expiresAt: notAfter ?? undefined,
      },
      (result, id) => {
        s.auditLogger.log({
          eventType: AuditEventType.SECRET_CREATE,
          secretId: id,
          ...callerColumns(caller),
          detail: {
            handle: result.handle,
            status: result.status,
            ...callerInterfaceDetail(caller),
          },
          sessionId: this.sessionId ?? undefined,
        });
      },
    );
    const secret = await s.secretManager.resolveHandle(handle);
    onResolved(secret.id);

    const keyEnc = encrypt(
      s.kek,
      new Uint8Array(Buffer.from(privateKeyPem, "utf8")),
      AAD_CERT_PRIVATE_KEY(secret.id),
    );

    const accountEnc =
      o.acmeAccountJson === undefined
        ? null
        : encrypt(
            s.kek,
            new Uint8Array(Buffer.from(o.acmeAccountJson, "utf8")),
            AAD_CERT_ACME_ACCOUNT(secret.id),
          );

    // Certificate row, the ACTIVE transition and the cert.issue audit row
    // commit together (NM3) — the row is unconditional, `acme` only records
    // which path produced it. The base secret row committed in the manager's
    // own transaction above — a crash between the two leaves a visibly
    // incomplete PENDING secret with no certificate row, not a completed-but-
    // unaudited import. The ACME account, when the issuance carries one, is
    // encrypted and inserted in this same transaction (E86b) — a certificate
    // can no longer commit without the account that renews it.
    s.store.transaction(() => {
      s.store.insertCertificate({
        secret_id: secret.id,
        subject,
        issuer,
        serial_number: serial,
        not_before: notBefore,
        not_after: notAfter,
        private_key_encrypted: keyEnc.ciphertext,
        private_key_iv: keyEnc.iv,
        private_key_tag: keyEnc.tag,
        certificate_pem: o.certificatePem ?? null,
        chain_pem: o.chainPem ?? null,
        csr_pem: o.csrPem ?? null,
        auto_renew: o.autoRenew ?? false,
        renew_before_days: o.renewBeforeDays ?? 30,
        acme_account_encrypted: accountEnc?.ciphertext ?? null,
        acme_account_iv: accountEnc?.iv ?? null,
        acme_account_tag: accountEnc?.tag ?? null,
      });
      if (o.certificatePem) {
        s.store.updateSecret(secret.id, { status: SecretStatus.ACTIVE, updated_at: Date.now() });
      }
      s.auditLogger.log({
        eventType: AuditEventType.CERT_ISSUE,
        secretId: secret.id,
        ...callerColumns(caller),
        detail: {
          handle,
          action: "import_certificate",
          subject,
          not_after: notAfter,
          acme: o.acmeIssued === true,
          acme_account: accountEnc !== null,
          ...callerInterfaceDetail(caller),
        },
        sessionId: this.sessionId ?? undefined,
      });
    });

    return { handle, secretId: secret.id };
  }

  /**
   * Attach a newly issued certificate to a secret that already holds the
   * matching private key — the completion half of both flows: a CSR-pending
   * import receiving its first leaf, and a renewal replacing an existing one.
   * The key never moves and is never re-supplied: the new leaf is verified
   * against the stored key before anything is written, so a certificate issued
   * for someone else's key cannot land on this row. The secret's `expires_at`
   * follows the new `not_after`, keeping renewed certificates inside the
   * ordinary expiry machinery.
   *
   * A revoked secret is not revivable — renewal completion must not resurrect
   * a credential an administrator retired.
   *
   * Gated like its OAuth counterpart `refreshOAuthToken`: replacing the
   * material a secret presents is a `rotate`-class change, refused before the
   * stored key is touched. The internal key read stays caller-less on purpose
   * — the engine reads it to verify the pair, the caller never sees it. Every
   * refusal below the gate is audited as a failed row of the same event, so a
   * rejected renewal is as visible as an accepted one.
   *
   * `opts.handle` is the string the interface resolved the id from — it lets a
   * concealed refusal read exactly like an unknown handle (R5); absent, the
   * refusal reads "Secret not found".
   */
  async updateCertificate(
    secretId: string,
    certificatePem: string,
    chainPem?: string,
    opts?: { renewed?: boolean; handle?: string },
    caller?: CallerContext,
  ): Promise<void> {
    const s = this.assertUnlocked();
    const eventType =
      opts?.renewed === true ? AuditEventType.CERT_RENEW : AuditEventType.CERT_ISSUE;
    this.checkResolvedCallerPolicy(
      s,
      secretId,
      caller,
      "rotate",
      eventType,
      { action: "update_certificate" },
      opts?.handle,
    );

    try {
      await this.doUpdateCertificate(s, secretId, certificatePem, eventType, chainPem, caller);
    } catch (err) {
      this.auditDenied(s, eventType, err, { action: "update_certificate" }, secretId, caller);
      throw err;
    }
  }

  private async doUpdateCertificate(
    s: UnlockedState,
    secretId: string,
    certificatePem: string,
    eventType: AuditEventType,
    chainPem?: string,
    caller?: CallerContext,
  ): Promise<void> {
    const row = s.store.getCertificate(secretId);
    if (!row) throw VaultError.certNotConfigured();

    const secret = s.store.getSecret(secretId);
    if (!secret) throw VaultError.secretNotFound();
    if (secret.status === SecretStatus.REVOKED) throw VaultError.secretRevoked();

    let cert: X509Certificate;
    try {
      cert = new X509Certificate(certificatePem);
    } catch {
      throw VaultError.certInvalid("certificate PEM is not parseable");
    }

    const keyPem = await this.getCertificatePrivateKey(secretId);
    if (!cert.checkPrivateKey(createPrivateKey(keyPem))) {
      throw VaultError.certPrivateKeyMismatch();
    }
    const notAfter = new Date(cert.validTo).getTime();

    // Certificate row, secret expiry/status and the audit row commit together
    // (NM3): a crash between them would leave a secret claiming a validity
    // window its stored certificate does not have. The CSR is kept — renewal
    // reuses it.
    s.store.transaction(() => {
      s.store.updateCertificate(secretId, {
        subject: cert.subject,
        issuer: cert.issuer,
        serial_number: cert.serialNumber,
        not_before: new Date(cert.validFrom).getTime(),
        not_after: notAfter,
        certificate_pem: certificatePem,
        chain_pem: chainPem ?? row.chain_pem,
      });
      s.store.updateSecret(secretId, {
        status: SecretStatus.ACTIVE,
        expires_at: notAfter,
        updated_at: Date.now(),
      });
      s.auditLogger.log({
        eventType,
        secretId,
        ...callerColumns(caller),
        detail: {
          action: "update_certificate",
          subject: cert.subject,
          not_after: notAfter,
          ...callerInterfaceDetail(caller),
        },
        sessionId: this.sessionId ?? undefined,
        success: true,
      });
    });
  }

  /**
   * Certificate metadata for health checks and UI. The renewal state is derived
   * from the stored validity window against the per-certificate
   * `renew_before_days`, so a status read never touches the private key — the
   * `secret.read` gate still applies, because subject/issuer/validity are the
   * metadata a policy-gated caller is being gated on.
   *
   * `handle` is the string the interface resolved the id from — it lets a
   * concealed refusal read exactly like an unknown handle (R5); absent, the
   * refusal reads "Secret not found".
   */
  getCertificateStatus(
    secretId: string,
    caller?: CallerContext,
    handle?: string,
  ): CertificateStatus {
    const s = this.assertUnlocked();
    this.checkResolvedCallerPolicy(
      s,
      secretId,
      caller,
      "read",
      AuditEventType.SECRET_READ,
      { config: "certificate_status" },
      handle,
    );

    const row = s.store.getCertificate(secretId);
    if (!row) throw VaultError.certNotConfigured();

    const status: CertificateStatus = {
      secret_id: secretId,
      subject: row.subject,
      issuer: row.issuer,
      not_before: row.not_before,
      not_after: row.not_after,
      auto_renew: row.auto_renew,
      renewal_status: computeCertificateRenewalStatus(row),
    };
    this.auditConfigRead(s, secretId, caller, { config: "certificate_status" });
    return status;
  }

  /**
   * The certificate's public material, stored verbatim: leaf, chain and the
   * pending CSR. A granted read is audited like every other configuration
   * read (E75a, 2026-09-02) — the material is public, the fact that a
   * principal read it is not; the private key is `getCertificatePrivateKey`.
   * The `read` gate applies: policy enforcement lives in the engine (V1), so a
   * gated secret cannot have its material read out by an interface that
   * happens to reach this method, and the refusal is audited like every other.
   *
   * `handle` is the string the interface resolved the id from — it lets a
   * concealed refusal read exactly like an unknown handle (R5); absent, the
   * refusal reads "Secret not found".
   */
  getCertificatePem(
    secretId: string,
    caller?: CallerContext,
    handle?: string,
  ): {
    certificatePem: string | null;
    chainPem: string | null;
    csrPem: string | null;
  } {
    const s = this.assertUnlocked();
    this.checkResolvedCallerPolicy(
      s,
      secretId,
      caller,
      "read",
      AuditEventType.SECRET_READ,
      { config: "certificate_pem" },
      handle,
    );

    const row = s.store.getCertificate(secretId);
    if (!row) throw VaultError.certNotConfigured();
    const pems = {
      certificatePem: row.certificate_pem,
      chainPem: row.chain_pem,
      csrPem: row.csr_pem,
    };
    this.auditConfigRead(s, secretId, caller, { config: "certificate_pem" });
    return pems;
  }

  /**
   * The decrypted certificate private key — the legitimate read path for key
   * material a certificate secret keeps out of the generic value accessors
   * (`CERT_VALUE_UNSUPPORTED`). NEVER return this to the LLM. Every successful
   * read writes its own `secret.read` row: `checkResolvedCallerPolicy` audits
   * denials only, so without this the granted reads of the most sensitive
   * field in the vault would be the ones missing from the trail (V2).
   *
   * `handle` is the string the interface resolved the id from — it lets a
   * concealed refusal read exactly like an unknown handle (R5); absent, the
   * refusal reads "Secret not found".
   */
  async getCertificatePrivateKey(
    secretId: string,
    caller?: CallerContext,
    handle?: string,
  ): Promise<string> {
    const s = this.assertUnlocked();
    this.checkResolvedCallerPolicy(
      s,
      secretId,
      caller,
      "read",
      AuditEventType.SECRET_READ,
      { config: "certificate_private_key" },
      handle,
    );

    const row = s.store.getCertificate(secretId);
    if (!row) throw VaultError.certNotConfigured();

    const pem = decrypt(
      s.kek,
      row.private_key_encrypted,
      row.private_key_iv,
      row.private_key_tag,
      AAD_CERT_PRIVATE_KEY(secretId),
    );

    s.auditLogger.log({
      eventType: AuditEventType.SECRET_READ,
      secretId,
      ...callerColumns(caller),
      detail: { config: "certificate_private_key", ...callerInterfaceDetail(caller) },
      sessionId: this.sessionId ?? undefined,
      success: true,
    });

    return Buffer.from(pem).toString("utf8");
  }

  /**
   * Certificates whose `not_after` falls inside the window — the renewal
   * scheduler's input, mirroring `getExpiringOAuthTokens`. Rows without a
   * certificate (CSR-only) and non-active secrets are excluded by the store.
   *
   * Rows carry encrypted private-key/ACME columns — in-process use only;
   * project to metadata before any REST/MCP serialization (Phase 10 obligation).
   */
  getExpiringCertificates(withinDays: number): CertificateRow[] {
    const s = this.assertUnlocked();
    return s.store.getExpiringCertificates(withinDays);
  }

  /**
   * Metadata-only projection of the certificates inside their renewal window
   * (D5) — the certificate counterpart of `getExpiringOAuthTokenStatuses`, and
   * policy-filtered the same silent way.
   *
   * There is no window argument: the query casts the scheduler's wide net and
   * each row is then judged against its own `renew_before_days`, so a census
   * cannot report a certificate as expiring under a window its owner never set.
   */
  getExpiringCertificateStatuses(caller?: CallerContext): ExpiringCertificateInfo[] {
    const s = this.assertUnlocked();
    const now = Date.now();
    // Per-row window first: it needs no metadata, and building the join costs a
    // KEK decrypt of every secret name in the vault (see
    // `getExpiringOAuthTokenStatuses`). The wide net routinely returns rows that
    // this filter then drops, so the zero-survivor case is not just the empty
    // vault.
    const rows = s.store
      .getExpiringCertificates(EXPIRING_CERT_QUERY_DAYS)
      .filter(
        (row) => row.not_after !== null && row.not_after <= now + row.renew_before_days * DAY_MS,
      );
    if (rows.length === 0) return [];

    const infoById = this.secretInfoById(s, caller);
    const out: ExpiringCertificateInfo[] = [];
    for (const row of rows) {
      const info = infoById.get(row.secret_id);
      if (!info) continue;
      out.push({
        handle: info.handle,
        name: info.name,
        project: info.project,
        subject: row.subject,
        not_after: row.not_after,
        auto_renew: row.auto_renew,
        renew_before_days: row.renew_before_days,
        renewal_status: computeCertificateRenewalStatus(row),
      });
    }
    return out;
  }

  /**
   * The stored ACME account, or null when the certificate was never
   * ACME-issued. The blob carries the account's private key, so it reads under
   * the same `read` gate and writes the same explicit `secret.read` row as
   * `getCertificatePrivateKey` (V2) — the absent-account case decrypts nothing
   * and therefore records nothing.
   *
   * `handle` is the string the interface resolved the id from — it lets a
   * concealed refusal read exactly like an unknown handle (R5); absent, the
   * refusal reads "Secret not found".
   */
  getAcmeAccount(secretId: string, caller?: CallerContext, handle?: string): string | null {
    const s = this.assertUnlocked();
    this.checkResolvedCallerPolicy(
      s,
      secretId,
      caller,
      "read",
      AuditEventType.SECRET_READ,
      { config: "acme_account" },
      handle,
    );

    const row = s.store.getCertificate(secretId);
    if (!row) throw VaultError.certNotConfigured();
    if (!row.acme_account_encrypted || !row.acme_account_iv || !row.acme_account_tag) return null;

    const dec = decrypt(
      s.kek,
      row.acme_account_encrypted,
      row.acme_account_iv,
      row.acme_account_tag,
      AAD_CERT_ACME_ACCOUNT(secretId),
    );

    s.auditLogger.log({
      eventType: AuditEventType.SECRET_READ,
      secretId,
      ...callerColumns(caller),
      detail: { config: "acme_account", ...callerInterfaceDetail(caller) },
      sessionId: this.sessionId ?? undefined,
      success: true,
    });

    return Buffer.from(dec).toString("utf8");
  }

  // ---------------------------------------------------------------------------
  // Agents
  // ---------------------------------------------------------------------------

  /**
   * Governance is vault-wide by definition (R11/N12, 2026-09-04): a token
   * carrying a `project` claim administers nothing here. The trusted path
   * passes no caller and is exempt; the refusal writes no row, like every
   * interface scope refusal. R7's admin_scope does not waive it.
   */
  private assertUnscopedGovernanceCaller(caller: CallerContext | undefined): void {
    if (caller?.project !== undefined) {
      throw VaultError.accessDenied("governance requires an unscoped admin token");
    }
  }

  /**
   * Register an agent — the named identity a token may later be issued to
   * (design §5.1). Governance operations have no per-secret referent, so the
   * `admin` check lives at the interface (REST route / CLI token path); the
   * engine adds the one vault-wide rule — a project-claimed caller is refused
   * (N12) — and otherwise treats the `caller` as audit attribution only
   * (§5.6): NULL principal columns mark the trusted local path.
   */
  registerAgent(input: RegisterAgentInput, caller?: CallerContext): Agent {
    const s = this.assertUnlocked();
    this.assertUnscopedGovernanceCaller(caller);
    return s.store.transaction(() => {
      const row = s.agentRegistry.register(input);

      s.auditLogger.log({
        eventType: AuditEventType.AGENT_REGISTER,
        ...callerColumns(caller),
        detail: {
          name: row.name,
          ...(row.owner !== null ? { owner: row.owner } : {}),
          ...callerInterfaceDetail(caller),
        },
        sessionId: this.sessionId ?? undefined,
      });

      return s.agentRegistry.toAgent(row);
    });
  }

  /** Governance read: unaudited on success (design §5.6); the caller is consulted only for the unscoped-token rule (N12). */
  getAgent(name: string, caller?: CallerContext): Agent {
    const s = this.assertUnlocked();
    this.assertUnscopedGovernanceCaller(caller);
    return s.agentRegistry.toAgent(s.agentRegistry.getByName(name));
  }

  /** Governance read: unaudited on success (design §5.6); the caller is consulted only for the unscoped-token rule (N12). */
  listAgents(status: AgentStatus | "all" = AgentStatus.ACTIVE, caller?: CallerContext): Agent[] {
    const s = this.assertUnlocked();
    this.assertUnscopedGovernanceCaller(caller);
    const now = Date.now();
    return s.agentRegistry.list(status).map((row) => s.agentRegistry.toAgent(row, now));
  }

  /**
   * Replace an agent's two metadata fields — an omitted field is cleared. The
   * audited `fields` are the ones the request carried; their complement is what
   * the replace cleared.
   */
  updateAgent(name: string, input: UpdateAgentInput, caller?: CallerContext): Agent {
    const s = this.assertUnlocked();
    this.assertUnscopedGovernanceCaller(caller);
    const fields = (["description", "owner"] as const).filter(
      (field) => input[field] !== undefined,
    );

    return s.store.transaction(() => {
      const row = s.agentRegistry.updateMetadata(name, input);

      s.auditLogger.log({
        eventType: AuditEventType.AGENT_UPDATE,
        ...callerColumns(caller),
        detail: { name: row.name, fields, ...callerInterfaceDetail(caller) },
        sessionId: this.sessionId ?? undefined,
      });

      return s.agentRegistry.toAgent(row);
    });
  }

  /** Reactivate a deactivated agent. Status only: tokens revoked on the way out stay revoked. */
  activateAgent(name: string, caller?: CallerContext): Agent {
    const s = this.assertUnlocked();
    this.assertUnscopedGovernanceCaller(caller);
    return s.store.transaction(() => {
      const row = s.agentRegistry.setStatus(name, AgentStatus.ACTIVE);

      s.auditLogger.log({
        eventType: AuditEventType.AGENT_ACTIVATE,
        ...callerColumns(caller),
        detail: { name: row.name, ...callerInterfaceDetail(caller) },
        sessionId: this.sessionId ?? undefined,
      });

      return s.agentRegistry.toAgent(row);
    });
  }

  /**
   * Deactivate an agent and revoke every token it still holds, in one
   * transaction: a deactivation that left live tokens behind would be
   * governance theatre. Grants are kept — reactivation restores the agent's
   * standing, and the tokens are the part that cannot be un-issued.
   * Idempotent on an already-inactive agent: 0 tokens, still audited, and the
   * status write is skipped so a repeat call cannot re-stamp `deactivated_at`.
   */
  deactivateAgent(name: string, caller?: CallerContext): { revoked_tokens: number } {
    const s = this.assertUnlocked();
    this.assertUnscopedGovernanceCaller(caller);
    return s.store.transaction(() => {
      const existing = s.agentRegistry.getByName(name);
      const row =
        existing.status === AgentStatus.INACTIVE
          ? existing
          : s.agentRegistry.setStatus(name, AgentStatus.INACTIVE);
      const revokedTokens = this.revokeLiveTokensForAgent(s, row.id, "agent_deactivated", caller);

      s.auditLogger.log({
        eventType: AuditEventType.AGENT_DEACTIVATE,
        ...callerColumns(caller),
        detail: { name: row.name, revoked_tokens: revokedTokens, ...callerInterfaceDetail(caller) },
        sessionId: this.sessionId ?? undefined,
      });

      return { revoked_tokens: revokedTokens };
    });
  }

  /**
   * Delete an agent: revoke its live tokens, remove every grant it holds and
   * drop the registry row — one transaction, so a partial deletion cannot
   * leave a nameless identity holding permissions. The issued-token rows
   * survive with a NULL `agent_id` (FK ON DELETE SET NULL): the token history
   * is the audit trail's to keep, not the agent's.
   */
  deleteAgent(
    name: string,
    caller?: CallerContext,
  ): { revoked_tokens: number; removed_grants: number } {
    const s = this.assertUnlocked();
    this.assertUnscopedGovernanceCaller(caller);
    return s.store.transaction(() => {
      const row = s.agentRegistry.getByName(name);
      const revokedTokens = this.revokeLiveTokensForAgent(s, row.id, "agent_deleted", caller);

      const removed = s.store.deletePoliciesForPrincipal("agent", row.name);
      for (const policy of removed) {
        s.auditLogger.log({
          eventType: AuditEventType.POLICY_REVOKE,
          secretId: policy.secret_id,
          ...callerColumns(caller),
          detail: {
            policy_id: policy.id,
            reason: "agent_deleted",
            ...callerInterfaceDetail(caller),
          },
          sessionId: this.sessionId ?? undefined,
        });
      }

      s.agentRegistry.delete(row.name);

      s.auditLogger.log({
        eventType: AuditEventType.AGENT_DELETE,
        ...callerColumns(caller),
        detail: {
          name: row.name,
          revoked_tokens: revokedTokens,
          removed_grants: removed.length,
          ...callerInterfaceDetail(caller),
        },
        sessionId: this.sessionId ?? undefined,
      });

      return { revoked_tokens: revokedTokens, removed_grants: removed.length };
    });
  }

  /**
   * Revoke every live token of one agent, mirroring the revocation onto its
   * issued-token row. Run inside the agent-lifecycle transactions, so the
   * revocations commit with the status change that caused them. `revoked_tokens`
   * stays the revocation truth `verifyToken` consults — each entry carries its
   * token's own registry expiry (R9/C33-A), which outlives the token by
   * construction.
   */
  private revokeLiveTokensForAgent(
    s: UnlockedState,
    agentId: string,
    reason: "agent_deactivated" | "agent_deleted",
    caller?: CallerContext,
  ): number {
    const now = Date.now();
    const live = s.store.listLiveTokensForAgent(agentId, now);

    for (const { jti, expires_at } of live) {
      s.store.insertRevokedToken(jti, expires_at);
      s.store.markIssuedTokenRevoked(jti, now);

      s.auditLogger.log({
        eventType: AuditEventType.TOKEN_REVOKE,
        ...callerColumns(caller),
        detail: { jti, reason, ...callerInterfaceDetail(caller) },
        sessionId: this.sessionId ?? undefined,
      });
    }

    return live.length;
  }

  // ---------------------------------------------------------------------------
  // Policies
  // ---------------------------------------------------------------------------

  /**
   * Grant a per-secret access policy. Administrative operation: a
   * token-derived caller needs an `admin` grant on the secret — the first row
   * included (R1, 2026-09-01), which is why the first grant on every secret
   * comes from the trusted local path (CLI, in-process SDK) or an admin-scoped
   * user-type token; otherwise a principal denied every other permission could
   * grant itself one.
   *
   * `create` is refused: a policy row is keyed by an existing secret, so the
   * permission to *add* secrets has no per-secret referent and is enforced
   * where it is decidable — the token's own scope at the interface layer.
   *
   * An `agent` principal must be registered and active (v1.4 §5.2): the
   * registry is the identity authority, so a grant cannot name an identity the
   * vault does not know. `tool`, `user` and `project` principals are unaffected.
   */
  grantPolicy(
    input: Omit<GrantPolicyInput, "createdBy">,
    createdBy: string,
    caller?: CallerContext,
  ): AccessPolicy {
    if (input.permissions.includes("create" as Permission)) {
      throw VaultError.invalidInput(CREATE_NOT_GRANTABLE_MESSAGE);
    }
    const s = this.assertUnlocked();
    if (input.principalType === "agent") s.agentRegistry.assertActive(input.principalId);
    this.checkResolvedCallerPolicy(
      s,
      input.secretId,
      caller,
      "admin",
      AuditEventType.POLICY_GRANT,
      { policy: "access", principal: `${input.principalType}:${input.principalId}` },
      undefined,
    );
    return s.store.transaction(() => {
      const policy = s.policyEngine.grantPolicy({ ...input, createdBy });

      s.auditLogger.log({
        eventType: AuditEventType.POLICY_GRANT,
        secretId: input.secretId,
        ...callerColumns(caller),
        detail: {
          policy_id: policy.id,
          principal: `${input.principalType}:${input.principalId}`,
          ...callerInterfaceDetail(caller),
        },
        sessionId: this.sessionId ?? undefined,
      });

      return policy;
    });
  }

  /**
   * `expectedSecretId` is the secret the interface resolved from its own path
   * — a policy belonging to any other secret refuses exactly like an unknown
   * id, so the cross-secret IDOR guard needs no caller-less membership read.
   */
  revokePolicy(policyId: string, caller?: CallerContext, expectedSecretId?: string): void {
    const s = this.assertUnlocked();
    // Resolved up front for the caller check; the lookup also lets the audit
    // row name the secret the revoked grant belonged to.
    const existing = s.store.getPolicy(policyId);
    if (!existing) {
      throw new VaultError(ErrorCode.POLICY_NOT_FOUND, `Policy not found: ${policyId}`);
    }
    if (expectedSecretId !== undefined && existing.secret_id !== expectedSecretId) {
      throw new VaultError(ErrorCode.POLICY_NOT_FOUND, `Policy not found: ${policyId}`);
    }
    this.checkResolvedCallerPolicy(
      s,
      existing.secret_id,
      caller,
      "admin",
      AuditEventType.POLICY_REVOKE,
      { policy: "access", policy_id: policyId },
      undefined,
    );
    s.store.transaction(() => {
      s.policyEngine.revokePolicy(policyId);

      s.auditLogger.log({
        eventType: AuditEventType.POLICY_REVOKE,
        secretId: existing.secret_id,
        ...callerColumns(caller),
        detail: { policy_id: policyId, ...callerInterfaceDetail(caller) },
        sessionId: this.sessionId ?? undefined,
      });
    });
  }

  /**
   * `handle` is the string the interface resolved the id from — it lets a
   * concealed refusal read exactly like an unknown handle (R5); absent, the
   * refusal reads "Secret not found".
   */
  listPolicies(secretId?: string, caller?: CallerContext, handle?: string): AccessPolicy[] {
    const s = this.assertUnlocked();
    // A token-derived caller must name the secret it is asking about: the
    // vault-wide listing cannot be checked against a single secret's policies.
    if (caller && !secretId) {
      throw VaultError.invalidInput("A secret id is required to list access policies");
    }
    if (secretId) {
      this.checkResolvedCallerPolicy(
        s,
        secretId,
        caller,
        "read",
        AuditEventType.SECRET_READ,
        { config: "access_policies" },
        handle,
      );
    }
    const policies = s.policyEngine.listPolicies(secretId);
    if (secretId) this.auditConfigRead(s, secretId, caller, { config: "access_policies" });
    return policies;
  }

  /**
   * Write one cell of the permission matrix — replace semantics for the
   * (agent, secret) pair (design §5.3). The existing grant/revoke pair is two
   * calls against a schema that permits duplicate rows, so a matrix edit built
   * from them can leave a cell holding two grants or none; this removes every
   * row the agent holds on the secret and writes at most one back, in a single
   * transaction with its audit rows.
   *
   * Empty `permissions` clears the cell. `gated_before`/`gated_after` report
   * whether any principal held an active row on the secret before and after the write,
   * both read inside the transaction — under R1 (2026-09-01) they describe the
   * matrix, not an enforcement mode: a secret with no cells is reachable by no
   * agent- or tool-type token. `create` is refused exactly as in
   * {@link grantPolicy} — same reason, same message — and the per-secret
   * `admin` check runs for a token-derived caller before anything is written.
   */
  setAgentPermissions(
    agentName: string,
    secretId: string,
    permissions: Permission[],
    expiresAt: number | undefined,
    createdBy: string,
    caller?: CallerContext,
  ): SetAgentPermissionsResult {
    if (permissions.includes("create" as Permission)) {
      throw VaultError.invalidInput(CREATE_NOT_GRANTABLE_MESSAGE);
    }
    const s = this.assertUnlocked();
    this.assertUnscopedGovernanceCaller(caller);
    s.agentRegistry.assertActive(agentName);
    this.checkResolvedCallerPolicy(
      s,
      secretId,
      caller,
      "admin",
      AuditEventType.POLICY_GRANT,
      { policy: "access", principal: `agent:${agentName}`, via: "matrix" },
      undefined,
    );

    return s.store.transaction(() => {
      const gatedBefore = s.policyEngine.hasActivePolicies(secretId);

      const removed = s.store.deletePoliciesForPrincipalOnSecret(secretId, "agent", agentName);
      for (const row of removed) {
        s.auditLogger.log({
          eventType: AuditEventType.POLICY_REVOKE,
          secretId,
          ...callerColumns(caller),
          detail: { policy_id: row.id, replaced: true, ...callerInterfaceDetail(caller) },
          sessionId: this.sessionId ?? undefined,
        });
      }

      let policy: AccessPolicy | null = null;
      if (permissions.length > 0) {
        policy = s.policyEngine.grantPolicy({
          secretId,
          principalType: "agent",
          principalId: agentName,
          permissions,
          expiresAt,
          createdBy,
        });

        s.auditLogger.log({
          eventType: AuditEventType.POLICY_GRANT,
          secretId,
          ...callerColumns(caller),
          detail: {
            policy_id: policy.id,
            principal: `agent:${agentName}`,
            ...callerInterfaceDetail(caller),
          },
          sessionId: this.sessionId ?? undefined,
        });
      }

      return {
        policy,
        gated_before: gatedBefore,
        gated_after: s.policyEngine.hasActivePolicies(secretId),
      };
    });
  }

  /**
   * The agent's row of the matrix: its non-expired grants with the secret
   * handle resolved. Governance read — unaudited on success (design §5.6) and
   * the caller is consulted only for the unscoped-token rule (N12).
   * Registration is checked with `getByName`, not `assertActive`: deactivation
   * keeps an agent's grants (see {@link deactivateAgent}), so hiding them would
   * misreport what a reactivation would restore. A grant whose secret no longer
   * resolves is skipped rather than reported handle-less.
   */
  listAgentPolicies(agentName: string, caller?: CallerContext): AgentPolicy[] {
    const s = this.assertUnlocked();
    this.assertUnscopedGovernanceCaller(caller);
    const name = s.agentRegistry.getByName(agentName).name;
    const now = Date.now();

    const handles = new Map(
      s.secretManager.listSecretsWithIds().map((entry) => [entry.id, entry.info.handle]),
    );

    const listed: AgentPolicy[] = [];
    for (const policy of s.store.listPoliciesByPrincipal("agent", name)) {
      if (policy.expires_at !== null && policy.expires_at <= now) continue;
      const handle = handles.get(policy.secret_id);
      if (handle === undefined) continue;

      listed.push({
        policy_id: policy.id,
        secret_id: policy.secret_id,
        handle,
        permissions: policy.permissions,
        expires_at: policy.expires_at,
        created_at: policy.created_at,
      });
    }

    return listed;
  }

  // ---------------------------------------------------------------------------
  // Audit
  // ---------------------------------------------------------------------------

  /**
   * Query the audit log. `scope` carries the requesting token's non-permission
   * scope dimensions (project, secret-name patterns): rows about a secret the
   * token may not address are dropped, so a project- or name-scoped admin token
   * can no longer read every secret's audit detail — nor use `secret_id` as a
   * targeted oracle (L10). Rows without a `secret_id` (vault lifecycle, token
   * issuance, server start) carry no per-secret metadata and stay visible.
   *
   * The visibility filter is applied inside the query, ahead of `limit`, so a
   * scoped token gets up to `limit` rows it may see. An absent scope is the
   * unrestricted case: no filtering work is done at all.
   */
  queryAudit(options?: AuditQueryOptions, scope?: AuditVisibilityScope): DecryptedAuditEvent[] {
    const s = this.assertUnlocked();
    if (!scope || (scope.project === undefined && !scope.secrets?.length)) {
      return s.auditQuery.query(options);
    }

    const visible = s.secretManager
      .listSecretsWithIds()
      .filter(
        (entry) =>
          (scope.project === undefined || entry.info.project === scope.project) &&
          matchesSecretNameScope(entry.info.name, scope.secrets),
      )
      .map((entry) => entry.id);

    return s.auditQuery.query({ ...options, visibleSecretIds: visible });
  }

  /**
   * Record a server start in the tamper-evident trail — one row per process
   * or listener start on every transport (R4/B22, 2026-09-02; review finding
   * W6 introduced the row for the tokenless waiver alone). The stdio MCP
   * server writes it before its guard and server are constructed: the waiver
   * (`tokenless: true`), the token-bearing start (`tokenless: false` plus the
   * launch token's `subject`) and the refused start (`success: false` with
   * the refusal code). The MCP Streamable HTTP and REST listeners write it
   * once per listener with the bound `port` and `host`, never per session.
   *
   * Deliberately unattributed (NULL principal columns, `vault.unlock` shape):
   * a server start is a process-level event, not a requesting principal's
   * operation — the subject rides in the detail. No state mutation
   * accompanies it, so no outer transaction is needed — chain linearity is
   * handled inside the logger.
   *
   * Fail-closed by omission: this method does not swallow write failures, so a
   * caller that cannot record the start must not proceed to serve. On the
   * refusal branch that means an audit-write failure replaces `TOKEN_REQUIRED`
   * as the thrown error — both outcomes refuse the start (D5).
   */
  auditServerStart(options: {
    transport: ServerTransport;
    tokenless: boolean;
    ttyPrompt?: boolean;
    subject?: string;
    port?: number;
    host?: string;
    success?: false;
    error?: ErrorCode;
  }): void {
    const s = this.assertUnlocked();
    s.auditLogger.log({
      eventType: AuditEventType.SERVER_START,
      detail: {
        transport: options.transport,
        tokenless: options.tokenless,
        tty_prompt: options.ttyPrompt ?? false,
        ...(options.subject !== undefined ? { subject: options.subject } : {}),
        ...(options.port !== undefined ? { port: options.port } : {}),
        ...(options.host !== undefined ? { host: options.host } : {}),
        ...(options.error ? { error: options.error } : {}),
      },
      success: options.success ?? true,
      sessionId: this.sessionId ?? undefined,
    });
  }

  /**
   * The graceful counterpart of `auditServerStart` (R4/D67, 2026-09-02): one
   * row per started listener, written by the process's shutdown path before
   * `destroy()`. Unattributed like the start. Throws on a sealed vault exactly
   * as the start does — the caller decides that a stop it cannot record must
   * not block the shutdown (the CLI and `harpoc-mcp` wrap it in a try/catch);
   * a crash or SIGKILL leaves a start without a stop, and that is the record.
   */
  auditServerStop(options: {
    transport: ServerTransport;
    tokenless: boolean;
    port?: number;
    uptimeMs: number;
    trigger: ServerStopTrigger;
  }): void {
    const s = this.assertUnlocked();
    s.auditLogger.log({
      eventType: AuditEventType.SERVER_STOP,
      detail: {
        transport: options.transport,
        tokenless: options.tokenless,
        ...(options.port !== undefined ? { port: options.port } : {}),
        uptime_ms: options.uptimeMs,
        trigger: options.trigger,
      },
      sessionId: this.sessionId ?? undefined,
    });
  }

  /**
   * Record a scheduled renewal that failed after its retries — the daemon's
   * one path with no engine write of its own (N5). NULL principal: the
   * scheduler is the trusted local path, like `auditServerStart`. Throws on
   * a sealed engine; the scheduler swallows that (the audit write must not
   * halt the loop).
   */
  auditCertRenewFailure(secretId: string, error: unknown): void {
    const s = this.assertUnlocked();
    s.auditLogger.log({
      eventType: AuditEventType.CERT_RENEW,
      secretId,
      detail: {
        action: "scheduled_renewal",
        error: error instanceof VaultError ? error.code : ErrorCode.INTERNAL_ERROR,
      },
      success: false,
      sessionId: this.sessionId ?? undefined,
    });
  }

  /**
   * The current audit-chain tail as an exportable anchor, or null when the log
   * is empty or its newest row carries no link. The anchor contains nothing
   * sensitive — its value against tail truncation and rollback comes entirely
   * from the operator storing it OFF-HOST (the vault cannot supply that trust
   * domain itself).
   */
  getAuditChainTail(): AuditChainAnchor | null {
    const s = this.assertUnlocked();
    const tail = s.auditQuery.chainTail();
    if (!tail) return null;
    return {
      format: AUDIT_CHAIN_ANCHOR_FORMAT,
      vault_id: s.vaultId,
      last_id: tail.lastId,
      timestamp: tail.timestamp,
      row_hmac: Buffer.from(tail.rowHmac).toString("hex"),
    };
  }

  /**
   * Verify the tamper-evidence HMAC chain over the audit log. With an anchor,
   * additionally assert the anchored row still exists with exactly that link —
   * detecting tail truncation and rollback, which the chain alone cannot see.
   * The result always carries the current tail for comparison/re-anchoring.
   */
  verifyAuditChain(options?: { anchor?: AuditChainAnchor }): AuditChainVerificationReport {
    const s = this.assertUnlocked();
    const anchor = options?.anchor;
    if (anchor && anchor.vault_id !== s.vaultId) {
      throw new VaultError(
        ErrorCode.INVALID_INPUT,
        `Anchor was taken from a different vault (anchor ${anchor.vault_id}, this vault ${s.vaultId})`,
      );
    }
    const verification = s.auditQuery.verifyChain(
      anchor
        ? { lastId: anchor.last_id, rowHmac: new Uint8Array(Buffer.from(anchor.row_hmac, "hex")) }
        : undefined,
    );
    return { ...verification, tail: this.getAuditChainTail() };
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
   *
   * `options.principalType` sets the token's principal identity for
   * per-secret policy matching (thesis §4.6): agent, tool or user — the claim
   * is always minted (default agent). `project` is not issuable; project
   * principals derive from the token's project claim.
   *
   * An agent-typed subject must be a registered, active agent (v1.4 §5.2) —
   * the registration gate is what makes the registry authoritative rather than
   * advisory. The claims metadata of every issued token is recorded in
   * `issued_tokens` in the same transaction as its `token.create` row; the JWT
   * itself is never stored.
   */
  createToken(
    subject: string,
    scope: Permission[],
    ttlMs: number = 3600_000,
    options?: {
      project?: string;
      secrets?: string[];
      principalType?: TokenPrincipalType;
      label?: string;
    },
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

    if (
      options?.principalType !== undefined &&
      !Object.values(TokenPrincipalTypeValues).includes(options.principalType)
    ) {
      throw new VaultError(
        ErrorCode.INVALID_INPUT,
        `Invalid principal type: "${options.principalType as string}". Valid: agent, tool, user`,
      );
    }

    if (options?.label !== undefined && options.label.length > TOKEN_LABEL_MAX_LENGTH) {
      throw VaultError.invalidInput(`Token label exceeds ${TOKEN_LABEL_MAX_LENGTH} characters`);
    }

    const effectiveType = options?.principalType ?? "agent";
    const agent = effectiveType === "agent" ? s.agentRegistry.assertActive(subject) : undefined;

    const effectiveTtl = Math.min(Math.max(ttlMs, 0), MAX_TOKEN_TTL_MS);
    const now = Math.floor(Date.now() / 1000);
    const payload: VaultApiToken = {
      sub: subject,
      vault_id: s.vaultId,
      scope,
      iat: now,
      exp: now + Math.floor(effectiveTtl / 1000),
      jti: generateUUIDv7(),
      principal_type: effectiveType,
    };

    if (options?.project) payload.project = options.project;
    if (options?.secrets?.length) payload.secrets = options.secrets;

    const token = this.signJwt(payload);

    s.store.transaction(() => {
      s.store.insertIssuedToken({
        jti: payload.jti,
        subject,
        principal_type: effectiveType,
        agent_id: agent ? agent.id : null,
        scope,
        // The registry row mirrors the claims the JWT actually carries: an
        // empty narrowing sets no claim, and a stored `[]` would read as
        // "restricted to nothing" for a token that is in fact unrestricted.
        project: options?.project || null,
        secrets: options?.secrets?.length ? options.secrets : null,
        label: options?.label ?? null,
        issued_at: Date.now(),
        // The JWT exp is in seconds; the registry column is milliseconds.
        expires_at: payload.exp * 1000,
        revoked_at: null,
      });

      s.auditLogger.log({
        eventType: AuditEventType.TOKEN_CREATE,
        detail: {
          subject,
          jti: payload.jti,
          scope,
          project: options?.project,
          principal_type: effectiveType,
          ...(options?.label !== undefined ? { label: options.label } : {}),
        },
        sessionId: this.sessionId ?? undefined,
      });
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
   * Whether a token JTI has been revoked.
   *
   * The stdio MCP transport verifies its launch token once, at construction —
   * there is no per-request re-verification as on the HTTP transport — so a
   * long-lived server needs a cheap way to re-consult the revocation store on
   * every call. Without it `harpoc auth revoke` could not restrain the server
   * its token launched (H7).
   */
  isTokenRevoked(jti: string): boolean {
    const s = this.assertUnlocked();
    return s.store.isTokenRevoked(jti);
  }

  /**
   * Revoke a JWT token by JTI — registry-authoritative (R9/C33-A): the
   * issued-token registry supplies the token's expiry, so the denylist entry
   * lives exactly as long as the token it names, and a jti the registry does
   * not know is refused with `INVALID_INPUT` (an input check ahead of any
   * write — unaudited, like the schema gates). `verifyToken` prunes entries
   * whose `expires_at` has passed before it consults them; `createToken`
   * stores `expires_at = exp × 1000` and a token is accepted only while
   * `exp > ⌊now / 1000⌋`, so a still-valid token's entry is never pruned. A
   * repeat revocation is idempotent; an already-expired token is accepted
   * (its mirror stamps, its entry prunes).
   *
   * `caller` is attribution only (v1.4 R6): a token-derived revocation — REST
   * `DELETE /tokens/:jti`, and the Web UI through it — names its principal on
   * the `token.revoke` row. The trusted local paths (`harpoc auth revoke`, the
   * in-process SDK) pass none and keep the NULL principal columns.
   */
  revokeToken(jti: string, caller?: CallerContext): void {
    const s = this.assertUnlocked();
    this.assertUnscopedGovernanceCaller(caller);
    const issued = s.store.getIssuedToken(jti);
    if (!issued) {
      throw VaultError.invalidInput(`Unknown token jti: ${jti}`);
    }
    s.store.transaction(() => {
      s.store.insertRevokedToken(jti, issued.expires_at);
      // History mirror; revoked_tokens stays the revocation truth verifyToken
      // consults.
      s.store.markIssuedTokenRevoked(jti, Date.now());

      s.auditLogger.log({
        eventType: AuditEventType.TOKEN_REVOKE,
        ...callerColumns(caller),
        detail: { jti, ...callerInterfaceDetail(caller) },
        sessionId: this.sessionId ?? undefined,
      });
    });
  }

  /**
   * List the claims metadata of issued tokens (v1.4 issued-token registry) —
   * never a JWT. Status is derived, not stored: a revocation stamp wins over
   * an elapsed expiry, so a token revoked before it lapsed reads `revoked`.
   *
   * Governance read: unaudited on success (design §5.6); the caller is
   * consulted only for the unscoped-token rule (N12).
   */
  listIssuedTokens(
    filter?: { agent?: string; status?: IssuedTokenStatusFilter },
    caller?: CallerContext,
  ): IssuedToken[] {
    const s = this.assertUnlocked();
    this.assertUnscopedGovernanceCaller(caller);

    const agentId =
      filter?.agent !== undefined ? s.agentRegistry.getByName(filter.agent).id : undefined;
    const status = filter?.status ?? IssuedTokenStatus.ACTIVE;
    const now = Date.now();

    return s.store
      .listIssuedTokens(agentId !== undefined ? { agentId } : undefined)
      .map((row) => ({
        jti: row.jti,
        subject: row.subject,
        principal_type: row.principal_type,
        agent: row.agent_name,
        scope: row.scope,
        project: row.project,
        secrets: row.secrets,
        label: row.label,
        issued_at: row.issued_at,
        expires_at: row.expires_at,
        revoked_at: row.revoked_at,
        status:
          row.revoked_at !== null
            ? IssuedTokenStatus.REVOKED
            : row.expires_at <= now
              ? IssuedTokenStatus.EXPIRED
              : IssuedTokenStatus.ACTIVE,
      }))
      .filter((token) => status === "all" || token.status === status);
  }

  // ---------------------------------------------------------------------------
  // Password change
  // ---------------------------------------------------------------------------

  async changePassword(oldPassword: string, newPassword: string): Promise<void> {
    this.validatePassword(newPassword);

    const s = this.assertUnlocked();

    // A wrong old password is a master-password guess — subject to the same
    // lockout as unlock() (shared counter: they are one guessing surface).
    this.checkLockout(s.store);

    const salt = this.loadBase64Meta(s.store, "kdf_salt");
    const wrappedKek = this.loadBase64Meta(s.store, "wrapped_kek");
    const wrappedKekIv = this.loadBase64Meta(s.store, "wrapped_kek_iv");
    const wrappedKekTag = this.loadBase64Meta(s.store, "wrapped_kek_tag");

    let result: Awaited<ReturnType<typeof changePassword>>;
    try {
      result = await changePassword(
        oldPassword,
        newPassword,
        salt,
        wrappedKek,
        wrappedKekIv,
        wrappedKekTag,
      );
    } catch (err) {
      // The KEK unwrap fails with ENCRYPTION_ERROR on a wrong old password —
      // map it to INVALID_PASSWORD and feed the lockout counter, as unlock does.
      if (err instanceof VaultError && err.code === ErrorCode.ENCRYPTION_ERROR) {
        this.incrementLockout(s.store);
        const invalid = VaultError.invalidPassword();
        this.auditDenied(s, AuditEventType.VAULT_PASSWORD_CHANGE, invalid, {});
        throw invalid;
      }
      throw err;
    }

    // Salt, wrapped-KEK triple, lockout reset and the audit row commit in one
    // transaction (NM3) — a crash between the salt and wrapped-KEK writes would
    // otherwise leave them from different generations, bricking master-password
    // unlock for both the old and the new password.
    s.store.transaction(() => {
      s.store.setMeta("kdf_salt", Buffer.from(result.newSalt).toString("base64"));
      s.store.setMeta("wrapped_kek", Buffer.from(result.newWrappedKek).toString("base64"));
      s.store.setMeta("wrapped_kek_iv", Buffer.from(result.newWrappedKekIv).toString("base64"));
      s.store.setMeta("wrapped_kek_tag", Buffer.from(result.newWrappedKekTag).toString("base64"));

      // Successful re-auth clears the shared lockout counter, as unlock does.
      s.store.setMeta("failed_attempts", "0");

      // JWT and audit keys are unchanged — they're wrapped with KEK, not derived from master key

      s.auditLogger.log({
        eventType: AuditEventType.VAULT_PASSWORD_CHANGE,
        sessionId: this.sessionId ?? undefined,
      });
    });

    // Write new session with updated keys
    await this.writeNewSession();
  }

  /**
   * Resolve a secret handle to its internal UUID. A failed resolution is
   * audited as a failed `secret.read { handle }` — the row `getSecretInfo`
   * writes for an unknown handle — so a probe through a route that resolves
   * before an id-addressed call leaves the trace a probe through the secrets
   * routes leaves (2026-09-02); an ambiguous handle is concealed for a
   * grantless token caller (concealHandleError).
   */
  async resolveSecretId(handle: string, caller?: CallerContext): Promise<string> {
    const s = this.assertUnlocked();
    try {
      const secret = await s.secretManager.resolveHandle(handle);
      return secret.id;
    } catch (err) {
      this.auditDenied(s, AuditEventType.SECRET_READ, err, { handle }, undefined, caller);
      throw await this.concealHandleError(s, err, handle, caller);
    }
  }

  // ---------------------------------------------------------------------------
  // Private: state management
  // ---------------------------------------------------------------------------

  /**
   * The success row of a per-secret configuration read (E75a, 2026-09-02) —
   * the row `getSecretInfo` writes, with the read's `config` kind in the
   * detail: unconditional, so the trusted local path leaves the same
   * NULL-principal trace it leaves for `harpoc secret info`. The detail is
   * the read's own denial detail minus `required_permission` and `error`.
   */
  private auditConfigRead(
    s: UnlockedState,
    secretId: string,
    caller: CallerContext | undefined,
    detail: Record<string, unknown>,
  ): void {
    s.auditLogger.log({
      eventType: AuditEventType.SECRET_READ,
      secretId,
      ...callerColumns(caller),
      detail: { ...detail, ...callerInterfaceDetail(caller) },
      sessionId: this.sessionId ?? undefined,
    });
  }

  /**
   * R5's existence rule applied to an ambiguous handle (ruled 2026-09-02): a
   * bare name that resolves to more than one secret answered AMBIGUOUS_HANDLE
   * to any caller — for a token caller holding none of read/list/admin on any
   * candidate, that 409 said "two or more secrets of this name exist" where
   * an unknown name says nothing. Such a caller now reads the byte-identical
   * SECRET_NOT_FOUND; the audit row written beside it keeps the true code.
   * Every other caller — a candidate's grant holder, an admin-scoped user
   * token, the trusted path — keeps the 409 it can act on.
   */
  private async concealHandleError(
    s: UnlockedState,
    err: unknown,
    handle: string,
    caller: CallerContext | undefined,
  ): Promise<unknown> {
    if (!(err instanceof VaultError) || err.code !== ErrorCode.AMBIGUOUS_HANDLE) return err;
    if (!caller || isAdminUserCaller(caller)) return err;
    const principals = this.callerPrincipals(caller);
    for (const candidate of await s.secretManager.findByHandle(handle)) {
      const held = s.policyEngine.grantedPermissions(candidate.id, principals);
      if (held.has("read") || held.has("list") || held.has("admin")) return err;
    }
    return VaultError.secretNotFound(handle);
  }

  /**
   * Audit a denied operation (`success: false`, error code in detail) without
   * altering the thrown error. Denied access must be as visible in the trail
   * as granted access — a scoped token probing revoked/expired secrets is
   * exactly what the audit trail exists to catch. A non-VaultError is recorded
   * as INTERNAL_ERROR — a raw failure is still a denial the trail must show.
   */
  private auditDenied(
    s: UnlockedState,
    eventType: AuditEventType,
    err: unknown,
    detail: Record<string, unknown>,
    secretId?: string,
    caller?: CallerContext,
  ): void {
    const code = err instanceof VaultError ? err.code : ErrorCode.INTERNAL_ERROR;
    s.auditLogger.log({
      eventType,
      secretId,
      ...callerColumns(caller),
      detail: { ...detail, error: code, ...callerInterfaceDetail(caller) },
      success: false,
      sessionId: this.sessionId ?? undefined,
    });
  }

  /**
   * Every secret the caller may enumerate, keyed by internal id — the join
   * table the row-shaped expiry accessors project through. Same filter as
   * `listSecrets` (W2): a secret is listed only when a grant to one of the
   * caller's principals carries `list` or `admin` (R1, 2026-09-01: a secret
   * with no rows is listed to no token caller), silent, and an absent caller
   * (trusted local path) — or an admin-scoped user-type token, exempt since R7
   * (v1.4.1) — sees everything.
   *
   * Certificate and OAuth rows are keyed by secret id and carry no handle or
   * name, so the metadata has to come from here; a missing entry means the
   * caller may not enumerate that secret and the row is dropped.
   */
  private secretInfoById(s: UnlockedState, caller?: CallerContext): Map<string, SecretInfo> {
    const entries = s.secretManager.listSecretsWithIds(undefined);
    const permitted =
      caller && !isAdminUserCaller(caller)
        ? s.policyEngine.filterPermitted(
            entries.map((entry) => entry.id),
            this.callerPrincipals(caller),
            "list",
          )
        : null;

    const map = new Map<string, SecretInfo>();
    for (const entry of entries) {
      if (!permitted || permitted.has(entry.id)) map.set(entry.id, entry.info);
    }
    return map;
  }

  /**
   * The identities a caller acts under: the token subject under its issued
   * principal type, plus the derived project principal when the token is
   * project-scoped (a grant to `(project, api)` covers every token issued
   * `--project api`). Single source for the point check and the enumeration
   * filter — two derivations of "who is this caller" would eventually let a
   * listing show what a gate denies, or the reverse.
   */
  private callerPrincipals(caller: CallerContext): PolicyPrincipal[] {
    const principals: PolicyPrincipal[] = [
      { type: caller.principal_type, id: caller.principal_id },
    ];
    if (caller.project !== undefined) {
      principals.push({ type: PrincipalType.PROJECT, id: caller.project });
    }
    return principals;
  }

  /**
   * Per-secret access-policy enforcement on an already-resolved secret
   * (thesis §4.6). Explicit-grant (R1, 2026-09-01): a token-derived caller
   * needs a matching, unexpired grant — checked against the caller's
   * principal set (the token subject under its issued principal type, plus a
   * derived project principal when the token is project-scoped; `admin`
   * implies every permission) — and a secret without policy rows is reachable
   * by no such caller. An absent caller is the trusted local path (thesis
   * §4.7) and is never checked. R7 (v1.4.1) adds one further exempt class: an
   * admin-scoped user-type token, the operator's own proxy, passes without a
   * per-secret grant — agent- and tool-type callers stay gated whatever their
   * token scope.
   * Denials are audited under the operation's event type with the requesting
   * principal before anything is decrypted, injected or mutated — always as
   * `ACCESS_DENIED` with the real secret id. What the caller is told follows
   * R5: holding none of `read`/`list`/`admin` on the secret it gets
   * `SECRET_NOT_FOUND` naming `handle`, byte-identical to the unknown-handle
   * refusal, so a right name and a wrong one are indistinguishable on the
   * wire — except on a policy-write (`admin`) check, which stays
   * `ACCESS_DENIED` so the matrix editor's `harpoc policy grant …` remedy
   * survives; a caller that may already know the secret exists (it holds
   * `read` or `list`) is told which permission it lacks.
   */
  private checkResolvedCallerPolicy(
    s: UnlockedState,
    secretId: string,
    caller: CallerContext | undefined,
    permission: Permission,
    eventType: AuditEventType,
    detail: Record<string, unknown>,
    handle: string | undefined,
  ): void {
    if (!caller) return;
    // R7 (v1.4.1): an admin-scoped user-type token is the operator's proxy —
    // exempt from per-secret rows, still bound by 3-dim token scope upstream.
    if (isAdminUserCaller(caller)) return;

    const held = s.policyEngine.grantedPermissions(secretId, this.callerPrincipals(caller));
    if (held.has("admin") || held.has(permission)) return;

    s.auditLogger.log({
      eventType,
      secretId,
      ...callerColumns(caller),
      detail: {
        ...detail,
        required_permission: permission,
        error: ErrorCode.ACCESS_DENIED,
        ...callerInterfaceDetail(caller),
      },
      success: false,
      sessionId: this.sessionId ?? undefined,
    });

    if (permission !== "admin" && !held.has("read") && !held.has("list")) {
      throw VaultError.secretNotFound(handle);
    }
    throw VaultError.accessDenied(`Principal lacks '${permission}' permission on this secret`);
  }

  /**
   * Handle-resolving wrapper around checkResolvedCallerPolicy for engine
   * methods whose secret manager call resolves internally. With no caller
   * (trusted local path) this is a no-op — no extra handle resolution,
   * byte-identical behavior; with a caller — the tokenless stdio server's
   * synthetic caller included (R4/E78b) — a resolution failure is audited as
   * the denied operation (with the requesting principal), concealed for a
   * grantless token caller when ambiguous, and rethrown.
   */
  private async enforceCallerPolicy(
    s: UnlockedState,
    handle: string,
    caller: CallerContext | undefined,
    permission: Permission,
    eventType: AuditEventType,
    detail: Record<string, unknown>,
  ): Promise<void> {
    if (!caller) return;
    let secret: Secret;
    try {
      secret = await s.secretManager.resolveHandle(handle);
    } catch (err) {
      this.auditDenied(s, eventType, err, detail, undefined, caller);
      throw await this.concealHandleError(s, err, handle, caller);
    }
    this.checkResolvedCallerPolicy(s, secret.id, caller, permission, eventType, detail, handle);
  }

  private assertUnlocked(): UnlockedState {
    // Synchronous TTL enforcement: an engine kept alive past its session
    // expiry (SDK direct mode never ran the monitor before) seals here on the
    // next authenticated operation — the monitor stays the ≤30 s backstop.
    if (
      this.state === VaultState.UNLOCKED &&
      this.sessionExpiresAt !== null &&
      Date.now() > this.sessionExpiresAt
    ) {
      this.sealExpired();
    }
    if (this.state !== VaultState.UNLOCKED) {
      throw VaultError.vaultLocked();
    }
    // Every authenticated operation passes through here — the session TTL
    // slides on use (thesis §5.4.7), not on process liveness.
    this.touchSession();
    return {
      store: this.store as SqliteStore,
      kek: this.kek as Uint8Array,
      jwtKey: this.jwtKey as Uint8Array,
      auditKey: this.auditKey as Uint8Array,
      vaultId: this.vaultId as string,
      secretManager: this.secretManager as SecretManager,
      policyEngine: this.policyEngine as PolicyEngine,
      agentRegistry: this.agentRegistry as AgentRegistry,
      auditLogger: this.auditLogger as AuditLogger,
      auditQuery: this.auditQuery as AuditQuery,
      httpInjector: this.httpInjector as HttpInjector,
      processInjector: this.processInjector as ProcessInjector,
      mcpInjector: this.mcpInjector as McpInjector,
      mcpRegistry: this.mcpRegistry as McpConnectionRegistry,
      databaseInjector: this.databaseInjector as DatabaseInjector,
      sshInjector: this.sshInjector as SshInjector,
      gitInjector: this.gitInjector as GitInjector,
      smtpInjector: this.smtpInjector as SmtpRunner,
      imapInjector: this.imapInjector as ImapRunner,
      websocketExecutor: this.websocketExecutor,
      sftpExecutor: this.sftpExecutor,
      dockerExecutor: this.dockerExecutor,
    };
  }

  private initManagers(): void {
    const store = this.store as SqliteStore;
    const kek = this.kek as Uint8Array;
    const auditKey = this.auditKey as Uint8Array;

    // The lazy-expiry hook runs on secret access, long after initManagers
    // completes — this.auditLogger (assigned below) is always set by then.
    this.secretManager = new SecretManager(store, kek, (secretId, handle) => {
      this.auditLogger?.log({
        eventType: AuditEventType.SECRET_EXPIRE,
        secretId,
        detail: { handle },
        sessionId: this.sessionId ?? undefined,
      });
      // An expired credential must not stay live in a downstream child (L2).
      // Queued rather than awaited: this hook runs inside the status-write
      // transaction (NM3), so the terminate — which writes its own audit row —
      // runs after that transaction has committed.
      queueMicrotask(() => {
        void this.mcpRegistry?.terminate(secretId, "secret_expired").catch(() => undefined);
      });
    });
    this.policyEngine = new PolicyEngine(store);
    this.agentRegistry = new AgentRegistry(store);
    this.auditLogger = new AuditLogger(store, auditKey);
    this.auditQuery = new AuditQuery(store, auditKey);
    this.httpInjector = new HttpInjector(this.auditLogger);
    this.processInjector = new ProcessInjector(this.auditLogger);
    this.mcpRegistry = new McpConnectionRegistry(this.auditLogger);
    this.mcpInjector = new McpInjector(this.auditLogger, this.mcpRegistry);
    this.databaseInjector = new DatabaseInjector(this.auditLogger);
    this.sshInjector = new SshInjector(this.auditLogger);
    this.gitInjector = new GitInjector(this.auditLogger);
    // The v1.3 mail injectors take no AuditLogger: they return a metadata-only
    // projection and the engine writes the `secret.use` row (design §7.2).
    this.smtpInjector = new SmtpInjector();
    this.imapInjector = new ImapInjector();
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
    this.oauthRefreshInFlight.clear();

    this.secretManager = null;
    this.policyEngine = null;
    this.agentRegistry = null;
    this.auditLogger = null;
    this.auditQuery = null;
    this.httpInjector = null;
    this.processInjector = null;
    this.mcpInjector = null;
    this.mcpRegistry = null;
    this.sessionId = null;
    this.vaultId = null;
    this.sessionExpiresAt = null;
  }

  // ---------------------------------------------------------------------------
  // Private: session
  // ---------------------------------------------------------------------------

  private async writeNewSession(): Promise<void> {
    // A use-driven expiry slide may be writing the session file right now
    // (e.g. changePassword's own assertUnlocked started one) — settle it so
    // the two writers cannot collide on the write-then-rename.
    await this.settleSessionSlide();

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
        this.sessionTtlMs,
      );

      await this.sessionManager.writeSession(session);
      this.sessionExpiresAt = session.expires_at;
    } finally {
      wipeBuffer(sessionKey);
    }
  }

  private startSessionMonitor(): void {
    this.stopSessionMonitor();
    this.lastSessionSlideAt = 0;
    this.sessionMonitorInterval = setInterval(() => {
      void this.sessionMonitorTick();
    }, SESSION_CLEANUP_INTERVAL_MS);

    // Don't block Node.js exit
    if (this.sessionMonitorInterval.unref) {
      this.sessionMonitorInterval.unref();
    }
  }

  /**
   * Monitor tick — enforcement only. The monitor never extends the session:
   * the TTL slides exclusively on authenticated use (touchSession), so an
   * idle-but-running engine process reaches expiry and seals instead of
   * keeping the session alive to the absolute ceiling by mere liveness.
   */
  private async sessionMonitorTick(): Promise<void> {
    let session: SessionFile | null;
    try {
      session = await this.sessionManager.readStoredSession();
    } catch {
      // The session file exists but could not be read (EMFILE, EIO, …). That
      // is not evidence the session ended — skip this tick rather than seal a
      // live vault on a transient filesystem failure (L6). Expiry is still
      // enforced synchronously by assertUnlocked and by the next tick.
      return;
    }
    if (session) return;
    // Session expired or removed — close store and seal
    await this.mcpRegistry?.closeAll("session_expired");
    this.wipeKeys();
    this.store?.close();
    this.store = null;
    this.state = VaultState.SEALED;
    this.stopSessionMonitor();
  }

  /**
   * Synchronous seal on lazily-detected TTL expiry (from assertUnlocked). The
   * async monitor tick does a graceful downstream close; here wipeKeys()'s
   * killAllSync suffices — the operation that tripped this is about to throw.
   */
  private sealExpired(): void {
    this.wipeKeys();
    this.store?.close();
    this.store = null;
    this.state = VaultState.SEALED;
    this.sessionExpiresAt = null;
    this.stopSessionMonitor();
  }

  /**
   * Seal after a session write that failed once the keys were installed
   * (R8/D54): the engine must not stay unlocked with no protected session
   * file behind it. The same wipe-close-seal as sealExpired, so the SDK
   * direct client and the CLI see exactly the sealed engine the thrown
   * SESSION_KEYSTORE_UNAVAILABLE describes.
   */
  private sealAfterFailedSessionWrite(): void {
    this.sealExpired();
  }

  /**
   * Slide the session's expiry window on authenticated use, throttled to one
   * write per SESSION_SLIDE_INTERVAL_MS per process — the same file-write
   * cadence the monitor produced when it did the sliding. Called from
   * assertUnlocked (every authenticated operation passes through it) and
   * again on use_secret completion, so a long-running action both starts and
   * ends with a fresh window. Fire-and-forget: a failed or already-expired
   * slide never fails the operation — expiry enforcement stays with the
   * monitor. The slide operates on the stored form (no keystore roundtrip);
   * lock() settles an in-flight write before erasing the file.
   */
  private touchSession(): void {
    if (this.state !== VaultState.UNLOCKED) return;
    const now = Date.now();
    if (this.sessionSlide !== null || now - this.lastSessionSlideAt < SESSION_SLIDE_INTERVAL_MS) {
      return;
    }
    this.lastSessionSlideAt = now;
    this.sessionSlide = this.sessionManager
      .extendSession(this.sessionTtlMs, true)
      .then((updated) => {
        // Track the new expiry; a null result means the file is gone (another
        // process locked/erased it) — mark expired so the next op seals.
        this.sessionExpiresAt = updated ? updated.expires_at : 0;
      })
      .catch(() => undefined)
      .finally(() => {
        this.sessionSlide = null;
      });
  }

  /** Await an in-flight expiry slide (never throws — slides swallow errors). */
  private async settleSessionSlide(): Promise<void> {
    if (this.sessionSlide) await this.sessionSlide;
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

    let payload: VaultApiToken;
    try {
      payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as VaultApiToken;
    } catch {
      throw new VaultError(ErrorCode.INVALID_TOKEN, "Invalid token payload");
    }
    if (
      typeof payload !== "object" ||
      payload === null ||
      !(Object.values(TokenPrincipalTypeValues) as string[]).includes(payload.principal_type)
    ) {
      throw new VaultError(ErrorCode.INVALID_TOKEN, "Invalid token payload");
    }
    return payload;
  }

  // ---------------------------------------------------------------------------
  // Private: helpers
  // ---------------------------------------------------------------------------

  private validatePassword(password: string): void {
    if (password.length < MIN_PASSWORD_LENGTH) {
      throw VaultError.weakPassword(MIN_PASSWORD_LENGTH);
    }
  }

  private loadWrappedKey(store: SqliteStore, prefix: string): WrappedKey {
    const ct = store.getMeta(`${prefix}`);
    const iv = store.getMeta(`${prefix}_iv`);
    const tag = store.getMeta(`${prefix}_tag`);
    if (!ct || !iv || !tag) {
      throw VaultError.vaultCorrupted(`Missing ${prefix}`);
    }
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
