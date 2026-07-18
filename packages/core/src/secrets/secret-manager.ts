import type { CreateSecretResponse, ParsedHandle, Secret, SecretType } from "@harpoc/shared";
import {
  AES_KEY_LENGTH,
  ErrorCode,
  SecretStatus,
  VaultError,
  formatHandle,
  parseHandle,
} from "@harpoc/shared";
import {
  computeNameHmac,
  decryptName,
  decryptSecretValue,
  encryptName,
  encryptSecretValue,
  unwrapDek,
  wrapDek,
} from "../crypto/key-hierarchy.js";
import { generateRandomBytes, generateUUIDv7, wipeBuffer } from "../crypto/random.js";
import { isUniqueConstraintError } from "../storage/sqlite-store.js";
import type { SqliteStore } from "../storage/sqlite-store.js";

export interface CreateSecretInput {
  name: string;
  type: SecretType;
  project?: string;
  value?: Uint8Array;
  expiresAt?: number;
}

/** Info about a secret without its value (safe to return to LLM). */
export interface SecretInfo {
  handle: string;
  name: string;
  type: SecretType;
  project: string | null;
  status: string;
  version: number;
  createdAt: number;
  updatedAt: number;
  expiresAt: number | null;
  rotatedAt: number | null;
}

export class SecretManager {
  private backfillDone = false;

  constructor(
    private readonly store: SqliteStore,
    private readonly kek: Uint8Array,
    /**
     * Fired when a lazy-expiry check transitions a secret to EXPIRED — the
     * status write is a vault mutation and must reach the audit trail, which
     * lives at the engine layer.
     */
    private readonly onLazyExpire: (secretId: string, handle: string) => void = (): void => {},
  ) {}

  /**
   * One-time migration: backfill name_hmac for secrets that don't have one.
   * Called lazily on first resolve/create to avoid blocking constructor.
   */
  private async ensureNameHmacBackfill(): Promise<void> {
    if (this.backfillDone) return;
    this.backfillDone = true;

    const secrets = this.store.listSecrets();
    for (const secret of secrets) {
      if (secret.name_hmac) continue;
      const name = decryptName(
        this.kek,
        secret.name_encrypted,
        secret.name_iv,
        secret.name_tag,
        secret.id,
      );
      const hmac = await computeNameHmac(this.kek, name, secret.project);
      this.store.updateSecretNameHmac(secret.id, hmac);
    }
  }

  /**
   * Create a new secret. If no value is provided, status is PENDING.
   *
   * `onCommit` runs synchronously inside the insert transaction (receiving the
   * response the caller will get) so the engine's audit row commits atomically
   * with the secret row — a crash cannot yield a created-but-unaudited secret,
   * and a failed audit write rolls the create back.
   */
  async createSecret(
    input: CreateSecretInput,
    onCommit?: (result: CreateSecretResponse) => void,
  ): Promise<CreateSecretResponse> {
    const { name, type, project, value, expiresAt } = input;

    // Validates name and project before any row is written — a post-insert
    // failure would leave an unaddressable row that breaks every listSecrets.
    const handle = formatHandle(name, project);

    await this.ensureNameHmacBackfill();

    const id = generateUUIDv7();
    const now = Date.now();

    // Compute name HMAC for O(1) lookup (also drives the duplicate check).
    const nameHmac = await computeNameHmac(this.kek, name, project ?? null);

    // Encrypt name with KEK
    const nameEnc = encryptName(this.kek, name, id);

    // Generate DEK and wrap it — wiped in a finally like the other DEK users,
    // so a throwing wrap/encrypt cannot leave the plaintext DEK live.
    const dek = generateRandomBytes(AES_KEY_LENGTH);

    let wrapped: ReturnType<typeof wrapDek>;
    let status: typeof SecretStatus.ACTIVE | typeof SecretStatus.PENDING;
    let ciphertext: Uint8Array;
    let ctIv: Uint8Array;
    let ctTag: Uint8Array;

    try {
      wrapped = wrapDek(this.kek, dek, id);

      if (value) {
        // Encrypt the value
        const encrypted = encryptSecretValue(dek, value, id, 1);
        ciphertext = encrypted.ciphertext;
        ctIv = encrypted.iv;
        ctTag = encrypted.tag;
        status = SecretStatus.ACTIVE;
      } else {
        // Pending secret — store empty encrypted payload
        const encrypted = encryptSecretValue(dek, new Uint8Array(0), id, 1);
        ciphertext = encrypted.ciphertext;
        ctIv = encrypted.iv;
        ctTag = encrypted.tag;
        status = SecretStatus.PENDING;
      }
    } finally {
      // Wipe DEK from memory
      wipeBuffer(dek);
    }

    const secret: Secret = {
      id,
      name_encrypted: nameEnc.ciphertext,
      name_iv: nameEnc.iv,
      name_tag: nameEnc.tag,
      type,
      project: project ?? null,
      wrapped_dek: wrapped.wrappedDek,
      dek_iv: wrapped.dekIv,
      dek_tag: wrapped.dekTag,
      ciphertext,
      ct_iv: ctIv,
      ct_tag: ctTag,
      metadata_encrypted: null,
      metadata_iv: null,
      metadata_tag: null,
      created_at: now,
      updated_at: now,
      expires_at: expiresAt ?? null,
      rotated_at: null,
      version: 1,
      status,
      sync_version: 0,
      name_hmac: nameHmac,
    };

    const response: CreateSecretResponse = {
      handle,
      status: value ? "created" : "pending",
      message: value
        ? `Secret ${handle} created`
        : `Secret ${handle} created with pending status — set value via CLI`,
    };

    // Duplicate check and insert run in one transaction with no await between
    // them, so two concurrent creates in this process cannot interleave; the
    // partial unique index (migration 009) is the cross-process backstop and
    // surfaces as a UNIQUE constraint, mapped to DUPLICATE_SECRET here.
    try {
      this.store.transaction(() => {
        this.assertNoDuplicateByHmac(nameHmac, name);
        this.store.insertSecret(secret);
        onCommit?.(response);
      });
    } catch (err) {
      if (isUniqueConstraintError(err)) {
        throw VaultError.duplicateSecret(name);
      }
      throw err;
    }

    return response;
  }

  /**
   * Set the value for a PENDING secret (transitions to ACTIVE).
   * `onCommit` runs inside the update transaction (see createSecret).
   */
  async setSecretValue(handle: string, value: Uint8Array, onCommit?: () => void): Promise<void> {
    const secret = await this.resolveHandleToSecret(handle);

    if (secret.status !== SecretStatus.PENDING) {
      throw new VaultError(
        ErrorCode.INVALID_INPUT,
        `Secret ${handle} is not pending — use rotate to update an active secret`,
      );
    }

    // Unwrap DEK
    const dek = unwrapDek(this.kek, secret.wrapped_dek, secret.dek_iv, secret.dek_tag, secret.id);

    try {
      const encrypted = encryptSecretValue(dek, value, secret.id, secret.version);

      this.store.transaction(() => {
        this.store.updateSecret(secret.id, {
          ciphertext: encrypted.ciphertext,
          ct_iv: encrypted.iv,
          ct_tag: encrypted.tag,
          status: SecretStatus.ACTIVE,
          updated_at: Date.now(),
        });
        onCommit?.();
      });
    } finally {
      wipeBuffer(dek);
    }
  }

  /**
   * Get secret info (metadata only, no value) — safe to return to LLM.
   */
  async getSecretInfo(handle: string): Promise<SecretInfo> {
    const secret = await this.resolveHandleToSecret(handle);
    const name = decryptName(
      this.kek,
      secret.name_encrypted,
      secret.name_iv,
      secret.name_tag,
      secret.id,
    );

    return {
      handle: formatHandle(name, secret.project ?? undefined),
      name,
      type: secret.type,
      project: secret.project,
      status: this.effectiveStatus(secret),
      version: secret.version,
      createdAt: secret.created_at,
      updatedAt: secret.updated_at,
      expiresAt: secret.expires_at,
      rotatedAt: secret.rotated_at,
    };
  }

  /**
   * Get the decrypted secret value. NEVER return this to the LLM.
   */
  async getSecretValue(handle: string): Promise<Uint8Array> {
    const secret = await this.resolveHandleToSecret(handle);
    this.assertUsable(secret, handle);

    const dek = unwrapDek(this.kek, secret.wrapped_dek, secret.dek_iv, secret.dek_tag, secret.id);

    try {
      return decryptSecretValue(
        dek,
        secret.ciphertext,
        secret.ct_iv,
        secret.ct_tag,
        secret.id,
        secret.version,
      );
    } finally {
      wipeBuffer(dek);
    }
  }

  /**
   * List all secrets (metadata only).
   */
  listSecrets(project?: string): SecretInfo[] {
    const secrets = this.store.listSecrets(project ? { project } : undefined);

    return secrets.map((s) => {
      const name = decryptName(this.kek, s.name_encrypted, s.name_iv, s.name_tag, s.id);
      return {
        handle: formatHandle(name, s.project ?? undefined),
        name,
        type: s.type,
        project: s.project,
        status: this.effectiveStatus(s),
        version: s.version,
        createdAt: s.created_at,
        updatedAt: s.updated_at,
        expiresAt: s.expires_at,
        rotatedAt: s.rotated_at,
      };
    });
  }

  /**
   * Rotate a secret: new DEK, new ciphertext, version incremented.
   * `onCommit` runs inside the update transaction (see createSecret).
   */
  async rotateSecret(handle: string, newValue: Uint8Array, onCommit?: () => void): Promise<void> {
    const secret = await this.resolveHandleToSecret(handle);
    this.assertUsable(secret, handle);

    const newVersion = secret.version + 1;
    const newDek = generateRandomBytes(AES_KEY_LENGTH);

    try {
      const wrapped = wrapDek(this.kek, newDek, secret.id);
      const encrypted = encryptSecretValue(newDek, newValue, secret.id, newVersion);

      this.store.transaction(() => {
        this.store.updateSecret(secret.id, {
          wrapped_dek: wrapped.wrappedDek,
          dek_iv: wrapped.dekIv,
          dek_tag: wrapped.dekTag,
          ciphertext: encrypted.ciphertext,
          ct_iv: encrypted.iv,
          ct_tag: encrypted.tag,
          version: newVersion,
          rotated_at: Date.now(),
          updated_at: Date.now(),
        });
        onCommit?.();
      });
    } finally {
      wipeBuffer(newDek);
    }
  }

  /**
   * Revoke a secret (sets status to REVOKED).
   * `onCommit` runs inside the update transaction (see createSecret).
   */
  async revokeSecret(handle: string, onCommit?: () => void): Promise<void> {
    const secret = await this.resolveHandleToSecret(handle);

    if (secret.status === SecretStatus.REVOKED) {
      throw VaultError.secretRevoked(handle);
    }

    this.store.transaction(() => {
      this.store.updateSecret(secret.id, {
        status: SecretStatus.REVOKED,
        updated_at: Date.now(),
      });
      onCommit?.();
    });
  }

  /**
   * Resolve a handle to a secret record.
   */
  async resolveHandle(handle: string): Promise<Secret> {
    return this.resolveHandleToSecret(handle);
  }

  // ---------------------------------------------------------------------------
  // Private
  // ---------------------------------------------------------------------------

  private async resolveHandleToSecret(handle: string): Promise<Secret> {
    await this.ensureNameHmacBackfill();

    const parsed: ParsedHandle = parseHandle(handle);
    const nameHmac = await computeNameHmac(this.kek, parsed.name, parsed.project ?? null);
    const matches = this.store.getSecretsByNameHmac(nameHmac);

    if (matches.length === 0) {
      throw VaultError.secretNotFound(handle);
    }

    // Prefer non-revoked matches to avoid AMBIGUOUS_HANDLE when a revoked
    // secret coexists with an active one of the same name.
    const nonRevoked = matches.filter((s) => s.status !== SecretStatus.REVOKED);

    if (nonRevoked.length === 1) {
      return nonRevoked[0] as Secret;
    }
    if (nonRevoked.length > 1) {
      throw new VaultError(ErrorCode.AMBIGUOUS_HANDLE, `Ambiguous handle: ${handle}`);
    }

    // All matches are revoked — fall through to single/multi logic
    if (matches.length > 1) {
      throw new VaultError(ErrorCode.AMBIGUOUS_HANDLE, `Ambiguous handle: ${handle}`);
    }

    return matches[0] as Secret;
  }

  private effectiveStatus(secret: Secret): string {
    if (
      secret.status !== SecretStatus.EXPIRED &&
      secret.expires_at !== null &&
      secret.expires_at <= Date.now()
    ) {
      return SecretStatus.EXPIRED;
    }
    return secret.status;
  }

  /**
   * Synchronous duplicate check by precomputed name HMAC — runs inside the
   * create transaction so it cannot be separated from the insert by an await.
   * A non-revoked match blocks; revoked rows never do.
   */
  private assertNoDuplicateByHmac(nameHmac: string, name: string): void {
    const matches = this.store.getSecretsByNameHmac(nameHmac);
    for (const secret of matches) {
      if (secret.status === SecretStatus.REVOKED) continue;
      throw VaultError.duplicateSecret(name);
    }
  }

  private assertUsable(secret: Secret, handle: string): void {
    // Lazy expiry: if expires_at is set and past, transition to EXPIRED. The
    // status write and the engine's audit row (via onLazyExpire) commit in one
    // transaction; the expiry then persists even though the access is denied.
    if (
      secret.status !== SecretStatus.EXPIRED &&
      secret.expires_at !== null &&
      secret.expires_at <= Date.now()
    ) {
      this.store.transaction(() => {
        this.store.updateSecret(secret.id, {
          status: SecretStatus.EXPIRED,
          updated_at: Date.now(),
        });
        this.onLazyExpire(secret.id, handle);
      });
      throw VaultError.secretExpired(handle);
    }

    if (secret.status === SecretStatus.EXPIRED) {
      throw VaultError.secretExpired(handle);
    }
    if (secret.status === SecretStatus.REVOKED) {
      throw VaultError.secretRevoked(handle);
    }
    if (secret.status === SecretStatus.PENDING) {
      throw new VaultError(ErrorCode.SECRET_VALUE_REQUIRED, `Secret ${handle} has no value set`);
    }
  }
}
