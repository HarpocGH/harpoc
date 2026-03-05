// Crypto
export { encrypt, decrypt } from "./crypto/aes-gcm.js";
export type { EncryptResult } from "./crypto/aes-gcm.js";
export { deriveKey, generateSalt } from "./crypto/argon2.js";
export { deriveSubkey } from "./crypto/hkdf.js";
export {
  createVaultKeys,
  unlockVault,
  wrapDek,
  unwrapDek,
  encryptSecretValue,
  decryptSecretValue,
  encryptName,
  decryptName,
  changePassword,
  wrapKeyWithKek,
  unwrapKeyFromKek,
  computeNameHmac,
} from "./crypto/key-hierarchy.js";
export type { VaultKeys, UnlockedKeys, WrappedDek, EncryptedValue, WrappedKey } from "./crypto/key-hierarchy.js";
export { generateRandomBytes, generateUUIDv7, wipeBuffer } from "./crypto/random.js";

// Storage
export { SqliteStore } from "./storage/sqlite-store.js";
export type { SecretFilter, AuditFilter } from "./storage/sqlite-store.js";

// Session
export { SessionManager } from "./session/session-manager.js";

// Audit
export { AuditLogger } from "./audit/audit-logger.js";
export type { AuditLogOptions } from "./audit/audit-logger.js";
export { AuditQuery } from "./audit/audit-query.js";
export type { AuditQueryOptions, DecryptedAuditEvent } from "./audit/audit-query.js";

// Access
export { PolicyEngine } from "./access/policy-engine.js";
export type { GrantPolicyInput } from "./access/policy-engine.js";

// Secrets
export { SecretManager } from "./secrets/secret-manager.js";
export type { CreateSecretInput, SecretInfo } from "./secrets/secret-manager.js";

// Injection
export { validateUrl, isPrivateIp, isLoopback } from "./injection/url-validator.js";
export { HttpInjector } from "./injection/http-injector.js";
export type { HttpInjectorRequest } from "./injection/http-injector.js";
export { InjectionGuard } from "./injection/injection-guard.js";

// VaultEngine
export { VaultEngine } from "./vault-engine.js";
export type { VaultEngineOptions } from "./vault-engine.js";
