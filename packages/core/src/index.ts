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
export type {
  VaultKeys,
  UnlockedKeys,
  WrappedDek,
  EncryptedValue,
  WrappedKey,
} from "./crypto/key-hierarchy.js";
export { generateRandomBytes, generateUUIDv7, wipeBuffer } from "./crypto/random.js";

// Storage
export { SqliteStore } from "./storage/sqlite-store.js";
export type {
  SecretFilter,
  AuditFilter,
  OAuthTokenRow,
  CertificateRow,
  InjectionPolicyRow,
  McpServerRow,
  ConnectionConfigRow,
} from "./storage/sqlite-store.js";

// Session
export { SessionManager } from "./session/session-manager.js";
export type { SessionManagerOptions } from "./session/session-manager.js";
export {
  DpapiSessionKeyProtector,
  NoneSessionKeyProtector,
  createSessionKeyProtector,
} from "./session/session-key-protector.js";
export type {
  SessionKeyProtector,
  DpapiSessionKeyProtectorOptions,
} from "./session/session-key-protector.js";

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
export { validateUrl, validateHostPort, isPrivateIp, isLoopback } from "./injection/url-validator.js";
export type { ValidatedHostPort } from "./injection/url-validator.js";
export { HttpInjector } from "./injection/http-injector.js";
export type { HttpInjectorRequest } from "./injection/http-injector.js";
export { InjectionGuard } from "./injection/injection-guard.js";
export { ProcessInjector } from "./injection/process-injector.js";
export { spawnCaptured } from "./injection/spawn-captured.js";
export type { SpawnCapturedResult, SpawnCapturedOptions } from "./injection/spawn-captured.js";
export { DatabaseInjector } from "./injection/database-injector.js";
export type {
  DbEngineAdapter,
  DbConnection,
  DbConnectOptions,
  DbQueryResult,
} from "./injection/db-adapters.js";
export { SshInjector } from "./injection/ssh-injector.js";
export { EphemeralSshAgent } from "./injection/ssh-agent.js";
export { GitInjector } from "./injection/git-injector.js";
export {
  matchesUrlAllowlist,
  matchesHostAllowlist,
  matchesHostPortAllowlist,
  resolveAndMatchCommand,
  resolveExecutable,
  controlledPathDirs,
} from "./injection/allowlist.js";
export { redactSecretEncodings, mapStringLeaves } from "./injection/output-sanitizer.js";
export { sanitizeUseSecretResult } from "./injection/sanitize-result.js";
export { McpInjector } from "./injection/mcp-injector.js";
export { McpConnectionRegistry } from "./injection/mcp-registry.js";
export type { McpConnectionEntry, McpEntryState } from "./injection/mcp-registry.js";
export { StdioChildTransport } from "./injection/mcp-stdio-transport.js";
export type { ChildExitInfo, StdioChildParams } from "./injection/mcp-stdio-transport.js";

// VaultEngine
export { VaultEngine } from "./vault-engine.js";
export type { VaultEngineOptions } from "./vault-engine.js";
