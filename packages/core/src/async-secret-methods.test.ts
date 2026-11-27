import { describe, expect, it } from "vitest";
import { SecretManager } from "./secrets/secret-manager.js";
import { VaultEngine } from "./vault-engine.js";

interface Classification {
  readonly SecretManager: readonly (keyof SecretManager)[];
  readonly VaultEngine: readonly (keyof VaultEngine)[];
}

const VALUE_METHODS = {
  SecretManager: ["getSecretValue"],
  VaultEngine: [
    "getSecretValue",
    "useSecret",
    "resolveForProxy",
    "signForAgentSocket",
    "getAcmeAccount",
    "getCertificatePrivateKey",
    "loadProxyCa",
    "refreshOAuthToken",
    "enrollUnlockKey",
  ],
} as const satisfies Classification;

const OTHER_METHODS = {
  SecretManager: [
    "createSecret",
    "setSecretValue",
    "getSecretInfo",
    "listSecrets",
    "listSecretsWithIds",
    "rotateSecret",
    "revokeSecret",
    "revokeResolved",
    "resolveHandle",
    "findByHandle",
    "hasActiveSecret",
    "assertUsable",
  ],
  VaultEngine: [
    "initVault",
    "unlock",
    "unlockWithKey",
    "loadSession",
    "lock",
    "destroy",
    "getState",
    "declareDaemon",
    "createSecret",
    "getSecretInfo",
    "listSecrets",
    "setSecretValue",
    "rotateSecret",
    "secretNameTaken",
    "refuseTakenSecretName",
    "assertRotateAllowed",
    "revokeSecret",
    "listAgentSocketIdentities",
    "setInjectionPolicy",
    "getInjectionPolicy",
    "setMcpServerConfig",
    "getMcpServerConfig",
    "deleteMcpServerConfig",
    "setConnectionConfig",
    "getConnectionConfig",
    "deleteConnectionConfig",
    "createOAuthSecret",
    "completeOAuthFlow",
    "getOAuthTokenStatus",
    "getExpiringOAuthTokens",
    "getExpiringOAuthTokenStatuses",
    "importCertificate",
    "updateCertificate",
    "getCertificateStatus",
    "getCertificatePem",
    "getExpiringCertificates",
    "getExpiringCertificateStatuses",
    "auditGovernanceRefusal",
    "auditScopeRefusal",
    "auditProxyRefusal",
    "assertProxyConsumer",
    "registerAgent",
    "getAgent",
    "listAgents",
    "updateAgent",
    "activateAgent",
    "deactivateAgent",
    "deleteAgent",
    "grantPolicy",
    "revokePolicy",
    "listPolicies",
    "setAgentPermissions",
    "listAgentPolicies",
    "queryAudit",
    "auditServerStart",
    "auditServerStop",
    "auditCertRenewFailure",
    "getAuditChainTail",
    "verifyAuditChain",
    "createToken",
    "verifyToken",
    "isTokenRevoked",
    "revokeToken",
    "listIssuedTokens",
    "changePassword",
    "revokeUnlockKey",
    "unlockKeyStatus",
    "backupToDirectory",
    "backupToFile",
    "createProxyCa",
    "proxyCaCertificate",
    "resolveSecretId",
  ],
} as const satisfies Classification;

const PRIVATE_NAMES = {
  SecretManager: ["resolveHandleToSecret", "effectiveStatus", "assertNoDuplicateByHmac"],
  VaultEngine: [
    "assertVaultVersionOpenable",
    "unlockFromSlot",
    "auditRevocation",
    "endRevokedChild",
    "terminateAfterRow",
    "useSecretInner",
    "decryptJudged",
    "showsNoHttpCa",
    "openProxyLease",
    "agentSocketKeys",
    "agentSocketPublicKey",
    "agentSocketDerivedSecret",
    "agentSocketHost",
    "handleOf",
    "assertDockerIsolationAllowed",
    "assertSmtpUsageAllowed",
    "assertImapUsageAllowed",
    "assertTimeoutAllowed",
    "refuseRenderOnly",
    "refuseBootstrapOnly",
    "endSecretForBootstrap",
    "refuseOnBootstrapMark",
    "judgeBootstrapAction",
    "runSshBootstrap",
    "judgeRenderAction",
    "judgeRenderSlot",
    "runSftpRender",
    "holdsCallKeys",
    "assertCallKeys",
    "openUse",
    "sealUse",
    "auditUse",
    "loadInjectionPolicy",
    "loadMcpServerConfig",
    "mcpLaunchChanged",
    "loadConnectionConfig",
    "doCreateOAuthSecret",
    "doCompleteOAuthFlow",
    "storedAuthMethod",
    "joinOrStartRefresh",
    "doRefreshOAuthToken",
    "doRefreshOAuthTokenInner",
    "getOAuthAccessToken",
    "doImportCertificate",
    "doUpdateCertificate",
    "assertUnscopedGovernanceCaller",
    "revokeLiveTokensForAgent",
    "chainTailAnchor",
    "assertRotationLive",
    "assertUnlockedByPassword",
    "takeBackup",
    "findProxyCaSecret",
    "auditConfigRead",
    "auditVaultRead",
    "concealHandleError",
    "auditDenied",
    "refuseAudited",
    "secretInfoById",
    "listableEntries",
    "callerPrincipals",
    "checkResolvedCallerPolicy",
    "resolveForConfig",
    "enforceCallerPolicy",
    "assertUnlocked",
    "assertUnlockedWithoutSlide",
    "initManagers",
    "wipeKeys",
    "writeNewSession",
    "startSessionMonitor",
    "sessionMonitorTick",
    "sealExpired",
    "sealAfterFailedSessionWrite",
    "sessionExpectation",
    "touchSession",
    "settleSessionSlide",
    "stopSessionMonitor",
    "checkLockout",
    "incrementLockout",
    "signJwt",
    "verifyJwt",
    "validatePassword",
    "loadWrappedKey",
    "storeWrappedKey",
    "loadBase64Meta",
  ],
} as const;

type NotPublic<C, Names extends readonly string[]> = readonly Exclude<Names[number], keyof C>[];

const PRIVATE_METHODS = PRIVATE_NAMES satisfies {
  readonly SecretManager: NotPublic<SecretManager, typeof PRIVATE_NAMES.SecretManager>;
  readonly VaultEngine: NotPublic<VaultEngine, typeof PRIVATE_NAMES.VaultEngine>;
};

const CLASSES = [
  {
    name: "SecretManager",
    prototype: SecretManager.prototype as object,
    value: VALUE_METHODS.SecretManager,
    other: OTHER_METHODS.SecretManager,
    hidden: PRIVATE_METHODS.SecretManager,
  },
  {
    name: "VaultEngine",
    prototype: VaultEngine.prototype as object,
    value: VALUE_METHODS.VaultEngine,
    other: OTHER_METHODS.VaultEngine,
    hidden: PRIVATE_METHODS.VaultEngine,
  },
];

function isAsync(prototype: object, name: string): boolean {
  const method: unknown = Reflect.get(prototype, name);
  return typeof method === "function" && method.constructor.name === "AsyncFunction";
}

describe.each(CLASSES)("$name — a method that returns a secret value is async", (subject) => {
  it("every public method is classified", () => {
    const hidden: readonly string[] = subject.hidden;
    const declared = Object.getOwnPropertyNames(subject.prototype).filter(
      (name) => name !== "constructor" && !hidden.includes(name),
    );
    expect(declared.sort()).toStrictEqual([...subject.value, ...subject.other].sort());
  });

  it("every value method is async", () => {
    const value: readonly string[] = subject.value;
    expect(value.filter((name) => !isAsync(subject.prototype, name))).toStrictEqual([]);
  });
});
