import { vi } from "vitest";
import type { Mock } from "vitest";
import { ErrorCode, TokenPrincipalType, VaultError } from "@harpoc/shared";
import type { VaultApiToken } from "@harpoc/shared";
import type { ProxyLease, ProxyOutcome } from "@harpoc/core";
import type { ProxyEngine } from "../proxy.js";
import { FIXTURE_CA_PEM } from "./upstream-server.js";

/** The credential every recording lease hands out unless a test names another. */
export const SECRET_VALUE = "s3cr3t-Pr0xy-v4lue";

/** The bearer each test sends as `Proxy-Authorization`; the double maps it to a payload or a refusal. */
export const TOKENS = {
  use: "tok-use",
  read: "tok-read",
  project: "tok-project",
  expired: "tok-expired",
  revoked: "tok-revoked",
  sealed: "tok-sealed",
} as const;

function payload(scope: VaultApiToken["scope"], project?: string): VaultApiToken {
  return {
    sub: "agent-a",
    vault_id: "vault-1",
    scope,
    iat: 1,
    exp: 4_102_444_800,
    jti: "jti-1",
    principal_type: TokenPrincipalType.AGENT,
    ...(project === undefined ? {} : { project }),
  };
}

function verify(token: string): VaultApiToken {
  switch (token) {
    case TOKENS.use:
      return payload(["use"]);
    case TOKENS.read:
      return payload(["read"]);
    case TOKENS.project:
      return payload(["use"], "team");
    case TOKENS.expired:
      throw VaultError.tokenExpired();
    case TOKENS.revoked:
      throw VaultError.tokenRevoked();
    case TOKENS.sealed:
      throw VaultError.vaultLocked();
    default:
      throw new VaultError(ErrorCode.INVALID_TOKEN, "Invalid token format");
  }
}

export interface RecordingLease extends ProxyLease {
  complete: Mock<(outcome: ProxyOutcome) => void>;
}

/** A lease whose `complete` records every call — the exactly-once pins read it; `caPem: null` pins no CA. */
export function recordingLease(
  value: string = SECRET_VALUE,
  caPem: string | null = FIXTURE_CA_PEM,
): RecordingLease {
  return {
    value: new Uint8Array(Buffer.from(value)),
    ...(caPem === null ? {} : { caPem }),
    complete: vi.fn<(outcome: ProxyOutcome) => void>(),
  };
}

export interface EngineDouble {
  engine: ProxyEngine;
  verifyToken: Mock<ProxyEngine["verifyToken"]>;
  auditScopeRefusal: Mock<ProxyEngine["auditScopeRefusal"]>;
  auditServerStart: Mock<ProxyEngine["auditServerStart"]>;
  resolveForProxy: Mock<ProxyEngine["resolveForProxy"]>;
  /** Every lease the default `resolveForProxy` handed out, in order. */
  leases: RecordingLease[];
}

/** The engine surface with `resolveForProxy` answering a fresh recording lease per call. */
export function engineDouble(): EngineDouble {
  const leases: RecordingLease[] = [];
  const double: EngineDouble = {
    verifyToken: vi.fn<ProxyEngine["verifyToken"]>(verify),
    auditScopeRefusal: vi.fn<ProxyEngine["auditScopeRefusal"]>(),
    auditServerStart: vi.fn<ProxyEngine["auditServerStart"]>(),
    resolveForProxy: vi.fn<ProxyEngine["resolveForProxy"]>(async () => {
      const lease = recordingLease();
      leases.push(lease);
      return lease;
    }),
    leases,
    engine: undefined as unknown as ProxyEngine,
  };
  double.engine = {
    verifyToken: double.verifyToken,
    auditScopeRefusal: double.auditScopeRefusal,
    auditServerStart: double.auditServerStart,
    resolveForProxy: double.resolveForProxy,
  };
  return double;
}
