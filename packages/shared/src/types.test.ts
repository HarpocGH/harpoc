import { describe, expect, it } from "vitest";

import {
  AuditEventType,
  FollowRedirects,
  InjectionType,
  Permission,
  PrincipalType,
  SecretStatus,
  SecretType,
  VaultState,
} from "./types.js";
import { ErrorCode } from "./errors.js";

// ---------------------------------------------------------------------------
// Enum member counts — regression gates for downstream switch/Zod schemas
// ---------------------------------------------------------------------------

describe("enum member counts", () => {
  it("SecretType has 3 members", () => {
    expect(Object.values(SecretType)).toHaveLength(3);
  });

  it("SecretStatus has 4 members", () => {
    expect(Object.values(SecretStatus)).toHaveLength(4);
  });

  it("Permission has 7 members", () => {
    expect(Object.values(Permission)).toHaveLength(7);
  });

  it("AuditEventType has 22 members", () => {
    expect(Object.values(AuditEventType)).toHaveLength(22);
  });

  it("PrincipalType has 4 members", () => {
    expect(Object.values(PrincipalType)).toHaveLength(4);
  });

  it("InjectionType has 4 members", () => {
    expect(Object.values(InjectionType)).toHaveLength(4);
  });

  it("FollowRedirects has 3 members", () => {
    expect(Object.values(FollowRedirects)).toHaveLength(3);
  });

  it("VaultState has 2 members", () => {
    expect(Object.values(VaultState)).toHaveLength(2);
  });

  it("ErrorCode has 40 members", () => {
    // Filter out reverse mappings (numeric keys) from TypeScript enum
    const members = Object.values(ErrorCode).filter((v) => typeof v === "string");
    expect(members).toHaveLength(40);
  });
});

// ---------------------------------------------------------------------------
// Critical enum values — verify specific values for the 3 most important enums
// ---------------------------------------------------------------------------

describe("SecretType values", () => {
  it("API_KEY is 'api_key'", () => {
    expect(SecretType.API_KEY).toBe("api_key");
  });

  it("OAUTH_TOKEN is 'oauth_token'", () => {
    expect(SecretType.OAUTH_TOKEN).toBe("oauth_token");
  });

  it("CERTIFICATE is 'certificate'", () => {
    expect(SecretType.CERTIFICATE).toBe("certificate");
  });
});

describe("Permission values", () => {
  it.each([
    ["LIST", "list"],
    ["READ", "read"],
    ["USE", "use"],
    ["CREATE", "create"],
    ["ROTATE", "rotate"],
    ["REVOKE", "revoke"],
    ["ADMIN", "admin"],
  ] as const)("%s is '%s'", (key, value) => {
    expect(Permission[key]).toBe(value);
  });
});

describe("SecretStatus values", () => {
  it.each([
    ["ACTIVE", "active"],
    ["PENDING", "pending"],
    ["EXPIRED", "expired"],
    ["REVOKED", "revoked"],
  ] as const)("%s is '%s'", (key, value) => {
    expect(SecretStatus[key]).toBe(value);
  });
});

describe("InjectionType values", () => {
  it.each([
    ["HEADER", "header"],
    ["QUERY", "query"],
    ["BASIC_AUTH", "basic_auth"],
    ["BEARER", "bearer"],
  ] as const)("%s is '%s'", (key, value) => {
    expect(InjectionType[key]).toBe(value);
  });
});
