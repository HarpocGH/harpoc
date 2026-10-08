import { describe, expect, it } from "vitest";

import {
  auditChainAnchorSchema,
  auditQuerySchema,
  healthResponseSchema,
  sessionFileSchema,
} from "./schemas.js";

// ---------------------------------------------------------------------------
// healthResponseSchema
// ---------------------------------------------------------------------------

describe("healthResponseSchema", () => {
  it("accepts a valid health response", () => {
    const result = healthResponseSchema.parse({ state: "unlocked", version: "1.0.0" });
    expect(result.state).toBe("unlocked");
    expect(result.version).toBe("1.0.0");
  });

  it("rejects an unknown state", () => {
    expect(() => healthResponseSchema.parse({ state: "open", version: "1.0.0" })).toThrow();
  });

  it("rejects a missing version", () => {
    expect(() => healthResponseSchema.parse({ state: "sealed" })).toThrow();
  });
});

// ---------------------------------------------------------------------------
// auditQuerySchema
// ---------------------------------------------------------------------------

describe("auditQuerySchema", () => {
  it("accepts empty query (all optional)", () => {
    expect(auditQuerySchema.parse({})).toEqual({});
  });

  it("accepts full query", () => {
    const result = auditQuerySchema.parse({
      event_type: "secret.create",
      limit: 100,
    });
    expect(result.event_type).toBe("secret.create");
    expect(result.limit).toBe(100);
  });

  it("rejects limit over 1000", () => {
    expect(() => auditQuerySchema.parse({ limit: 1001 })).toThrow();
  });

  it("rejects limit: 0", () => {
    expect(() => auditQuerySchema.parse({ limit: 0 })).toThrow();
  });

  it("accepts limit: 1 (minimum positive)", () => {
    expect(auditQuerySchema.parse({ limit: 1 }).limit).toBe(1);
  });

  it("accepts limit: 1000 (maximum)", () => {
    expect(auditQuerySchema.parse({ limit: 1000 }).limit).toBe(1000);
  });

  it("accepts since: 0 (nonnegative)", () => {
    expect(auditQuerySchema.parse({ since: 0 }).since).toBe(0);
  });

  it("rejects since: -1", () => {
    expect(() => auditQuerySchema.parse({ since: -1 })).toThrow();
  });

  it("accepts valid UUID for secret_id", () => {
    const uuid = "550e8400-e29b-41d4-a716-446655440000";
    expect(auditQuerySchema.parse({ secret_id: uuid }).secret_id).toBe(uuid);
  });

  it("rejects non-UUID secret_id", () => {
    expect(() => auditQuerySchema.parse({ secret_id: "not-uuid" })).toThrow();
  });

  it("accepts success: true and success: false", () => {
    expect(auditQuerySchema.parse({ success: true }).success).toBe(true);
    expect(auditQuerySchema.parse({ success: false }).success).toBe(false);
  });

  it("rejects non-boolean success", () => {
    expect(() => auditQuerySchema.parse({ success: "false" })).toThrow();
  });

  it("accepts principal_type: 'agent' with principal_id (v1.4)", () => {
    const result = auditQuerySchema.parse({ principal_type: "agent", principal_id: "claude-code" });
    expect(result.principal_type).toBe("agent");
    expect(result.principal_id).toBe("claude-code");
  });

  it("rejects an unknown principal_type (v1.4)", () => {
    expect(() => auditQuerySchema.parse({ principal_type: "robot" })).toThrow();
  });

  it("rejects an empty principal_id (v1.4)", () => {
    expect(() => auditQuerySchema.parse({ principal_id: "" })).toThrow();
  });
});

// ---------------------------------------------------------------------------
// sessionFileSchema
// ---------------------------------------------------------------------------

describe("sessionFileSchema", () => {
  const validSession = {
    version: 1 as const,
    session_id: "01234567-89ab-cdef-0123-456789abcdef",
    vault_id: "vault-001",
    created_at: Date.now(),
    expires_at: Date.now() + 900_000,
    max_expires_at: Date.now() + 86_400_000,
    key_protection: "none" as const,
    session_key: "c2Vzc2lvbi1rZXk=",
    wrapped_kek: "d3JhcHBlZC1rZWs=",
    wrapped_kek_iv: "aXY=",
    wrapped_kek_tag: "dGFn",
    wrapped_jwt_key: "and0LWtleQ==",
    wrapped_jwt_key_iv: "and0LWl2",
    wrapped_jwt_key_tag: "and0LXRhZw==",
    wrapped_audit_key: "YXVkaXQta2V5",
    wrapped_audit_key_iv: "YXVkaXQtaXY=",
    wrapped_audit_key_tag: "YXVkaXQtdGFn",
  };

  it("accepts valid session file", () => {
    const result = sessionFileSchema.parse(validSession);
    expect(result.version).toBe(1);
    expect(result.session_id).toBe(validSession.session_id);
  });

  it("rejects wrong version", () => {
    expect(() => sessionFileSchema.parse({ ...validSession, version: 2 })).toThrow();
  });

  it("rejects missing fields", () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { session_key: _omitted, ...incomplete } = validSession;
    expect(() => sessionFileSchema.parse(incomplete)).toThrow();
  });

  it("rejects empty string for base64 fields", () => {
    expect(() => sessionFileSchema.parse({ ...validSession, session_key: "" })).toThrow();
  });

  it.each([
    "session_key",
    "wrapped_kek",
    "wrapped_kek_iv",
    "wrapped_kek_tag",
    "wrapped_jwt_key",
    "wrapped_jwt_key_iv",
    "wrapped_jwt_key_tag",
    "wrapped_audit_key",
    "wrapped_audit_key_iv",
    "wrapped_audit_key_tag",
  ] as const)("rejects empty string for %s", (field) => {
    expect(() => sessionFileSchema.parse({ ...validSession, [field]: "" })).toThrow();
  });

  it("rejects created_at: 0", () => {
    expect(() => sessionFileSchema.parse({ ...validSession, created_at: 0 })).toThrow();
  });

  it("rejects created_at: -1", () => {
    expect(() => sessionFileSchema.parse({ ...validSession, created_at: -1 })).toThrow();
  });

  it("rejects non-base64 string for session_key", () => {
    expect(() =>
      sessionFileSchema.parse({ ...validSession, session_key: "not base64!!!" }),
    ).toThrow();
  });

  it("rejects non-base64 string for wrapped_kek", () => {
    expect(() =>
      sessionFileSchema.parse({ ...validSession, wrapped_kek: "%%%invalid%%%" }),
    ).toThrow();
  });

  it("accepts every key_protection scheme", () => {
    for (const scheme of ["none", "dpapi", "keychain", "secret-service", "keyring"] as const) {
      expect(
        sessionFileSchema.parse({ ...validSession, key_protection: scheme }).key_protection,
      ).toBe(scheme);
    }
  });

  it("requires key_protection (a field-less file is refused, forcing a re-unlock)", () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { key_protection: _omitted, ...withoutField } = validSession;
    expect(sessionFileSchema.safeParse(withoutField).success).toBe(false);
  });

  it("rejects unknown key_protection values", () => {
    expect(() => sessionFileSchema.parse({ ...validSession, key_protection: "tpm" })).toThrow();
  });
});

describe("auditChainAnchorSchema", () => {
  const validAnchor = {
    format: "harpoc-audit-anchor/1",
    vault_id: "9f1c2e34-0000-4000-8000-000000000000",
    last_id: 4213,
    timestamp: 1784306411000,
    row_hmac: "a".repeat(64),
  };

  it("parses a valid anchor", () => {
    expect(auditChainAnchorSchema.parse(validAnchor)).toEqual(validAnchor);
  });

  it("round-trips through JSON", () => {
    const parsed = auditChainAnchorSchema.parse(JSON.parse(JSON.stringify(validAnchor)));
    expect(parsed).toEqual(validAnchor);
  });

  it("rejects a wrong format literal", () => {
    expect(() =>
      auditChainAnchorSchema.parse({ ...validAnchor, format: "harpoc-audit-anchor/2" }),
    ).toThrow();
    expect(() => auditChainAnchorSchema.parse({ ...validAnchor, format: "anchor" })).toThrow();
  });

  it.each(["format", "vault_id", "last_id", "timestamp", "row_hmac"] as const)(
    "rejects a missing %s field",
    (field) => {
      const partial = Object.fromEntries(
        Object.entries(validAnchor).filter(([key]) => key !== field),
      );
      expect(() => auditChainAnchorSchema.parse(partial)).toThrow();
    },
  );

  it("rejects unknown extra keys (strict)", () => {
    expect(() => auditChainAnchorSchema.parse({ ...validAnchor, extra: 1 })).toThrow();
  });

  it("rejects an uppercase row_hmac", () => {
    expect(() =>
      auditChainAnchorSchema.parse({ ...validAnchor, row_hmac: "A".repeat(64) }),
    ).toThrow();
  });

  it("rejects a short or long row_hmac", () => {
    expect(() =>
      auditChainAnchorSchema.parse({ ...validAnchor, row_hmac: "a".repeat(63) }),
    ).toThrow();
    expect(() =>
      auditChainAnchorSchema.parse({ ...validAnchor, row_hmac: "a".repeat(65) }),
    ).toThrow();
  });

  it("rejects non-hex characters in row_hmac", () => {
    expect(() =>
      auditChainAnchorSchema.parse({ ...validAnchor, row_hmac: "g".repeat(64) }),
    ).toThrow();
  });

  it("rejects a non-integer or non-positive last_id", () => {
    expect(() => auditChainAnchorSchema.parse({ ...validAnchor, last_id: 1.5 })).toThrow();
    expect(() => auditChainAnchorSchema.parse({ ...validAnchor, last_id: 0 })).toThrow();
    expect(() => auditChainAnchorSchema.parse({ ...validAnchor, last_id: "4213" })).toThrow();
  });

  it("rejects an empty vault_id", () => {
    expect(() => auditChainAnchorSchema.parse({ ...validAnchor, vault_id: "" })).toThrow();
  });
});
