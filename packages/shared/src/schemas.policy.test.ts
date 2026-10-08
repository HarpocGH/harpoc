import { describe, expect, it } from "vitest";
import { z } from "zod";

import {
  accessPolicyInputSchema,
  connectionConfigSchema,
  injectionPolicyInputSchema,
  injectionPolicySchema,
  setInjectionPolicyRequestSchema,
} from "./schemas.js";
import type { InjectionPolicy, SetInjectionPolicyRequest } from "./schemas.js";

// ---------------------------------------------------------------------------
// injectionPolicyInputSchema
// ---------------------------------------------------------------------------

describe("injectionPolicyInputSchema", () => {
  it("defaults all allowlists to empty arrays and response_mode to filtered", () => {
    const result = injectionPolicyInputSchema.parse({});
    expect(result).toEqual({
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
      strict_tree_exit: false,
    });
  });

  it("round-trips network_isolation true", () => {
    const enabled = injectionPolicyInputSchema.parse({ network_isolation: true });
    expect(enabled.network_isolation).toBe(true);
    expect(
      injectionPolicyInputSchema.parse(JSON.parse(JSON.stringify(enabled))).network_isolation,
    ).toBe(true);
  });

  it("accepts a legacy body without network_isolation (REST back-compat)", () => {
    const result = injectionPolicyInputSchema.parse({
      url_allowlist: ["https://api.github.com/*"],
      response_mode: "status_only",
    });
    expect(result.network_isolation).toBe(false);
    expect(result.response_mode).toBe("status_only");
  });

  it("rejects a non-boolean network_isolation", () => {
    expect(() => injectionPolicyInputSchema.parse({ network_isolation: "yes" })).toThrow();
    expect(() => injectionPolicyInputSchema.parse({ network_isolation: 1 })).toThrow();
  });

  it("fs_isolation accepts explicit true", () => {
    expect(injectionPolicyInputSchema.parse({ fs_isolation: true }).fs_isolation).toBe(true);
  });

  it("accepts populated allowlists", () => {
    const result = injectionPolicyInputSchema.parse({
      url_allowlist: ["https://api.github.com/*"],
      command_allowlist: ["gh", "/usr/bin/git"],
      env_allowlist: ["PATH", "HOME"],
    });
    expect(result.command_allowlist).toEqual(["gh", "/usr/bin/git"]);
  });

  it("rejects an invalid env var name in env_allowlist", () => {
    expect(() => injectionPolicyInputSchema.parse({ env_allowlist: ["has-dash"] })).toThrow();
  });

  it("rejects an empty command allowlist entry", () => {
    expect(() => injectionPolicyInputSchema.parse({ command_allowlist: [""] })).toThrow();
  });

  it("accepts response_mode and response_header_allowlist", () => {
    const result = injectionPolicyInputSchema.parse({
      response_mode: "status_only",
      response_header_allowlist: ["Content-Type", "X-Request-Id"],
    });
    expect(result.response_mode).toBe("status_only");
    expect(result.response_header_allowlist).toEqual(["Content-Type", "X-Request-Id"]);
  });

  it("rejects an invalid response_mode", () => {
    expect(() => injectionPolicyInputSchema.parse({ response_mode: "raw" })).toThrow();
  });

  it("rejects invalid response header names", () => {
    expect(() =>
      injectionPolicyInputSchema.parse({ response_header_allowlist: ["Bad: Header"] }),
    ).toThrow();
    expect(() =>
      injectionPolicyInputSchema.parse({ response_header_allowlist: ["x\r\ny"] }),
    ).toThrow();
    expect(() => injectionPolicyInputSchema.parse({ response_header_allowlist: [""] })).toThrow();
  });

  it("refuses an unknown key, naming it (strict — D2c)", () => {
    const parsed = injectionPolicyInputSchema.safeParse({ network_isolaton: true });
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(parsed.error.issues[0]?.message).toBe('Unrecognized key: "network_isolaton"');
    }
  });

  it("refuses a recipient pattern longer than 320 characters", () => {
    const at320 = `${"a".repeat(308)}@example.com`;
    expect(
      injectionPolicyInputSchema.safeParse({ smtp_recipient_allowlist: [at320] }).success,
    ).toBe(true);
    expect(
      injectionPolicyInputSchema.safeParse({ smtp_recipient_allowlist: [`a${at320}`] }).success,
    ).toBe(false);
  });
});

describe("injectionPolicySchema (the stored-blob shape, R2/C43)", () => {
  const complete = {
    url_allowlist: ["https://api.example.com/*"],
    command_allowlist: ["/usr/bin/gh"],
    env_allowlist: ["HOME"],
    host_allowlist: ["db.example.com:5432"],
    response_mode: "filtered",
    response_header_allowlist: ["content-type"],
    network_isolation: false,
    fs_isolation: true,
    smtp_recipient_allowlist: ["*@example.com"],
    imap_read_only: false,
    strict_tree_exit: false,
  };

  it("accepts a complete policy unchanged", () => {
    expect(injectionPolicySchema.parse(complete)).toEqual(complete);
  });

  it("refuses a missing key, naming it", () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { strict_tree_exit: _dropped, ...partial } = complete;
    const result = injectionPolicySchema.safeParse(partial);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.map((i) => i.path.join("."))).toContain("strict_tree_exit");
    }
  });

  it("refuses an unknown key (strict)", () => {
    expect(injectionPolicySchema.safeParse({ ...complete, extra: 1 }).success).toBe(false);
  });

  it("applies no defaults — an empty object is eleven misses", () => {
    const result = injectionPolicySchema.safeParse({});
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error.issues).toHaveLength(11);
  });

  it("shares the field validators with the input schema", () => {
    expect(
      injectionPolicySchema.safeParse({ ...complete, smtp_recipient_allowlist: ["*@*"] }).success,
    ).toBe(false);
    expect(injectionPolicySchema.safeParse({ ...complete, env_allowlist: ["1BAD"] }).success).toBe(
      false,
    );
    expect(Object.keys(injectionPolicySchema.shape)).toEqual(
      Object.keys(injectionPolicyInputSchema.shape),
    );
  });

  it("compile-time pin: InjectionPolicy is the input schema's output shape", () => {
    type Equal<A, B> =
      (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
    const identical: Equal<InjectionPolicy, z.output<typeof injectionPolicyInputSchema>> = true;
    expect(identical).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// setInjectionPolicyRequestSchema
// ---------------------------------------------------------------------------

describe("setInjectionPolicyRequestSchema", () => {
  const complete = {
    url_allowlist: ["https://api.github.com/*"],
    command_allowlist: ["gh"],
    env_allowlist: ["HOME"],
    host_allowlist: ["db.internal:5432"],
    response_mode: "filtered",
    response_header_allowlist: ["Content-Type"],
    network_isolation: false,
    fs_isolation: false,
    smtp_recipient_allowlist: ["*@corp.example"],
    imap_read_only: false,
    strict_tree_exit: false,
  };

  it("is the stored policy shape plus the acknowledgement flag (key-set pin)", () => {
    expect(Object.keys(setInjectionPolicyRequestSchema.shape)).toEqual([
      ...Object.keys(injectionPolicySchema.shape),
      "acknowledge_interpreters",
    ]);
  });

  it.each(Object.keys(injectionPolicySchema.shape))(
    "refuses a body omitting %s, naming the field (R3)",
    (field) => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { [field]: _omitted, ...partial } = complete as Record<string, unknown>;
      const result = setInjectionPolicyRequestSchema.safeParse(partial);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues.map((i) => i.path.join("."))).toContain(field);
      }
    },
  );

  it("refuses an unknown key (strict — inherited from injectionPolicySchema through .extend)", () => {
    const result = setInjectionPolicyRequestSchema.safeParse({
      ...complete,
      fs_isolaton: true,
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).toContain('Unrecognized key: "fs_isolaton"');
    }
  });

  it("acknowledge_interpreters is optional and defaults to false", () => {
    const result = setInjectionPolicyRequestSchema.parse(complete);
    expect(result.acknowledge_interpreters).toBe(false);
    expect(
      setInjectionPolicyRequestSchema.parse({
        ...complete,
        acknowledge_interpreters: true,
      }).acknowledge_interpreters,
    ).toBe(true);
  });

  it("refuses a non-boolean acknowledge_interpreters", () => {
    expect(
      setInjectionPolicyRequestSchema.safeParse({
        ...complete,
        acknowledge_interpreters: "yes",
      }).success,
    ).toBe(false);
  });

  it("compile-time pin: SetInjectionPolicyRequest requires every policy key and leaves the flag optional", () => {
    const full: SetInjectionPolicyRequest = {
      ...complete,
      response_mode: "filtered",
    };
    // @ts-expect-error — a partial policy is not a request body
    const partial: SetInjectionPolicyRequest = { url_allowlist: [] };
    expect(full.acknowledge_interpreters).toBeUndefined();
    expect(partial).toBeDefined();
  });

  it("still validates the policy fields", () => {
    expect(() =>
      setInjectionPolicyRequestSchema.parse({
        ...complete,
        command_allowlist: [""],
        acknowledge_interpreters: true,
      }),
    ).toThrow();
  });
});

// ---------------------------------------------------------------------------
// accessPolicyInputSchema
// ---------------------------------------------------------------------------

describe("accessPolicyInputSchema", () => {
  it("accepts valid policy", () => {
    const result = accessPolicyInputSchema.parse({
      principal_type: "agent",
      principal_id: "claude-code",
      permissions: ["read", "use"],
    });
    expect(result.principal_type).toBe("agent");
    expect(result.permissions).toEqual(["read", "use"]);
  });

  it("rejects empty permissions array", () => {
    expect(() =>
      accessPolicyInputSchema.parse({
        principal_type: "agent",
        principal_id: "claude-code",
        permissions: [],
      }),
    ).toThrow();
  });

  it("rejects empty principal_id", () => {
    expect(() =>
      accessPolicyInputSchema.parse({
        principal_type: "agent",
        principal_id: "",
        permissions: ["read"],
      }),
    ).toThrow();
  });

  it("rejects expires_at: 0", () => {
    expect(() =>
      accessPolicyInputSchema.parse({
        principal_type: "agent",
        principal_id: "claude-code",
        permissions: ["read"],
        expires_at: 0,
      }),
    ).toThrow();
  });

  it("rejects expires_at: -1", () => {
    expect(() =>
      accessPolicyInputSchema.parse({
        principal_type: "agent",
        principal_id: "claude-code",
        permissions: ["read"],
        expires_at: -1,
      }),
    ).toThrow();
  });

  it("refuses an agent-type principal_id that is not a valid agent name (C34)", () => {
    const base = { permissions: ["read"] as const, principal_type: "agent" as const };
    expect(accessPolicyInputSchema.safeParse({ ...base, principal_id: "a b" }).success).toBe(false);
    expect(accessPolicyInputSchema.safeParse({ ...base, principal_id: "svc-1" }).success).toBe(
      true,
    );
    // tool/user principals stay free-string.
    expect(
      accessPolicyInputSchema.safeParse({ ...base, principal_type: "tool", principal_id: "a b" })
        .success,
    ).toBe(true);
  });
});

describe("connectionConfigSchema", () => {
  const CA = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

  it("accepts a git group carrying a CA PEM", () => {
    const parsed = connectionConfigSchema.safeParse({ git: { ca_pem: CA } });
    expect(parsed.success).toBe(true);
    if (parsed.success) expect(parsed.data.git).toEqual({ ca_pem: CA });
  });

  it("refuses a git group without ca_pem", () => {
    expect(connectionConfigSchema.safeParse({ git: {} }).success).toBe(false);
  });

  it("accepts an http group carrying a CA PEM alone (D2h)", () => {
    const parsed = connectionConfigSchema.safeParse({ http: { ca_pem: CA } });
    expect(parsed.success).toBe(true);
    if (parsed.success) expect(parsed.data.http).toEqual({ ca_pem: CA });
  });

  it("refuses an http group without ca_pem (D2h)", () => {
    expect(connectionConfigSchema.safeParse({ http: {} }).success).toBe(false);
  });

  it("refuses an empty config, naming all five groups", () => {
    const parsed = connectionConfigSchema.safeParse({});
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(parsed.error.issues[0]?.message).toBe(
        "connection config must set at least one of database, ssh, mail, git or http",
      );
    }
  });

  it("still accepts each existing group alone", () => {
    expect(connectionConfigSchema.safeParse({ database: { tls_mode: "require" } }).success).toBe(
      true,
    );
    expect(
      connectionConfigSchema.safeParse({ ssh: { known_hosts: ["h ssh-ed25519 AAAA"] } }).success,
    ).toBe(true);
    expect(connectionConfigSchema.safeParse({ mail: { tls: false } }).success).toBe(true);
  });
});
