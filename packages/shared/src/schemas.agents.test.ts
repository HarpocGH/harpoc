import { describe, expect, it } from "vitest";

import {
  agentNameSchema,
  listAgentsQuerySchema,
  listTokensQuerySchema,
  registerAgentInputSchema,
  setAgentPermissionsInputSchema,
  updateAgentInputSchema,
} from "./schemas.js";

// ---------------------------------------------------------------------------
// Agent governance schemas (v1.4)
// ---------------------------------------------------------------------------

describe("agentNameSchema", () => {
  it("accepts cli-user, web-ui and a_b", () => {
    for (const name of ["cli-user", "web-ui", "a_b"]) {
      expect(agentNameSchema.parse(name)).toBe(name);
    }
  });

  it("refuses a name with a space", () => {
    expect(() => agentNameSchema.parse("with space")).toThrow();
  });

  it("refuses a name with a dot", () => {
    expect(() => agentNameSchema.parse("a.b")).toThrow();
  });

  it("refuses a name longer than 255 characters", () => {
    expect(() => agentNameSchema.parse("a".repeat(256))).toThrow();
  });

  it("accepts a name of exactly 255 characters", () => {
    expect(agentNameSchema.parse("a".repeat(255))).toBe("a".repeat(255));
  });
});

describe("registerAgentInputSchema", () => {
  it("accepts a minimal valid input", () => {
    const result = registerAgentInputSchema.parse({ name: "claude-code" });
    expect(result.name).toBe("claude-code");
    expect(result.description).toBeUndefined();
    expect(result.owner).toBeUndefined();
  });

  it("accepts a description up to 1024 characters", () => {
    const description = "a".repeat(1024);
    const result = registerAgentInputSchema.parse({ name: "claude-code", description });
    expect(result.description).toBe(description);
  });

  it("refuses a description over 1024 characters", () => {
    expect(() =>
      registerAgentInputSchema.parse({ name: "claude-code", description: "a".repeat(1025) }),
    ).toThrow();
  });

  it("accepts an owner up to 255 characters", () => {
    const owner = "a".repeat(255);
    const result = registerAgentInputSchema.parse({ name: "claude-code", owner });
    expect(result.owner).toBe(owner);
  });

  it("refuses an owner over 255 characters", () => {
    expect(() =>
      registerAgentInputSchema.parse({ name: "claude-code", owner: "a".repeat(256) }),
    ).toThrow();
  });
});

describe("updateAgentInputSchema", () => {
  it("accepts an empty update and a description/owner update", () => {
    expect(updateAgentInputSchema.parse({})).toEqual({});
    const result = updateAgentInputSchema.parse({ description: "d", owner: "o" });
    expect(result.description).toBe("d");
    expect(result.owner).toBe("o");
  });

  it("refuses a description over the cap", () => {
    expect(() => updateAgentInputSchema.parse({ description: "a".repeat(1025) })).toThrow();
  });
});

describe("setAgentPermissionsInputSchema", () => {
  it("accepts an empty permissions array", () => {
    const result = setAgentPermissionsInputSchema.parse({ permissions: [] });
    expect(result.permissions).toEqual([]);
  });

  it("refuses an unknown permission", () => {
    expect(() => setAgentPermissionsInputSchema.parse({ permissions: ["manage"] })).toThrow();
  });

  it("accepts an expires_at", () => {
    const result = setAgentPermissionsInputSchema.parse({ permissions: ["read"], expires_at: 1 });
    expect(result.expires_at).toBe(1);
  });
});

describe("listAgentsQuerySchema", () => {
  it("accepts an empty query and a status filter", () => {
    expect(listAgentsQuerySchema.parse({})).toEqual({});
    expect(listAgentsQuerySchema.parse({ status: "active" }).status).toBe("active");
  });

  it("refuses an unknown status", () => {
    expect(() => listAgentsQuerySchema.parse({ status: "disabled" })).toThrow();
  });
});

describe("listTokensQuerySchema", () => {
  it("refuses status: 'live'", () => {
    expect(() => listTokensQuerySchema.parse({ status: "live" })).toThrow();
  });

  it("accepts a valid status filter and agent name", () => {
    const result = listTokensQuerySchema.parse({ status: "active", agent: "claude-code" });
    expect(result.status).toBe("active");
    expect(result.agent).toBe("claude-code");
  });
});
