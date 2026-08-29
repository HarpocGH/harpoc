import { describe, it, expect, vi, beforeEach } from "vitest";
import { Hono } from "hono";
import type { Agent, AgentPolicy, SetAgentPermissionsResult, VaultApiToken } from "@harpoc/shared";
import { VaultError } from "@harpoc/shared";
import { authMiddleware } from "../middleware/auth.js";
import { errorHandler } from "../middleware/error-handler.js";
import { createAgentRoutes } from "./agents.js";
import type { HarpocEnv } from "../types.js";

const ADMIN_TOKEN: VaultApiToken = {
  sub: "admin-agent",
  vault_id: "vault-1",
  scope: ["admin"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-admin",
  principal_type: "agent",
};

const READ_TOKEN: VaultApiToken = {
  ...ADMIN_TOKEN,
  sub: "read-agent",
  scope: ["read"],
  jti: "jti-read",
};

const MOCK_AGENT: Agent = {
  id: "agent-uuid-1",
  name: "deploy-bot",
  description: "ships things",
  owner: "platform",
  status: "active",
  created_at: 1000,
  updated_at: 1000,
  deactivated_at: null,
  last_active_at: 2000,
  active_tokens: 2,
  grants: 3,
};

const MOCK_AGENT_POLICY: AgentPolicy = {
  policy_id: "policy-1",
  secret_id: "secret-uuid-1",
  handle: "secret://test-key",
  permissions: ["read", "use"],
  expires_at: null,
  created_at: 1000,
};

const MOCK_SET_RESULT: SetAgentPermissionsResult = {
  policy: null,
  gated_before: false,
  gated_after: true,
};

/** The caller every route must thread into the engine (`callerFromToken(token, "rest")`). */
const ADMIN_CALLER = {
  principal_type: "agent",
  principal_id: "admin-agent",
  interface: "rest",
  // R7 (v1.4.1): callerFromToken marks every admin-scoped token. The mark
  // exempts user-type callers only — this agent-type caller stays gated.
  admin_scope: true,
};

function createMockEngine(token: VaultApiToken = ADMIN_TOKEN) {
  return {
    verifyToken: vi.fn().mockReturnValue(token),
    resolveSecretId: vi.fn().mockResolvedValue("secret-uuid-1"),
    listAgents: vi.fn().mockReturnValue([MOCK_AGENT]),
    registerAgent: vi.fn().mockReturnValue(MOCK_AGENT),
    getAgent: vi.fn().mockReturnValue(MOCK_AGENT),
    updateAgent: vi.fn().mockReturnValue(MOCK_AGENT),
    deactivateAgent: vi.fn().mockReturnValue({ revoked_tokens: 2 }),
    activateAgent: vi.fn().mockReturnValue(MOCK_AGENT),
    deleteAgent: vi.fn().mockReturnValue({ revoked_tokens: 2, removed_grants: 3 }),
    listAgentPolicies: vi.fn().mockReturnValue([MOCK_AGENT_POLICY]),
    setAgentPermissions: vi.fn().mockReturnValue(MOCK_SET_RESULT),
  };
}

function buildApp(engineForApp: ReturnType<typeof createMockEngine>): Hono<HarpocEnv> {
  const instance = new Hono<HarpocEnv>();
  instance.onError(errorHandler);
  instance.use("*", async (c, next) => {
    c.set("engine", engineForApp as never);
    await next();
  });
  instance.use("/api/v1/agents/*", authMiddleware);
  instance.route("/api/v1/agents", createAgentRoutes());
  return instance;
}

let app: Hono<HarpocEnv>;
let engine: ReturnType<typeof createMockEngine>;

beforeEach(() => {
  engine = createMockEngine();
  app = buildApp(engine);
});

const AUTH = { authorization: "Bearer valid-jwt" };
const JSON_AUTH = { ...AUTH, "content-type": "application/json" };

describe("GET /api/v1/agents", () => {
  it("lists active agents by default", async () => {
    const res = await app.request("/api/v1/agents", { headers: AUTH });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toHaveLength(1);
    expect(body.data[0].name).toBe("deploy-bot");
    expect(engine.listAgents).toHaveBeenCalledWith("active", ADMIN_CALLER);
  });

  it("forwards ?status=all", async () => {
    await app.request("/api/v1/agents?status=all", { headers: AUTH });
    expect(engine.listAgents).toHaveBeenCalledWith("all", ADMIN_CALLER);
  });

  it("forwards ?status=inactive", async () => {
    await app.request("/api/v1/agents?status=inactive", { headers: AUTH });
    expect(engine.listAgents).toHaveBeenCalledWith("inactive", ADMIN_CALLER);
  });

  it("rejects an unknown ?status= value before the engine call", async () => {
    const res = await app.request("/api/v1/agents?status=live", { headers: AUTH });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("SCHEMA_VALIDATION_ERROR");
    expect(engine.listAgents).not.toHaveBeenCalled();
  });

  it("requires admin scope before the engine call", async () => {
    engine = createMockEngine(READ_TOKEN);
    app = buildApp(engine);
    const res = await app.request("/api/v1/agents", { headers: AUTH });
    expect(res.status).toBe(403);
    expect(engine.listAgents).not.toHaveBeenCalled();
  });

  it("requires auth", async () => {
    const res = await app.request("/api/v1/agents");
    expect(res.status).toBe(401);
  });
});

describe("POST /api/v1/agents", () => {
  it("registers an agent and answers 201", async () => {
    const res = await app.request("/api/v1/agents", {
      method: "POST",
      headers: JSON_AUTH,
      body: JSON.stringify({ name: "deploy-bot", description: "ships things", owner: "platform" }),
    });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.data.name).toBe("deploy-bot");
    expect(engine.registerAgent).toHaveBeenCalledWith(
      { name: "deploy-bot", description: "ships things", owner: "platform" },
      ADMIN_CALLER,
    );
  });

  it("rejects a malformed name before the engine call", async () => {
    const res = await app.request("/api/v1/agents", {
      method: "POST",
      headers: JSON_AUTH,
      body: JSON.stringify({ name: "bad name" }),
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("SCHEMA_VALIDATION_ERROR");
    expect(engine.registerAgent).not.toHaveBeenCalled();
  });

  it("rejects an empty body with the framing message", async () => {
    const res = await app.request("/api/v1/agents", { method: "POST", headers: JSON_AUTH });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("SCHEMA_VALIDATION_ERROR");
    expect(body.message).toBe("Request body must be valid JSON");
    expect(engine.registerAgent).not.toHaveBeenCalled();
  });

  it("rejects a malformed JSON body with the framing message", async () => {
    const res = await app.request("/api/v1/agents", {
      method: "POST",
      headers: JSON_AUTH,
      body: "{not json",
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.message).toBe("Request body must be valid JSON");
  });

  it("maps AGENT_EXISTS to 409", async () => {
    engine.registerAgent.mockImplementation(() => {
      throw VaultError.agentExists("deploy-bot");
    });
    const res = await app.request("/api/v1/agents", {
      method: "POST",
      headers: JSON_AUTH,
      body: JSON.stringify({ name: "deploy-bot" }),
    });
    expect(res.status).toBe(409);
    const body = await res.json();
    expect(body.error).toBe("AGENT_EXISTS");
  });

  it("requires admin scope before the engine call", async () => {
    engine = createMockEngine(READ_TOKEN);
    app = buildApp(engine);
    const res = await app.request("/api/v1/agents", {
      method: "POST",
      headers: JSON_AUTH,
      body: JSON.stringify({ name: "deploy-bot" }),
    });
    expect(res.status).toBe(403);
    expect(engine.registerAgent).not.toHaveBeenCalled();
  });
});

describe("GET /api/v1/agents/:name", () => {
  it("returns one agent", async () => {
    const res = await app.request("/api/v1/agents/deploy-bot", { headers: AUTH });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data.name).toBe("deploy-bot");
    expect(engine.getAgent).toHaveBeenCalledWith("deploy-bot", ADMIN_CALLER);
  });

  it("maps AGENT_NOT_FOUND to 404", async () => {
    engine.getAgent.mockImplementation(() => {
      throw VaultError.agentNotFound("ghost");
    });
    const res = await app.request("/api/v1/agents/ghost", { headers: AUTH });
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error).toBe("AGENT_NOT_FOUND");
  });

  it("rejects a malformed :name before the engine call", async () => {
    const res = await app.request("/api/v1/agents/bad%20name", { headers: AUTH });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("SCHEMA_VALIDATION_ERROR");
    expect(engine.getAgent).not.toHaveBeenCalled();
  });

  it("requires admin scope before the engine call", async () => {
    engine = createMockEngine(READ_TOKEN);
    app = buildApp(engine);
    const res = await app.request("/api/v1/agents/deploy-bot", { headers: AUTH });
    expect(res.status).toBe(403);
    expect(engine.getAgent).not.toHaveBeenCalled();
  });
});

describe("PUT /api/v1/agents/:name", () => {
  it("replaces the agent's metadata", async () => {
    const res = await app.request("/api/v1/agents/deploy-bot", {
      method: "PUT",
      headers: JSON_AUTH,
      body: JSON.stringify({ description: "new", owner: "sre" }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data.name).toBe("deploy-bot");
    expect(engine.updateAgent).toHaveBeenCalledWith(
      "deploy-bot",
      { description: "new", owner: "sre" },
      ADMIN_CALLER,
    );
  });

  it("rejects a malformed :name before the engine call", async () => {
    const res = await app.request("/api/v1/agents/bad%20name", {
      method: "PUT",
      headers: JSON_AUTH,
      body: JSON.stringify({ description: "new" }),
    });
    expect(res.status).toBe(400);
    expect(engine.updateAgent).not.toHaveBeenCalled();
  });

  it("rejects an empty body with the framing message", async () => {
    const res = await app.request("/api/v1/agents/deploy-bot", {
      method: "PUT",
      headers: JSON_AUTH,
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.message).toBe("Request body must be valid JSON");
    expect(engine.updateAgent).not.toHaveBeenCalled();
  });

  it("maps AGENT_NOT_FOUND to 404", async () => {
    engine.updateAgent.mockImplementation(() => {
      throw VaultError.agentNotFound("ghost");
    });
    const res = await app.request("/api/v1/agents/ghost", {
      method: "PUT",
      headers: JSON_AUTH,
      body: JSON.stringify({ description: "new" }),
    });
    expect(res.status).toBe(404);
  });

  it("requires admin scope before the engine call", async () => {
    engine = createMockEngine(READ_TOKEN);
    app = buildApp(engine);
    const res = await app.request("/api/v1/agents/deploy-bot", {
      method: "PUT",
      headers: JSON_AUTH,
      body: JSON.stringify({ description: "new" }),
    });
    expect(res.status).toBe(403);
    expect(engine.updateAgent).not.toHaveBeenCalled();
  });
});

describe("POST /api/v1/agents/:name/deactivate", () => {
  it("deactivates and reports the revoked-token count", async () => {
    const res = await app.request("/api/v1/agents/deploy-bot/deactivate", {
      method: "POST",
      headers: AUTH,
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toEqual({ revoked_tokens: 2 });
    expect(engine.deactivateAgent).toHaveBeenCalledWith("deploy-bot", ADMIN_CALLER);
  });

  it("reads no body — a body-less POST succeeds", async () => {
    const res = await app.request("/api/v1/agents/deploy-bot/deactivate", {
      method: "POST",
      headers: { ...AUTH, "content-type": "application/json" },
    });
    expect(res.status).toBe(200);
  });

  it("rejects a malformed :name before the engine call", async () => {
    const res = await app.request("/api/v1/agents/bad%20name/deactivate", {
      method: "POST",
      headers: AUTH,
    });
    expect(res.status).toBe(400);
    expect(engine.deactivateAgent).not.toHaveBeenCalled();
  });

  it("maps AGENT_NOT_FOUND to 404", async () => {
    engine.deactivateAgent.mockImplementation(() => {
      throw VaultError.agentNotFound("ghost");
    });
    const res = await app.request("/api/v1/agents/ghost/deactivate", {
      method: "POST",
      headers: AUTH,
    });
    expect(res.status).toBe(404);
  });

  it("requires admin scope before the engine call", async () => {
    engine = createMockEngine(READ_TOKEN);
    app = buildApp(engine);
    const res = await app.request("/api/v1/agents/deploy-bot/deactivate", {
      method: "POST",
      headers: AUTH,
    });
    expect(res.status).toBe(403);
    expect(engine.deactivateAgent).not.toHaveBeenCalled();
  });
});

describe("POST /api/v1/agents/:name/activate", () => {
  it("activates and returns the agent", async () => {
    const res = await app.request("/api/v1/agents/deploy-bot/activate", {
      method: "POST",
      headers: AUTH,
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data.name).toBe("deploy-bot");
    expect(engine.activateAgent).toHaveBeenCalledWith("deploy-bot", ADMIN_CALLER);
  });

  it("rejects a malformed :name before the engine call", async () => {
    const res = await app.request("/api/v1/agents/bad%20name/activate", {
      method: "POST",
      headers: AUTH,
    });
    expect(res.status).toBe(400);
    expect(engine.activateAgent).not.toHaveBeenCalled();
  });

  it("requires admin scope before the engine call", async () => {
    engine = createMockEngine(READ_TOKEN);
    app = buildApp(engine);
    const res = await app.request("/api/v1/agents/deploy-bot/activate", {
      method: "POST",
      headers: AUTH,
    });
    expect(res.status).toBe(403);
    expect(engine.activateAgent).not.toHaveBeenCalled();
  });
});

describe("DELETE /api/v1/agents/:name", () => {
  it("deletes and reports both counts", async () => {
    const res = await app.request("/api/v1/agents/deploy-bot", {
      method: "DELETE",
      headers: AUTH,
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toEqual({ revoked_tokens: 2, removed_grants: 3 });
    expect(engine.deleteAgent).toHaveBeenCalledWith("deploy-bot", ADMIN_CALLER);
  });

  it("rejects a malformed :name before the engine call", async () => {
    const res = await app.request("/api/v1/agents/bad%20name", {
      method: "DELETE",
      headers: AUTH,
    });
    expect(res.status).toBe(400);
    expect(engine.deleteAgent).not.toHaveBeenCalled();
  });

  it("maps AGENT_NOT_FOUND to 404", async () => {
    engine.deleteAgent.mockImplementation(() => {
      throw VaultError.agentNotFound("ghost");
    });
    const res = await app.request("/api/v1/agents/ghost", { method: "DELETE", headers: AUTH });
    expect(res.status).toBe(404);
  });

  it("requires admin scope before the engine call", async () => {
    engine = createMockEngine(READ_TOKEN);
    app = buildApp(engine);
    const res = await app.request("/api/v1/agents/deploy-bot", {
      method: "DELETE",
      headers: AUTH,
    });
    expect(res.status).toBe(403);
    expect(engine.deleteAgent).not.toHaveBeenCalled();
  });
});

describe("GET /api/v1/agents/:name/policies", () => {
  it("lists the agent's grants", async () => {
    const res = await app.request("/api/v1/agents/deploy-bot/policies", { headers: AUTH });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toHaveLength(1);
    expect(body.data[0].handle).toBe("secret://test-key");
    expect(engine.listAgentPolicies).toHaveBeenCalledWith("deploy-bot", ADMIN_CALLER);
  });

  it("rejects a malformed :name before the engine call", async () => {
    const res = await app.request("/api/v1/agents/bad%20name/policies", { headers: AUTH });
    expect(res.status).toBe(400);
    expect(engine.listAgentPolicies).not.toHaveBeenCalled();
  });

  it("requires admin scope before the engine call", async () => {
    engine = createMockEngine(READ_TOKEN);
    app = buildApp(engine);
    const res = await app.request("/api/v1/agents/deploy-bot/policies", { headers: AUTH });
    expect(res.status).toBe(403);
    expect(engine.listAgentPolicies).not.toHaveBeenCalled();
  });
});

describe("PUT /api/v1/agents/:name/secrets/:handle/permissions", () => {
  it("sets the matrix cell", async () => {
    const res = await app.request("/api/v1/agents/deploy-bot/secrets/test-key/permissions", {
      method: "PUT",
      headers: JSON_AUTH,
      body: JSON.stringify({ permissions: ["read", "use"], expires_at: 9999 }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toEqual({ policy: null, gated_before: false, gated_after: true });
    expect(engine.resolveSecretId).toHaveBeenCalledWith("secret://test-key");
    expect(engine.setAgentPermissions).toHaveBeenCalledWith(
      "deploy-bot",
      "secret-uuid-1",
      ["read", "use"],
      9999,
      "admin-agent",
      ADMIN_CALLER,
    );
  });

  it("passes an omitted expires_at through as undefined", async () => {
    await app.request("/api/v1/agents/deploy-bot/secrets/test-key/permissions", {
      method: "PUT",
      headers: JSON_AUTH,
      body: JSON.stringify({ permissions: [] }),
    });
    expect(engine.setAgentPermissions).toHaveBeenCalledWith(
      "deploy-bot",
      "secret-uuid-1",
      [],
      undefined,
      "admin-agent",
      ADMIN_CALLER,
    );
  });

  it("resolves a project-scoped handle", async () => {
    await app.request("/api/v1/agents/deploy-bot/secrets/myproj%2Ftest-key/permissions", {
      method: "PUT",
      headers: JSON_AUTH,
      body: JSON.stringify({ permissions: ["read"] }),
    });
    expect(engine.resolveSecretId).toHaveBeenCalledWith("secret://myproj/test-key");
  });

  // The cell touches one named secret, so the token's project/name dimensions
  // apply on top of the governance `admin` check.
  it("refuses a handle outside a project-scoped admin token", async () => {
    engine = createMockEngine({ ...ADMIN_TOKEN, project: "p" });
    app = buildApp(engine);
    const res = await app.request("/api/v1/agents/deploy-bot/secrets/q%2Fx/permissions", {
      method: "PUT",
      headers: JSON_AUTH,
      body: JSON.stringify({ permissions: ["read"] }),
    });
    expect(res.status).toBe(403);
    expect(engine.setAgentPermissions).not.toHaveBeenCalled();
    expect(engine.resolveSecretId).not.toHaveBeenCalled();
  });

  it("rejects a malformed :name before the engine call", async () => {
    const res = await app.request("/api/v1/agents/bad%20name/secrets/test-key/permissions", {
      method: "PUT",
      headers: JSON_AUTH,
      body: JSON.stringify({ permissions: ["read"] }),
    });
    expect(res.status).toBe(400);
    expect(engine.setAgentPermissions).not.toHaveBeenCalled();
    expect(engine.resolveSecretId).not.toHaveBeenCalled();
  });

  it("rejects an empty body with the framing message", async () => {
    const res = await app.request("/api/v1/agents/deploy-bot/secrets/test-key/permissions", {
      method: "PUT",
      headers: JSON_AUTH,
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.message).toBe("Request body must be valid JSON");
    expect(engine.setAgentPermissions).not.toHaveBeenCalled();
  });

  it("maps AGENT_INACTIVE to 403", async () => {
    engine.setAgentPermissions.mockImplementation(() => {
      throw VaultError.agentInactive("deploy-bot");
    });
    const res = await app.request("/api/v1/agents/deploy-bot/secrets/test-key/permissions", {
      method: "PUT",
      headers: JSON_AUTH,
      body: JSON.stringify({ permissions: ["read"] }),
    });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toBe("AGENT_INACTIVE");
  });

  it("requires admin scope before the engine call", async () => {
    engine = createMockEngine(READ_TOKEN);
    app = buildApp(engine);
    const res = await app.request("/api/v1/agents/deploy-bot/secrets/test-key/permissions", {
      method: "PUT",
      headers: JSON_AUTH,
      body: JSON.stringify({ permissions: ["read"] }),
    });
    expect(res.status).toBe(403);
    expect(engine.setAgentPermissions).not.toHaveBeenCalled();
  });
});
