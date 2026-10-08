import type { AccessPolicy, Agent, AgentPolicy, IssuedToken } from "@harpoc/shared";
import type { AuditEventWire, SecretInfo } from "../api/client";

/**
 * The page suites' fixture builders, one home each. Every builder returns a complete wire record
 * with neutral defaults; a test file wraps it under its own local name carrying only the defaults
 * its cases depend on. Test-only: no product module imports this file, and Vite bundles from
 * `main.tsx` alone.
 */

/** base64url without padding — the JWT segment alphabet. */
export const b64url = (text: string): string =>
  btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/** A three-segment token whose payload decodes — nothing here verifies one. */
export const unsignedJwt = (
  payload: unknown,
  header: unknown = { alg: "HS256", typ: "JWT" },
): string => `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}.signature`;

export const makeAgent = (over: Partial<Agent> = {}): Agent => ({
  id: "id-1",
  name: "ci-bot",
  description: "CI runner",
  owner: "platform",
  status: "active",
  created_at: 0,
  updated_at: 0,
  deactivated_at: null,
  last_active_at: null,
  active_tokens: 2,
  grants: 1,
  ...over,
});

export const makeSecret = (over: Partial<SecretInfo> = {}): SecretInfo => ({
  handle: "secret://k1",
  name: "k1",
  type: "api_key",
  project: null,
  status: "active",
  version: 1,
  createdAt: 0,
  updatedAt: 0,
  expiresAt: null,
  rotatedAt: null,
  ...over,
});

export const makeToken = (over: Partial<IssuedToken> = {}): IssuedToken => ({
  jti: "jti-1",
  subject: "ci-bot",
  principal_type: "agent",
  agent: "ci-bot",
  scope: ["read", "use"],
  project: null,
  secrets: null,
  label: "deploy",
  issued_at: 0,
  expires_at: 1700000000000,
  revoked_at: null,
  status: "active",
  ...over,
});

export const makeEvent = (over: Partial<AuditEventWire> = {}): AuditEventWire => ({
  id: 1,
  timestamp: 1700000000000,
  event_type: "secret.use",
  secret_id: null,
  principal_type: null,
  principal_id: null,
  detail: null,
  ip_address: null,
  session_id: null,
  success: true,
  ...over,
});

export const makeAgentPolicy = (over: Partial<AgentPolicy> = {}): AgentPolicy => ({
  policy_id: "p-1",
  secret_id: "s-1",
  handle: "secret://myproj/test-key",
  permissions: ["read", "use"],
  expires_at: null,
  created_at: 0,
  ...over,
});

export const makeAccessPolicy = (over: Partial<AccessPolicy> = {}): AccessPolicy => ({
  id: "ap-1",
  secret_id: "s-1",
  principal_type: "agent",
  principal_id: "ci-bot",
  permissions: ["read", "use"],
  created_at: 0,
  expires_at: null,
  created_by: "cli",
  ...over,
});
