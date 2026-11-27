import { describe, expect, it } from "vitest";
import type { CallerContext, VaultApiToken } from "@harpoc/shared";
import { callerFromToken, proxySocketCaller } from "@harpoc/shared";
import {
  attributionFromCaller,
  callerColumns,
  callerInterfaceDetail,
  withAttribution,
} from "./attribution.js";
import type { AuditLogOptions } from "./audit-logger.js";

const CALLER: CallerContext = {
  principal_type: "agent",
  principal_id: "alice",
  interface: "rest",
};

describe("attributionFromCaller", () => {
  it("returns undefined when caller and session are both absent (trusted local, no session)", () => {
    expect(attributionFromCaller(undefined, null)).toBeUndefined();
    expect(attributionFromCaller(undefined, undefined)).toBeUndefined();
  });

  it("carries the principal, interface and session when all are present", () => {
    expect(attributionFromCaller(CALLER, "sess-1")).toEqual({
      principal_type: "agent",
      principal_id: "alice",
      interface: "rest",
      session_id: "sess-1",
    });
  });

  it("session-only for the trusted local path — rows stay session-attributed, never principal-attributed", () => {
    expect(attributionFromCaller(undefined, "sess-1")).toEqual({ session_id: "sess-1" });
  });

  it("omits the interface when the caller carries none", () => {
    const attribution = attributionFromCaller(
      { principal_type: "tool", principal_id: "ci" },
      "sess-1",
    );
    expect(attribution).toEqual({
      principal_type: "tool",
      principal_id: "ci",
      session_id: "sess-1",
    });
    expect(attribution && "interface" in attribution).toBe(false);
  });
});

describe("withAttribution", () => {
  const base = (): AuditLogOptions => ({
    eventType: "secret.use",
    secretId: "s-1",
    detail: { context: "process" },
    success: true,
  });

  it("returns the options untouched when there is no attribution", () => {
    const options = base();
    const merged = withAttribution(options, undefined);
    expect(merged).toBe(options);
    expect(merged.principalType).toBeUndefined();
    expect(merged.principalId).toBeUndefined();
    expect(merged.sessionId).toBeUndefined();
  });

  it("stamps principal and session as columns and the interface into detail", () => {
    const merged = withAttribution(base(), {
      principal_type: "agent",
      principal_id: "alice",
      session_id: "sess-1",
      interface: "mcp-http",
    });
    expect(merged.principalType).toBe("agent");
    expect(merged.principalId).toBe("alice");
    expect(merged.sessionId).toBe("sess-1");
    expect(merged.detail).toEqual({ context: "process", interface: "mcp-http" });
  });

  it("preserves the existing detail keys when merging the interface", () => {
    const merged = withAttribution(
      { eventType: "secret.use", detail: { a: 1, b: "x" } },
      { interface: "rest" },
    );
    expect(merged.detail).toEqual({ a: 1, b: "x", interface: "rest" });
  });

  it("creates a detail carrying only the interface when the entry had none", () => {
    const merged = withAttribution({ eventType: "secret.use" }, { interface: "mcp" });
    expect(merged.detail).toEqual({ interface: "mcp" });
  });

  it("leaves detail untouched for an interface-less attribution (local session)", () => {
    const merged = withAttribution(base(), { session_id: "sess-1" });
    expect(merged.sessionId).toBe("sess-1");
    expect(merged.detail).toEqual({ context: "process" });
    expect(merged.principalType).toBeUndefined();
  });
});

describe("callerInterfaceDetail", () => {
  it("is empty for an absent caller and for a caller without an interface", () => {
    expect(callerInterfaceDetail(undefined)).toEqual({});
    expect(callerInterfaceDetail({ principal_type: "agent", principal_id: "a" })).toEqual({});
  });

  it("carries the interface when set", () => {
    expect(callerInterfaceDetail(CALLER)).toEqual({ interface: "rest" });
  });
});

describe("remote_address → ip_address (E75i)", () => {
  it("attributionFromCaller carries the caller's socket peer", () => {
    expect(attributionFromCaller({ ...CALLER, remote_address: "10.0.0.7" }, "sess-1")).toEqual({
      principal_type: "agent",
      principal_id: "alice",
      interface: "rest",
      remote_address: "10.0.0.7",
      session_id: "sess-1",
    });
    expect("remote_address" in (attributionFromCaller(CALLER, "sess-1") ?? {})).toBe(false);
  });

  it("withAttribution lands the peer in ipAddress", () => {
    const base: AuditLogOptions = { eventType: "secret.use" };
    expect(withAttribution(base, { remote_address: "10.0.0.7" }).ipAddress).toBe("10.0.0.7");
    expect("ipAddress" in withAttribution(base, { principal_id: "alice" })).toBe(false);
  });
});

describe("tokenless", () => {
  const proxyUse = (): AuditLogOptions => ({
    eventType: "secret.use",
    detail: { context: "proxy" },
  });
  const proxyToken: VaultApiToken = {
    sub: "agent1",
    vault_id: "vault-1",
    scope: ["use"],
    iat: 0,
    exp: 2_000_000_000,
    jti: "jti-1",
    principal_type: "agent",
  };

  it("the detail built for a proxySocketCaller holds interface proxy and tokenless true", () => {
    const caller = proxySocketCaller("agent1", ["a", "b-*"]);
    const attribution = attributionFromCaller(caller, "sess-1");
    expect(attribution).toEqual({
      principal_type: "agent",
      principal_id: "agent1",
      interface: "proxy",
      tokenless: true,
      session_id: "sess-1",
    });
    expect(withAttribution(proxyUse(), attribution).detail).toEqual({
      context: "proxy",
      interface: "proxy",
      tokenless: true,
    });
    expect(callerInterfaceDetail(caller)).toEqual({ interface: "proxy", tokenless: true });
  });

  it('the detail built for a callerFromToken(…, "proxy") caller holds no tokenless key', () => {
    const caller = callerFromToken(proxyToken, "proxy");
    const attribution = attributionFromCaller(caller, "sess-1");
    expect("tokenless" in (attribution as object)).toBe(false);
    const detail = withAttribution(proxyUse(), attribution).detail;
    expect(detail).toEqual({ context: "proxy", interface: "proxy" });
    expect("tokenless" in (detail as object)).toBe(false);
    const engineDetail = callerInterfaceDetail(caller);
    expect(engineDetail).toEqual({ interface: "proxy" });
    expect("tokenless" in engineDetail).toBe(false);
  });
});

describe("callerColumns", () => {
  it("is empty for the trusted local path", () => {
    expect(callerColumns(undefined)).toEqual({});
  });

  it("carries type and id, and the peer only when the caller has one", () => {
    expect(callerColumns(CALLER)).toEqual({
      principalType: "agent",
      principalId: "alice",
    });
    expect(callerColumns({ ...CALLER, remote_address: "10.0.0.7" })).toEqual({
      principalType: "agent",
      principalId: "alice",
      ipAddress: "10.0.0.7",
    });
  });
});
