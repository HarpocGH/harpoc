import { describe, it, expect } from "vitest";
import { connect as tlsConnect } from "node:tls";
import { ECHO_HTTPS, ATTACKER, assertFleetUp } from "./backends.js";

/** Handshake against the bound socket under an arbitrary SNI/verification name. */
function handshakeAs(servername: string): Promise<{ authorized: boolean; error?: string }> {
  return new Promise((resolve) => {
    const socket = tlsConnect({ host: ECHO_HTTPS.ip, port: ECHO_HTTPS.port, servername }, () => {
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
 * Smoke coverage for the TLS echo backend, ahead of the http demonstration cell
 * that depends on it. Three things are proven here so a cell failure later can
 * only be about the vault:
 *
 *  1. a real TLS handshake succeeds against a private-CA certificate — the
 *     first one on the http path (the database arms hold the only other),
 *  2. the certificate verifies by NAME, so `NODE_EXTRA_CA_CERTS` reached this
 *     process from the `test:e2e` wrapper and the SANs cover the address used,
 *  3. the service reflects the credential in exactly the encodings the vault's
 *     `filtered` mode redacts, and echoes the benign marker untouched.
 */
const BASE = `https://${ECHO_HTTPS.host}:${String(ECHO_HTTPS.port)}`;

describe("echo-https backend", () => {
  it("completes a verified TLS handshake and reflects every encoding", async () => {
    assertFleetUp("echo-https");

    const credential = "echo-smoke-credential-1";
    const marker = "echo-smoke-marker-1";
    const response = await fetch(`${BASE}/echo`, {
      headers: {
        authorization: `Bearer ${credential}`,
        [ECHO_HTTPS.markerHeader]: marker,
      },
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      marker: string | null;
      credential: Record<string, string> | null;
    };

    expect(body.marker).toBe(marker);
    const bytes = Buffer.from(credential, "utf8");
    expect(body.credential).toEqual({
      raw: credential,
      base64: bytes.toString("base64"),
      base64url: bytes.toString("base64url"),
      hex: bytes.toString("hex"),
      hex_upper: bytes.toString("hex").toUpperCase(),
      percent: encodeURIComponent(credential),
    });
    expect(response.headers.get("x-echo-credential")).toBe(credential);
  });

  it("is reachable as the IP literal too (the cell's fallback address)", async () => {
    assertFleetUp("echo-https");
    const response = await fetch(`https://${ECHO_HTTPS.ip}:${String(ECHO_HTTPS.port)}/health`);
    expect(response.status).toBe(200);
  });

  /**
   * Phase 4 channels. They live on their own paths so `/echo` — which the
   * Phase 3 demonstration cells depend on byte for byte — stays frozen (D7): a
   * demonstration cell must never fail for a scenario's reason.
   */
  describe("phase 4 scenario channels", () => {
    const credential = "echo-phase4-credential-1";

    it("keeps /echo frozen: no partial or out-of-set forms leak into it", async () => {
      assertFleetUp("echo-https");
      const response = await fetch(`${BASE}/echo`, {
        headers: { authorization: `Bearer ${credential}` },
      });
      const body = (await response.json()) as { credential: Record<string, string> };
      // Exactly the set the vault's `filtered` mode redacts, and nothing else.
      expect(Object.keys(body.credential).sort()).toEqual([
        "base64",
        "base64url",
        "hex",
        "hex_upper",
        "percent",
        "raw",
      ]);
    });

    it("returns substrings of the credential on /echo/partial", async () => {
      assertFleetUp("echo-https");
      const response = await fetch(`${BASE}/echo/partial`, {
        headers: { authorization: `Bearer ${credential}` },
      });
      expect(response.status).toBe(200);
      const body = (await response.json()) as Record<string, string>;

      // Contiguous-pattern matching cannot catch these by construction — that
      // is the §6.2.7 class-2 residual, and it needs a real emitter to measure.
      expect(body["first8"]).toBe(credential.slice(0, 8));
      expect(body["last4"]).toBe(credential.slice(-4));
      expect(body["alternating"]).toBe(
        credential
          .split("")
          .filter((_, i) => i % 2 === 0)
          .join(""),
      );
      // A partial echo must not accidentally contain the whole credential, or
      // the arm would measure the wrong class.
      expect(JSON.stringify(body)).not.toContain(credential);
    });

    it("puts the credential in the status reason phrase on /echo/reason", async () => {
      assertFleetUp("echo-https");
      const response = await fetch(`${BASE}/echo/reason`, {
        headers: { authorization: `Bearer ${credential}` },
      });
      expect(response.status).toBe(200);
      // fetch surfaces the reason phrase as statusText; the vault's HttpResult
      // has no such field, which is the point of the D9 arm.
      expect(response.statusText).toContain(credential);
    });

    it("redirects to the attacker sink, carrying the credential in the target", async () => {
      assertFleetUp("echo-https");
      const response = await fetch(`${BASE}/redirect-to-attacker`, {
        headers: { authorization: `Bearer ${credential}` },
        redirect: "manual",
      });
      expect(response.status).toBe(302);
      const location = response.headers.get("location") ?? "";
      // H2: an endpoint-authored redirect target that embeds the credential.
      // A refusal message quoting this URL would leak it to the model.
      expect(location).toContain(String(ATTACKER.port));
      expect(location).toContain(credential);
    });
  });

  it("verifies the certificate by name — an unlisted name is refused", async () => {
    assertFleetUp("echo-https");

    // Same bound socket, same certificate, only the verification name differs:
    // the SANs are DNS:echo-https, DNS:localhost and IP:127.0.0.1. A name
    // outside that set must fail, which is what makes the successes above
    // evidence of a *verified* handshake rather than of a disabled check.
    expect(await handshakeAs("localhost")).toMatchObject({ authorized: true });
    const foreign = await handshakeAs("not-in-the-san.example");
    expect(foreign.authorized).toBe(false);
    expect(foreign.error ?? "").toMatch(/altname|hostname|certificate/i);
  });
});
