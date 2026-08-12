import { describe, it, expect } from "vitest";
import { connect as tlsConnect } from "node:tls";
import { ECHO_HTTPS, assertFleetUp } from "./backends.js";

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
