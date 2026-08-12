// TLS echo backend for the E2E harness.
//
// Reflects the credential the vault injected back at the caller in several
// encodings, in the body and in a response header. That makes the response the
// adversarial channel thesis §4.5.2 calls I2a: the backend genuinely received
// the credential, so a redacted caller-visible result proves the vault's
// filtering, not the credential's absence.
//
// The reflection set is deliberately the set the vault's `filtered` mode
// redacts (raw, base64, base64url, hex in both cases, percent-encoded). Classes
// OUTSIDE that set belong to the Phase 4 response-channel-echo scenario, where
// a surviving encoding is the finding; emitting them here would make the
// demonstration cell fail for a reason the cell is not about.
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
