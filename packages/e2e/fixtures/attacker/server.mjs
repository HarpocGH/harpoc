// Exfiltration sink for the E2E harness — the endpoint the two-arm scenarios
// (C-3) try to move a credential to.
//
// This service is load-bearing for the whole two-arm construction. The baseline
// arm has to genuinely exfiltrate: without a reachable sink that records what
// arrived, "baseline leaks / Harpoc blocks" is an assertion rather than a
// controlled comparison with a visible effect.
//
// It serves TLS with a fixture-CA certificate on purpose. A Harpoc arm must be
// refused by the secret's URL allowlist — not by an unreachable host and not by
// an untrusted certificate, either of which would make the refusal prove the
// wrong thing (P4-R3).
//
//   ANY /<path>     recorded, then answered 200. This is the sink.
//   ANY /challenge/<path>  recorded, then answered 401 with a Basic challenge
//                   until credentials arrive. A client whose credential comes
//                   from a helper rather than the URL sends nothing until it is
//                   asked: curl (and therefore git) supplies a helper-held
//                   credential only in response to a 401, and drops a
//                   URL-embedded one across a host boundary. Without a
//                   challenging endpoint the git redirect and submodule arms
//                   would record a bodiless GET and read as "no leak", which is
//                   the false negative that makes a paired row vacuous.
//   GET  /health    liveness; NOT recorded.
//   GET  /recorded  harness-only side channel listing what arrived.
//   DELETE /recorded  empties the recorder.
//
// The control endpoints are excluded from recording deliberately: an arm's
// discriminating check is "the sink is empty", and a recorder that logged the
// GET which reads it could never be observed empty.
//
// `/leak` and the catch-all 200 are FROZEN: the Phase 4A arms depend on their
// exact shape, so a later scenario's needs land on a new path (the D7 rule the
// echo-https fixture already follows).
import { createServer } from "node:https";
import { readFileSync } from "node:fs";

const PORT = Number(process.env.PORT ?? 8444);
const CERT = process.env.CERT_PATH ?? "/pki/attacker.crt";
const KEY = process.env.KEY_PATH ?? "/pki/attacker.key";
const MAX_BODY_BYTES = 256 * 1024;
const MAX_RECORDED = 100;

/** Every request that reached the sink, oldest first. */
const recorded = [];

function readBody(req) {
  return new Promise((resolve) => {
    let size = 0;
    const chunks = [];
    req.on("data", (chunk) => {
      size += chunk.length;
      // Truncate rather than reject: a body over the cap is still evidence that
      // something arrived, and dropping the request would hide a leak.
      if (size <= MAX_BODY_BYTES) chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", () => resolve(""));
  });
}

const server = createServer({ cert: readFileSync(CERT), key: readFileSync(KEY) }, (req, res) => {
  void (async () => {
    const url = new URL(req.url ?? "/", "https://attacker");

    if (url.pathname === "/health") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
      return;
    }

    if (url.pathname === "/recorded") {
      if (req.method === "DELETE") {
        recorded.length = 0;
        res.writeHead(204);
        res.end();
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ requests: recorded }));
      return;
    }

    recorded.push({
      method: req.method ?? "",
      path: url.pathname,
      authorization: req.headers["authorization"] ?? null,
      headers: req.headers,
      query: Object.fromEntries(url.searchParams),
      body: await readBody(req),
    });
    if (recorded.length > MAX_RECORDED) recorded.shift();

    // Recorded BEFORE the branch, so the unauthenticated first hop is evidence
    // too: it proves the client reached the attacker even when it then declines
    // to authenticate.
    if (url.pathname.startsWith("/challenge") && !req.headers["authorization"]) {
      res.writeHead(401, {
        "www-authenticate": 'Basic realm="attacker"',
        "content-type": "text/plain",
      });
      res.end("unauthorized");
      return;
    }

    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
  })();
});

server.listen(PORT, "0.0.0.0", () => {
  process.stdout.write(`attacker listening on ${String(PORT)}\n`);
});
