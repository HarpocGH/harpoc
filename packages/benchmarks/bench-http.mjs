// Scenario (c) — end-to-end use_secret (HTTP bearer) vs. a direct HTTP call.
// Thesis: Ch. 6 §Baseline Performance. Loopback target: plaintext HTTP to
// 127.0.0.1 is permitted by design (§4.5.2 loopback exception) and removes
// network RTT — the worst case for the RELATIVE overhead, so the headline
// figure is the ABSOLUTE delta of medians. Pass --remote-url <https://…> for
// an additional real-endpoint triple: direct with connection reuse, direct
// without it, and the vault — three measurements because the vault cannot reuse
// a connection and a two-way comparison silently charges it for that.

import { createServer } from "node:http";
import { Agent as HttpsAgent, request as httpsRequest } from "node:https";
import { randomBytes } from "node:crypto";

import { assertSane, isMain, measure, stats } from "./lib/harness.mjs";
import { printScenario } from "./lib/report.mjs";
import { createBenchSecret, createVault } from "./lib/vault-fixture.mjs";

const SAMPLES = 200;
const WARMUP = 20;

function startEchoServer() {
  let count = 0;
  const server = createServer((req, res) => {
    count += 1;
    res.setHeader("content-type", "application/json");
    res.end('{"ok":true}');
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({
        url: `http://127.0.0.1:${port}/`,
        getCount: () => count,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

export async function run({ remoteUrl } = {}) {
  const fx = await createVault();
  const echo = await startEchoServer();
  try {
    const token = `bench-${randomBytes(24).toString("base64url")}`;
    const handle = await createBenchSecret(fx.engine, "bench-http", Buffer.from(token, "utf8"));
    const action = { type: "http", method: "GET", url: echo.url, injection: { type: "bearer" } };

    // Probe both paths once before timing (fails fast on a miswired setup).
    const probeDirect = await fetch(echo.url, { headers: { authorization: `Bearer ${token}` } });
    await probeDirect.text();
    assertSane(probeDirect.status === 200, `direct probe returned ${probeDirect.status}`);
    const probeVault = await fx.engine.useSecret(handle, action);
    const probeStatus = probeVault?.result?.status ?? probeVault?.status;
    assertSane(probeStatus === 200, `vault probe returned ${JSON.stringify(probeStatus)}`);

    const before = echo.getCount();
    const directNs = await measure(
      async () => {
        const res = await fetch(echo.url, { headers: { authorization: `Bearer ${token}` } });
        await res.text();
      },
      { samples: SAMPLES, warmup: WARMUP },
    );
    const vaultNs = await measure(() => fx.engine.useSecret(handle, action), {
      samples: SAMPLES,
      warmup: WARMUP,
    });
    const requests = echo.getCount() - before;
    assertSane(
      requests === 2 * (SAMPLES + WARMUP),
      `loopback server saw ${requests} requests, expected ${2 * (SAMPLES + WARMUP)}`,
    );

    const direct = stats(directNs);
    const vault = stats(vaultNs);
    const deltaMs = Math.round((vault.medianMs - direct.medianMs) * 1000) / 1000;

    const metrics = {
      "direct fetch (loopback)": direct,
      "use_secret http/bearer (loopback)": vault,
    };
    const notes = [
      `Absolute overhead (median delta): ${deltaMs} ms — URL/SSRF validation with DNS pre-flight, policy load, value decrypt, audit write, response redaction (default \`filtered\` mode).`,
      "Loopback removes network RTT: this is the worst case for the relative figure; against a real endpoint the delta is amortized by the round-trip.",
    ];

    if (remoteUrl) {
      const remoteDirectNs = await measure(
        async () => {
          const res = await fetch(remoteUrl, { headers: { authorization: `Bearer ${token}` } });
          await res.text();
        },
        { samples: 30, warmup: 3 },
      );
      // Control: the same request WITHOUT connection reuse. Without it the
      // remote comparison is not like-for-like — `fetch` rides Node's global
      // keep-alive agent, while the injector builds a pinned dispatcher per
      // call and closes it (http-injector.ts), because the DNS-rebinding fix
      // pins the resolved address per request. So a naive remote delta charges
      // the vault for a TLS handshake the direct call never pays, which is
      // invisible on plaintext loopback and dominant against TLS.
      const remoteFreshNs = await measure(
        async () => {
          const agent = new HttpsAgent({ keepAlive: false });
          try {
            await new Promise((resolve, reject) => {
              const req = httpsRequest(
                remoteUrl,
                { agent, headers: { authorization: `Bearer ${token}` } },
                (res) => {
                  res.resume();
                  res.on("end", resolve);
                  res.on("error", reject);
                },
              );
              req.on("error", reject);
              req.end();
            });
          } finally {
            agent.destroy();
          }
        },
        { samples: 30, warmup: 3 },
      );
      const remoteAction = { ...action, url: remoteUrl };
      const remoteVaultNs = await measure(() => fx.engine.useSecret(handle, remoteAction), {
        samples: 30,
        warmup: 3,
      });
      const remoteDirect = stats(remoteDirectNs);
      const remoteFresh = stats(remoteFreshNs);
      const remoteVault = stats(remoteVaultNs);
      metrics[`direct fetch, connection reused (${remoteUrl})`] = remoteDirect;
      metrics[`direct request, fresh connection (${remoteUrl})`] = remoteFresh;
      metrics[`use_secret http/bearer (${remoteUrl})`] = remoteVault;
      const handshakeMs = Math.round((remoteFresh.medianMs - remoteDirect.medianMs) * 1000) / 1000;
      const vaultOwnMs = Math.round((remoteVault.medianMs - remoteFresh.medianMs) * 1000) / 1000;
      notes.push(
        `Remote TLS pair: ${String(handshakeMs)} ms of the vault-vs-reused-connection delta is the TLS handshake ` +
          `the vault cannot amortize (pinned dispatcher per call, DNS-rebinding defence); ` +
          `${String(vaultOwnMs)} ms is the vault's own work against the same endpoint on equal connection terms.`,
      );
      notes.push("Remote measurements use 30 samples; expect network variance to dominate.");
    }

    return {
      scenario: "http-end-to-end",
      thesis: "(c) end-to-end use_secret vs. direct HTTP call",
      metrics,
      notes,
    };
  } finally {
    await echo.close();
    await fx.cleanup();
  }
}

if (isMain(import.meta)) {
  const idx = process.argv.indexOf("--remote-url");
  const remoteUrl = idx !== -1 ? process.argv[idx + 1] : undefined;
  printScenario(await run({ remoteUrl }));
}
