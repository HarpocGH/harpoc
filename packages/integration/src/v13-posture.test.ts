import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AuditEventType } from "@harpoc/shared";
import type { UseSecretAction } from "@harpoc/shared";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { startFakeSmtp, FIXTURE_CA_PEM } from "./helpers/fake-smtp-server.js";
import { startFakeImap } from "./helpers/fake-imap-server.js";
import { startFakeWsServer } from "./helpers/fake-ws-server.js";
import { LOOPBACK_HOST } from "./helpers/loopback-cert.js";

/**
 * v1.3 Extended Injection Contexts — the opacity sweep (Task 17), the thesis's
 * central claim carried onto the five new contexts: no context leaks the
 * credential it injects through any observable channel. A distinctive
 * credential is planted behind each of the five fakes, the full `useSecret`
 * lifecycle runs through the real `VaultEngine`, and every observable output —
 * the `useSecret` result, every `secret.use` audit-row detail, and every
 * refusal message — is swept for the credential value AND its base64 /
 * base64url / hex / percent encodings. None may appear, across all five.
 *
 * This is a NEW sweep, not an extension of the existing OAuth/certificate one
 * in `security-oauth-certs.test.ts`: that sweep pins a disjoint needle set
 * (client secrets, refresh tokens, PEM private keys) over a disjoint surface
 * set (REST bodies, MCP results, both SDK clients) with newline canonical, and
 * has no encoding pass. The injection-context result/audit shapes and the
 * value+encodings needles share nothing with it, so a parallel file is the
 * honest structure; the pattern (needle list, observation list, positive
 * controls proving the needles are live and the matcher fires) is reused.
 *
 * The matcher is proven to genuinely catch a leak by a positive control (test
 * "the sweep catches a planted leak"): the same `findLeaks` used for the real
 * assertion, run over a crafted observation carrying every encoding, reports
 * every one of them.
 */

const PASSWORD = "v13-posture-pw";

// Distinctive, high-entropy credentials with `@ . / +` so the base64/base64url/
// percent encodings genuinely diverge and cannot collide with the vault's
// public vocabulary (secret names, hosts, image references).
const SMTP_USER = "smtp-user";
const SMTP_PASS = "Sm7pP@ss.a1b2c3d4e5f6/leak+z";
const SMTP_VALUE = `${SMTP_USER}:${SMTP_PASS}`;

const IMAP_USER = "imap-user";
const IMAP_PASS = "Im4pP@ss.f6e5d4c3b2a1/leak+z";
const IMAP_VALUE = `${IMAP_USER}:${IMAP_PASS}`;

const WS_VALUE = "Ws-Bearer.9z8y7x6w5v4u/leak+q";

const SFTP_VALUE = "Sf7pKey.q1w2e3r4t5y6/leak+k";

const DOCKER_USER = "docker-user";
const DOCKER_PASS = "Dk7rP@ss.u7i8o9p0q1/leak+d";
const DOCKER_VALUE = `${DOCKER_USER}:${DOCKER_PASS}`;

/** The secret strings that must never appear in an observable channel. */
const SECRET_STRINGS = [
  SMTP_VALUE,
  SMTP_PASS,
  IMAP_VALUE,
  IMAP_PASS,
  WS_VALUE,
  SFTP_VALUE,
  DOCKER_VALUE,
  DOCKER_PASS,
];

interface Needle {
  label: string;
  needle: string;
}

/** A credential leaks verbatim or re-encoded — the value and its base64,
 * base64url, hex and percent forms are all needles (mirrors core's
 * `redactSecretEncodings` matched set). */
function encodingsOf(value: string): Needle[] {
  const buf = Buffer.from(value, "utf8");
  return [
    { label: `${value} (raw)`, needle: value },
    { label: `${value} (base64)`, needle: buf.toString("base64") },
    { label: `${value} (base64url)`, needle: buf.toString("base64url") },
    { label: `${value} (hex)`, needle: buf.toString("hex") },
    { label: `${value} (percent)`, needle: encodeURIComponent(value) },
  ];
}

const NEEDLES: Needle[] = SECRET_STRINGS.flatMap(encodingsOf);

interface Observation {
  surface: string;
  text: string;
}

const observed: Observation[] = [];

function record(surface: string, text: string): void {
  observed.push({ surface, text });
}

/** Every needle a set of observations carries — empty is the clean result. */
function findLeaks(observations: Observation[], needles: Needle[]): string[] {
  return observations.flatMap(({ surface, text }) =>
    needles.filter((n) => text.includes(n.needle)).map((n) => `${surface} carries ${n.label}`),
  );
}

let vault: TestVault;
let wsAuthHeader: string | undefined;
let smtpPostTls = "";
let imapRaw = "";

/** Record the result (or the refusal), plus every `secret.use` audit-row
 * detail, for one context — the three observable channels the sweep covers. */
async function recordUse(context: string, handle: string, action: UseSecretAction): Promise<void> {
  try {
    const result = await vault.engine.useSecret(handle, action);
    record(`${context} result`, JSON.stringify(result));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    record(`${context} refusal message`, `${message}\n${JSON.stringify(err)}`);
  }
  const secretId = await vault.engine.resolveSecretId(handle);
  for (const row of vault.engine.queryAudit({ secretId, eventType: AuditEventType.SECRET_USE })) {
    record(`${context} audit detail`, JSON.stringify(row.detail));
  }
}

async function makeSecret(name: string, value: string): Promise<string> {
  const created = await vault.engine.createSecret({
    name,
    type: "api_key",
    value: new Uint8Array(Buffer.from(value, "utf8")),
  });
  return created.handle;
}

beforeAll(async () => {
  vault = createTestVault();
  await vault.engine.initVault(PASSWORD);

  // smtp — implicit TLS, credential authenticated over the wire.
  const smtp = await startFakeSmtp({
    starttls: false,
    implicitTls: true,
    authMechanisms: ["PLAIN"],
    auth: "ok",
    rcpt: "ok",
  });
  try {
    const handle = await makeSecret("v13p-smtp", SMTP_VALUE);
    await vault.engine.setInjectionPolicy(handle, {
      host_allowlist: [`${LOOPBACK_HOST}:${smtp.port}`],
    });
    await vault.engine.setConnectionConfig(handle, { mail: { tls: { ca: FIXTURE_CA_PEM } } });
    await recordUse("smtp", handle, {
      type: "smtp",
      host: LOOPBACK_HOST,
      port: smtp.port,
      security: "tls",
      from: "agent@harpoc.local",
      to: ["ops@example.com"],
      subject: "posture",
      text: "body",
    });
    smtpPostTls = smtp.wire().postTls.toString("utf8");
  } finally {
    await smtp.close();
  }

  // imap — implicit TLS, credential authenticated over the wire.
  const imap = await startFakeImap({ auth: "ok", searchResults: [201, 202, 203] });
  try {
    const handle = await makeSecret("v13p-imap", IMAP_VALUE);
    await vault.engine.setInjectionPolicy(handle, {
      host_allowlist: [`${LOOPBACK_HOST}:${imap.port}`],
    });
    await vault.engine.setConnectionConfig(handle, { mail: { tls: { ca: FIXTURE_CA_PEM } } });
    await recordUse("imap", handle, {
      type: "imap",
      host: LOOPBACK_HOST,
      port: imap.port,
      mailbox: "INBOX",
      operation: { kind: "search", subject: "report" },
    });
    imapRaw = imap.raw().toString("utf8");
  } finally {
    await imap.close();
  }

  // websocket — credential applied at the upgrade handshake.
  const ws = await startFakeWsServer({ messages: ["pong"] });
  try {
    const handle = await makeSecret("v13p-ws", WS_VALUE);
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [`ws://127.0.0.1:${ws.port}/*`],
    });
    await recordUse("websocket", handle, {
      type: "websocket",
      url: `ws://127.0.0.1:${ws.port}/feed`,
      injection: { type: "bearer" },
      message: "ping",
      collect: { max_messages: 1, window_ms: 2000 },
    });
    wsAuthHeader = ws.requests()[0]?.headers.authorization;
  } finally {
    await ws.close();
  }

  // sftp — no backend: the credential is withheld at the fail-safe host deny,
  // and neither the refusal nor the failed audit row may carry it.
  {
    const handle = await makeSecret("v13p-sftp", SFTP_VALUE);
    await vault.engine.setInjectionPolicy(handle, {});
    await recordUse("sftp", handle, {
      type: "sftp",
      host: "deploy.example.com",
      user: "deploy",
      operation: "upload",
      remote_path: "/srv/report.pdf",
      local_path: "/tmp/report.pdf",
    });
  }

  // docker — no backend: the injector-level host deny (credential is decrypted
  // then withheld) and the engine-level isolation refusal (credential never
  // decrypted). Both audited; neither row nor message may carry the credential.
  {
    const handle = await makeSecret("v13p-docker", DOCKER_VALUE);
    await vault.engine.setInjectionPolicy(handle, {});
    await recordUse("docker host-deny", handle, {
      type: "docker_registry",
      operation: "pull",
      image: "registry.example.com/team/app:1.0",
      timeout_ms: 300_000,
    });
  }
  {
    const handle = await makeSecret("v13p-docker-iso", DOCKER_VALUE);
    await vault.engine.setInjectionPolicy(handle, { network_isolation: true });
    await recordUse("docker isolation-refusal", handle, {
      type: "docker_registry",
      operation: "pull",
      image: "registry.example.com/team/app:1.0",
      timeout_ms: 300_000,
    });
  }
});

afterAll(async () => {
  await destroyTestVault(vault).catch(() => undefined);
});

describe("v1.3 contexts — credential opacity across every observable channel", () => {
  it("the credentials are genuinely in play (positive controls)", async () => {
    // A clean sweep below is the vault withholding the credential, not a
    // credential that never travelled: each was injected and/or is held.
    expect(observed.map((o) => o.surface)).toEqual([
      "smtp result",
      "smtp audit detail",
      "imap result",
      "imap audit detail",
      "websocket result",
      "websocket audit detail",
      "sftp refusal message",
      "sftp audit detail",
      "docker host-deny refusal message",
      "docker host-deny audit detail",
      "docker isolation-refusal refusal message",
      "docker isolation-refusal audit detail",
    ]);

    // smtp: the AUTH PLAIN blob carrying the credential crossed the TLS leg.
    const authBlob = Buffer.from(`\0${SMTP_USER}\0${SMTP_PASS}`, "utf8").toString("base64");
    expect(smtpPostTls).toContain(`AUTH PLAIN ${authBlob}`);

    // imap: the password crossed the TLS leg as a LOGIN argument.
    expect(imapRaw).toContain(IMAP_PASS);

    // websocket: the credential rode the upgrade handshake.
    expect(wsAuthHeader).toBe(`Bearer ${WS_VALUE}`);

    // Every planted credential is genuinely held by the vault — the value the
    // sweep looks for is the value the vault stored.
    expect(
      Buffer.from(await vault.engine.getSecretValue("secret://v13p-smtp")).toString("utf8"),
    ).toBe(SMTP_VALUE);
    expect(
      Buffer.from(await vault.engine.getSecretValue("secret://v13p-ws")).toString("utf8"),
    ).toBe(WS_VALUE);
    expect(
      Buffer.from(await vault.engine.getSecretValue("secret://v13p-sftp")).toString("utf8"),
    ).toBe(SFTP_VALUE);
    expect(
      Buffer.from(await vault.engine.getSecretValue("secret://v13p-docker")).toString("utf8"),
    ).toBe(DOCKER_VALUE);
  });

  it("no result, audit detail or refusal message carries the credential or an encoding of it", () => {
    // Guard against a needle colliding with the public vocabulary (a name, a
    // host, an image ref) — that would fail the sweep for the wrong reason.
    const publicVocabulary = [
      "v13p-smtp",
      "v13p-imap",
      "v13p-ws",
      "v13p-sftp",
      "v13p-docker",
      "v13p-docker-iso",
      "deploy.example.com",
      "registry.example.com/team/app:1.0",
      "agent@harpoc.local",
      "ops@example.com",
    ].join(" ");
    for (const n of NEEDLES) {
      expect(publicVocabulary, n.label).not.toContain(n.needle);
    }

    expect(findLeaks(observed, NEEDLES)).toEqual([]);
  });

  it("the audit trail as a whole carries no credential material", () => {
    const rows = vault.engine.queryAudit({});
    const serialized = JSON.stringify(rows);

    // Non-degenerate: the trail really covers the five flows just run.
    expect(serialized).toContain("v13p-smtp");
    expect(serialized).toContain("v13p-docker-iso");
    expect(vault.engine.verifyAuditChain().valid).toBe(true);

    const leaks = NEEDLES.filter((n) => serialized.includes(n.needle)).map((n) => n.label);
    expect(leaks).toEqual([]);
  });

  it("the sweep catches a planted leak (RED proof the matcher fires)", () => {
    // The same `findLeaks` the real assertion uses, proven to fire on every
    // needle — the value AND each of its four encodings, for all five contexts'
    // credentials. If any of these came back empty, the clean sweep above would
    // be worthless. Each needle is checked in isolation so a needle that is a
    // substring of another (e.g. the password within `user:password`) cannot
    // mask a genuine miss.
    for (const n of NEEDLES) {
      const hits = findLeaks([{ surface: "planted-leak", text: `noise ${n.needle} noise` }], [n]);
      expect(hits, `matcher missed ${n.label}`).toEqual([`planted-leak carries ${n.label}`]);
    }

    // And the real-shaped assertion catches a credential planted into an
    // observation exactly like the ones the sweep reads: non-empty here is the
    // proof that an empty result over `observed` means the vault withheld it.
    const withPlant = [
      ...observed,
      { surface: "planted result", text: `{"leaked":"${WS_VALUE}"}` },
    ];
    expect(findLeaks(withPlant, NEEDLES)).toContain(`planted result carries ${WS_VALUE} (raw)`);
  });
});
