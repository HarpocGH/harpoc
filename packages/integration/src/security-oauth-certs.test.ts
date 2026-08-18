import { X509Certificate } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createMcpServer } from "@harpoc/mcp-server";
import { providerConfigFromFlowInput } from "@harpoc/oauth-proxy";
import { DirectClient, RestClient } from "@harpoc/sdk";
import {
  ErrorCode,
  renewCertificateRequestSchema,
  startOAuthFlowInputSchema,
} from "@harpoc/shared";
import type { ExpiringCertificateInfo, ExpiringOAuthTokenInfo } from "@harpoc/shared";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { startTestServer } from "./helpers/rest-helpers.js";
import type { TestServer } from "./helpers/rest-helpers.js";
import { callTool, listTools } from "./helpers/mcp-helpers.js";
import { startMockOAuthProvider } from "./helpers/mock-oauth-provider.js";
import type { MockOAuthProvider } from "./helpers/mock-oauth-provider.js";
import { KEY_PEM, CERT_PEM, EXPIRED_KEY_PEM, EXPIRED_CERT_PEM } from "./helpers/cert-fixtures.js";

/**
 * Security posture of the OAuth and certificate surfaces (Phase 10): the two
 * secret kinds this tranche wired both hold material an LLM must never see — a
 * client secret, a refresh token, a certificate's private key. The pins here
 * are about what leaves the vault rather than what it stores:
 *
 * 1. the MCP tool contract offers no place to put a client secret — nor an
 *    http-01 bind port (D1) — and a smuggled one of either is dropped rather
 *    than acted on;
 * 2. every REST body, MCP tool result and caught error message produced by a
 *    real client-credentials flow and a real certificate import is swept for
 *    the material in play — with the mock provider's own traffic and the
 *    vault's own key accessor as the positive controls that prove the needles
 *    are the live values;
 * 3. the audit trail gets the same sweep;
 * 4. the two expiring-status projections (D5) hand out exactly their metadata
 *    key set, over the engine and over `check_secret_health`, which is the one
 *    wired surface that serializes them.
 *
 * One ordered lifecycle over a single vault, one REST server and one MCP
 * server: the sweeps read what the flow test recorded, so the file runs as a
 * whole.
 */

const PASSWORD = "security-posture-pw";
const PRINCIPAL = "posture-agent";

const CC_NAME = "cc-app-17";
const CC_CLIENT_ID = "cc-client-17";
const CC_CLIENT_SECRET = "cc-secret-17";
const CC_ACCESS_TOKEN = "at17-cc-do-not-leak";

const AC_NAME = "ac-app-17";
const AC_CLIENT_ID = "ac-client-17";
const AC_CLIENT_SECRET = "ac-secret-17";
const AC_ACCESS_TOKEN = "at17-ac-do-not-leak";
const AC_REFRESH_TOKEN = "rt17-ac-do-not-leak";
const ROTATED_ACCESS_TOKEN = "at17-rotated-do-not-leak";
const ROTATED_REFRESH_TOKEN = "rt17-rotated-do-not-leak";

const SMUGGLE_NAME = "smuggle-app-17";
const SMUGGLE_CLIENT_ID = "smuggle-client-17";
const SMUGGLED_CLIENT_SECRET = "smuggled-secret-17";

const IMPORTED_NAME = "posture-cert-17";
const EXPIRING_NAME = "posture-expiring-17";
const REFUSED_NAME = "posture-refused-17";

const PEM_ARMOR = "-----BEGIN";
const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 86_400_000;

/**
 * The `start_oauth_flow` input contract as Task 6 shipped it: ten keys, all of
 * them public metadata. `client_secret` is absent by construction — a
 * confidential client's secret is collected out-of-band — while the REST
 * authorize schema does accept one, because REST is the trusted admin path.
 */
const START_OAUTH_FLOW_KEYS = [
  "auth_endpoint",
  "client_id",
  "device_authorization_endpoint",
  "grant_type",
  "name",
  "project",
  "provider",
  "scopes",
  "token_endpoint",
  "token_endpoint_auth_method",
];

const OAUTH_PROJECTION_KEYS = [
  "access_token_expires_at",
  "handle",
  "has_refresh_token",
  "name",
  "project",
  "provider",
  "refresh_status",
];

const CERT_PROJECTION_KEYS = [
  "auto_renew",
  "handle",
  "name",
  "not_after",
  "project",
  "renew_before_days",
  "renewal_status",
  "subject",
];

/**
 * The narrowest renewal window that still reaches the fixture's validity end —
 * derived, not assumed, so a regenerated fixture keeps the row in window.
 */
function windowDaysCovering(certPem: string): number {
  const validToMs = new Date(new X509Certificate(certPem).validTo).getTime();
  return Math.min(365, Math.max(1, Math.ceil((validToMs - Date.now()) / DAY_MS) + 1));
}

/**
 * `EXPIRED_CERT_PEM`, not the long-lived `CERT_PEM` above, drives this: the D5
 * certificate projection only reports rows inside their own renewal window,
 * and the store casts a 366-day net before that filter — so a decade-out
 * fixture can never land in it, whatever `renew_before_days` says. The
 * already-expired pair sits inside every window by construction, covering
 * that state without `setNotAfter`-style surgery.
 */
const EXPIRING_WINDOW_DAYS = windowDaysCovering(EXPIRED_CERT_PEM);

interface Needle {
  label: string;
  value: string;
}

/**
 * A private key leaks either verbatim (armored, wrapped at 64 chars) or
 * re-encoded, so both the first base64 line and the unwrapped body are needles.
 */
function keyNeedles(label: string, pem: string): Needle[] {
  const lines = pem
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("-----"));
  return [
    { label: `${label} (first base64 line)`, value: lines[0] as string },
    { label: `${label} (unwrapped base64 body)`, value: lines.join("") },
  ];
}

const NEEDLES: Needle[] = [
  { label: "client_credentials client secret", value: CC_CLIENT_SECRET },
  { label: "authorization_code client secret", value: AC_CLIENT_SECRET },
  { label: "client secret smuggled into an MCP call", value: SMUGGLED_CLIENT_SECRET },
  { label: "seeded refresh token", value: AC_REFRESH_TOKEN },
  { label: "rotated refresh token", value: ROTATED_REFRESH_TOKEN },
  { label: "client_credentials access token", value: CC_ACCESS_TOKEN },
  { label: "seeded access token", value: AC_ACCESS_TOKEN },
  { label: "rotated access token", value: ROTATED_ACCESS_TOKEN },
  ...keyNeedles("imported certificate private key", KEY_PEM),
  ...keyNeedles("expiring certificate private key", EXPIRED_KEY_PEM),
  { label: "PEM armor", value: PEM_ARMOR },
];

interface Observation {
  surface: string;
  text: string;
}

interface HealthPayload {
  vault_state: string;
  total_secrets: number;
  oauth_refresh_needed: ExpiringOAuthTokenInfo[];
  certificates_nearing_renewal: ExpiringCertificateInfo[];
}

const observed: Observation[] = [];

let mock: MockOAuthProvider;
let vault: TestVault;
let rest: TestServer;
let mcp: McpServer;
let token: string;
let importedSecretId: string;
let health: HealthPayload;

function record(surface: string, text: string): void {
  observed.push({ surface, text });
}

interface SqliteHandle {
  prepare(sql: string): { run(...params: unknown[]): unknown };
}

/**
 * Fixture surgery, the idiom of core's `vault-engine-expiring-status.test.ts`:
 * every checked-in certificate is either long expired or valid for a decade, so
 * only moving `not_after` out-of-band puts a *live* row inside its own renewal
 * window. The engine's own connection is borrowed the way
 * `security-hardening.test.ts` borrows it — no second handle on the file, and
 * `better-sqlite3` stays out of this package's dependencies.
 */
function setNotAfter(secretId: string, notAfter: number): void {
  const db = (vault.engine as unknown as { store: { db: SqliteHandle } }).store.db;
  db.prepare("UPDATE certificates SET not_after = ? WHERE secret_id = ?").run(notAfter, secretId);
}

function authHeaders(): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

function jsonHeaders(): Record<string, string> {
  return { ...authHeaders(), "content-type": "application/json" };
}

async function restCall(
  surface: string,
  path: string,
  init: RequestInit,
): Promise<{ status: number; raw: string }> {
  const res = await fetch(`${rest.baseUrl}${path}`, init);
  const raw = await res.text();
  record(surface, raw);
  return { status: res.status, raw };
}

function postJson(surface: string, path: string, body: unknown) {
  return restCall(surface, path, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify(body),
  });
}

async function mcpCall(
  surface: string,
  name: string,
  args: Record<string, unknown>,
): Promise<{ isError: boolean; text: string }> {
  const result = await callTool(mcp, name, args);
  record(surface, JSON.stringify(result));
  return { isError: result.isError ?? false, text: result.content[0]?.text ?? "" };
}

/**
 * Record what a refusal tells its caller: the message becomes an MCP tool
 * result or a REST error body, and the enumerable own properties (code,
 * statusCode, details) ride along on anything that re-serializes the error.
 */
async function recordRejection(surface: string, work: Promise<unknown>): Promise<unknown> {
  let caught: unknown;
  let resolved = false;
  try {
    await work;
    resolved = true;
  } catch (err) {
    caught = err;
  }
  expect(resolved, `${surface} resolved — this sweep observes the refusal`).toBe(false);
  const message = caught instanceof Error ? caught.message : String(caught);
  record(surface, `${message}\n${JSON.stringify(caught)}`);
  return caught;
}

beforeAll(async () => {
  mock = await startMockOAuthProvider();
  vault = createTestVault();
  await vault.engine.initVault(PASSWORD);
  rest = startTestServer(vault.engine);
  mcp = createMcpServer({ engine: vault.engine, allowTokenless: true });
  token = vault.engine.createToken(PRINCIPAL, ["create", "read", "rotate", "list"]);
});

afterAll(async () => {
  await rest.close();
  await destroyTestVault(vault).catch(() => {});
  await mock.close();
});

describe("OAuth and certificate security posture across the wired surfaces", () => {
  it("1. no MCP tool takes a client secret — start_oauth_flow advertises the public ten", async () => {
    const tools = await listTools(mcp);
    const flow = tools.find((t) => t.name === "start_oauth_flow");

    expect(flow).toBeDefined();
    expect(Object.keys(flow?.inputSchema.properties ?? {}).sort()).toEqual(START_OAUTH_FLOW_KEYS);

    // The whole advertised surface, not just this one tool: `client_secret` is
    // not an input any tool offers.
    for (const tool of tools) {
      expect(Object.keys(tool.inputSchema.properties ?? {})).not.toContain("client_secret");
    }

    // The asymmetry is deliberate, so it is pinned rather than left to the
    // reader: REST is the trusted admin path and does take a client secret.
    expect(Object.keys(startOAuthFlowInputSchema.shape)).toContain("client_secret");
  });

  it("1b. no MCP tool picks a listening port — renew_certificate advertises a handle and nothing else", async () => {
    const tools = await listTools(mcp);
    const renew = tools.find((t) => t.name === "renew_certificate");

    expect(renew).toBeDefined();
    expect(Object.keys(renew?.inputSchema.properties ?? {})).toEqual(["handle"]);

    // Same shape of asymmetry as the client secret above: the trusted admin
    // paths (CLI `--http-port`, REST renew body) still choose the http-01
    // responder's port, so the field lives on in the shared request schema —
    // what an agent may ask for is what shrank.
    expect(Object.keys(renewCertificateRequestSchema.shape)).toContain("http_port");
  });

  it("2. the OAuth and certificate flows run over REST, MCP and both SDK clients", async () => {
    mock.setNextTokens({ access_token: CC_ACCESS_TOKEN, expires_in: 1800 });
    const authorized = await postJson(
      "rest POST /oauth/authorize (client_credentials)",
      "/api/v1/oauth/authorize",
      {
        name: CC_NAME,
        provider: "custom",
        grant_type: "client_credentials",
        client_id: CC_CLIENT_ID,
        client_secret: CC_CLIENT_SECRET,
        token_endpoint: mock.tokenEndpoint,
      },
    );
    expect(authorized.status).toBe(201);

    const oauthStatus = await restCall(
      "rest GET /oauth/:handle/status",
      `/api/v1/oauth/${CC_NAME}/status`,
      { headers: authHeaders() },
    );
    expect(oauthStatus.status).toBe(200);

    // A client-credentials grant stores no refresh token, so the refresh needle
    // needs an authorization-code-shaped secret: seeded on the trusted local
    // path, then rotated over REST against the same provider.
    const { config } = providerConfigFromFlowInput({
      name: AC_NAME,
      provider: "custom",
      grant_type: "authorization_code",
      client_id: AC_CLIENT_ID,
      client_secret: AC_CLIENT_SECRET,
      token_endpoint: mock.tokenEndpoint,
      auth_endpoint: mock.tokenEndpoint.replace(/\/token$/, "/authorize"),
    });
    const seeded = await vault.engine.createOAuthSecret(AC_NAME, config);
    await vault.engine.completeOAuthFlow(
      seeded.secretId,
      AC_ACCESS_TOKEN,
      AC_REFRESH_TOKEN,
      Date.now() + 30 * 60 * 1000,
    );
    mock.setNextTokens({
      access_token: ROTATED_ACCESS_TOKEN,
      refresh_token: ROTATED_REFRESH_TOKEN,
      expires_in: 1800,
    });
    const refreshed = await restCall(
      "rest POST /oauth/:handle/refresh",
      `/api/v1/oauth/${AC_NAME}/refresh`,
      { method: "POST", headers: authHeaders() },
    );
    expect(refreshed.status).toBe(200);

    const imported = await postJson(
      "rest POST /certificates/import",
      "/api/v1/certificates/import",
      { name: IMPORTED_NAME, private_key_pem: KEY_PEM, certificate_pem: CERT_PEM },
    );
    expect(imported.status).toBe(201);
    importedSecretId = (JSON.parse(imported.raw) as { data: { secret_id: string } }).data.secret_id;

    const expiring = await postJson(
      "rest POST /certificates/import (in renewal window)",
      "/api/v1/certificates/import",
      {
        name: EXPIRING_NAME,
        private_key_pem: EXPIRED_KEY_PEM,
        certificate_pem: EXPIRED_CERT_PEM,
        renew_before_days: EXPIRING_WINDOW_DAYS,
      },
    );
    expect(expiring.status).toBe(201);

    // The second in-window row, and the one the renewal daemon would act on: a
    // live certificate whose own window has opened. Its secret stays ACTIVE
    // (the surgery touches the certificate row, not `secrets.expires_at`),
    // which the store's projection query requires.
    setNotAfter(importedSecretId, Date.now() + 10 * DAY_MS);

    const certStatus = await restCall(
      "rest GET /certificates/:handle/status",
      `/api/v1/certificates/${IMPORTED_NAME}/status`,
      { headers: authHeaders() },
    );
    expect(certStatus.status).toBe(200);

    const renewRefused = await postJson(
      "rest POST /certificates/:handle/renew (refused)",
      `/api/v1/certificates/${IMPORTED_NAME}/renew`,
      {},
    );
    expect(renewRefused.status).toBe(502);
    expect(JSON.parse(renewRefused.raw)).toMatchObject({ error: ErrorCode.CERT_ACME_FAILED });

    // The refused request carried the real private key: a schema message that
    // echoed the offending value would put it in the response body.
    const importRefused = await postJson(
      "rest POST /certificates/import (refused, malformed certificate_pem)",
      "/api/v1/certificates/import",
      { name: REFUSED_NAME, private_key_pem: KEY_PEM, certificate_pem: "not-a-pem" },
    );
    expect(importRefused.status).toBe(400);
    expect(JSON.parse(importRefused.raw)).toMatchObject({
      error: ErrorCode.SCHEMA_VALIDATION_ERROR,
    });

    const census = await restCall("rest GET /health/expiring", "/api/v1/health/expiring?days=365", {
      headers: authHeaders(),
    });
    expect(census.status).toBe(200);

    const healthResult = await mcpCall("mcp check_secret_health", "check_secret_health", {});
    expect(healthResult.isError).toBe(false);
    health = JSON.parse(healthResult.text) as HealthPayload;

    const certInfo = await mcpCall("mcp get_secret_info (certificate)", "get_secret_info", {
      handle: `secret://${IMPORTED_NAME}`,
    });
    expect(certInfo.isError).toBe(false);

    const oauthInfo = await mcpCall("mcp get_secret_info (oauth)", "get_secret_info", {
      handle: `secret://${CC_NAME}`,
    });
    expect(oauthInfo.isError).toBe(false);

    const listed = await mcpCall("mcp list_secrets", "list_secrets", {});
    expect(listed.isError).toBe(false);

    const mcpRenew = await mcpCall("mcp renew_certificate (refused)", "renew_certificate", {
      handle: `secret://${IMPORTED_NAME}`,
    });
    expect(mcpRenew.isError).toBe(true);
    expect(mcpRenew.text).toContain("no ACME account for this certificate");

    // A client secret smuggled into the tool call as an undeclared argument:
    // the grant still falls through to out-of-band collection (unavailable
    // here) rather than exchanging the smuggled credential, and the provider
    // sees no request at all.
    const providerCalls = mock.requests.length;
    const smuggled = await mcpCall(
      "mcp start_oauth_flow (smuggled client_secret)",
      "start_oauth_flow",
      {
        name: SMUGGLE_NAME,
        provider: "custom",
        grant_type: "client_credentials",
        client_id: SMUGGLE_CLIENT_ID,
        token_endpoint: mock.tokenEndpoint,
        client_secret: SMUGGLED_CLIENT_SECRET,
      },
    );
    expect(smuggled.isError).toBe(false);
    expect(JSON.parse(smuggled.text)).toMatchObject({ status: "pending" });
    expect(smuggled.text).toContain("No out-of-band channel was available");
    expect(mock.requests.length).toBe(providerCalls);

    const directRefusal = await recordRejection(
      "sdk DirectClient.renewCertificate (refused)",
      new DirectClient(vault.engine).renewCertificate(`secret://${IMPORTED_NAME}`),
    );
    expect(directRefusal).toMatchObject({ code: ErrorCode.CERT_ACME_FAILED });

    const restRefusal = await recordRejection(
      "sdk RestClient.renewCertificate (refused)",
      new RestClient({ baseUrl: rest.baseUrl, token }).renewCertificate(
        `secret://${IMPORTED_NAME}`,
      ),
    );
    expect(restRefusal).toMatchObject({ code: ErrorCode.CERT_ACME_FAILED });
  });

  it("3. no response body, tool result or refusal message carries secret material", async () => {
    // The sweep is only worth its assertions if it covers the flow it claims
    // to: a dropped surface would otherwise shrink it silently.
    expect(observed.map((o) => o.surface).sort()).toEqual([
      "mcp check_secret_health",
      "mcp get_secret_info (certificate)",
      "mcp get_secret_info (oauth)",
      "mcp list_secrets",
      "mcp renew_certificate (refused)",
      "mcp start_oauth_flow (smuggled client_secret)",
      "rest GET /certificates/:handle/status",
      "rest GET /health/expiring",
      "rest GET /oauth/:handle/status",
      "rest POST /certificates/:handle/renew (refused)",
      "rest POST /certificates/import",
      "rest POST /certificates/import (in renewal window)",
      "rest POST /certificates/import (refused, malformed certificate_pem)",
      "rest POST /oauth/:handle/refresh",
      "rest POST /oauth/authorize (client_credentials)",
      "sdk DirectClient.renewCertificate (refused)",
      "sdk RestClient.renewCertificate (refused)",
    ]);

    // A needle that collides with the vault's own public vocabulary — a secret
    // name, a handle, a client id — would fail the sweep for the wrong reason
    // (`rt-17` is a substring of `posture-cert-17`).
    const publicVocabulary = [
      CC_NAME,
      AC_NAME,
      SMUGGLE_NAME,
      IMPORTED_NAME,
      EXPIRING_NAME,
      REFUSED_NAME,
      CC_CLIENT_ID,
      AC_CLIENT_ID,
      SMUGGLE_CLIENT_ID,
      PRINCIPAL,
    ].join(" ");
    for (const needle of NEEDLES) {
      expect(publicVocabulary, needle.label).not.toContain(needle.value);
    }

    // Positive controls: the credentials really are in play under exactly these
    // bytes. The provider received the client secret and the refresh token, and
    // the vault holds the private key — the needles match there, so a clean
    // sweep below is the vault withholding them, not a matcher that never fires.
    const providerTraffic = JSON.stringify(mock.requests);
    expect(providerTraffic).toContain(CC_CLIENT_SECRET);
    expect(providerTraffic).toContain(AC_CLIENT_SECRET);
    expect(providerTraffic).toContain(AC_REFRESH_TOKEN);
    const storedKey = await vault.engine.getCertificatePrivateKey(importedSecretId);
    for (const needle of keyNeedles("control", KEY_PEM)) {
      expect(storedKey.replaceAll("\n", "")).toContain(needle.value.replaceAll("\n", ""));
    }
    expect(storedKey).toContain(PEM_ARMOR);

    const leaks = observed.flatMap(({ surface, text }) =>
      NEEDLES.filter((n) => text.includes(n.value)).map((n) => `${surface} carries ${n.label}`),
    );
    expect(leaks).toEqual([]);
  });

  it("4. the audit trail carries no secret material either", () => {
    const rows = vault.engine.queryAudit({});
    const serialized = JSON.stringify(rows);

    // Non-degenerate: the trail actually covers the flows just run.
    expect(serialized).toContain(CC_NAME);
    expect(serialized).toContain(IMPORTED_NAME);
    expect(vault.engine.verifyAuditChain().valid).toBe(true);

    const leaks = NEEDLES.filter((n) => serialized.includes(n.value)).map((n) => n.label);
    expect(leaks).toEqual([]);
  });

  it("5. the expiring-status projections are metadata only (D5)", () => {
    const oauthItems = vault.engine.getExpiringOAuthTokenStatuses(HOUR_MS);
    // The smuggle flow's secret holds no token at all, so it is not expiring.
    expect(oauthItems.map((i) => i.name).sort()).toEqual([AC_NAME, CC_NAME].sort());
    for (const item of oauthItems) {
      expect(Object.keys(item).sort()).toEqual(OAUTH_PROJECTION_KEYS);
    }

    // Both in-window rows, soonest first: the expired fixture and the
    // backdated live one. Neither the CSR-less refusal nor an out-of-window
    // certificate exists here, so the two states the daemon distinguishes —
    // already expired, window open — are both projected.
    const certItems = vault.engine.getExpiringCertificateStatuses();
    expect(certItems.map((i) => i.name)).toEqual([EXPIRING_NAME, IMPORTED_NAME]);
    for (const item of certItems) {
      expect(Object.keys(item).sort()).toEqual(CERT_PROJECTION_KEYS);
    }
    expect(certItems[0]).toMatchObject({
      auto_renew: false,
      renew_before_days: EXPIRING_WINDOW_DAYS,
      renewal_status: "expired",
    });
    expect(certItems[1]).toMatchObject({
      auto_renew: false,
      // The import left `renew_before_days` to the schema default (30), and the
      // backdated notAfter is 10 days out — inside it.
      renew_before_days: 30,
      renewal_status: "expiring_soon",
    });

    const serialized = JSON.stringify([...oauthItems, ...certItems]);
    for (const columnMarker of ["encrypted", "_iv", "_tag"]) {
      expect(serialized).not.toContain(columnMarker);
    }

    // The same two projections as an LLM receives them: check_secret_health is
    // the one wired surface that serializes them.
    expect(health.oauth_refresh_needed).toEqual(oauthItems);
    expect(health.certificates_nearing_renewal).toEqual(certItems);
  });
});

/**
 * Renewal-daemon scope (10F): the `auto_renew: false → skipped` tick is already
 * pinned by `packages/cert-manager/src/renewal-scheduler.test.ts:92` ("tick
 * renews only auto_renew rows inside their per-row window") — four
 * `CertificateRow`-shaped rows through one `tick()`, the `auto_renew: false`
 * row one day from expiry, and the spy renewer called for the auto-renew rows
 * only. Not duplicated here.
 */

/**
 * Injection-boundary scope (10F): that response redaction covers the *freshly
 * fetched* OAuth access token — the one `use_secret` actually injects — is
 * pinned by `oauth-lifecycle.test.ts:227-229`, where the refreshed token
 * reaches the sink's `Authorization` header while neither it nor the token it
 * replaced appears in the REST response body. That test owns the injection
 * path end to end (policy, sink, refresh accounting); not duplicated here.
 */

/**
 * SDK status scope (10F): the certificate-status projection is swept for PEM
 * armor over both SDK clients in `cert-lifecycle.test.ts` (test 2, "both SDK
 * clients report the same status REST does, and neither leaks PEM"), which also
 * pins them equal to the REST payload. The sweeps here cover the SDK only where
 * it refuses (`renewCertificate`), so the two files together carry all four
 * surfaces.
 */
