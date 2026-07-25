import { createServer } from "node:http";
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SecretType } from "@harpoc/shared";
import { VaultEngine } from "../vault-engine.js";

// Argon2 mocked for speed — the at-rest property under test is the AES-GCM
// encryption of names/values/audit details, which runs for real either way.
vi.mock("argon2", () => ({
  hash: async (password: Buffer | string, opts: { salt: Buffer | Uint8Array }) => {
    const { createHash } = await import("node:crypto");
    const salt = opts.salt instanceof Uint8Array ? Buffer.from(opts.salt) : opts.salt;
    return createHash("sha256")
      .update(typeof password === "string" ? password : Buffer.from(password))
      .update(salt)
      .digest();
  },
}));

const SENTINEL_NAME = "sentinel-name-zq7x9k2m4p";
const SENTINEL_VALUE = "SENTINEL-VALUE-zq8y3w5v7u1t9r0s";

/** Every rendering an on-disk grep (or exfiltrated file) could match. */
function encodings(sentinel: string): Buffer[] {
  const raw = Buffer.from(sentinel, "utf8");
  return [
    raw,
    Buffer.from(raw.toString("base64"), "utf8"),
    Buffer.from(raw.toString("base64url"), "utf8"),
    Buffer.from(raw.toString("hex"), "utf8"),
    Buffer.from(sentinel, "utf16le"),
  ];
}

describe("at-rest opacity (thesis: encrypted at rest)", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = join(tmpdir(), `harpoc-atrest-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(tempDir, { recursive: true });
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it("neither the secret name nor its value reaches the vault files in any common encoding", async () => {
    const dbPath = join(tempDir, "test.vault.db");
    const engine = new VaultEngine({ dbPath, sessionPath: join(tempDir, "session.json") });

    await engine.initVault("at-rest-test-password");
    await engine.createSecret({
      name: SENTINEL_NAME,
      type: SecretType.API_KEY,
      value: new TextEncoder().encode(SENTINEL_VALUE),
    });
    // Touch read paths too, so audit detail rows exist for the sentinel secret.
    await engine.getSecretValue(`secret://${SENTINEL_NAME}`);
    await engine.getSecretInfo(`secret://${SENTINEL_NAME}`);
    await engine.destroy(); // closes the store; better-sqlite3 checkpoints WAL

    const haystacks: Buffer[] = [readFileSync(dbPath)];
    for (const suffix of ["-wal", "-shm"]) {
      if (existsSync(dbPath + suffix)) {
        haystacks.push(readFileSync(dbPath + suffix));
      }
    }

    // Positive control: the read works and plaintext columns are visible —
    // the schema's table name is stored as-is.
    const combined = Buffer.concat(haystacks);
    expect(combined.includes(Buffer.from("secrets", "utf8"))).toBe(true);

    for (const sentinel of [SENTINEL_NAME, SENTINEL_VALUE]) {
      for (const needle of encodings(sentinel)) {
        expect(combined.includes(needle)).toBe(false);
      }
    }
  });

  /**
   * T17: the secret value/name path was scanned, the OAuth path never — yet
   * `oauth_tokens` holds the longest-lived material in the vault (a refresh
   * token mints access tokens indefinitely) plus the client secret. Storing a
   * rotated refresh_token verbatim would have kept every test green.
   */
  it("no OAuth client secret, access token or refresh token reaches the vault files", async () => {
    const CLIENT_SECRET = "SENTINEL-CLIENT-SECRET-4h8n2j6k";
    const ACCESS_TOKEN = "SENTINEL-ACCESS-TOKEN-9p3q7r1s";
    const REFRESH_TOKEN = "SENTINEL-REFRESH-TOKEN-5t2u8v4w";
    const ROTATED_REFRESH = "SENTINEL-ROTATED-REFRESH-6x9y3z7a";
    const ROTATED_ACCESS = "SENTINEL-ROTATED-ACCESS-1b4c8d2e";

    // Token endpoint that hands back a rotated pair, so the refresh write path
    // — not just the initial store — is covered.
    const tokenServer = createServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          access_token: ROTATED_ACCESS,
          refresh_token: ROTATED_REFRESH,
          expires_in: 3600,
        }),
      );
    });
    await new Promise<void>((resolve) => tokenServer.listen(0, "127.0.0.1", () => resolve()));
    const port = (tokenServer.address() as { port: number }).port;

    const dbPath = join(tempDir, "oauth.vault.db");
    const engine = new VaultEngine({ dbPath, sessionPath: join(tempDir, "session.json") });

    try {
      await engine.initVault("at-rest-oauth-password");
      const { secretId } = await engine.createOAuthSecret("oauth-sentinel", {
        provider: "github",
        grant_type: "authorization_code",
        token_endpoint: `http://127.0.0.1:${port}`,
        auth_endpoint: "https://github.com/login/oauth/authorize",
        client_id: "sentinel-client-id",
        client_secret: CLIENT_SECRET,
        scopes: ["repo"],
      });

      await engine.completeOAuthFlow(secretId, ACCESS_TOKEN, REFRESH_TOKEN, Date.now() - 1_000);
      // Expired above, so this exercises the refresh + re-store path.
      await engine.refreshOAuthToken(secretId);
      await engine.getOAuthTokenStatus(secretId);
    } finally {
      await engine.destroy();
      await new Promise<void>((resolve) => tokenServer.close(() => resolve()));
    }

    const haystacks: Buffer[] = [readFileSync(dbPath)];
    for (const suffix of ["-wal", "-shm"]) {
      if (existsSync(dbPath + suffix)) haystacks.push(readFileSync(dbPath + suffix));
    }
    const combined = Buffer.concat(haystacks);

    // Positive control: the OAuth row exists and its non-secret parts are there.
    expect(combined.includes(Buffer.from("oauth_tokens", "utf8"))).toBe(true);

    for (const sentinel of [
      CLIENT_SECRET,
      ACCESS_TOKEN,
      REFRESH_TOKEN,
      ROTATED_REFRESH,
      ROTATED_ACCESS,
    ]) {
      for (const needle of encodings(sentinel)) {
        expect(combined.includes(needle), `${sentinel} found at rest`).toBe(false);
      }
    }
  });
});
