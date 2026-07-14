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
});
