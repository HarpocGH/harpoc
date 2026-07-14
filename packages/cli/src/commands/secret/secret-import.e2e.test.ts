import { createPrivateKey, generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SecretType } from "@harpoc/shared";
import { EphemeralSshAgent, VaultEngine } from "@harpoc/core";
import { resolveSecretValue } from "../../utils/secret-value.js";

/**
 * Full decrypt-at-import chain (thesis §4.5.7): encrypted key file →
 * resolveSecretValue (passphrase prompt, in-memory decrypt) → engine storage →
 * use-time EphemeralSshAgent. Plus the at-rest invariant: the passphrase never
 * reaches the vault process's persistence layer.
 */

const TEST_PASSWORD = "test-password-123";
const PASSPHRASE = "sentinel-passphrase-do-not-persist";

let tempDir: string;
let dbPath: string;
let sessionPath: string;
let engine: VaultEngine;

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-imp-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  dbPath = join(tempDir, "test.vault.db");
  sessionPath = join(tempDir, "session.json");
  engine = new VaultEngine({ dbPath, sessionPath });
  await engine.initVault(TEST_PASSWORD);
});

afterEach(async () => {
  await engine.destroy();
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
});

describe("encrypted SSH key import — end to end", () => {
  it("imports an encrypted PKCS#8 key and serves it through the ephemeral agent", async () => {
    const { privateKey } = generateKeyPairSync("ed25519", {
      privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
        cipher: "aes-256-cbc",
        passphrase: PASSPHRASE,
      },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const keyFile = join(tempDir, "id_ed25519_enc.pem");
    writeFileSync(keyFile, privateKey);

    const input = new PassThrough();
    const pending = resolveSecretValue({ fromFile: keyFile, input, output: new PassThrough() });
    input.write(`${PASSPHRASE}\n`);
    const value = await pending;

    const created = await engine.createSecret({
      name: "deploy-key",
      type: SecretType.API_KEY,
      value,
    });

    const stored = await engine.getSecretValue(created.handle);
    const storedPem = Buffer.from(stored).toString("utf8");

    // Stored form is the decrypted PKCS#8 PEM — parses without a passphrase.
    expect(storedPem.startsWith("-----BEGIN PRIVATE KEY-----")).toBe(true);
    expect(() => createPrivateKey(storedPem)).not.toThrow();

    // The exact use_secret path: the ephemeral agent loads the stored value.
    const agent = await EphemeralSshAgent.start(storedPem);
    try {
      expect(agent).toBeTruthy();
    } finally {
      agent.dispose();
    }
  });

  it("never persists the passphrase: sentinel absent from db bytes in every encoding", async () => {
    const { privateKey } = generateKeyPairSync("ed25519", {
      privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
        cipher: "aes-256-cbc",
        passphrase: PASSPHRASE,
      },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const keyFile = join(tempDir, "key.pem");
    writeFileSync(keyFile, privateKey);

    const input = new PassThrough();
    const pending = resolveSecretValue({ fromFile: keyFile, input, output: new PassThrough() });
    input.write(`${PASSPHRASE}\n`);
    const value = await pending;
    await engine.createSecret({ name: "scan-key", type: SecretType.API_KEY, value });

    const blobs: Buffer[] = [readFileSync(dbPath)];
    for (const suffix of ["-wal", "-shm"]) {
      if (existsSync(dbPath + suffix)) blobs.push(readFileSync(dbPath + suffix));
    }
    const haystack = Buffer.concat(blobs);

    const needles = [
      Buffer.from(PASSPHRASE, "utf8"),
      Buffer.from(Buffer.from(PASSPHRASE, "utf8").toString("base64"), "utf8"),
      Buffer.from(Buffer.from(PASSPHRASE, "utf8").toString("hex"), "utf8"),
      Buffer.from(PASSPHRASE, "utf16le"),
    ];
    for (const needle of needles) {
      expect(haystack.includes(needle)).toBe(false);
    }

    // Positive control: the same scan does find plaintext deliberately written to disk.
    const controlPath = join(tempDir, "control.txt");
    writeFileSync(controlPath, PASSPHRASE);
    expect(readFileSync(controlPath).includes(Buffer.from(PASSPHRASE, "utf8"))).toBe(true);
  });
});
