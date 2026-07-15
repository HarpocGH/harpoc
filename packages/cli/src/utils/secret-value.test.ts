import { createPrivateKey, createPublicKey, generateKeyPairSync } from "node:crypto";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  MAX_SECRET_FILE_BYTES,
  readSecretValueFromFile,
  resolveSecretValue,
} from "./secret-value.js";

const PASSPHRASE = "correct horse battery";

let tempDir: string;

beforeEach(() => {
  tempDir = join(tmpdir(), `harpoc-sv-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
});

afterEach(() => {
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
});

function writeTemp(name: string, content: string | Buffer): string {
  const path = join(tempDir, name);
  writeFileSync(path, content);
  return path;
}

function encryptedPkcs8Ed25519(): { privateKey: string; publicKey: string } {
  return generateKeyPairSync("ed25519", {
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
      cipher: "aes-256-cbc",
      passphrase: PASSPHRASE,
    },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
}

function endedInput(): PassThrough {
  const input = new PassThrough();
  input.end();
  return input;
}

function sink(): PassThrough {
  return new PassThrough();
}

describe("readSecretValueFromFile", () => {
  it("returns file bytes exactly (multi-line PEM survives)", () => {
    const pem = "-----BEGIN PRIVATE KEY-----\nline1\nline2\n-----END PRIVATE KEY-----\n";
    const path = writeTemp("key.pem", pem);
    expect(readSecretValueFromFile(path).toString("utf8")).toBe(pem);
  });

  it("rejects a missing file with a clean message", () => {
    expect(() => readSecretValueFromFile(join(tempDir, "nope.pem"))).toThrow(/Cannot read file/);
  });

  it("rejects a directory", () => {
    expect(() => readSecretValueFromFile(tempDir)).toThrow(/Cannot read file/);
  });

  it("rejects an empty file", () => {
    const path = writeTemp("empty", "");
    expect(() => readSecretValueFromFile(path)).toThrow("Secret value cannot be empty.");
  });

  it("rejects a file over the 1 MiB cap", () => {
    const path = writeTemp("big.bin", Buffer.alloc(MAX_SECRET_FILE_BYTES + 1));
    expect(() => readSecretValueFromFile(path)).toThrow(/1 MiB/);
  });
});

describe("resolveSecretValue — acquisition", () => {
  it("uses the file without consulting the prompt", async () => {
    const path = writeTemp("v.txt", "plain-api-key");
    // An already-ended input would resolve any prompt to "" and error out,
    // so success proves the prompt was never consulted.
    const value = await resolveSecretValue({ fromFile: path, input: endedInput(), output: sink() });
    expect(value.toString("utf8")).toBe("plain-api-key");
  });

  it("prompts when no file is given", async () => {
    const input = new PassThrough();
    const p = resolveSecretValue({ input, output: sink() });
    input.write("typed-value\n");
    expect((await p).toString("utf8")).toBe("typed-value");
  });

  it("rejects an empty prompted value", async () => {
    await expect(resolveSecretValue({ input: endedInput(), output: sink() })).rejects.toThrow(
      "Secret value cannot be empty.",
    );
  });

  it("passes a non-key value through byte-exact without any passphrase prompt", async () => {
    const path = writeTemp("v.txt", "sk-abc123");
    const value = await resolveSecretValue({ fromFile: path, input: endedInput(), output: sink() });
    expect(value.toString("utf8")).toBe("sk-abc123");
  });

  it("pins the gap --from-file closes: the prompt path keeps only the first PEM line", async () => {
    const input = new PassThrough();
    const p = resolveSecretValue({ input, output: sink() });
    input.write(
      "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n",
    );
    expect((await p).toString("utf8")).toBe("-----BEGIN PRIVATE KEY-----");
  });

  it("passes an unencrypted key through byte-exact", async () => {
    const { privateKey } = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const path = writeTemp("plain.pem", privateKey);
    const value = await resolveSecretValue({ fromFile: path, input: endedInput(), output: sink() });
    expect(value.toString("utf8")).toBe(privateKey);
  });
});

describe("resolveSecretValue — decrypt at import", () => {
  it("decrypts an encrypted PKCS#8 key with the prompted passphrase", async () => {
    const { privateKey, publicKey } = encryptedPkcs8Ed25519();
    const path = writeTemp("enc.pem", privateKey);

    const input = new PassThrough();
    const p = resolveSecretValue({ fromFile: path, input, output: sink() });
    input.write(`${PASSPHRASE}\n`);
    const value = await p;

    const pemText = value.toString("utf8");
    expect(pemText.startsWith("-----BEGIN PRIVATE KEY-----")).toBe(true);
    const decrypted = createPrivateKey(pemText);
    expect(createPublicKey(decrypted).export({ format: "pem", type: "spki" })).toBe(publicKey);
  });

  it("decrypts an encrypted legacy PEM through the same path", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: {
        type: "pkcs1",
        format: "pem",
        cipher: "aes-128-cbc",
        passphrase: PASSPHRASE,
      },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const path = writeTemp("legacy.pem", privateKey);

    const input = new PassThrough();
    const p = resolveSecretValue({ fromFile: path, input, output: sink() });
    input.write(`${PASSPHRASE}\n`);
    const value = await p;

    const decrypted = createPrivateKey(value.toString("utf8"));
    expect(createPublicKey(decrypted).export({ format: "pem", type: "spki" })).toBe(publicKey);
  });

  it("propagates KEY_PASSPHRASE_INVALID on a wrong passphrase", async () => {
    const { privateKey } = encryptedPkcs8Ed25519();
    const path = writeTemp("enc.pem", privateKey);

    const input = new PassThrough();
    const p = resolveSecretValue({ fromFile: path, input, output: sink() });
    input.write("wrong-passphrase\n");
    await expect(p).rejects.toMatchObject({ code: ErrorCode.KEY_PASSPHRASE_INVALID });
  });

  it("rejects an empty passphrase without writing anything", async () => {
    const { privateKey } = encryptedPkcs8Ed25519();
    const path = writeTemp("enc.pem", privateKey);
    await expect(
      resolveSecretValue({ fromFile: path, input: endedInput(), output: sink() }),
    ).rejects.toThrow("Key passphrase cannot be empty.");
  });

  it("refuses an encrypted OpenSSH key before any passphrase prompt", async () => {
    // Minimal openssh-key-v1 container: magic + length-prefixed cipher name.
    const magic = Buffer.from("openssh-key-v1\0", "binary");
    const cipher = Buffer.from("aes256-ctr", "utf8");
    const len = Buffer.alloc(4);
    len.writeUInt32BE(cipher.length);
    const body = Buffer.concat([magic, len, cipher]).toString("base64");
    const opensshEnc = `-----BEGIN OPENSSH PRIVATE KEY-----\n${body}\n-----END OPENSSH PRIVATE KEY-----`;
    const path = writeTemp("enc_openssh", opensshEnc);

    // An ended input would turn a passphrase prompt into the empty-passphrase
    // error, so getting ENCRYPTED_KEY_UNSUPPORTED proves no prompt happened.
    const p = resolveSecretValue({ fromFile: path, input: endedInput(), output: sink() });
    await expect(p).rejects.toMatchObject({ code: ErrorCode.ENCRYPTED_KEY_UNSUPPORTED });
    await expect(p).rejects.toThrow(/ssh-keygen -p -f <keyfile> -m PKCS8/);
  });

  it("stores the encrypted blob verbatim under --no-decrypt", async () => {
    const { privateKey } = encryptedPkcs8Ed25519();
    const path = writeTemp("enc.pem", privateKey);
    const value = await resolveSecretValue({
      fromFile: path,
      noDecrypt: true,
      input: endedInput(),
      output: sink(),
    });
    expect(value.toString("utf8")).toBe(privateKey);
  });

  it("never leaks the passphrase into the thrown error", async () => {
    const { privateKey } = encryptedPkcs8Ed25519();
    const path = writeTemp("enc.pem", privateKey);
    const input = new PassThrough();
    const p = resolveSecretValue({ fromFile: path, input, output: sink() });
    input.write("sentinel-passphrase-xyz\n");
    const err = await p.then(
      () => {
        throw new Error("should reject");
      },
      (e: unknown) => e as Error,
    );
    expect(err.message).not.toContain("sentinel-passphrase-xyz");
  });
});

describe("resolveSecretValue — vault-error passthrough", () => {
  it("propagates a VaultError instance unchanged", async () => {
    const { privateKey } = encryptedPkcs8Ed25519();
    const path = writeTemp("enc.pem", privateKey);
    const input = new PassThrough();
    const p = resolveSecretValue({ fromFile: path, input, output: sink() });
    input.write("wrong\n");
    await expect(p).rejects.toBeInstanceOf(VaultError);
  });
});
