import { readFileSync, statSync } from "node:fs";
import type { Readable } from "node:stream";
import { VaultError } from "@harpoc/shared";
import { analyzeKeyMaterial, decryptKeyForImport, wipeBuffer } from "@harpoc/core";
import { promptHidden } from "./prompt.js";

export const MAX_SECRET_FILE_BYTES = 1024 * 1024; // 1 MiB

type PromptInput = Readable & {
  isRaw?: boolean;
  setRawMode?: (mode: boolean) => unknown;
};

export interface ResolveSecretValueOptions {
  /** Read the value from this file instead of prompting. */
  fromFile?: string;
  /** Store encrypted private-key material verbatim instead of decrypting at import. */
  noDecrypt?: boolean;
  /** Prompt shown when reading the value from stdin (default "Secret value: "). */
  promptMessage?: string;
  input?: PromptInput;
  output?: NodeJS.WritableStream;
}

export function readSecretValueFromFile(path: string): Buffer {
  let size: number;
  try {
    const stat = statSync(path);
    if (!stat.isFile()) throw new Error("not a file");
    size = stat.size;
  } catch {
    throw new Error(`Cannot read file: ${path}`);
  }
  if (size > MAX_SECRET_FILE_BYTES) {
    throw new Error(`File exceeds the 1 MiB secret-value limit: ${path}`);
  }
  const value = readFileSync(path);
  if (value.length === 0) {
    throw new Error("Secret value cannot be empty.");
  }
  return value;
}

/**
 * Obtain a secret value (file or hidden prompt) and, unless opted out, decrypt
 * encrypted private-key material in memory (thesis §4.5.7, decrypt-at-import):
 * encrypted PKCS#8 / legacy PEM prompt once for the passphrase and store the
 * decrypted key under the vault's own encryption; encrypted OpenSSH-format
 * keys are refused before any prompt with the ssh-keygen conversion pointer.
 * The passphrase is never persisted. The returned buffer is the caller's to
 * wipe after the engine handoff.
 */
export async function resolveSecretValue(options: ResolveSecretValueOptions): Promise<Buffer> {
  let value: Buffer;
  if (options.fromFile) {
    value = readSecretValueFromFile(options.fromFile);
  } else {
    const typed = await promptHidden(
      options.promptMessage ?? "Secret value: ",
      options.input,
      options.output,
    );
    if (!typed) {
      throw new Error("Secret value cannot be empty.");
    }
    value = Buffer.from(typed, "utf8");
  }

  if (options.noDecrypt) {
    return value;
  }

  const kind = analyzeKeyMaterial(value.toString("utf8"));
  if (kind === "encrypted-openssh") {
    wipeBuffer(value);
    throw VaultError.encryptedKeyUnsupported();
  }
  if (kind === "encrypted-key-bundle") {
    // Refused before the passphrase prompt: decrypting would store only the
    // key and silently drop the certificate blocks (review fix F3).
    wipeBuffer(value);
    throw VaultError.keyBundleUnsupported();
  }
  if (kind === "encrypted-pkcs8" || kind === "encrypted-legacy-pem") {
    const passphrase = await promptHidden("Key passphrase: ", options.input, options.output);
    if (!passphrase) {
      wipeBuffer(value);
      throw new Error("Key passphrase cannot be empty.");
    }
    try {
      return decryptKeyForImport(value.toString("utf8"), passphrase);
    } finally {
      wipeBuffer(value);
    }
  }

  return value;
}
