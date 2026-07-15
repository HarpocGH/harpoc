import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { SessionFile, SessionKeyProtectionScheme } from "@harpoc/shared";
import { DEFAULT_SESSION_TTL_MS, ErrorCode, MAX_SESSION_TTL_MS, VaultError } from "@harpoc/shared";
import { SessionManager } from "./session-manager.js";
import type { WrappingKeyStore } from "./wrapping-key-store.js";
import { KeystoreWrappedSessionKeyProtector, WRAPPING_KEY_LENGTH } from "./wrapping-key-store.js";

class InMemoryWrappingKeyStore implements WrappingKeyStore {
  key: Uint8Array | null = null;
  loads = 0;
  stores = 0;
  failStorePersistence = false;

  constructor(readonly scheme: SessionKeyProtectionScheme = "keychain") {}

  async loadWrappingKey(): Promise<Uint8Array | null> {
    this.loads++;
    // Copies: the protector wipes returned buffers after use.
    return this.key ? new Uint8Array(this.key) : null;
  }

  async storeWrappingKey(key: Uint8Array): Promise<void> {
    this.stores++;
    if (this.failStorePersistence) return; // silently drop — the -i swallowed-failure scenario
    this.key = new Uint8Array(key);
  }
}

async function expectSessionFileError(promise: Promise<unknown>): Promise<void> {
  try {
    await promise;
    expect.unreachable("expected rejection");
  } catch (err) {
    expect(err).toBeInstanceOf(VaultError);
    expect((err as VaultError).code).toBe(ErrorCode.SESSION_FILE_ERROR);
  }
}

describe("KeystoreWrappedSessionKeyProtector", () => {
  it("roundtrips a session key; blob is neither the key nor its length", async () => {
    const store = new InMemoryWrappingKeyStore();
    const protector = new KeystoreWrappedSessionKeyProtector(store);
    const key = new Uint8Array(randomBytes(32));

    const blob = await protector.protect(key);
    expect(blob.length).toBeGreaterThan(key.length);
    expect(Buffer.from(blob).includes(Buffer.from(key))).toBe(false);

    const unwrapped = await protector.unprotect(blob);
    expect(Buffer.from(unwrapped).equals(Buffer.from(key))).toBe(true);
  });

  it("reports the store's scheme", () => {
    expect(
      new KeystoreWrappedSessionKeyProtector(new InMemoryWrappingKeyStore("keyring")).scheme,
    ).toBe("keyring");
  });

  it("produces different blobs for the same key (fresh IV per wrap)", async () => {
    const protector = new KeystoreWrappedSessionKeyProtector(new InMemoryWrappingKeyStore());
    const key = new Uint8Array(randomBytes(32));

    const blob1 = await protector.protect(key);
    const blob2 = await protector.protect(key);
    expect(Buffer.from(blob1).equals(Buffer.from(blob2))).toBe(false);
  });

  it("rejects a tampered blob in every region (iv, tag, ciphertext)", async () => {
    const protector = new KeystoreWrappedSessionKeyProtector(new InMemoryWrappingKeyStore());
    const blob = await protector.protect(new Uint8Array(randomBytes(32)));

    for (const index of [5, 20, blob.length - 1]) {
      const tampered = new Uint8Array(blob);
      tampered[index] = (tampered[index] ?? 0) ^ 0xff;
      await expectSessionFileError(protector.unprotect(tampered));
    }
  });

  it("rejects a blob wrapped under a different wrapping key", async () => {
    const storeA = new InMemoryWrappingKeyStore();
    const storeB = new InMemoryWrappingKeyStore();
    const key = new Uint8Array(randomBytes(32));

    const blob = await new KeystoreWrappedSessionKeyProtector(storeA).protect(key);
    // storeB holds its own, different wrapping key.
    await new KeystoreWrappedSessionKeyProtector(storeB).protect(key);
    await expectSessionFileError(new KeystoreWrappedSessionKeyProtector(storeB).unprotect(blob));
  });

  it("rejects a blob produced under a different scheme (AAD binding)", async () => {
    const keychainStore = new InMemoryWrappingKeyStore("keychain");
    const blob = await new KeystoreWrappedSessionKeyProtector(keychainStore).protect(
      new Uint8Array(randomBytes(32)),
    );

    // Same wrapping key, different claimed scheme — only the AAD differs.
    const foreignScheme = new InMemoryWrappingKeyStore("secret-service");
    foreignScheme.key = keychainStore.key;
    await expectSessionFileError(
      new KeystoreWrappedSessionKeyProtector(foreignScheme).unprotect(blob),
    );
  });

  it("rejects truncated blobs, unknown versions, and empty input", async () => {
    const store = new InMemoryWrappingKeyStore();
    const protector = new KeystoreWrappedSessionKeyProtector(store);
    const blob = await protector.protect(new Uint8Array(randomBytes(32)));

    await expectSessionFileError(protector.unprotect(blob.subarray(0, 20)));

    const wrongVersion = new Uint8Array(blob);
    wrongVersion[0] = 0x02;
    await expectSessionFileError(protector.unprotect(wrongVersion));

    await expectSessionFileError(protector.protect(new Uint8Array(0)));
    await expectSessionFileError(protector.unprotect(new Uint8Array(0)));
  });

  it("fails closed when the keystore item is missing at unprotect", async () => {
    const store = new InMemoryWrappingKeyStore();
    const protector = new KeystoreWrappedSessionKeyProtector(store);
    const blob = await protector.protect(new Uint8Array(randomBytes(32)));

    store.key = null; // rebooted kernel keyring / deleted item
    await expectSessionFileError(protector.unprotect(blob));
  });

  it("creates the wrapping key once and reuses it; unprotect never stores", async () => {
    const store = new InMemoryWrappingKeyStore();
    const protector = new KeystoreWrappedSessionKeyProtector(store);
    const key = new Uint8Array(randomBytes(32));

    const blob = await protector.protect(key);
    expect(store.stores).toBe(1);
    expect(store.loads).toBe(2); // miss, then read-back verification

    await protector.protect(key);
    expect(store.stores).toBe(1);

    await protector.unprotect(blob);
    expect(store.stores).toBe(1);
    expect(store.key?.length).toBe(WRAPPING_KEY_LENGTH);
  });

  it("fails when the keystore silently drops the write (read-back verification)", async () => {
    const store = new InMemoryWrappingKeyStore();
    store.failStorePersistence = true;
    const protector = new KeystoreWrappedSessionKeyProtector(store);
    await expectSessionFileError(protector.protect(new Uint8Array(randomBytes(32))));
  });

  it("resolves toward the stored winner when a concurrent creation displaces the fresh key (review T8)", async () => {
    // Another process's key wins the first-creation race: the store keeps
    // ITS key, not the one this protector just generated. The wrap must land
    // under the winner — returning the displaced local candidate would
    // produce a blob nothing can ever unwrap.
    const store = new InMemoryWrappingKeyStore();
    const winner = new Uint8Array(randomBytes(32));
    store.storeWrappingKey = async () => {
      store.stores++;
      store.key = new Uint8Array(winner);
    };
    const protector = new KeystoreWrappedSessionKeyProtector(store);
    const sessionKey = new Uint8Array(randomBytes(32));

    const blob = await protector.protect(sessionKey);

    const unwrapped = await new KeystoreWrappedSessionKeyProtector(store).unprotect(blob);
    expect(Buffer.from(unwrapped).equals(Buffer.from(sessionKey))).toBe(true);
  });

  it("rejects a keystore item of unexpected length", async () => {
    const store = new InMemoryWrappingKeyStore();
    store.key = new Uint8Array(randomBytes(16));
    const protector = new KeystoreWrappedSessionKeyProtector(store);
    await expectSessionFileError(protector.protect(new Uint8Array(randomBytes(32))));
  });
});

describe("KeystoreWrappedSessionKeyProtector through SessionManager", () => {
  let sessionDir: string;
  let sessionPath: string;

  function makeValidSession(): SessionFile {
    const now = Date.now();
    const b64 = randomBytes(32).toString("base64");
    return {
      version: 1,
      session_id: "keystore-session",
      vault_id: "keystore-vault",
      created_at: now,
      expires_at: now + DEFAULT_SESSION_TTL_MS,
      max_expires_at: now + MAX_SESSION_TTL_MS,
      session_key: b64,
      wrapped_kek: b64,
      wrapped_kek_iv: b64,
      wrapped_kek_tag: b64,
      wrapped_jwt_key: b64,
      wrapped_jwt_key_iv: b64,
      wrapped_jwt_key_tag: b64,
      wrapped_audit_key: b64,
      wrapped_audit_key_iv: b64,
      wrapped_audit_key_tag: b64,
    };
  }

  beforeEach(() => {
    sessionDir = join(tmpdir(), `harpoc-kw-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(sessionDir, { recursive: true });
    sessionPath = join(sessionDir, "session.json");
  });

  afterEach(() => {
    rmSync(sessionDir, { recursive: true, force: true });
  });

  it("writes a keychain-tagged file whose session_key is not the raw key, and reads it back", async () => {
    const store = new InMemoryWrappingKeyStore("keychain");
    const manager = new SessionManager(sessionPath, {
      protector: new KeystoreWrappedSessionKeyProtector(store),
    });
    const session = makeValidSession();
    await manager.writeSession(session);

    const onDisk = JSON.parse(readFileSync(sessionPath, "utf8")) as SessionFile;
    expect(onDisk.key_protection).toBe("keychain");
    expect(onDisk.session_key).not.toBe(session.session_key);

    const read = await manager.readSession();
    expect(read?.session_key).toBe(session.session_key);
    expect(read?.key_protection).toBe("none");
  });

  it("fails closed on a scheme mismatch (keychain file, keyring protector)", async () => {
    const writeStore = new InMemoryWrappingKeyStore("keychain");
    const writer = new SessionManager(sessionPath, {
      protector: new KeystoreWrappedSessionKeyProtector(writeStore),
    });
    await writer.writeSession(makeValidSession());

    const readStore = new InMemoryWrappingKeyStore("keyring");
    readStore.key = writeStore.key; // even with the identical wrapping key
    const reader = new SessionManager(sessionPath, {
      protector: new KeystoreWrappedSessionKeyProtector(readStore),
    });
    expect(await reader.readSession()).toBeNull();
  });

  it("falls back to an unwrapped file when the keystore fails at write time", async () => {
    const store = new InMemoryWrappingKeyStore("keychain");
    store.failStorePersistence = true;
    const fallbacks: Error[] = [];
    const manager = new SessionManager(sessionPath, {
      protector: new KeystoreWrappedSessionKeyProtector(store),
      onProtectionFallback: (err) => fallbacks.push(err),
    });
    const session = makeValidSession();
    await manager.writeSession(session);

    expect(fallbacks).toHaveLength(1);
    const onDisk = JSON.parse(readFileSync(sessionPath, "utf8")) as SessionFile;
    expect(onDisk.key_protection).toBe("none");
    expect(onDisk.session_key).toBe(session.session_key);
    expect(await manager.readSession()).not.toBeNull();
  });
});
