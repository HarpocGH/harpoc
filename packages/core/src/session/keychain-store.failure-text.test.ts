import { existsSync, mkdtempSync, readdirSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SessionFile } from "@harpoc/shared";
import { DEFAULT_SESSION_TTL_MS, ErrorCode, MAX_SESSION_TTL_MS } from "@harpoc/shared";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";
import { KeychainWrappingKeyStore } from "./keychain-store.js";
import { runKeystoreHelper } from "./keystore-helper.js";
import { SessionManager } from "./session-manager.js";
import { KeystoreWrappedSessionKeyProtector } from "./wrapping-key-store.js";

vi.mock("./keystore-helper.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./keystore-helper.js")>();
  return { ...actual, runKeystoreHelper: vi.fn(actual.runKeystoreHelper) };
});

const HELPER_TEXT = "helper-text-marker-3f9c";
const ABSENT_SECURITY = "/nonexistent/harpoc-test/security";
const TEST_SERVICE = "harpoc.test.failure-text";
const TEST_KEYCHAIN = "/nonexistent/harpoc-test/failure-text.keychain";
const READ_COMMAND = `find-generic-password -s ${TEST_SERVICE} -a harpoc -w ${TEST_KEYCHAIN}\n`;
const WRITE_COMMAND = `add-generic-password -U -s ${TEST_SERVICE} -a harpoc -w <key> ${TEST_KEYCHAIN}\n`;
const READ_FAILURE = {
  stdout: "",
  stderr: `security: SecKeychainSearchCopyNext: ${HELPER_TEXT}`,
  exitCode: 36,
};
const READ_MISS = {
  stdout: "",
  stderr:
    "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.",
  exitCode: 44,
};
/** The shape of `security -i`'s line for a failed `add-generic-password`, measured on CI's macOS legs (R0). */
const WRITE_FAILURE_STDERR =
  `security: SecKeychainItemCreateFromContent (/Users/runner/Library/Keychains/${HELPER_TEXT}.keychain-db): ` +
  "The specified item already exists in the keychain.\nadd-generic-password: returned -25299\n";
const KEY = new Uint8Array(32).fill(0x5c);
const KEY_HEX = Buffer.from(KEY).toString("hex");

function testStore(): KeychainWrappingKeyStore {
  return new KeychainWrappingKeyStore({
    executablePath: ABSENT_SECURITY,
    service: TEST_SERVICE,
    keychain: TEST_KEYCHAIN,
  });
}

function handed(): { path: string; label: string; command: string }[] {
  return vi.mocked(runKeystoreHelper).mock.calls.map(([path, , stdin, options]) => ({
    path,
    label: options.label,
    command: stdin.replace(/ -w [0-9a-f]{64} /, " -w <key> "),
  }));
}

function unavailable(cause: string): string {
  return `Session keystore unavailable: the keychain keystore could not protect the session key (${cause}). Repair the keystore and unlock again, or set HARPOC_SESSION_KEYSTORE=off to keep the session under file permissions only`;
}

async function failingSecurityWrite(): Promise<string[]> {
  const actual =
    await vi.importActual<typeof import("./keystore-helper.js")>("./keystore-helper.js");
  const script = `const chunks = []; process.stdin.on("data", (chunk) => chunks.push(chunk)); process.stdin.on("end", () => process.stderr.write(Buffer.concat(chunks).toString("utf8") + ${JSON.stringify(WRITE_FAILURE_STDERR)}, () => process.exit(45)));`;
  const stdins: string[] = [];
  vi.mocked(runKeystoreHelper).mockImplementationOnce((_path, _args, stdinPayload, options) => {
    stdins.push(stdinPayload);
    return actual.runKeystoreHelper(process.execPath, ["-e", script], stdinPayload, options);
  });
  return stdins;
}

function makeValidSession(): SessionFile {
  const now = Date.now();
  const b64 = Buffer.from("keychain-failure-text").toString("base64");
  return {
    version: 1,
    session_id: "test-session",
    vault_id: "test-vault",
    created_at: now,
    expires_at: now + DEFAULT_SESSION_TTL_MS,
    max_expires_at: now + MAX_SESSION_TTL_MS,
    key_protection: "none",
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

let sessionDir: string;

beforeEach(() => {
  vi.mocked(runKeystoreHelper).mockReset();
  sessionDir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-keychain-failure-")));
});

afterEach(() => {
  rmSync(sessionDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("the Keychain store's failures name the exit status, never what security wrote", () => {
  it("a Keychain read failure names the exit status alone", async () => {
    vi.mocked(runKeystoreHelper).mockResolvedValueOnce(READ_FAILURE);

    const err = await expectVaultError(
      () => testStore().loadWrappingKey(),
      ErrorCode.SESSION_FILE_ERROR,
    );
    expectAbsent(err.message, HELPER_TEXT);
    expect(err.message).toBe("Session file error: Keychain read failed (exit 36)");
    expect(handed()).toEqual([
      { path: ABSENT_SECURITY, label: "Keychain read", command: READ_COMMAND },
    ]);
  });

  it("a Keychain write failure names the exit status alone, nothing of security's line or the key it was handed", async () => {
    const stdins = await failingSecurityWrite();

    const err = await expectVaultError(
      () => testStore().storeWrappingKey(KEY),
      ErrorCode.SESSION_FILE_ERROR,
    );
    expectAbsent(err.message, KEY_HEX);
    expectAbsent(err.message, HELPER_TEXT);
    expect(err.message).toBe("Session file error: Keychain write failed (exit 45)");
    expect(stdins.map((stdin) => stdin.includes(` -w ${KEY_HEX} `))).toEqual([true]);
    expect(handed()).toEqual([
      { path: ABSENT_SECURITY, label: "Keychain write", command: WRITE_COMMAND },
    ]);
  });

  it("through the session write, SESSION_KEYSTORE_UNAVAILABLE carries the exit status and no helper text", async () => {
    vi.mocked(runKeystoreHelper).mockResolvedValueOnce(READ_FAILURE);
    const sessionPath = join(sessionDir, "session.json");
    const manager = new SessionManager(sessionPath, {
      protector: new KeystoreWrappedSessionKeyProtector(testStore()),
    });

    const err = await expectVaultError(
      () => manager.writeSession(makeValidSession()),
      ErrorCode.SESSION_KEYSTORE_UNAVAILABLE,
    );
    expectAbsent(err.message, HELPER_TEXT);
    expect(err.message).toBe(unavailable("Session file error: Keychain read failed (exit 36)"));
    expect(handed()).toEqual([
      { path: ABSENT_SECURITY, label: "Keychain read", command: READ_COMMAND },
    ]);
    expect(existsSync(sessionPath)).toBe(false);
    expect(readdirSync(sessionDir)).toEqual([]);
  });

  it("through the session write, a failed add after a miss carries the exit status and nothing of security's line or the key", async () => {
    vi.mocked(runKeystoreHelper).mockResolvedValueOnce(READ_MISS);
    const stdins = await failingSecurityWrite();
    const sessionPath = join(sessionDir, "session.json");
    const manager = new SessionManager(sessionPath, {
      protector: new KeystoreWrappedSessionKeyProtector(testStore()),
    });

    const err = await expectVaultError(
      () => manager.writeSession(makeValidSession()),
      ErrorCode.SESSION_KEYSTORE_UNAVAILABLE,
    );
    const handedKey = / -w ([0-9a-f]{64}) /.exec(stdins[0] ?? "")?.[1];
    expect(handedKey === undefined).toBe(false);
    expectAbsent(err.message, handedKey as string);
    expectAbsent(err.message, HELPER_TEXT);
    expect(err.message).toBe(unavailable("Session file error: Keychain write failed (exit 45)"));
    expect(handed()).toEqual([
      { path: ABSENT_SECURITY, label: "Keychain read", command: READ_COMMAND },
      { path: ABSENT_SECURITY, label: "Keychain write", command: WRITE_COMMAND },
    ]);
    expect(existsSync(sessionPath)).toBe(false);
    expect(readdirSync(sessionDir)).toEqual([]);
  });
});
