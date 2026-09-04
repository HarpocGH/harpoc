import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { SessionFile, SessionKeyProtectionScheme } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { SessionManager } from "./session-manager.js";
import type { SessionKeyProtector } from "./session-key-protector.js";
import { expectVaultError } from "@harpoc/test-utils";

/** Protector that records the raw key it was handed, then fails. */
class RecordingFailingProtector implements SessionKeyProtector {
  readonly scheme: SessionKeyProtectionScheme = "dpapi";
  captured: Uint8Array | null = null;

  async protect(key: Uint8Array): Promise<Uint8Array> {
    this.captured = key; // same reference the finally-block wipes
    throw new Error("keystore unavailable");
  }

  async unprotect(blob: Uint8Array): Promise<Uint8Array> {
    return blob;
  }
}

let tempDir: string;
let sessionPath: string;

const sampleSession = (): SessionFile =>
  SessionManager.createSessionData(
    "01890000-0000-7000-8000-000000000000",
    "vault-1",
    Buffer.from(new Uint8Array(32).fill(7)).toString("base64"),
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
    "i",
  );

beforeEach(() => {
  tempDir = mkdtempSync(join(tmpdir(), "harpoc-sm-wipe-"));
  sessionPath = join(tempDir, "session.json");
});

afterEach(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

describe("writeSession raw-key wiping on protector failure", () => {
  it("wipes the raw session key and refuses the write when protect() throws", async () => {
    const protector = new RecordingFailingProtector();
    const manager = new SessionManager(sessionPath, { protector });

    await expectVaultError(
      () => manager.writeSession(sampleSession()),
      ErrorCode.SESSION_KEYSTORE_UNAVAILABLE,
    );

    // The raw key buffer handed to the (failing) protector must be zeroed.
    expect(protector.captured).toBeInstanceOf(Uint8Array);
    expect((protector.captured as Uint8Array).every((b) => b === 0)).toBe(true);

    // Fail closed (R8/D54): nothing is written, unwrapped or otherwise.
    expect(existsSync(sessionPath)).toBe(false);
  });
});
