import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { EphemeralSshAgent } from "./index.js";
import { expectVaultError } from "@harpoc/test-utils";

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, mkdtempSync: vi.fn(actual.mkdtempSync) };
});

const { mkdtempSync: realMkdtempSync } = await vi.importActual<typeof import("node:fs")>("node:fs");

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "__fixtures__", "ssh");
const KEY_PEM = readFileSync(join(FIXTURES, "ed25519_openssh"), "utf8");
const AGENT_DIR_UNCREATED =
  "Ephemeral ssh-agent failed: the agent's socket directory could not be created";

function ioError(code: string, path: string): NodeJS.ErrnoException {
  const err = new Error(`${code}: injected, '${path}'`) as NodeJS.ErrnoException;
  err.code = code;
  err.path = path;
  return err;
}

beforeEach(() => {
  vi.mocked(mkdtempSync).mockImplementation((prefix, options) => {
    if (basename(prefix) === "harpoc-agent-") throw ioError("ENOSPC", `${prefix}XXXXXX`);
    return realMkdtempSync(prefix, options);
  });
});

afterEach(() => {
  vi.mocked(mkdtempSync).mockReset();
});

// POSIX only: on win32 the agent serves a named pipe and creates no socket directory.
describe.skipIf(process.platform === "win32")(
  "the agent's socket directory cannot be created",
  () => {
    it("returns a promise — no throw before it — when mkdtempSync fails", async () => {
      let outcome: unknown;
      expect(() => {
        outcome = EphemeralSshAgent.start(KEY_PEM);
      }).not.toThrow();
      expect(outcome).toBeInstanceOf(Promise);
      await expect(outcome).rejects.toBeInstanceOf(VaultError);
    });

    it("rejects SSH_AGENT_FAILED with a fixed message that names no path", async () => {
      const err = await expectVaultError(
        () => EphemeralSshAgent.start(KEY_PEM),
        ErrorCode.SSH_AGENT_FAILED,
      );
      expect(mkdtempSync).toHaveBeenCalledTimes(1);
      expect(err.message.includes(tmpdir())).toBe(false);
      expect(err.message.includes("harpoc-agent-")).toBe(false);
      expect(err.message === AGENT_DIR_UNCREATED).toBe(true);
    });
  },
);
