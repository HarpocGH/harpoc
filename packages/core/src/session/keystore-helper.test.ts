import { describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";
import { runKeystoreHelper } from "./keystore-helper.js";

const NODE = process.execPath;
const HELPER_TEXT = "helper-text-marker-3f9c";

/**
 * Direct pins for the generic bridge-runner guards (review T7): output caps,
 * settle-once, EPIPE tolerance, timeout. The platform bridges (DPAPI,
 * Keychain, secret-tool, keyctl) are thin wrappers over this seam, so a
 * regression here would surface on every platform — the fake "bridge" is
 * node itself with inline scripts.
 */
describe("runKeystoreHelper — generic guards", () => {
  it("roundtrips stdin to stdout on a clean exit", async () => {
    const result = await runKeystoreHelper(
      NODE,
      ["-e", "process.stdin.pipe(process.stdout)"],
      "payload-bytes",
      { label: "Echo" },
    );
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("payload-bytes");
  });

  it("rejects oversized stdout instead of buffering it unbounded (64 KiB cap)", async () => {
    await expect(
      runKeystoreHelper(
        NODE,
        ["-e", "process.stdout.write(Buffer.alloc(70 * 1024, 65), () => process.exit(0))"],
        "",
        { label: "Oversize" },
      ),
    ).rejects.toMatchObject({
      code: ErrorCode.SESSION_FILE_ERROR,
      message: expect.stringContaining("oversized output") as string,
    });
  });

  it("a non-zero exit names the label and the exit status, nothing the helper wrote", async () => {
    const err = await expectVaultError(
      () =>
        runKeystoreHelper(
          NODE,
          ["-e", `process.stderr.write(${JSON.stringify(HELPER_TEXT)}, () => process.exit(3))`],
          "",
          { label: "StderrSpam" },
        ),
      ErrorCode.SESSION_FILE_ERROR,
    );
    expectAbsent(err.message, HELPER_TEXT);
    expect(err.message).toBe("Session file error: StderrSpam failed (exit 3)");
  });

  it("settles exactly once when output arrives before a non-zero exit", async () => {
    // A bridge that writes output AND fails: the close-time rejection must be
    // the only settlement (no resolve-then-reject crash).
    await expect(
      runKeystoreHelper(
        NODE,
        ["-e", 'process.stdout.write("partial", () => process.exit(2))'],
        "",
        { label: "SettleOnce" },
      ),
    ).rejects.toMatchObject({ code: ErrorCode.SESSION_FILE_ERROR });
  });

  it("tolerates a child that exits without reading stdin (EPIPE)", async () => {
    // 1 MiB payload overflows the pipe buffer; the immediate exit makes the
    // write EPIPE. Pre-hardening this crashed with an unhandled stream error.
    const result = await runKeystoreHelper(
      NODE,
      ["-e", "process.exit(0)"],
      "x".repeat(1024 * 1024),
      { label: "Epipe", expectZeroExit: false },
    );
    expect(result.exitCode).toBe(0);
  });

  it("kills a hung bridge at the timeout", async () => {
    await expect(
      runKeystoreHelper(NODE, ["-e", "setTimeout(() => {}, 60000)"], "", {
        label: "Hang",
        timeoutMs: 500,
      }),
    ).rejects.toMatchObject({
      code: ErrorCode.SESSION_FILE_ERROR,
      message: expect.stringContaining("timed out after 500ms") as string,
    });
  });

  it("expectZeroExit: false returns the non-zero exit to the caller (miss signaling)", async () => {
    const result = await runKeystoreHelper(NODE, ["-e", "process.exit(1)"], "", {
      label: "Miss",
      expectZeroExit: false,
    });
    expect(result.exitCode).toBe(1);
  });

  it("a helper that does not start names node's code, not its text", async () => {
    const err = await expectVaultError(
      () => runKeystoreHelper("/nonexistent/keystore-bridge", [], "", { label: "Ghost" }),
      ErrorCode.SESSION_FILE_ERROR,
    );
    expect(err.message).toBe("Session file error: Ghost helper failed to start: ENOENT");
  });
});
