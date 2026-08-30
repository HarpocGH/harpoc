import { describe, expect, it } from "vitest";
import { spawnCaptured } from "./spawn-captured.js";

const ENV: Record<string, string> = {
  PATH: process.env.PATH ?? process.env.Path ?? "",
  ...(process.platform === "win32" && process.env.SystemRoot
    ? { SystemRoot: process.env.SystemRoot }
    : {}),
};

function nodeWriting(text: string): string[] {
  return ["-e", `process.stdout.write(${JSON.stringify(text)})`];
}

describe("spawnCaptured — the redacted flag (E70)", () => {
  it("is true only when a redaction changed the captured output", async () => {
    const echo = await spawnCaptured(process.execPath, nodeWriting("token=s3cret-value"), {
      env: ENV,
      timeoutMs: 10_000,
      redact: ["s3cret-value"],
    });
    expect(echo.stdout).toBe("token=[REDACTED]");
    expect(echo.redacted).toBe(true);

    const clean = await spawnCaptured(process.execPath, nodeWriting("token=nothing"), {
      env: ENV,
      timeoutMs: 10_000,
      redact: ["s3cret-value"],
    });
    expect(clean.stdout).toBe("token=nothing");
    expect(clean.redacted).toBe(false);
  });

  it("is false on a spawn failure", async () => {
    const failed = await spawnCaptured("/nonexistent/harpoc-no-such-binary", [], {
      env: ENV,
      timeoutMs: 10_000,
      redact: ["s3cret-value"],
    });
    expect(failed.spawn_failed || failed.exit_code !== 0).toBe(true);
    expect(failed.redacted).toBe(false);
  });
});
