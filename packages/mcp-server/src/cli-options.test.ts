import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DEFAULT_MCP_HTTP_PORT } from "./http.js";
import {
  MAX_LAUNCH_TOKEN_FILE_BYTES,
  parseHttpPortOption,
  readLaunchTokenFile,
} from "./cli-options.js";

describe("parseHttpPortOption", () => {
  it("defaults to DEFAULT_MCP_HTTP_PORT when --port is absent", () => {
    expect(parseHttpPortOption(undefined)).toEqual({
      ok: true,
      port: DEFAULT_MCP_HTTP_PORT,
    });
  });

  it.each(["1", "3001", "65535"])("accepts %j", (raw) => {
    expect(parseHttpPortOption(raw)).toEqual({ ok: true, port: Number(raw) });
  });

  // The message is byte-identical to the pre-tranche `Number()` parser's, so a
  // launcher matching on it sees no change; only the accepted forms narrow.
  it.each(["0", "65536", "abc", "0x10", "1e2", " 5 ", "5.0", "+5", ""])(
    "refuses %j with the unchanged message",
    (raw) => {
      expect(parseHttpPortOption(raw)).toEqual({
        ok: false,
        message: `Error: Invalid port "${raw}". Must be 1-65535.\n`,
      });
    },
  );

  // Source-text tripwire: main() is not exported, and the integration test
  // `mcp-port-refusal.test.ts` spawns the built binary; this tripwire keeps
  // `index.ts` on the helper even when that dist is stale.
  it("index.ts routes --port through parseHttpPortOption and never coerces it", () => {
    const source = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
    expect(source).toContain("parseHttpPortOption(");
    // Rename-proof: index.ts has no numeric coercion at all — every numeric
    // flag routes through shared's isDecimalInteger via parseHttpPortOption.
    expect(source).not.toMatch(/\b(Number|parseInt|parseFloat)\(/);
  });
});

describe("readLaunchTokenFile (R9/A10)", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "harpoc-token-file-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("returns the trimmed content of a regular file", () => {
    const path = join(dir, "token");
    writeFileSync(path, "  a.b.c\n", "utf8");
    expect(readLaunchTokenFile(path)).toEqual({ ok: true, token: "a.b.c" });
  });

  it("refuses a missing file, naming the path", () => {
    const path = join(dir, "missing");
    const result = readLaunchTokenFile(path);
    expect(result.ok).toBe(false);
    expect((result as { message: string }).message).toContain(`Cannot read --token-file ${path}`);
    expect((result as { message: string }).message.endsWith("\n")).toBe(true);
  });

  it("refuses an empty or whitespace-only file", () => {
    const path = join(dir, "empty");
    writeFileSync(path, "\n \n", "utf8");
    expect(readLaunchTokenFile(path)).toEqual({
      ok: false,
      message: `Error: --token-file ${path} is empty.\n`,
    });
  });

  it("refuses a directory", () => {
    expect(readLaunchTokenFile(dir)).toEqual({
      ok: false,
      message: `Error: --token-file ${dir} is not a regular file.\n`,
    });
  });

  it("refuses a file over the 16 KiB cap without reading it", () => {
    const path = join(dir, "big");
    writeFileSync(path, "x".repeat(MAX_LAUNCH_TOKEN_FILE_BYTES + 1), "utf8");
    expect(readLaunchTokenFile(path)).toEqual({
      ok: false,
      message: `Error: --token-file ${path} exceeds the 16 KiB launch-token limit.\n`,
    });
  });

  // Source-text tripwire, like the --port one above: index.ts reads the
  // launch token through the helper and carries no argv value channel.
  it("index.ts reads the launch token through readLaunchTokenFile and never from an argv value", () => {
    const source = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
    expect(source).toContain("readLaunchTokenFile(");
    expect(source).not.toMatch(/launchToken:\s*\(?values\.token\b/);
  });
});
