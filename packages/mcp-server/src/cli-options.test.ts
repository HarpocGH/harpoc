import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { DEFAULT_MCP_HTTP_PORT } from "./http.js";
import { parseHttpPortOption } from "./cli-options.js";

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

  // Source-text tripwire: main() is not exported and no test spawns the binary,
  // so this is what keeps index.ts on the strict parser.
  it("index.ts routes --port through parseHttpPortOption and never coerces it", () => {
    const source = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
    expect(source).toContain("parseHttpPortOption(");
    // Rename-proof: index.ts has no numeric coercion at all — every numeric
    // flag routes through shared's isDecimalInteger via parseHttpPortOption.
    expect(source).not.toMatch(/\b(Number|parseInt|parseFloat)\(/);
  });
});
