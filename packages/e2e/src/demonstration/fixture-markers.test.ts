import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { MCP_DOWNSTREAM } from "../harness/backends.js";
import { STDIO_DOWNSTREAM_MARKER } from "./contexts.js";

/**
 * Both downstream MCP fixtures return a benign marker beside the credential, so
 * the two `mcp` arms have the negative control every other arm has: blanket
 * redaction of a tool result satisfies every opacity assertion, and only a
 * surviving benign string tells surgical redaction from a mute vault.
 *
 * Neither fixture can import the constant it has to match — one is a container
 * image, the other a bare script the vault spawns — so the values are duplicated
 * by necessity. These are the drift pins for that duplication, and they are
 * static reads: a marker that silently stopped matching would otherwise surface
 * only as an unexplained `assertPresent` failure in a full fleet run.
 */
function fixtureSource(relative: string): string {
  return readFileSync(
    fileURLToPath(new URL(`../../fixtures/${relative}`, import.meta.url)),
    "utf8",
  );
}

describe("downstream fixture markers", () => {
  it("the http downstream emits the marker backends.ts advertises", () => {
    const source = fixtureSource("mcp-downstream/server.mjs");
    expect(source).toContain(`"${MCP_DOWNSTREAM.benignMarker}"`);
    expect(source).toContain("marker: BENIGN_MARKER");
  });

  it("the stdio downstream emits the marker contexts.ts advertises", () => {
    const source = fixtureSource("mcp/downstream-server.mjs");
    expect(source).toContain(`"${STDIO_DOWNSTREAM_MARKER}"`);
    expect(source).toContain("marker: BENIGN_MARKER");
  });

  it("the two markers are distinct, so neither arm can pass on the other's control", () => {
    expect(STDIO_DOWNSTREAM_MARKER).not.toBe(MCP_DOWNSTREAM.benignMarker);
  });
});
