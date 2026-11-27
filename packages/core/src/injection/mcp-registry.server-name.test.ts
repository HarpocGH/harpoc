import { describe, expect, it, vi } from "vitest";
import { ErrorCode, recordOf } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { passError } from "./error-pass.js";
import type { McpConnectionEntry } from "./mcp-registry.js";
import { McpConnectionRegistry } from "./mcp-registry.js";

const WORD_SESSION = "session";

function entryWithoutRedact(secretId: string): McpConnectionEntry {
  return {
    secretId,
    serverName: "slot-mcp",
    transportKind: "stdio",
    client: { close: vi.fn().mockResolvedValue(undefined) } as never,
    state: "connecting",
    crashed: false,
    credentialFingerprint: "f",
    configFingerprint: "g",
    isolation: { network: false, fs: false },
    strictTreeExit: false,
    spawnedAt: Date.now(),
    lastUsedAt: Date.now(),
  };
}

describe("McpConnectionRegistry — the server name of an entry that holds no value to redact", () => {
  it("a connect the session ended under is refused without a record, so a pass redacts it whole", async () => {
    const registry = new McpConnectionRegistry(null);
    let resolveFirst: (entry: McpConnectionEntry) => void = () => undefined;
    const first = registry.acquire(
      "s1",
      () => new Promise<McpConnectionEntry>((resolve) => (resolveFirst = resolve)),
    );
    await registry.closeAll("vault_lock");
    resolveFirst(entryWithoutRedact("s1"));

    const err = await expectVaultError(() => first, ErrorCode.MCP_CONNECT_FAILED);

    expect(recordOf(err)).toBeUndefined();
    expect((passError(err, [WORD_SESSION]) as Error).message).toBe(
      "Failed to connect to MCP server 'slot-mcp': vault [REDACTED] ended while connecting",
    );
  });
});
