import { describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { VaultEngine } from "@harpoc/core";
import { HARPOC_VERSION } from "@harpoc/shared";
import { createMcpServer } from "./server.js";

function mockEngine(): VaultEngine {
  return {
    listSecrets: vi.fn().mockReturnValue([]),
    getSecretInfo: vi.fn().mockResolvedValue({}),
    useSecret: vi.fn().mockResolvedValue({ status: 200, body: "" }),
    createSecret: vi.fn().mockResolvedValue({
      handle: "secret://x",
      status: "pending",
      message: "",
    }),
    rotateSecret: vi.fn().mockResolvedValue(undefined),
    revokeSecret: vi.fn().mockResolvedValue(undefined),
    resolveSecretId: vi.fn().mockResolvedValue("uuid-123"),
    getState: vi.fn().mockReturnValue("unlocked"),
    queryAudit: vi.fn().mockReturnValue([]),
    auditServerStart: vi.fn(),
    isTokenRevoked: vi.fn().mockReturnValue(false),
    verifyToken: vi.fn(),
  } as unknown as VaultEngine;
}

// The name and version a host displays for this server come from one place:
// HARPOC_VERSION, pinned to every manifest in @harpoc/shared. Until v1.5.0 the
// server announced the placeholder "0.0.0" it had carried since the pre-1.0
// CLI phase.
describe("MCP serverInfo", () => {
  it("announces name harpoc and the product version", async () => {
    const server = createMcpServer({
      engine: mockEngine(),
      allowTokenless: true,
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({ name: "server-info-test", version: "0.0.0" });
    await client.connect(clientTransport);
    try {
      expect(client.getServerVersion()).toMatchObject({
        name: "harpoc",
        version: HARPOC_VERSION,
      });
      expect(HARPOC_VERSION).not.toBe("0.0.0");
    } finally {
      await client.close();
      await server.close();
    }
  });
});
