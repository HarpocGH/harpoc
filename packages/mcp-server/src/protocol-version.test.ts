import { describe, expect, it, vi } from "vitest";
import { LATEST_PROTOCOL_VERSION } from "@modelcontextprotocol/core/internal";
import type { VaultEngine } from "@harpoc/core";
import { connectInMemoryClient, connectModernInMemoryClient } from "@harpoc/test-utils";
import { createMcpServer } from "./server.js";

function mockEngine(): VaultEngine {
  return {
    auditServerStart: vi.fn(),
  } as unknown as VaultEngine;
}

// v1.5.0's release notes state the MCP revision the server speaks. The SDK
// owns the constant; this pin turns the statement into a tested fact and
// fails the day a bump moves it (compromise audit R10/B28).
describe("MCP protocol revision", () => {
  it("the installed SDK's latest revision is 2025-11-25", () => {
    expect(LATEST_PROTOCOL_VERSION).toBe("2025-11-25");
  });

  it("negotiates 2026-07-28 with a pinned modern client", async () => {
    const modern = await connectModernInMemoryClient(() =>
      createMcpServer({ engine: mockEngine(), allowTokenless: true }),
    );
    try {
      expect(modern.client.getNegotiatedProtocolVersion()).toBe("2026-07-28");
      expect(modern.client.getProtocolEra()).toBe("modern");
    } finally {
      await modern.close();
    }
  });

  it("negotiates 2025-11-25 with a legacy client", async () => {
    const legacy = await connectInMemoryClient(
      createMcpServer({ engine: mockEngine(), allowTokenless: true }),
    );
    try {
      expect(legacy.client.getNegotiatedProtocolVersion()).toBe("2025-11-25");
      expect(legacy.client.getProtocolEra()).toBe("legacy");
    } finally {
      await legacy.close();
    }
  });
});
