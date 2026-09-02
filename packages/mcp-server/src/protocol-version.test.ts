import { describe, expect, it } from "vitest";
import { LATEST_PROTOCOL_VERSION } from "@modelcontextprotocol/sdk/types.js";

// v1.5.0's release notes state the MCP revision the server speaks. The SDK
// owns the constant; this pin turns the statement into a tested fact and
// fails the day a bump moves it (compromise audit R10/B28).
describe("MCP protocol revision", () => {
  it("the installed SDK's latest revision is 2025-11-25", () => {
    expect(LATEST_PROTOCOL_VERSION).toBe("2025-11-25");
  });
});
