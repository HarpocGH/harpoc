import { describe, expect, it, vi } from "vitest";
import type { VaultClient } from "@harpoc/sdk";
import { VaultState } from "@harpoc/shared";
import { createBridgeServer } from "./bridge.js";
import { connectInMemoryClient } from "@harpoc/test-utils";

// The bridge's module graph never loads the engine (B1): any import of
// `@harpoc/core` — by `bridge.ts` or anything it imports — runs this factory,
// and the factory's throw fails this file's import before a case runs. The
// built binary's twin is `index.spawn.test.ts`'s resolve-hook tripwire.
vi.mock("@harpoc/core", () => {
  throw new Error("@harpoc/core was loaded on the bridge path");
});

describe("createBridgeServer without @harpoc/core (B1)", () => {
  it("serves tools and resources with the engine module unloadable", async () => {
    const client = {
      listSecrets: vi.fn().mockResolvedValue([]),
      getHealth: vi.fn().mockResolvedValue({ state: VaultState.UNLOCKED, version: "1.5.0" }),
    } as unknown as VaultClient;
    const bridge = await connectInMemoryClient(
      createBridgeServer({ client: () => client, baseUrl: "http://127.0.0.1:1" }),
    );
    try {
      expect(await bridge.listTools()).toHaveLength(9);
      const result = await bridge.callTool("list_secrets", {});
      expect(result.isError).toBeUndefined();
      expect(await bridge.readResource("secret://vault/health")).toMatchObject({
        contents: [{ uri: "secret://vault/health" }],
      });
    } finally {
      await bridge.close();
    }
  });
});
