import { describe, expect, it, vi } from "vitest";
import { DirectClient } from "./direct-client.js";

vi.mock("@harpoc/shared", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@harpoc/shared")>()),
  HARPOC_VERSION: "9.9.9-product",
}));

describe("DirectClient.getHealth version", () => {
  it("reports the product version, not the vault-format stamp", async () => {
    const client = new DirectClient({ getState: () => "unlocked" } as never);
    expect((await client.getHealth()).version).toBe("9.9.9-product");
  });
});
