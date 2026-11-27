import { describe, expect, it } from "vitest";

describe("the SDK's export surface", () => {
  it("the SDK exports its two clients and nothing of the error text", async () => {
    expect(Object.keys(await import("./index.js")).sort()).toEqual(["DirectClient", "RestClient"]);
  });
});
