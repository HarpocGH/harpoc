import { beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode } from "@harpoc/shared";

const lookupMock = vi.hoisted(() => vi.fn());

vi.mock("node:dns", () => ({
  promises: { lookup: lookupMock },
  lookup: vi.fn(),
}));

import { validateUrl } from "./url-validator.js";

// The pre-flight A/AAAA resolution branch of validateUrl — reached only for
// public hostnames, so node:dns is mocked (test-env convention: no real DNS).
describe("validateUrl DNS resolution", () => {
  beforeEach(() => {
    lookupMock.mockReset();
  });

  it("resolves all addresses and returns them in order for pinning", async () => {
    lookupMock.mockResolvedValue([
      { address: "93.184.216.34", family: 4 },
      { address: "2606:2800:21f:cb07:6820:80da:af6b:8b2c", family: 6 },
    ]);

    const result = await validateUrl("https://multi.example.com/api");

    expect(lookupMock).toHaveBeenCalledWith("multi.example.com", { all: true });
    expect(result.resolvedAddresses).toEqual([
      "93.184.216.34",
      "2606:2800:21f:cb07:6820:80da:af6b:8b2c",
    ]);
  });

  it("blocks the request when any resolved address is private (multi-A rebinding)", async () => {
    lookupMock.mockResolvedValue([
      { address: "93.184.216.34", family: 4 },
      { address: "10.0.0.5", family: 4 },
    ]);

    await expect(validateUrl("https://rebind.example.com/")).rejects.toMatchObject({
      code: ErrorCode.SSRF_BLOCKED,
    });
  });

  it("blocks the request when the hostname resolves to loopback", async () => {
    lookupMock.mockResolvedValue([{ address: "127.0.0.1", family: 4 }]);

    await expect(validateUrl("https://rebind.example.com/")).rejects.toMatchObject({
      code: ErrorCode.SSRF_BLOCKED,
    });
  });

  it("fails with DNS_RESOLUTION_FAILED when the lookup returns no addresses", async () => {
    lookupMock.mockResolvedValue([]);

    await expect(validateUrl("https://empty.example.com/")).rejects.toMatchObject({
      code: ErrorCode.DNS_RESOLUTION_FAILED,
    });
  });

  it("fails with DNS_RESOLUTION_FAILED when the resolver errors", async () => {
    lookupMock.mockRejectedValue(new Error("getaddrinfo ENOTFOUND"));

    await expect(validateUrl("https://missing.example.com/")).rejects.toMatchObject({
      code: ErrorCode.DNS_RESOLUTION_FAILED,
    });
  });
});
