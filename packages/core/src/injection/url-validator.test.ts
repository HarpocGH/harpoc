import { describe, expect, it } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { isLoopback, isPrivateIp, validateUrl } from "./url-validator.js";

describe("isPrivateIp", () => {
  it.each([
    "10.0.0.1",
    "10.255.255.255",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.0.1",
    "192.168.1.100",
    "169.254.1.1",
    "127.0.0.1",
    "127.255.255.255",
  ])("returns true for private IPv4 %s", (ip) => {
    expect(isPrivateIp(ip)).toBe(true);
  });

  it.each(["0.0.0.0", "0.0.0.1", "0.255.255.255"])(
    "returns true for 0.0.0.0/8 address %s",
    (ip) => {
      expect(isPrivateIp(ip)).toBe(true);
    },
  );

  it.each(["8.8.8.8", "1.1.1.1", "203.0.113.1", "172.32.0.1", "11.0.0.1"])(
    "returns false for public IPv4 %s",
    (ip) => {
      expect(isPrivateIp(ip)).toBe(false);
    },
  );

  it("returns true for IPv6 loopback", () => {
    expect(isPrivateIp("::1")).toBe(true);
    expect(isPrivateIp("[::1]")).toBe(true);
  });

  it("returns true for IPv6 ULA", () => {
    expect(isPrivateIp("fc00::1")).toBe(true);
    expect(isPrivateIp("fd12:3456::1")).toBe(true);
  });

  it("returns true for IPv6 link-local", () => {
    expect(isPrivateIp("fe80::1")).toBe(true);
  });

  it("returns false for public IPv6", () => {
    expect(isPrivateIp("2001:db8::1")).toBe(false);
  });

  it("returns true for IPv4-mapped IPv6 private addresses", () => {
    expect(isPrivateIp("::ffff:192.168.1.1")).toBe(true);
    expect(isPrivateIp("::ffff:10.0.0.1")).toBe(true);
    expect(isPrivateIp("::ffff:172.16.0.1")).toBe(true);
    expect(isPrivateIp("::ffff:127.0.0.1")).toBe(true);
  });

  it("returns false for IPv4-mapped IPv6 public addresses", () => {
    expect(isPrivateIp("::ffff:8.8.8.8")).toBe(false);
    expect(isPrivateIp("::ffff:1.1.1.1")).toBe(false);
  });
});

describe("isLoopback", () => {
  it.each(["localhost", "127.0.0.1", "::1", "[::1]", "LOCALHOST"])(
    "returns true for %s",
    (host) => {
      expect(isLoopback(host)).toBe(true);
    },
  );

  it.each(["example.com", "10.0.0.1", "192.168.1.1"])("returns false for %s", (host) => {
    expect(isLoopback(host)).toBe(false);
  });
});

describe("validateUrl", () => {
  it("accepts valid HTTPS URLs", async () => {
    // Use an IP address to avoid DNS resolution in test environment
    const result = await validateUrl("https://8.8.8.8/v1/test");
    expect(result.url.protocol).toBe("https:");
  });

  it("accepts HTTP for localhost", async () => {
    const result = await validateUrl("http://localhost:3000/api");
    expect(result.url.protocol).toBe("http:");
  });

  it("accepts HTTP for 127.0.0.1", async () => {
    const result = await validateUrl("http://127.0.0.1:8080/test");
    expect(result.url.hostname).toBe("127.0.0.1");
  });

  it("rejects HTTP for non-loopback", async () => {
    try {
      await validateUrl("http://api.example.com/test");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.URL_HTTPS_REQUIRED);
    }
  });

  it("rejects non-HTTP(S) schemes", async () => {
    try {
      await validateUrl("ftp://example.com/file");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.URL_HTTPS_REQUIRED);
    }
  });

  it("rejects invalid URLs", async () => {
    try {
      await validateUrl("not-a-url");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.URL_INVALID);
    }
  });

  it("blocks SSRF for private IPs", async () => {
    try {
      await validateUrl("https://10.0.0.1/api");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SSRF_BLOCKED);
    }
  });

  it("blocks SSRF for 192.168.x.x", async () => {
    try {
      await validateUrl("https://192.168.1.1/api");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SSRF_BLOCKED);
    }
  });

  it("blocks SSRF for 172.16-31.x.x", async () => {
    try {
      await validateUrl("https://172.16.0.1/api");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SSRF_BLOCKED);
    }
  });

  it("allows loopback despite being 'private'", async () => {
    await expect(validateUrl("http://127.0.0.1/test")).resolves.not.toThrow();
    await expect(validateUrl("http://localhost/test")).resolves.not.toThrow();
  });

  it("blocks SSRF for IPv4-mapped IPv6 private addresses", async () => {
    try {
      await validateUrl("https://[::ffff:192.168.1.1]/api");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SSRF_BLOCKED);
    }
  });

  it("blocks SSRF for 0.0.0.0", async () => {
    try {
      await validateUrl("https://0.0.0.0/api");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SSRF_BLOCKED);
    }
  });

  it("returns resolvedAddress for IP-based URLs as undefined", async () => {
    const result = await validateUrl("https://8.8.8.8/v1/test");
    expect(result.resolvedAddress).toBeUndefined();
  });

  it("returns resolvedAddress as undefined for loopback", async () => {
    const result = await validateUrl("http://127.0.0.1:3000/api");
    expect(result.resolvedAddress).toBeUndefined();
  });
});
