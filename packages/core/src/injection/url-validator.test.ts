import { describe, expect, it } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";
import {
  WS_SCHEMES,
  isLoopback,
  isPrivateIp,
  validateHostPort,
  validateUrl,
} from "./url-validator.js";
import { expectVaultError } from "../test-helpers/expect-vault-error.js";

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

  // --- Boundary tests ---

  it("172.15.255.255 is allowed (below 172.16.0.0/12 range)", () => {
    expect(isPrivateIp("172.15.255.255")).toBe(false);
  });

  it("172.32.0.0 is allowed (above 172.16-31.x.x range)", () => {
    expect(isPrivateIp("172.32.0.0")).toBe(false);
  });

  it("192.167.0.1 is allowed (below 192.168.0.0/16 range)", () => {
    expect(isPrivateIp("192.167.0.1")).toBe(false);
  });

  it("192.169.0.1 is allowed (above 192.168.x.x range)", () => {
    expect(isPrivateIp("192.169.0.1")).toBe(false);
  });

  it("169.253.0.1 is allowed (below link-local 169.254.0.0/16)", () => {
    expect(isPrivateIp("169.253.0.1")).toBe(false);
  });

  it.each(["127.0.0.2", "127.1.0.0", "127.255.255.254"])(
    "full loopback range: %s is private",
    (ip) => {
      expect(isPrivateIp(ip)).toBe(true);
    },
  );

  /**
   * T20: this case used to assert `typeof result === "boolean"` — true for
   * every possible implementation, so it pinned nothing. The real question is
   * whether the un-normalized expanded form is *reachable*: it is not, because
   * every path into `isPrivateIp` hands it an address already normalized (the
   * WHATWG URL parser compresses IPv6 literals; `dns.lookup` returns the
   * compressed form). Both halves are now asserted — the helper's literal
   * behavior, and the end-to-end refusal that makes it harmless.
   */
  it("does not normalize an expanded IPv6 literal on its own (known limitation)", () => {
    expect(isPrivateIp("0000:0000:0000:0000:0000:0000:0000:0001")).toBe(false);
    // The compressed form every caller actually supplies is recognized.
    expect(isPrivateIp("::1")).toBe(true);
  });

  it.each([
    ["fd00:0000:0000:0000:0000:0000:0000:0001", "fd00::1"],
    ["fe80:0000:0000:0000:0000:0000:0000:0001", "fe80::1"],
  ])("URL parsing compresses %s to %s before the SSRF check sees it", (expanded, compressed) => {
    expect(new URL(`https://[${expanded}]/api`).hostname).toBe(`[${compressed}]`);
    expect(isPrivateIp(compressed)).toBe(true);
  });

  it("an expanded private IPv6 literal is still refused end to end", async () => {
    await expect(
      validateUrl("https://[fd00:0000:0000:0000:0000:0000:0000:0001]/api"),
    ).rejects.toMatchObject({ code: ErrorCode.SSRF_BLOCKED });
  });

  it("an expanded loopback literal is treated exactly like ::1", async () => {
    await expect(
      validateUrl("http://[0000:0000:0000:0000:0000:0000:0000:0001]:8080/api"),
    ).resolves.toBeDefined();
  });

  it.each(["fcff:ffff::1", "fdff:ffff::1"])("IPv6 ULA expanded %s is private", (ip) => {
    expect(isPrivateIp(ip)).toBe(true);
  });

  it("IPv4-mapped IPv6 hex form ::ffff:c0a8:0101 (192.168.1.1) is private", () => {
    expect(isPrivateIp("::ffff:c0a8:0101")).toBe(true);
  });

  it("IPv4-mapped IPv6 hex form ::ffff:0a00:0001 (10.0.0.1) is private", () => {
    expect(isPrivateIp("::ffff:0a00:0001")).toBe(true);
  });

  it.each(["2600:1f18::1", "2607:f8b0:4004:800::200e"])("public IPv6 %s is not private", (ip) => {
    expect(isPrivateIp(ip)).toBe(false);
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
    await expectVaultError(
      () => validateUrl("http://api.example.com/test"),
      ErrorCode.URL_HTTPS_REQUIRED,
    );
  });

  it("rejects non-HTTP(S) schemes", async () => {
    await expectVaultError(
      () => validateUrl("ftp://example.com/file"),
      ErrorCode.URL_HTTPS_REQUIRED,
    );
  });

  it("rejects invalid URLs", async () => {
    await expectVaultError(() => validateUrl("not-a-url"), ErrorCode.URL_INVALID);
  });

  it("blocks SSRF for private IPs", async () => {
    await expectVaultError(() => validateUrl("https://10.0.0.1/api"), ErrorCode.SSRF_BLOCKED);
  });

  it("blocks SSRF for 192.168.x.x", async () => {
    await expectVaultError(() => validateUrl("https://192.168.1.1/api"), ErrorCode.SSRF_BLOCKED);
  });

  it("blocks SSRF for 172.16-31.x.x", async () => {
    await expectVaultError(() => validateUrl("https://172.16.0.1/api"), ErrorCode.SSRF_BLOCKED);
  });

  it("allows loopback despite being 'private'", async () => {
    await expect(validateUrl("http://127.0.0.1/test")).resolves.not.toThrow();
    await expect(validateUrl("http://localhost/test")).resolves.not.toThrow();
  });

  it("blocks SSRF for IPv4-mapped IPv6 private addresses", async () => {
    await expectVaultError(
      () => validateUrl("https://[::ffff:192.168.1.1]/api"),
      ErrorCode.SSRF_BLOCKED,
    );
  });

  it("blocks SSRF for 0.0.0.0", async () => {
    await expectVaultError(() => validateUrl("https://0.0.0.0/api"), ErrorCode.SSRF_BLOCKED);
  });

  it("returns resolvedAddresses for IP-based URLs as undefined", async () => {
    const result = await validateUrl("https://8.8.8.8/v1/test");
    expect(result.resolvedAddresses).toBeUndefined();
  });

  it("returns resolvedAddresses as undefined for loopback", async () => {
    const result = await validateUrl("http://127.0.0.1:3000/api");
    expect(result.resolvedAddresses).toBeUndefined();
  });

  // --- Edge case tests ---

  it("rejects empty string", async () => {
    await expectVaultError(() => validateUrl(""), ErrorCode.URL_INVALID);
  });

  it("rejects URL with no host (https:///path)", async () => {
    // URL constructor may parse this or throw — either SSRF_BLOCKED or URL_INVALID is acceptable
    let thrown: unknown;
    try {
      await validateUrl("https:///path");
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(VaultError);
    expect([
      ErrorCode.URL_INVALID,
      ErrorCode.SSRF_BLOCKED,
      ErrorCode.DNS_RESOLUTION_FAILED,
    ]).toContain((thrown as VaultError).code);
  });

  it("rejects javascript: scheme", async () => {
    let thrown: unknown;
    try {
      await validateUrl("javascript:alert(1)");
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(VaultError);
    expect([ErrorCode.URL_INVALID, ErrorCode.URL_HTTPS_REQUIRED]).toContain(
      (thrown as VaultError).code,
    );
  });

  it("rejects data: scheme", async () => {
    let thrown: unknown;
    try {
      await validateUrl("data:text/html,<h1>test</h1>");
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(VaultError);
    expect([ErrorCode.URL_INVALID, ErrorCode.URL_HTTPS_REQUIRED]).toContain(
      (thrown as VaultError).code,
    );
  });

  it("accepts HTTPS URL with explicit non-default port", async () => {
    const result = await validateUrl("https://8.8.8.8:8443/v1/test");
    expect(result.url.protocol).toBe("https:");
    expect(result.url.port).toBe("8443");
  });

  it("blocks HTTP loopback with IPv6 [::1] as SSRF or allows as loopback", async () => {
    // [::1] is loopback — HTTP should be allowed
    const result = await validateUrl("http://[::1]:3000/api");
    expect(result.url.protocol).toBe("http:");
  });

  it("blocks IPv6 ULA in URL https://[fc00::1]/api", async () => {
    await expectVaultError(() => validateUrl("https://[fc00::1]/api"), ErrorCode.SSRF_BLOCKED);
  });

  it("blocks IPv6 link-local in URL https://[fe80::1]/api", async () => {
    await expectVaultError(() => validateUrl("https://[fe80::1]/api"), ErrorCode.SSRF_BLOCKED);
  });

  it("blocks IPv4-mapped IPv6 in URL https://[::ffff:10.0.0.1]/api", async () => {
    await expectVaultError(
      () => validateUrl("https://[::ffff:10.0.0.1]/api"),
      ErrorCode.SSRF_BLOCKED,
    );
  });
});

describe("validateHostPort", () => {
  it("accepts a public literal IP and returns it as the resolved address", async () => {
    const result = await validateHostPort("8.8.8.8", 5432);
    expect(result.resolvedAddress).toBe("8.8.8.8");
    expect(result.port).toBe(5432);
  });

  it("allows loopback (trusted local socket)", async () => {
    const result = await validateHostPort("127.0.0.1", 5432);
    expect(result.resolvedAddress).toBe("127.0.0.1");
    await expect(validateHostPort("localhost", 3306)).resolves.toBeDefined();
  });

  it.each(["10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.1.1", "0.0.0.0"])(
    "blocks SSRF for private literal IP %s",
    async (ip) => {
      await expect(validateHostPort(ip, 5432)).rejects.toMatchObject({
        code: ErrorCode.SSRF_BLOCKED,
      });
    },
  );

  it("blocks SSRF for an IPv6 ULA literal", async () => {
    await expect(validateHostPort("fc00::1", 5432)).rejects.toMatchObject({
      code: ErrorCode.SSRF_BLOCKED,
    });
  });
});

describe("validateUrl with a custom scheme policy (WS_SCHEMES)", () => {
  // Literal IPs throughout — DNS is never touched for these (thesis-aligned
  // convention: url-validator tests avoid real lookups).

  it("accepts wss: for a public literal IP", async () => {
    const result = await validateUrl("wss://8.8.8.8/v1/test", WS_SCHEMES);
    expect(result.url.protocol).toBe("wss:");
    expect(result.resolvedAddresses).toBeUndefined();
  });

  it("accepts ws: for loopback", async () => {
    const result = await validateUrl("ws://127.0.0.1:3000/api", WS_SCHEMES);
    expect(result.url.protocol).toBe("ws:");
  });

  it("rejects ws: for a non-loopback target", async () => {
    await expect(validateUrl("ws://8.8.8.8/api", WS_SCHEMES)).rejects.toMatchObject({
      code: ErrorCode.URL_HTTPS_REQUIRED,
    });
  });

  it("rejects an http: URL under the ws scheme policy", async () => {
    await expect(validateUrl("http://127.0.0.1:3000/api", WS_SCHEMES)).rejects.toMatchObject({
      code: ErrorCode.URL_HTTPS_REQUIRED,
    });
  });

  it("blocks SSRF for a private literal IP under wss:", async () => {
    await expect(validateUrl("wss://10.0.0.1/api", WS_SCHEMES)).rejects.toMatchObject({
      code: ErrorCode.SSRF_BLOCKED,
    });
  });

  it("defaults to the HTTP(S) scheme policy when none is passed", async () => {
    const result = await validateUrl("https://8.8.8.8/v1/test");
    expect(result.url.protocol).toBe("https:");
  });
});
