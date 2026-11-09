import { X509Certificate } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import { createCa, issueLeaf } from "@harpoc/cert-manager";
import { ErrorCode } from "@harpoc/shared";
import {
  DEFAULT_LEAF_CACHE_SIZE,
  DEFAULT_LEAF_TTL_MS,
  createLeafCache,
  hostPermitted,
} from "./ca.js";
import type { LeafIssuer, ProxyCaOptions } from "./ca.js";
import { expectVaultError } from "@harpoc/test-utils";

const HOSTS = ["localhost", "127.0.0.1", "::1", "api.github.com"];
const CA = createCa({ permittedHosts: HOSTS, validityDays: 30 });
const DAY_MS = 86_400_000;

function cacheWith(extra: Partial<ProxyCaOptions> = {}): {
  cache: ReturnType<typeof createLeafCache>;
  issue: Mock<LeafIssuer>;
} {
  const issue = vi.fn<LeafIssuer>(issueLeaf);
  const cache = createLeafCache({
    ca: { certPem: CA.certPem, keyPem: CA.keyPem, hosts: HOSTS, ...extra },
    issue,
  });
  return { cache, issue };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("hostPermitted — the rule the CA's name constraints encode (RFC 5280 § 4.2.1.10)", () => {
  const ca = { hosts: ["github.com", "127.0.0.1", "2001:db8::1"] };

  it.each([
    ["github.com", true],
    ["api.github.com", true],
    ["a.b.github.com", true],
    ["API.GitHub.COM", true],
    ["evilgithub.com", false],
    ["github.com.evil.example", false],
    ["com", false],
    ["github.com.", false],
    ["127.0.0.1", true],
    ["127.0.0.2", false],
    ["2001:db8::1", true],
    ["2001:DB8:0:0:0:0:0:1", true],
    ["2001:db8::2", false],
  ])("%s → %s", (host, permitted) => {
    expect(hostPermitted(ca, host)).toBe(permitted);
  });

  it("a DNS entry never permits an IP literal, nor an IP entry a name", () => {
    expect(hostPermitted({ hosts: ["localhost"] }, "127.0.0.1")).toBe(false);
    expect(hostPermitted({ hosts: ["127.0.0.1"] }, "localhost")).toBe(false);
  });

  it("the stored hosts bound the set under the unconstrained fallback CA too (RD-B8-13); an empty list permits none", () => {
    const fallback = createCa({ permittedHosts: [], unconstrained: true, validityDays: 7 });
    const stored = {
      certPem: fallback.certPem,
      keyPem: fallback.keyPem,
      hosts: ["localhost"],
      unconstrained: true,
    };
    expect(hostPermitted(stored, "localhost")).toBe(true);
    expect(hostPermitted(stored, "evil.example")).toBe(false);
    expect(hostPermitted({ hosts: [] }, "localhost")).toBe(false);
  });
});

describe("createLeafCache — per-host leaves under the proxy CA", () => {
  it("the defaults: a 7-day leaf, 256 hosts", () => {
    expect(DEFAULT_LEAF_TTL_MS).toBe(7 * DAY_MS);
    expect(DEFAULT_LEAF_CACHE_SIZE).toBe(256);
  });

  it("issues on first use for the lower-cased host with the validity asked, and reuses the leaf after", () => {
    const { cache, issue } = cacheWith();
    const first = cache.contextFor("LocalHost");
    const second = cache.contextFor("localhost");

    expect(second).toBe(first);
    expect(issue).toHaveBeenCalledTimes(1);
    expect(issue.mock.calls[0]?.[1]).toMatchObject({
      host: "localhost",
      validityMs: DEFAULT_LEAF_TTL_MS,
    });
    const leaf = issue.mock.results[0]?.value as ReturnType<LeafIssuer>;
    const cert = new X509Certificate(leaf.certPem);
    expect(cert.checkIssued(new X509Certificate(CA.certPem))).toBe(true);
    expect(cert.checkHost("localhost")).toBe("localhost");
  });

  it("re-issues once half the leaf's validity has passed, not before", () => {
    vi.useFakeTimers({ now: new Date("2026-11-09T12:00:00Z") });
    const { cache, issue } = cacheWith({ leafTtlMs: 2 * DAY_MS });
    const first = cache.contextFor("localhost");

    vi.advanceTimersByTime(DAY_MS - 1);
    expect(cache.contextFor("localhost")).toBe(first);
    vi.advanceTimersByTime(1);
    expect(cache.contextFor("localhost")).not.toBe(first);
    expect(issue).toHaveBeenCalledTimes(2);
    expect(issue.mock.calls[1]?.[1].now).toEqual(new Date("2026-11-10T12:00:00Z"));
  });

  it("a clock set back before the leaf's issue time re-issues it", () => {
    vi.useFakeTimers({ now: new Date("2026-11-09T12:00:00Z") });
    const { cache, issue } = cacheWith();
    cache.contextFor("localhost");
    vi.setSystemTime(new Date("2026-11-09T11:00:00Z"));
    cache.contextFor("localhost");

    expect(issue).toHaveBeenCalledTimes(2);
  });

  it("holds at most leafCacheSize hosts, evicting the least recently used", () => {
    const { cache, issue } = cacheWith({ leafCacheSize: 2 });
    cache.contextFor("localhost");
    cache.contextFor("127.0.0.1");
    cache.contextFor("localhost");
    cache.contextFor("api.github.com");

    expect(cache.hosts()).toEqual(["localhost", "api.github.com"]);
    cache.contextFor("127.0.0.1");
    expect(issue).toHaveBeenCalledTimes(4);
  });

  it("clear() drops every leaf", () => {
    const { cache, issue } = cacheWith();
    cache.contextFor("localhost");
    cache.clear();
    cache.contextFor("localhost");

    expect(cache.hosts()).toEqual(["localhost"]);
    expect(issue).toHaveBeenCalledTimes(2);
  });

  it("a key that is not the CA's is refused when the cache is built", async () => {
    const other = createCa({ permittedHosts: ["localhost"], validityDays: 1 });
    await expectVaultError(
      () => createLeafCache({ ca: { certPem: CA.certPem, keyPem: other.keyPem, hosts: HOSTS } }),
      ErrorCode.CERT_PRIVATE_KEY_MISMATCH,
    );
  });
});
