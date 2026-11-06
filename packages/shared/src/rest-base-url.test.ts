import { describe, expect, it } from "vitest";
import { parseRestBaseUrl } from "./rest-base-url.js";

describe("parseRestBaseUrl", () => {
  it.each([
    ["http://127.0.0.1:3000", "http://127.0.0.1:3000/"],
    ["http://localhost:3000/", "http://localhost:3000/"],
    ["http://[::1]:3000", "http://[::1]:3000/"],
    ["https://vault.example", "https://vault.example/"],
    ["https://vault.example/harpoc/", "https://vault.example/harpoc/"],
  ])("accepts %s with the base URL %s (origin and path, nothing else)", (value, baseUrl) => {
    const parsed = parseRestBaseUrl(value);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.baseUrl).toBe(baseUrl);
      expect(parsed.url.href).toBe(baseUrl);
    }
  });

  it.each([
    ["-", "flag"],
    ["--token-file", "flag"],
    ["", "not_a_url"],
    ["  ", "not_a_url"],
    ["127.0.0.1:3000", "not_a_url"],
    ["vault", "not_a_url"],
    ["http://", "not_a_url"],
    ["ftp://vault.example", "scheme"],
    ["ws://vault.example", "scheme"],
    ["file:///run/harpoc", "scheme"],
    ["localhost:3000", "scheme"],
    ["https://user:s3cret@vault.example", "credentials"],
    ["https://user@vault.example", "credentials"],
    ["http://user:s3cret@vault.example", "credentials"],
    ["https://vault.example/?token=s3cret", "query_or_fragment"],
    ["https://vault.example/#s3cret", "query_or_fragment"],
    ["http://127.0.0.1:3000/?a=1", "query_or_fragment"],
    ["http://vault.example", "plain_http_off_loopback"],
    ["http://10.0.0.5:3000", "plain_http_off_loopback"],
    ["http://0.0.0.0:3000", "plain_http_off_loopback"],
  ])("refuses %s as %s", (value, reason) => {
    expect(parseRestBaseUrl(value)).toEqual({ ok: false, reason });
  });

  it("the refusal carries no part of the value", () => {
    expect(
      JSON.stringify(parseRestBaseUrl("https://user:s3cret@vault.example/?k=s3cret")),
    ).not.toContain("s3cret");
  });
});
