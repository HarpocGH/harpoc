import { describe, expect, it } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { LETS_ENCRYPT_PRODUCTION, LETS_ENCRYPT_STAGING, validateAcmeUrl } from "./directory.js";

const acmeFailed = expect.objectContaining({ code: ErrorCode.CERT_ACME_FAILED });

const messageOf = (url: string): string => {
  try {
    validateAcmeUrl(url);
  } catch (error) {
    return (error as VaultError).message;
  }
  return "";
};

describe("directory constants", () => {
  it("pins the Let's Encrypt production and staging directory URLs", () => {
    expect(LETS_ENCRYPT_PRODUCTION).toBe("https://acme-v02.api.letsencrypt.org/directory");
    expect(LETS_ENCRYPT_STAGING).toBe("https://acme-staging-v02.api.letsencrypt.org/directory");
  });

  it("accepts its own constants", () => {
    expect(() => validateAcmeUrl(LETS_ENCRYPT_PRODUCTION)).not.toThrow();
    expect(() => validateAcmeUrl(LETS_ENCRYPT_STAGING)).not.toThrow();
  });
});

describe("validateAcmeUrl", () => {
  it("accepts HTTPS on any host", () => {
    for (const url of [
      "https://acme.example.com/directory",
      "https://acme.example.com:8443/dir",
      "https://127.0.0.1:14000/dir",
    ]) {
      expect(() => validateAcmeUrl(url)).not.toThrow();
    }
  });

  it("accepts plain HTTP on loopback only", () => {
    for (const url of [
      "http://localhost:14000/dir",
      "http://127.0.0.1:14000/dir",
      "http://[::1]:14000/dir",
    ]) {
      expect(() => validateAcmeUrl(url)).not.toThrow();
    }
  });

  it("rejects plain HTTP on a remote host", () => {
    expect(() => validateAcmeUrl("http://acme.example.com")).toThrow(acmeFailed);
    expect(() => validateAcmeUrl("http://acme.example.com/directory")).toThrow(acmeFailed);
  });

  it("rejects hosts that merely look like loopback", () => {
    for (const url of [
      "http://127.0.0.1.evil.example.com/dir",
      "http://localhost.evil.example.com/dir",
      "http://127.0.0.2:14000/dir",
      "http://0.0.0.0:14000/dir",
    ]) {
      expect(() => validateAcmeUrl(url)).toThrow(acmeFailed);
    }
  });

  it("rejects a non-HTTP scheme and an unparseable URL", () => {
    expect(() => validateAcmeUrl("ftp://acme.example.com/dir")).toThrow(acmeFailed);
    expect(() => validateAcmeUrl("file:///etc/passwd")).toThrow(acmeFailed);
    expect(() => validateAcmeUrl("not a url")).toThrow(acmeFailed);
    expect(() => validateAcmeUrl("")).toThrow(acmeFailed);
  });

  it("names the origin only — never the path, query, fragment or userinfo", () => {
    const message = messageOf("http://user:pw@acme.example.com/dir/secret?token=SECRET#frag");
    expect(message).toContain("http://acme.example.com");
    expect(message).not.toContain("SECRET");
    expect(message).not.toContain("secret");
    expect(message).not.toContain("token");
    expect(message).not.toContain("frag");
    expect(message).not.toContain("user");
    expect(message).not.toContain("pw@");
  });

  it("keeps the path out of a non-HTTP-scheme rejection", () => {
    const file = messageOf("file:///etc/passwd");
    expect(file).toContain("file://");
    expect(file).not.toContain("passwd");
    const ftp = messageOf("ftp://acme.example.com/dir/secret");
    expect(ftp).toContain("ftp://acme.example.com");
    expect(ftp).not.toContain("secret");
  });

  it("echoes nothing at all when the URL will not parse", () => {
    const message = messageOf("http://[bad");
    expect(message).toContain("not parseable");
    expect(message).not.toContain("bad");
  });
});
