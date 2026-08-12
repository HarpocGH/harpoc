import { describe, it, expect, beforeAll } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { resolveBash, resolveOpenssl } from "./fixtures.js";
import { PKI_DIR, caPem, pkiReady } from "./pki.js";

// resolveBash, not bare "bash": on a Windows dev host PATH bash may be the
// System32 WSL launcher, which cannot open the absolute Windows script path.
// Forward slashes because the argument crosses into an MSYS program. openssl
// is resolved the same way — rarely on a Windows PATH, bundled by Git.
const BASH = resolveBash();
const GENERATE = join(PKI_DIR, "generate.sh").replace(/\\/g, "/");
const OPENSSL = resolveOpenssl();

describe("fixture PKI", () => {
  beforeAll(() => {
    execFileSync(BASH, [GENERATE], { stdio: "inherit" });
  });

  it("generates a CA and server certificates", () => {
    expect(pkiReady()).toBe(true);
    for (const f of ["ca.crt", "postgres-tls.crt", "postgres-tls.key", "mysql-tls.crt"]) {
      expect(existsSync(join(PKI_DIR, "out", f))).toBe(true);
    }
  });

  it("exposes the CA as a PEM string for ca_pem pinning", () => {
    expect(caPem()).toMatch(/^-----BEGIN CERTIFICATE-----/);
  });

  it("issues DNS-only SANs so an IP-literal target has no name to verify (M3)", () => {
    const text = execFileSync(
      OPENSSL,
      ["x509", "-in", join(PKI_DIR, "out", "postgres-tls.crt"), "-noout", "-text"],
      { encoding: "utf8" },
    );
    expect(text).toContain("DNS:localhost");
    expect(text).not.toContain("IP Address");
  });

  it("signs the server certificate with the fixture CA", () => {
    const text = execFileSync(
      OPENSSL,
      ["x509", "-in", join(PKI_DIR, "out", "postgres-tls.crt"), "-noout", "-issuer"],
      { encoding: "utf8" },
    );
    expect(text).toContain("Harpoc E2E Test CA");
  });

  it("is idempotent — a second run does not reissue", () => {
    const serial = () =>
      execFileSync(OPENSSL, ["x509", "-in", join(PKI_DIR, "out", "ca.crt"), "-noout", "-serial"], {
        encoding: "utf8",
      });
    const before = serial();
    execFileSync(BASH, [GENERATE], { stdio: "inherit" });
    expect(serial()).toBe(before);
  });
});
