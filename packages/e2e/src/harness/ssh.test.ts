import { describe, it, expect, beforeAll } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { KEYS_DIR, clientKeyPem, keysReady, knownHostPin } from "./ssh.js";

describe("fixture ssh keys", () => {
  beforeAll(() => {
    execFileSync("bash", [join(KEYS_DIR, "generate.sh")], { stdio: "inherit" });
  });

  it("generates the client identity and both host keypairs", () => {
    expect(keysReady()).toBe(true);
    for (const f of [
      "client_ed25519",
      "client_ed25519.pub",
      "hostkey_pinned_ed25519",
      "hostkey_pinned_ed25519.pub",
      "hostkey_rogue_ed25519",
      "hostkey_rogue_ed25519.pub",
      "authorized_keys",
    ]) {
      expect(existsSync(join(KEYS_DIR, "out", f))).toBe(true);
    }
  });

  it("stores the client private key in an unencrypted OpenSSH format the loader accepts", () => {
    const pem = clientKeyPem();
    expect(pem).toMatch(/^-----BEGIN OPENSSH PRIVATE KEY-----/);
    // Cipher `none` — an encrypted container would carry a bcrypt kdf marker.
    expect(pem).not.toMatch(/bcrypt/i);
  });

  it("authorizes exactly the client public key, nothing else", () => {
    const authorized = readFileSync(join(KEYS_DIR, "out", "authorized_keys"), "utf8").trim();
    const clientPub = readFileSync(join(KEYS_DIR, "out", "client_ed25519.pub"), "utf8").trim();
    expect(authorized).toBe(clientPub);
    expect(authorized.split("\n")).toHaveLength(1);
  });

  it("formats a known_hosts pin as `<host> <type> <base64>`", () => {
    const pin = knownHostPin("127.0.0.2", "pinned");
    expect(pin).toMatch(/^127\.0\.0\.2 ssh-ed25519 [A-Za-z0-9+/]+=*$/);
    // The bracketed non-22 form OpenSSH uses for git-over-ssh on a custom port.
    expect(knownHostPin("[127.0.0.1]:2222", "pinned")).toMatch(
      /^\[127\.0\.0\.1\]:2222 ssh-ed25519 /,
    );
  });

  it("pins the pinned and rogue host keys to DIFFERENT material (no TOFU, D4)", () => {
    const pinned = knownHostPin("127.0.0.3", "pinned");
    const rogue = knownHostPin("127.0.0.3", "rogue");
    // Same address, different key — this is what makes the mismatch arm a real
    // rejection rather than a broken fixture.
    expect(pinned).not.toBe(rogue);
  });

  it("is idempotent — a second run does not regenerate the client key", () => {
    const before = readFileSync(join(KEYS_DIR, "out", "client_ed25519"), "utf8");
    execFileSync("bash", [join(KEYS_DIR, "generate.sh")], { stdio: "inherit" });
    expect(readFileSync(join(KEYS_DIR, "out", "client_ed25519"), "utf8")).toBe(before);
  });
});
