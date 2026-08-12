import { describe, it, expect, beforeAll } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { resolveBash } from "./fixtures.js";
import { KEYS_DIR, clientKeyPem, keysReady, knownHostPin } from "./ssh.js";

// resolveBash, not bare "bash": on a Windows dev host PATH bash may be the
// System32 WSL launcher, which cannot open the absolute Windows script path.
// Forward slashes because the argument crosses into an MSYS program.
const BASH = resolveBash();
const GENERATE = join(KEYS_DIR, "generate.sh").replace(/\\/g, "/");

describe("fixture ssh keys", () => {
  beforeAll(() => {
    execFileSync(BASH, [GENERATE], { stdio: "inherit" });
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

  it("stores the client private key in an unencrypted OpenSSH container (cipher and kdf `none`)", () => {
    const pem = clientKeyPem();
    expect(pem).toMatch(/^-----BEGIN OPENSSH PRIVATE KEY-----/);
    // The cipher and kdf names live only inside the base64 payload — an
    // encrypted container never carries a literal "bcrypt" in the armor, so a
    // grep of the PEM text is vacuous. Decode the container and read the two
    // length-prefixed fields after the "openssh-key-v1\0" magic directly: a
    // passphrase-protected key reports aes256-ctr/bcrypt here.
    const body = pem
      .replace(/-----(?:BEGIN|END) OPENSSH PRIVATE KEY-----/g, "")
      .replace(/\s+/g, "");
    const blob = Buffer.from(body, "base64");
    const magic = "openssh-key-v1\0";
    expect(blob.subarray(0, magic.length).toString("latin1")).toBe(magic);
    let off = magic.length;
    const readString = (): string => {
      const len = blob.readUInt32BE(off);
      off += 4;
      const s = blob.subarray(off, off + len).toString("latin1");
      off += len;
      return s;
    };
    expect(readString()).toBe("none"); // ciphername
    expect(readString()).toBe("none"); // kdfname
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
    execFileSync(BASH, [GENERATE], { stdio: "inherit" });
    expect(readFileSync(join(KEYS_DIR, "out", "client_ed25519"), "utf8")).toBe(before);
  });
});
