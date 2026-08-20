import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ConnectionConfig } from "@harpoc/shared";
import { SecretType } from "@harpoc/shared";
import { VaultEngine } from "@harpoc/core";
import { mergeConnectionConfig } from "./connection.js";

const CA_PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

const STORED: ConnectionConfig = {
  database: { tls_mode: "require", ca_pem: CA_PEM, servername: "db.internal" },
  ssh: { known_hosts: ["host1 ssh-ed25519 AAAA1", "host2 ssh-ed25519 AAAA2"] },
  mail: { tls: { ca: CA_PEM } },
};

/** The other mail-group value: the audited plaintext opt-out (v1.3, SMTP leg). */
const STORED_MAIL_OPT_OUT: ConnectionConfig = {
  database: { tls_mode: "require" },
  mail: { tls: false },
};

let tempDir: string;
const savedEnvToken = process.env.HARPOC_TOKEN;

beforeEach(() => {
  tempDir = join(tmpdir(), `harpoc-conn-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  delete process.env.HARPOC_TOKEN;
});

afterEach(() => {
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
  if (savedEnvToken === undefined) delete process.env.HARPOC_TOKEN;
  else process.env.HARPOC_TOKEN = savedEnvToken;
});

describe("mergeConnectionConfig", () => {
  it("keeps the stored CA pin, servername and SSH group when only --db-tls is set", () => {
    const merged = mergeConnectionConfig(STORED, { dbTls: "disable" });
    expect(merged.database?.tls_mode).toBe("disable");
    expect(merged.database?.ca_pem).toBe(CA_PEM);
    expect(merged.database?.servername).toBe("db.internal");
    expect(merged.ssh).toEqual(STORED.ssh);
  });

  it("keeps the stored database group when only --known-host is set, replacing the SSH list", () => {
    const merged = mergeConnectionConfig(STORED, { knownHost: ["host3 ssh-rsa AAAA3"] });
    expect(merged.database).toEqual(STORED.database);
    expect(merged.ssh?.known_hosts).toEqual(["host3 ssh-rsa AAAA3"]);
  });

  it("returns the stored config unchanged when no flags are provided", () => {
    expect(mergeConnectionConfig(STORED, {})).toEqual(STORED);
  });

  // The mail group now has its own flags (--mail-no-tls/--mail-ca, below),
  // but an unrelated group's flags must still carry it through untouched —
  // the same "a downgrade of an endpoint-auth pin must be explicit" rule the
  // database CA pin gets above.
  it("keeps the stored mail CA pin when only --db-tls is set", () => {
    const merged = mergeConnectionConfig(STORED, { dbTls: "disable" });
    expect(merged.mail).toEqual({ tls: { ca: CA_PEM } });
  });

  it("keeps the stored mail TLS opt-out when only --db-tls is set", () => {
    const merged = mergeConnectionConfig(STORED_MAIL_OPT_OUT, { dbTls: "disable" });
    expect(merged.mail).toEqual({ tls: false });
    expect(merged.database?.tls_mode).toBe("disable");
  });

  it("keeps the stored mail group when only --known-host is set", () => {
    const merged = mergeConnectionConfig(STORED, { knownHost: ["host3 ssh-rsa AAAA3"] });
    expect(merged.mail).toEqual({ tls: { ca: CA_PEM } });
  });

  it("--clear starts from an empty config instead of the stored one", () => {
    const merged = mergeConnectionConfig(STORED, { clear: true, dbTls: "require" });
    expect(merged.database).toEqual({
      tls_mode: "require",
      ca_pem: undefined,
      servername: undefined,
    });
    expect(merged.ssh).toBeUndefined();
    // --clear is the explicit downgrade: the mail group goes with everything else.
    expect(merged.mail).toBeUndefined();
  });

  it("--clear drops a stored mail TLS opt-out too", () => {
    const merged = mergeConnectionConfig(STORED_MAIL_OPT_OUT, { clear: true, dbTls: "require" });
    expect(merged.mail).toBeUndefined();
  });

  it("builds from flags alone when no config is stored", () => {
    const merged = mergeConnectionConfig(null, {
      dbTls: "require",
      knownHost: ["h ssh-ed25519 AAAA"],
    });
    expect(merged.database?.tls_mode).toBe("require");
    expect(merged.ssh?.known_hosts).toEqual(["h ssh-ed25519 AAAA"]);
  });

  it("reads --db-ca-file into ca_pem without touching other stored fields", () => {
    const caPath = join(tempDir, "ca.pem");
    writeFileSync(caPath, CA_PEM);
    const merged = mergeConnectionConfig(
      { database: { tls_mode: "require" } },
      { dbCaFile: caPath },
    );
    expect(merged.database?.ca_pem).toBe(CA_PEM);
    expect(merged.database?.tls_mode).toBe("require");
  });

  it("parses --known-hosts-file, skipping comments and blank lines", () => {
    const khPath = join(tempDir, "known_hosts");
    writeFileSync(khPath, "# comment\nhost1 ssh-ed25519 AAAA1\n\nhost2 ssh-rsa AAAA2\n");
    const merged = mergeConnectionConfig(null, { knownHostsFile: khPath });
    expect(merged.ssh?.known_hosts).toEqual(["host1 ssh-ed25519 AAAA1", "host2 ssh-rsa AAAA2"]);
  });
});

describe("mergeConnectionConfig — mail TLS group (v1.3)", () => {
  it("--mail-no-tls sets the plaintext opt-out, replacing a stored CA pin", () => {
    const merged = mergeConnectionConfig(STORED, { mailNoTls: true });
    expect(merged.mail).toEqual({ tls: false });
    // Other groups are untouched.
    expect(merged.database).toEqual(STORED.database);
    expect(merged.ssh).toEqual(STORED.ssh);
  });

  it("--mail-ca pins a new CA and clears a stored plaintext opt-out", () => {
    const caPath = join(tempDir, "mail-ca.pem");
    writeFileSync(caPath, CA_PEM);
    const merged = mergeConnectionConfig(STORED_MAIL_OPT_OUT, { mailCa: caPath });
    expect(merged.mail).toEqual({ tls: { ca: CA_PEM } });
  });

  it("builds a plaintext mail opt-out from --mail-no-tls alone when nothing is stored", () => {
    const merged = mergeConnectionConfig(null, { mailNoTls: true });
    expect(merged.mail).toEqual({ tls: false });
  });

  it("builds a pinned-CA mail group from --mail-ca alone when nothing is stored", () => {
    const caPath = join(tempDir, "mail-ca2.pem");
    writeFileSync(caPath, CA_PEM);
    const merged = mergeConnectionConfig(null, { mailCa: caPath });
    expect(merged.mail).toEqual({ tls: { ca: CA_PEM } });
  });

  it("refuses --mail-no-tls combined with --mail-ca in the same invocation", () => {
    expect(() =>
      mergeConnectionConfig(STORED, {
        mailNoTls: true,
        mailCa: join(tempDir, "unread.pem"),
      }),
    ).toThrow("--mail-no-tls and --mail-ca cannot be combined");
  });

  it("--clear combined with --mail-no-tls drops every other stored group", () => {
    const merged = mergeConnectionConfig(STORED, { clear: true, mailNoTls: true });
    expect(merged.mail).toEqual({ tls: false });
    expect(merged.ssh).toBeUndefined();
    expect(merged.database).toBeUndefined();
  });
});

describe("mergeConnectionConfig against a real engine", () => {
  it("a tls-only update no longer drops a stored CA pin", async () => {
    const engine = new VaultEngine({
      dbPath: join(tempDir, "test.vault.db"),
      sessionPath: join(tempDir, "session.json"),
    });
    try {
      await engine.initVault("test-password-123");
      await engine.createSecret({
        name: "db-cred",
        type: SecretType.API_KEY,
        value: new TextEncoder().encode("user:password"),
      });

      const first = mergeConnectionConfig(null, { dbTls: "require" });
      await engine.setConnectionConfig("secret://db-cred", first);

      const caPath = join(tempDir, "ca.pem");
      writeFileSync(caPath, CA_PEM);
      const withCa = mergeConnectionConfig(await engine.getConnectionConfig("secret://db-cred"), {
        dbCaFile: caPath,
      });
      await engine.setConnectionConfig("secret://db-cred", withCa);

      const tlsOnly = mergeConnectionConfig(await engine.getConnectionConfig("secret://db-cred"), {
        dbTls: "require",
      });
      await engine.setConnectionConfig("secret://db-cred", tlsOnly);

      const final = await engine.getConnectionConfig("secret://db-cred");
      expect(final?.database?.ca_pem).toBe(CA_PEM);
      expect(final?.database?.tls_mode).toBe("require");
    } finally {
      await engine.destroy();
    }
  });
});
