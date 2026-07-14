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
};

let tempDir: string;

beforeEach(() => {
  tempDir = join(tmpdir(), `harpoc-conn-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
});

afterEach(() => {
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
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

  it("--clear starts from an empty config instead of the stored one", () => {
    const merged = mergeConnectionConfig(STORED, { clear: true, dbTls: "require" });
    expect(merged.database).toEqual({
      tls_mode: "require",
      ca_pem: undefined,
      servername: undefined,
    });
    expect(merged.ssh).toBeUndefined();
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
