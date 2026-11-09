import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import {
  connectSummary,
  CONSUMER_CA_FILE_MODE,
  EXPORTED_CA_FILE_MODE,
  fingerprintPrefix,
  loadProxyCaWiring,
  writeCaFile,
  writeConsumerCaFiles,
} from "./proxy-ca.js";

const ROOT_PEM = "-----BEGIN CERTIFICATE-----\nMIIBfixtureROOT\n-----END CERTIFICATE-----\n";
const CERT_PEM =
  "-----BEGIN CERTIFICATE-----\nMIIBfixtureINTERMEDIATE\n-----END CERTIFICATE-----\n";
const KEY_PEM = "-----BEGIN PRIVATE KEY-----\nMIGHfixturecaKEYbody\n-----END PRIVATE KEY-----\n";
const FP =
  "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";
const NOT_AFTER = Date.UTC(2026, 10, 16, 10, 0, 0);

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "harpoc-proxy-ca-util-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function material(unconstrained = false) {
  return {
    certPem: CERT_PEM,
    keyPem: Buffer.from(KEY_PEM, "utf8"),
    rootPem: ROOT_PEM,
    hosts: ["api.github.com", "127.0.0.1"],
    unconstrained,
    notAfter: NOT_AFTER,
    fingerprint256: FP,
  };
}

describe("writeCaFile — the token writer's shape", () => {
  it("writes the PEM and replaces an existing file, leaving no temporary", () => {
    const path = join(dir, "ca.pem");
    writeFileSync(path, "an older root\n");

    writeCaFile(path, ROOT_PEM, CONSUMER_CA_FILE_MODE);

    expect(readFileSync(path, "utf8")).toBe(ROOT_PEM);
    expect(readdirSync(dir)).toEqual(["ca.pem"]);
  });

  it.skipIf(process.platform === "win32")(
    "sets the mode whatever the umask: 0640 in a consumer directory, 0644 for an export (POSIX)",
    () => {
      const umask = process.umask(0o077);
      try {
        writeCaFile(join(dir, "consumer.pem"), ROOT_PEM, CONSUMER_CA_FILE_MODE);
        writeCaFile(join(dir, "export.pem"), ROOT_PEM, EXPORTED_CA_FILE_MODE);
      } finally {
        process.umask(umask);
      }

      expect(statSync(join(dir, "consumer.pem")).mode & 0o777).toBe(0o640);
      expect(statSync(join(dir, "export.pem")).mode & 0o777).toBe(0o644);
    },
  );

  it("refuses FILE_IO_ERROR naming the file and the errno code, never the content", async () => {
    const path = join(dir, "missing", "ca.pem");

    const err = await expectVaultError(
      () => writeCaFile(path, ROOT_PEM, CONSUMER_CA_FILE_MODE),
      ErrorCode.FILE_IO_ERROR,
    );

    expect(err.message).toBe(`could not write the CA certificate ${path} (ENOENT)`);
  });
});

describe("writeConsumerCaFiles", () => {
  it("writes <dir>/ca.pem into each directory, in order, and returns the paths", () => {
    const a = mkdtempSync(join(dir, "a-"));
    const b = mkdtempSync(join(dir, "b-"));

    expect(writeConsumerCaFiles([a, b], ROOT_PEM)).toEqual([join(a, "ca.pem"), join(b, "ca.pem")]);
    expect(readFileSync(join(b, "ca.pem"), "utf8")).toBe(ROOT_PEM);
  });

  it("writes nothing for no directory", () => {
    expect(writeConsumerCaFiles([], ROOT_PEM)).toEqual([]);
  });
});

describe("loadProxyCaWiring", () => {
  it("is undefined without a CA", async () => {
    expect(await loadProxyCaWiring({ loadProxyCa: vi.fn().mockResolvedValue(null) })).toBe(
      undefined,
    );
  });

  it("hands the proxy the intermediate, the key bytes and the host list — the root and the flag stay the daemon's", async () => {
    const loaded = material();

    expect(await loadProxyCaWiring({ loadProxyCa: vi.fn().mockResolvedValue(loaded) })).toEqual({
      options: { certPem: CERT_PEM, keyPem: loaded.keyPem, hosts: ["api.github.com", "127.0.0.1"] },
      rootPem: ROOT_PEM,
      unconstrained: false,
      notAfter: NOT_AFTER,
      fingerprint256: FP,
    });
  });
});

describe("the startup line's CONNECT clause", () => {
  it("names the first eight octets of the fingerprint", () => {
    expect(fingerprintPrefix(FP)).toBe("AB:CD:EF:01:23:45:67:89…");
  });

  it("a constrained CA: the host count in lane T's form", async () => {
    const wiring = await loadProxyCaWiring({ loadProxyCa: vi.fn().mockResolvedValue(material()) });

    expect(connectSummary(wiring as NonNullable<typeof wiring>)).toBe(
      " — CONNECT for 2 host(s) (Harpoc CA SHA-256 AB:CD:EF:01:23:45:67:89…)",
    );
  });

  it("the fallback: the same count, the certificates unconstrained and their expiry", async () => {
    const wiring = await loadProxyCaWiring({
      loadProxyCa: vi.fn().mockResolvedValue(material(true)),
    });

    expect(connectSummary(wiring as NonNullable<typeof wiring>)).toBe(
      " — CONNECT for 2 host(s), certificates unconstrained (Harpoc CA SHA-256 AB:CD:EF:01:23:45:67:89…, until 2026-11-16T10:00:00.000Z)",
    );
  });
});
