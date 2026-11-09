import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { MockInstance } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";

const { mockEngine, mockCreateCa, mockNormalizeHost } = vi.hoisted(() => ({
  mockEngine: {
    createProxyCa: vi.fn(),
    proxyCaCertificate: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
  mockCreateCa: vi.fn(),
  mockNormalizeHost: vi.fn(),
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

vi.mock("@harpoc/cert-manager", () => ({
  createCa: mockCreateCa,
  normalizeHost: mockNormalizeHost,
  MAX_UNCONSTRAINED_CA_DAYS: 30,
}));

import { loadUnlockedEngine } from "../../utils/vault-loader.js";
import { registerProxyCaCommands } from "./ca.js";
import { buildCli, spyCli, type CliSpies } from "../../__fixtures__/cli-harness.js";

const run = buildCli(
  (program) => registerProxyCaCommands(program.command("proxy")),
  ["proxy", "ca"],
);

/** Fixture material: the strings the mocked issuer returns — no key is generated here. */
const CERT_PEM =
  "-----BEGIN CERTIFICATE-----\nMIIBfixtureINTERMEDIATE\n-----END CERTIFICATE-----\n";
const ROOT_PEM = "-----BEGIN CERTIFICATE-----\nMIIBfixtureROOT\n-----END CERTIFICATE-----\n";
const KEY_PEM = "-----BEGIN PRIVATE KEY-----\nMIGHfixturecaKEYbody\n-----END PRIVATE KEY-----\n";
const CA_FP =
  "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";
const ROOT_FP =
  "01:02:03:04:05:06:07:08:01:02:03:04:05:06:07:08:01:02:03:04:05:06:07:08:01:02:03:04:05:06:07:08";
const NOT_AFTER = Date.UTC(2036, 10, 6, 10, 33, 14);
const NOT_AFTER_ISO = "2036-11-06T10:33:14.000Z";
const ROOT_NOT_AFTER = Date.UTC(2036, 10, 6, 10, 33, 15);
const ROOT_NOT_AFTER_ISO = "2036-11-06T10:33:15.000Z";

/** The issuer's refusal text, as `normalizeHost` throws it (lane X's grammar is its own suite's). */
const HOST_REFUSAL = "host must be an ASCII DNS name or an IP literal";

let spies: CliSpies;
let writeSpy: MockInstance;
let dir: string;

function created(hosts: string[], unconstrained: boolean, replaced = false) {
  return {
    handle: "secret://harpoc-ca",
    hosts,
    unconstrained,
    notAfter: NOT_AFTER,
    fingerprint256: CA_FP,
    rootNotAfter: ROOT_NOT_AFTER,
    rootFingerprint256: ROOT_FP,
    replaced,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  spies = spyCli();
  writeSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  dir = mkdtempSync(join(tmpdir(), "harpoc-proxy-ca-cli-"));
  mockNormalizeHost.mockImplementation((host: string) => {
    if (!/^[a-z0-9.:-]+$/i.test(host) || host.startsWith(".") || host.startsWith("-")) {
      throw VaultError.invalidInput(HOST_REFUSAL);
    }
    return host.toLowerCase();
  });
  mockCreateCa.mockReturnValue({ certPem: CERT_PEM, keyPem: KEY_PEM, rootPem: ROOT_PEM });
  mockEngine.createProxyCa.mockImplementation(
    async (input: { hosts: string[]; unconstrained: boolean }) =>
      created(input.hosts, input.unconstrained),
  );
  mockEngine.proxyCaCertificate.mockResolvedValue({
    handle: "secret://harpoc-ca",
    certPem: ROOT_PEM,
    notBefore: ROOT_NOT_AFTER - 3650 * 86_400_000,
    notAfter: ROOT_NOT_AFTER,
    fingerprint256: ROOT_FP,
  });
});

afterEach(() => {
  writeSpy.mockRestore();
  spies.restore();
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

/** Everything the command printed, on every channel: the key's body must be in none of it. */
function everything(): string {
  return [spies.stdout(), spies.stderr(), writeSpy.mock.calls.map(String).join("")].join("\n");
}

describe("proxy ca init — a name-constrained CA", () => {
  it("issues through cert-manager with the hosts and 3650 days, stores the three PEMs and the hosts, prints both expiries and fingerprints — never the key", async () => {
    await run(["init", "--name-constraints", "api.github.com", "--name-constraints", "127.0.0.1"]);

    expect(mockNormalizeHost.mock.calls).toEqual([["api.github.com"], ["127.0.0.1"]]);
    expect(mockCreateCa.mock.calls).toEqual([
      [{ permittedHosts: ["api.github.com", "127.0.0.1"], validityDays: 3650 }],
    ]);
    expect(mockEngine.createProxyCa.mock.calls).toEqual([
      [
        {
          certPem: CERT_PEM,
          keyPem: KEY_PEM,
          rootPem: ROOT_PEM,
          hosts: ["api.github.com", "127.0.0.1"],
          unconstrained: false,
          force: false,
        },
      ],
    ]);
    expect(spies.stdout()).toBe(
      [
        "Handle            secret://harpoc-ca",
        "Hosts             api.github.com, 127.0.0.1",
        "Name constraints  the hosts, in both certificates",
        `Root not after    ${ROOT_NOT_AFTER_ISO}`,
        `Root SHA-256      ${ROOT_FP}`,
        `CA not after      ${NOT_AFTER_ISO}`,
        `CA SHA-256        ${CA_FP}`,
      ].join("\n"),
    );
    expect(spies.stderr()).toBe(
      "OK: Harpoc CA created. Restart server start --proxy to serve CONNECT with it: it writes the root as <consumer>/ca.pem into every consumer directory, and harpoc proxy ca export prints it for any other consumer.",
    );
    expect(everything()).not.toContain("fixturecaKEYbody");
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
    expect(spies.exitSpy).not.toHaveBeenCalled();
  });

  it("--json prints the record as one object", async () => {
    await run(["init", "--name-constraints", "api.github.com", "--json"]);

    expect(JSON.parse(spies.stdout())).toEqual(created(["api.github.com"], false));
    expect(everything()).not.toContain("fixturecaKEYbody");
  });

  it("--json prints nothing beside the object: no OK line, and no warning for the fallback", async () => {
    await run(["init", "--name-constraints", "api.github.com", "--json"]);
    await run(["init", "--name-constraints", "api.github.com", "--unconstrained", "--json"]);

    expect(mockEngine.createProxyCa).toHaveBeenCalledTimes(2);
    expect(spies.stderr()).toBe("");
  });

  it("drops a host repeated after normalizing", async () => {
    await run([
      "init",
      "--name-constraints",
      "API.GitHub.com",
      "--name-constraints",
      "api.github.com",
    ]);

    expect(mockCreateCa.mock.calls[0]?.[0]).toMatchObject({ permittedHosts: ["api.github.com"] });
  });

  it("--days sets the lifetime within 3650", async () => {
    await run(["init", "--name-constraints", "api.github.com", "--days", "365"]);

    expect(mockCreateCa.mock.calls[0]?.[0]).toMatchObject({ validityDays: 365 });
  });

  it("--force replaces: the engine is asked to, and the line names the revocation and the re-export", async () => {
    mockEngine.createProxyCa.mockResolvedValueOnce(created(["api.github.com"], false, true));

    await run(["init", "--name-constraints", "api.github.com", "--force"]);

    expect(mockEngine.createProxyCa.mock.calls[0]?.[0]).toMatchObject({ force: true });
    expect(spies.stderr()).toBe(
      "OK: Harpoc CA replaced: the previous one is revoked. Restart server start --proxy (it rewrites <consumer>/ca.pem) and re-export the root for every consumer outside the runtime directory (harpoc proxy ca export).",
    );
  });

  it("an engine refusal (a CA exists) renders as the CLI renders DUPLICATE_SECRET (no code prefix) and destroys the engine", async () => {
    mockEngine.createProxyCa.mockRejectedValueOnce(
      new VaultError(
        ErrorCode.DUPLICATE_SECRET,
        "The Harpoc CA already exists (secret://harpoc-ca); harpoc proxy ca init --force replaces it",
      ),
    );

    await expect(run(["init", "--name-constraints", "api.github.com"])).rejects.toThrow(
      "process.exit",
    );

    expect(spies.errorSpy.mock.calls).toEqual([
      [
        "Error: The Harpoc CA already exists (secret://harpoc-ca); harpoc proxy ca init --force replaces it",
      ],
    ]);
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });
});

// RD-B8-13: --unconstrained names the certificates alone; the host list still bounds the proxy.
describe("proxy ca init --unconstrained — the fallback", () => {
  it("issues without constraints for 7 days, stores the hosts with the flag, and warns on stderr", async () => {
    await run(["init", "--name-constraints", "api.github.com", "--unconstrained"]);

    expect(mockNormalizeHost.mock.calls).toEqual([["api.github.com"]]);
    expect(mockCreateCa.mock.calls).toEqual([
      [{ permittedHosts: [], unconstrained: true, validityDays: 7 }],
    ]);
    expect(mockEngine.createProxyCa.mock.calls[0]?.[0]).toMatchObject({
      hosts: ["api.github.com"],
      unconstrained: true,
    });
    expect(spies.stdout().split("\n").slice(1, 3)).toEqual([
      "Hosts             api.github.com",
      "Name constraints  none (unconstrained certificates)",
    ]);
    expect(spies.errorSpy.mock.calls[0]).toEqual([
      `Warning: the Harpoc CA's certificates are unconstrained — a client trusting its root accepts a certificate for any host signed with its key, until ${NOT_AFTER_ISO}; the proxy itself serves CONNECT for the listed hosts alone.`,
    ]);
  });

  it("--days 30 is the longest fallback", async () => {
    await run(["init", "--name-constraints", "api.github.com", "--unconstrained", "--days", "30"]);

    expect(mockCreateCa.mock.calls[0]?.[0]).toMatchObject({ validityDays: 30 });
  });
});

describe("proxy ca init — refusals, before the vault opens", () => {
  const NEEDS_HOSTS =
    "Error: [INVALID_INPUT] proxy ca init needs --name-constraints <host> (repeatable): the hosts the proxy serves CONNECT for, with --unconstrained too";

  it.each([
    { label: "no --name-constraints", argv: ["init"], line: NEEDS_HOSTS },
    {
      label: "--unconstrained without a host",
      argv: ["init", "--unconstrained"],
      line: NEEDS_HOSTS,
    },
    {
      label: "an unconstrained --days over 30 (never clamped)",
      argv: ["init", "--name-constraints", "api.github.com", "--unconstrained", "--days", "31"],
      line: 'Error: [INVALID_INPUT] Invalid --days "31". Must be 1-30.',
    },
    {
      label: "a constrained --days over 3650",
      argv: ["init", "--name-constraints", "api.github.com", "--days", "3651"],
      line: 'Error: [INVALID_INPUT] Invalid --days "3651". Must be 1-3650.',
    },
    {
      label: "a hex --days",
      argv: ["init", "--name-constraints", "api.github.com", "--days", "0x10"],
      line: 'Error: [INVALID_INPUT] Invalid --days "0x10". Must be 1-3650.',
    },
    ...["https://api.github.com", "*.github.com", ".github.com", "--force"].map((host) => ({
      label: `the host ${JSON.stringify(host)} (the issuer's refusal, prefixed)`,
      argv: ["init", "--name-constraints", host],
      line: `Error: [INVALID_INPUT] --name-constraints ${JSON.stringify(host)}: ${HOST_REFUSAL}`,
    })),
  ])("refuses $label", async ({ argv, line }) => {
    await expect(run(argv)).rejects.toThrow("process.exit");

    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy.mock.calls).toEqual([[line]]);
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
    expect(mockCreateCa).not.toHaveBeenCalled();
  });

  it("renders a refusal through the --json envelope", async () => {
    await expect(run(["init", "--json"])).rejects.toThrow("process.exit");

    expect(JSON.parse(spies.stderr())).toEqual({
      error: "INVALID_INPUT",
      message:
        "proxy ca init needs --name-constraints <host> (repeatable): the hosts the proxy serves CONNECT for, with --unconstrained too",
    });
  });
});

describe("proxy ca export — the root", () => {
  it("prints the root PEM verbatim to stdout and destroys the engine", async () => {
    await run(["export"]);

    expect(writeSpy.mock.calls).toEqual([[ROOT_PEM]]);
    expect(spies.logSpy).not.toHaveBeenCalled();
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });

  it("--json prints the handle, the root PEM, its expiry and its fingerprint", async () => {
    await run(["export", "--json"]);

    expect(JSON.parse(spies.stdout())).toEqual({
      handle: "secret://harpoc-ca",
      certPem: ROOT_PEM,
      notAfter: ROOT_NOT_AFTER,
      fingerprint256: ROOT_FP,
    });
  });

  it("--out writes the root to the file and names it, its fingerprint and expiry on stderr", async () => {
    const out = join(dir, "harpoc-ca.pem");

    await run(["export", "--out", out]);

    expect(readFileSync(out, "utf8")).toBe(ROOT_PEM);
    expect(writeSpy).not.toHaveBeenCalled();
    expect(spies.stderr()).toBe(
      `OK: Harpoc CA root written to ${out} (SHA-256 ${ROOT_FP}, until ${ROOT_NOT_AFTER_ISO})`,
    );
  });

  it.skipIf(process.platform === "win32")(
    "--out writes mode 0644 whatever the umask (POSIX; win32 inherits the directory's list)",
    async () => {
      const out = join(dir, "harpoc-ca.pem");
      const umask = process.umask(0o077);
      try {
        await run(["export", "--out", out]);
      } finally {
        process.umask(umask);
      }

      expect(statSync(out).mode & 0o777).toBe(0o644);
    },
  );

  it("--out replaces an existing regular file (the re-export after init --force)", async () => {
    const out = join(dir, "harpoc-ca.pem");
    writeFileSync(out, "an older certificate\n");

    await run(["export", "--out", out]);

    expect(readFileSync(out, "utf8")).toBe(ROOT_PEM);
  });

  it.each([
    {
      label: "an empty --out",
      out: () => "",
      line: () => "Error: [INVALID_INPUT] --out: empty path",
    },
    {
      label: "a flag taken as --out",
      out: () => "--json",
      line: () =>
        "Error: [INVALID_INPUT] --out: a flag, not a path (give a path that starts with a dash as ./-name)",
    },
    {
      label: "a missing directory",
      out: () => join(dir, "missing", "ca.pem"),
      line: () => `Error: [INVALID_INPUT] --out: no such directory: ${join(dir, "missing")}`,
    },
    {
      label: "a directory in place of the file",
      out: () => {
        mkdirSync(join(dir, "taken"));
        return join(dir, "taken");
      },
      line: () =>
        `Error: [INVALID_INPUT] --out: ${join(dir, "taken")} exists and is not a regular file`,
    },
  ])("refuses $label before the vault opens", async ({ out, line }) => {
    await expect(run(["export", "--out", out()])).rejects.toThrow("process.exit");

    expect(spies.errorSpy.mock.calls).toEqual([[line()]]);
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("refuses a vault without a CA CERT_NOT_CONFIGURED naming proxy ca init", async () => {
    mockEngine.proxyCaCertificate.mockResolvedValueOnce(null);

    await expect(run(["export"])).rejects.toThrow("process.exit");

    expect(spies.errorSpy.mock.calls).toEqual([
      [
        "Error: [CERT_NOT_CONFIGURED] No Harpoc CA in this vault (secret://harpoc-ca); harpoc proxy ca init creates one",
      ],
    ]);
    expect(writeSpy).not.toHaveBeenCalled();
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });
});
