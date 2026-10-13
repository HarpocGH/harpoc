import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    listSecrets: vi.fn(),
    verifyToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { registerSecretListCommand } from "./list.js";
import { buildCli, spyCli, type CliSpies } from "../../__fixtures__/cli-harness.js";

const run = buildCli(
  (program) => registerSecretListCommand(program.command("secret")),
  ["secret", "list"],
);

function info(name: string, type: string, status: string): Record<string, unknown> {
  return {
    handle: `secret://${name}`,
    name,
    type,
    project: null,
    status,
    version: 1,
    createdAt: 0,
    updatedAt: 0,
    expiresAt: null,
    rotatedAt: null,
  };
}

// Two types crossed with two statuses: each filter keeps exactly the rows it names.
const MIXED_VAULT = [
  info("api-active", "api_key", "active"),
  info("api-revoked", "api_key", "revoked"),
  info("cert-active", "certificate", "active"),
  info("cert-revoked", "certificate", "revoked"),
];

// I30 (test-review-2026-10-09): getting-started documents `secret list --type`
// and `--status`; the command filters the engine's listing client-side.
describe("secret list — the --type and --status filters (I30)", () => {
  let spies: CliSpies;

  beforeEach(() => {
    vi.clearAllMocks();
    mockEngine.listSecrets.mockReturnValue(MIXED_VAULT);
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
  });

  function printedNames(): string[] {
    return (JSON.parse(spies.stdout()) as { name: string }[]).map((row) => row.name);
  }

  it("--type certificate prints the certificate rows only", async () => {
    await run(["--type", "certificate", "--json"]);
    expect(mockEngine.listSecrets).toHaveBeenCalledWith(undefined, undefined);
    expect(printedNames()).toEqual(["cert-active", "cert-revoked"]);
  });

  it("--status revoked prints the revoked rows only", async () => {
    await run(["--status", "revoked", "--json"]);
    expect(mockEngine.listSecrets).toHaveBeenCalledWith(undefined, undefined);
    expect(printedNames()).toEqual(["api-revoked", "cert-revoked"]);
  });

  it("--type and --status together print their intersection", async () => {
    await run(["--type", "api_key", "--status", "active", "--json"]);
    expect(printedNames()).toEqual(["api-active"]);
  });
});
