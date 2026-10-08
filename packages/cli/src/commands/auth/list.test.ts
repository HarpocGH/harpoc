import { describe, it, expect, expectTypeOf, vi, beforeEach, afterEach } from "vitest";
import type { IssuedToken } from "@harpoc/shared";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    listIssuedTokens: vi.fn(),
    verifyToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { registerAuthListCommand } from "./list.js";
import { buildCli, spyCli, type CliSpies } from "../../__fixtures__/cli-harness.js";

const TOKEN: IssuedToken = {
  jti: "01960000-0000-7000-8000-0000000000aa",
  subject: "bot",
  principal_type: "agent",
  agent: "bot",
  scope: ["use", "list"],
  project: null,
  secrets: null,
  label: "ci",
  issued_at: 1_700_000_000_000,
  expires_at: 1_700_003_600_000,
  revoked_at: null,
  status: "active",
};

const run = buildCli(
  (program) => registerAuthListCommand(program.command("auth")),
  ["auth", "list"],
);

describe("harpoc auth list", () => {
  let spies: CliSpies;

  beforeEach(() => {
    vi.clearAllMocks();
    mockEngine.listIssuedTokens.mockReturnValue([TOKEN]);

    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
  });

  it("lists active tokens by default", async () => {
    await run([]);
    expect(mockEngine.listIssuedTokens).toHaveBeenCalledWith(
      { agent: undefined, status: "active" },
      undefined,
    );
  });

  it("lists every token under --all", async () => {
    await run(["--all"]);
    expect(mockEngine.listIssuedTokens).toHaveBeenCalledWith(
      { agent: undefined, status: "all" },
      undefined,
    );
  });

  it("filters by agent", async () => {
    await run(["--agent", "bot"]);
    expect(mockEngine.listIssuedTokens).toHaveBeenCalledWith(
      { agent: "bot", status: "active" },
      undefined,
    );
  });

  it("prints the documented table columns", async () => {
    await run([]);
    const out = spies.stdout();
    for (const column of [
      "JTI",
      "Subject",
      "Type",
      "Agent",
      "Scope",
      "Label",
      "Issued",
      "Expires",
      "Status",
    ]) {
      expect(out).toContain(column);
    }
    expect(out).toContain(TOKEN.jti);
  });

  it("prints the engine return verbatim under --json", async () => {
    await run(["--json"]);
    expect(spies.logSpy).toHaveBeenCalledWith(JSON.stringify([TOKEN], null, 2));
  });

  it("the registry row a listing prints carries no token field (claims metadata only)", () => {
    expectTypeOf<IssuedToken>().not.toHaveProperty("token");
  });
});
