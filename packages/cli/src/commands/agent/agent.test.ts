import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { Agent, SetAgentPermissionsResult } from "@harpoc/shared";

const { mockEngine, mockPromptConfirm } = vi.hoisted(() => ({
  mockEngine: {
    registerAgent: vi.fn(),
    getAgent: vi.fn(),
    listAgents: vi.fn(),
    updateAgent: vi.fn(),
    deactivateAgent: vi.fn(),
    activateAgent: vi.fn(),
    deleteAgent: vi.fn(),
    setAgentPermissions: vi.fn(),
    verifyToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
  mockPromptConfirm: vi.fn(),
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
  resolveSecretId: vi.fn().mockResolvedValue("sid-1"),
}));
vi.mock("../../utils/prompt.js", () => ({ promptConfirm: mockPromptConfirm }));

import { Command } from "commander";
import { registerAgentRegisterCommand } from "./register.js";
import { registerAgentListCommand } from "./list.js";
import { registerAgentShowCommand } from "./show.js";
import { registerAgentUpdateCommand } from "./update.js";
import { registerAgentDeactivateCommand } from "./deactivate.js";
import { registerAgentActivateCommand } from "./activate.js";
import { registerAgentDeleteCommand } from "./delete.js";
import { registerAgentPermissionsCommand } from "./permissions.js";

const AGENT: Agent = {
  id: "01960000-0000-7000-8000-000000000001",
  name: "bot",
  description: "a bot",
  owner: "ops",
  status: "active",
  created_at: 1_700_000_000_000,
  updated_at: 1_700_000_100_000,
  deactivated_at: null,
  last_active_at: null,
  active_tokens: 2,
  grants: 3,
};

const POLICY = {
  id: "pol-1",
  secret_id: "sid-1",
  principal_type: "agent" as const,
  principal_id: "bot",
  permissions: ["read", "use"] as const,
  created_at: 1_700_000_000_000,
  expires_at: null,
  created_by: "cli-user",
};

function result(overrides: Partial<SetAgentPermissionsResult> = {}): SetAgentPermissionsResult {
  return {
    policy: POLICY as unknown as SetAgentPermissionsResult["policy"],
    gated_before: true,
    gated_after: true,
    ...overrides,
  };
}

function buildProgram(): Command {
  const program = new Command();
  program.option("--vault-dir <path>", "Path to vault directory");
  const agent = program.command("agent");
  registerAgentRegisterCommand(agent);
  registerAgentListCommand(agent);
  registerAgentShowCommand(agent);
  registerAgentUpdateCommand(agent);
  registerAgentDeactivateCommand(agent);
  registerAgentActivateCommand(agent);
  registerAgentDeleteCommand(agent);
  registerAgentPermissionsCommand(agent);
  return program;
}

async function run(args: string[]): Promise<void> {
  const program = buildProgram();
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  await program.parseAsync(["node", "harpoc", "agent", ...args]);
}

describe("harpoc agent group", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  const savedEnvToken = process.env.HARPOC_TOKEN;

  const stdout = (): string => logSpy.mock.calls.map((c) => String(c[0])).join("\n");
  const stderr = (): string => errorSpy.mock.calls.map((c) => String(c[0])).join("\n");

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;

    mockEngine.registerAgent.mockReturnValue(AGENT);
    mockEngine.getAgent.mockReturnValue(AGENT);
    mockEngine.listAgents.mockReturnValue([AGENT]);
    mockEngine.updateAgent.mockReturnValue(AGENT);
    mockEngine.deactivateAgent.mockReturnValue({ revoked_tokens: 3 });
    mockEngine.activateAgent.mockReturnValue(AGENT);
    mockEngine.deleteAgent.mockReturnValue({ revoked_tokens: 2, removed_grants: 3 });
    mockEngine.setAgentPermissions.mockReturnValue(result());
    mockPromptConfirm.mockResolvedValue(true);

    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errorSpy.mockRestore();
    logSpy.mockRestore();
    if (savedEnvToken === undefined) delete process.env.HARPOC_TOKEN;
    else process.env.HARPOC_TOKEN = savedEnvToken;
  });

  describe("agent register", () => {
    it("passes the name and both metadata flags to registerAgent", async () => {
      await run(["register", "bot", "--description", "a bot", "--owner", "ops"]);
      expect(mockEngine.registerAgent).toHaveBeenCalledWith(
        { name: "bot", description: "a bot", owner: "ops" },
        undefined,
      );
    });

    it("omits absent metadata rather than inventing it", async () => {
      await run(["register", "bot"]);
      expect(mockEngine.registerAgent).toHaveBeenCalledWith(
        { name: "bot", description: undefined, owner: undefined },
        undefined,
      );
    });

    it("prints the record and a success line by default", async () => {
      await run(["register", "bot"]);
      expect(stdout()).toContain("bot");
      expect(stdout()).toContain("active");
      expect(stderr()).toContain("OK: Agent registered.");
    });

    it("prints the engine return verbatim under --json", async () => {
      await run(["register", "bot", "--json"]);
      expect(logSpy).toHaveBeenCalledWith(JSON.stringify(AGENT, null, 2));
    });
  });

  describe("agent list", () => {
    it("lists active agents by default", async () => {
      await run(["list"]);
      expect(mockEngine.listAgents).toHaveBeenCalledWith("active", undefined);
    });

    it("lists every agent under --all", async () => {
      await run(["list", "--all"]);
      expect(mockEngine.listAgents).toHaveBeenCalledWith("all", undefined);
    });

    it("prints the documented table columns", async () => {
      await run(["list"]);
      const out = stdout();
      for (const column of ["Name", "Status", "Owner", "Last active", "Tokens", "Grants"]) {
        expect(out).toContain(column);
      }
    });

    it("prints the engine return verbatim under --json", async () => {
      await run(["list", "--json"]);
      expect(logSpy).toHaveBeenCalledWith(JSON.stringify([AGENT], null, 2));
    });
  });

  describe("agent show", () => {
    it("reads the named agent", async () => {
      await run(["show", "bot"]);
      expect(mockEngine.getAgent).toHaveBeenCalledWith("bot", undefined);
    });

    it("prints every Agent field", async () => {
      await run(["show", "bot"]);
      const out = stdout();
      expect(out).toContain(AGENT.id);
      expect(out).toContain("Active tokens");
      expect(out).toContain("Grants");
      expect(out).toContain("Last active");
      expect(out).toContain("Deactivated");
      // Nulls render as the table's "-" convention, never "null".
      expect(out).not.toContain("null");
    });

    it("prints the engine return verbatim under --json", async () => {
      await run(["show", "bot", "--json"]);
      expect(logSpy).toHaveBeenCalledWith(JSON.stringify(AGENT, null, 2));
    });
  });

  describe("agent update", () => {
    it("merges an omitted field from the stored agent", async () => {
      await run(["update", "bot", "--owner", "new-owner"]);
      expect(mockEngine.getAgent).toHaveBeenCalledWith("bot", undefined);
      expect(mockEngine.updateAgent).toHaveBeenCalledWith(
        "bot",
        { description: "a bot", owner: "new-owner" },
        undefined,
      );
    });

    it("clears the description with --clear-description while keeping the owner", async () => {
      await run(["update", "bot", "--clear-description"]);
      expect(mockEngine.updateAgent).toHaveBeenCalledWith(
        "bot",
        { description: undefined, owner: "ops" },
        undefined,
      );
    });

    it("clears the owner with --clear-owner while keeping the description", async () => {
      await run(["update", "bot", "--clear-owner"]);
      expect(mockEngine.updateAgent).toHaveBeenCalledWith(
        "bot",
        { description: "a bot", owner: undefined },
        undefined,
      );
    });

    it("carries a stored null through as undefined, not null", async () => {
      mockEngine.getAgent.mockReturnValue({ ...AGENT, description: null, owner: null });
      await run(["update", "bot", "--owner", "ops"]);
      expect(mockEngine.updateAgent).toHaveBeenCalledWith(
        "bot",
        { description: undefined, owner: "ops" },
        undefined,
      );
    });

    it("refuses with no flag at all, before reading the agent", async () => {
      await expect(run(["update", "bot"])).rejects.toThrow("process.exit");
      expect(stderr()).toContain("Nothing to update");
      expect(mockEngine.getAgent).not.toHaveBeenCalled();
      expect(mockEngine.updateAgent).not.toHaveBeenCalled();
    });

    it("refuses --description together with --clear-description", async () => {
      await expect(
        run(["update", "bot", "--description", "a bot", "--clear-description"]),
      ).rejects.toThrow("process.exit");
      expect(stderr()).toContain("--description and --clear-description are mutually exclusive");
      expect(mockEngine.getAgent).not.toHaveBeenCalled();
      expect(mockEngine.updateAgent).not.toHaveBeenCalled();
    });

    it("refuses --owner together with --clear-owner", async () => {
      await expect(run(["update", "bot", "--owner", "ops", "--clear-owner"])).rejects.toThrow(
        "process.exit",
      );
      expect(stderr()).toContain("--owner and --clear-owner are mutually exclusive");
      expect(mockEngine.getAgent).not.toHaveBeenCalled();
      expect(mockEngine.updateAgent).not.toHaveBeenCalled();
    });

    it("prints the engine return verbatim under --json", async () => {
      await run(["update", "bot", "--owner", "ops", "--json"]);
      expect(logSpy).toHaveBeenCalledWith(JSON.stringify(AGENT, null, 2));
    });
  });

  describe("agent deactivate", () => {
    it("deactivates and reports the revoked-token count", async () => {
      await run(["deactivate", "bot"]);
      expect(mockEngine.deactivateAgent).toHaveBeenCalledWith("bot", undefined);
      expect(stderr()).toContain("OK: Agent deactivated (bot); 3 token(s) revoked");
    });

    it("prints the engine return verbatim under --json", async () => {
      await run(["deactivate", "bot", "--json"]);
      expect(logSpy).toHaveBeenCalledWith(JSON.stringify({ revoked_tokens: 3 }, null, 2));
    });
  });

  describe("agent activate", () => {
    it("activates the agent", async () => {
      await run(["activate", "bot"]);
      expect(mockEngine.activateAgent).toHaveBeenCalledWith("bot", undefined);
      expect(stderr()).toContain("OK: Agent activated (bot)");
    });

    it("prints the engine return verbatim under --json", async () => {
      await run(["activate", "bot", "--json"]);
      expect(logSpy).toHaveBeenCalledWith(JSON.stringify(AGENT, null, 2));
    });
  });

  describe("agent delete", () => {
    it("names the counts it will revoke and remove in the confirmation", async () => {
      await run(["delete", "bot"]);
      expect(mockEngine.getAgent).toHaveBeenCalledWith("bot", undefined);
      expect(mockPromptConfirm).toHaveBeenCalledWith(
        "Delete agent bot? This revokes 2 live token(s) and removes 3 grant(s).",
      );
      expect(mockEngine.deleteAgent).toHaveBeenCalledWith("bot", undefined);
    });

    it("aborts on a declined confirmation without calling the engine", async () => {
      mockPromptConfirm.mockResolvedValue(false);
      await run(["delete", "bot"]);
      expect(stderr()).toContain("Aborted.");
      expect(mockEngine.deleteAgent).not.toHaveBeenCalled();
    });

    it("skips the prompt under --confirm", async () => {
      await run(["delete", "bot", "--confirm"]);
      expect(mockPromptConfirm).not.toHaveBeenCalled();
      expect(mockEngine.deleteAgent).toHaveBeenCalledWith("bot", undefined);
      expect(stderr()).toContain("OK: Agent deleted (bot); 2 token(s) revoked, 3 grant(s) removed");
    });

    it("surfaces an engine refusal before the prompt", async () => {
      const { VaultError } = await import("@harpoc/shared");
      mockEngine.getAgent.mockImplementation(() => {
        throw VaultError.agentNotFound("bot");
      });
      await expect(run(["delete", "bot"])).rejects.toThrow("process.exit");
      expect(mockPromptConfirm).not.toHaveBeenCalled();
      expect(mockEngine.deleteAgent).not.toHaveBeenCalled();
    });

    it("prints the engine return verbatim under --json", async () => {
      await run(["delete", "bot", "--confirm", "--json"]);
      expect(logSpy).toHaveBeenCalledWith(
        JSON.stringify({ revoked_tokens: 2, removed_grants: 3 }, null, 2),
      );
    });
  });

  describe("agent permissions", () => {
    it("writes the named cell", async () => {
      await run(["permissions", "bot", "secret://k", "--permissions", "read,use"]);
      expect(mockEngine.setAgentPermissions).toHaveBeenCalledWith(
        "bot",
        "sid-1",
        ["read", "use"],
        undefined,
        "cli-user",
        undefined,
      );
    });

    it("clears the cell with --clear", async () => {
      await run(["permissions", "bot", "secret://k", "--clear"]);
      expect(mockEngine.setAgentPermissions).toHaveBeenCalledWith(
        "bot",
        "sid-1",
        [],
        undefined,
        "cli-user",
        undefined,
      );
    });

    it("refuses --permissions together with --clear", async () => {
      await expect(
        run(["permissions", "bot", "secret://k", "--permissions", "use", "--clear"]),
      ).rejects.toThrow("process.exit");
      expect(stderr()).toContain("--permissions and --clear are mutually exclusive");
      expect(mockEngine.setAgentPermissions).not.toHaveBeenCalled();
    });

    it("refuses neither flag", async () => {
      await expect(run(["permissions", "bot", "secret://k"])).rejects.toThrow("process.exit");
      expect(stderr()).toContain("one of --permissions or --clear is required");
      expect(mockEngine.setAgentPermissions).not.toHaveBeenCalled();
    });

    it("refuses --expires together with --clear", async () => {
      await expect(
        run(["permissions", "bot", "secret://k", "--clear", "--expires", "60"]),
      ).rejects.toThrow("process.exit");
      expect(stderr()).toContain("--expires cannot be combined with --clear");
      expect(mockEngine.setAgentPermissions).not.toHaveBeenCalled();
    });

    it("refuses an unknown permission before the engine", async () => {
      await expect(
        run(["permissions", "bot", "secret://k", "--permissions", "sudo"]),
      ).rejects.toThrow("process.exit");
      expect(stderr()).toContain('Invalid permission: "sudo"');
      expect(mockEngine.setAgentPermissions).not.toHaveBeenCalled();
    });

    it("maps --expires minutes onto an absolute timestamp", async () => {
      const before = Date.now();
      await run(["permissions", "bot", "secret://k", "--permissions", "use", "--expires", "60"]);
      const after = Date.now();
      const call = mockEngine.setAgentPermissions.mock.calls[0] as unknown[];
      const expiresAt = call[3] as number;
      expect(expiresAt).toBeGreaterThanOrEqual(before + 60 * 60 * 1000);
      expect(expiresAt).toBeLessThanOrEqual(after + 60 * 60 * 1000);
    });

    it("refuses a non-positive --expires", async () => {
      await expect(
        run(["permissions", "bot", "secret://k", "--permissions", "use", "--expires", "0"]),
      ).rejects.toThrow("process.exit");
      expect(stderr()).toContain("--expires must be a positive number of minutes");
      expect(mockEngine.setAgentPermissions).not.toHaveBeenCalled();
    });

    it("prints the gating note when the secret becomes policy-gated", async () => {
      mockEngine.setAgentPermissions.mockReturnValue(
        result({ gated_before: false, gated_after: true }),
      );
      await run(["permissions", "bot", "secret://k", "--permissions", "use"]);
      expect(stderr()).toContain("Note: secret://k is now policy-gated");
    });

    it("prints the gating note when the secret stops being policy-gated", async () => {
      mockEngine.setAgentPermissions.mockReturnValue(
        result({ policy: null, gated_before: true, gated_after: false }),
      );
      await run(["permissions", "bot", "secret://k", "--clear"]);
      expect(stderr()).toContain("no longer policy-gated: token scope alone governs");
    });

    it("prints no gating note when the gate did not flip", async () => {
      await run(["permissions", "bot", "secret://k", "--permissions", "use"]);
      expect(stderr()).not.toContain("policy-gated");
    });

    it("names the cell in the human output", async () => {
      await run(["permissions", "bot", "secret://k", "--permissions", "read,use"]);
      const out = stdout();
      expect(out).toContain("bot");
      expect(out).toContain("secret://k");
      expect(out).toContain("read, use");
    });

    it("prints the engine return verbatim under --json", async () => {
      await run(["permissions", "bot", "secret://k", "--permissions", "use", "--json"]);
      expect(logSpy).toHaveBeenCalledWith(JSON.stringify(result(), null, 2));
    });
  });
});
