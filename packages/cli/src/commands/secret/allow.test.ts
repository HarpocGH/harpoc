import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import type { InjectionPolicy } from "@harpoc/shared";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    getInjectionPolicy: vi.fn(),
    setInjectionPolicy: vi.fn().mockResolvedValue(undefined),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { mergePolicy, registerSecretAllowCommand } from "./allow.js";

const current: InjectionPolicy = {
  url_allowlist: ["https://api.github.com/*"],
  command_allowlist: ["gh"],
  env_allowlist: ["HOME"],
  host_allowlist: ["db.example.com:5432"],
  response_mode: "status_only",
  response_header_allowlist: ["Content-Type"],
  network_isolation: true,
};

describe("mergePolicy", () => {
  it("preserves omitted groups — a --url update cannot reset the response mode", () => {
    const merged = mergePolicy(current, { url: ["https://api.example.com/*"] });
    expect(merged.url_allowlist).toEqual(["https://api.example.com/*"]);
    expect(merged.command_allowlist).toEqual(["gh"]);
    expect(merged.env_allowlist).toEqual(["HOME"]);
    expect(merged.host_allowlist).toEqual(["db.example.com:5432"]);
    expect(merged.response_mode).toBe("status_only");
    expect(merged.response_header_allowlist).toEqual(["Content-Type"]);
    expect(merged.network_isolation).toBe(true);
  });

  it("keeps a stored network_isolation when both flags are absent", () => {
    const merged = mergePolicy(current, { command: ["git"] });
    expect(merged.network_isolation).toBe(true);
  });

  it("sets and clears network_isolation via the tri-state option", () => {
    const off = mergePolicy(current, { networkIsolation: false });
    expect(off.network_isolation).toBe(false);
    expect(off.response_mode).toBe("status_only");

    const on = mergePolicy({ ...current, network_isolation: false }, { networkIsolation: true });
    expect(on.network_isolation).toBe(true);
  });

  it("replaces a provided group wholesale", () => {
    const merged = mergePolicy(current, { command: ["git"] });
    expect(merged.command_allowlist).toEqual(["git"]);
    expect(merged.url_allowlist).toEqual(["https://api.github.com/*"]);
  });

  it("sets the response mode without touching the allowlists", () => {
    const merged = mergePolicy(current, { responseMode: "filtered" });
    expect(merged.response_mode).toBe("filtered");
    expect(merged.command_allowlist).toEqual(["gh"]);
    expect(merged.response_header_allowlist).toEqual(["Content-Type"]);
  });

  it("replaces the response header allowlist when provided", () => {
    const merged = mergePolicy(current, { responseHeader: ["X-Request-Id"] });
    expect(merged.response_header_allowlist).toEqual(["X-Request-Id"]);
    expect(merged.response_mode).toBe("status_only");
  });

  it("--clear resets the policy before applying the other flags", () => {
    const merged = mergePolicy(current, { clear: true, url: ["https://only.example.com/*"] });
    expect(merged).toEqual({
      url_allowlist: ["https://only.example.com/*"],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [],
      response_mode: "filtered",
      response_header_allowlist: [],
      network_isolation: false,
    });
  });

  it("--clear alone yields the default policy", () => {
    const merged = mergePolicy(current, { clear: true });
    expect(merged.response_mode).toBe("filtered");
    expect(merged.url_allowlist).toEqual([]);
    expect(merged.response_header_allowlist).toEqual([]);
  });
});

describe("secret allow command — interpreter acknowledgement pass-through", () => {
  let errorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockEngine.getInjectionPolicy.mockResolvedValue({
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [],
      response_mode: "filtered",
      response_header_allowlist: [],
      network_isolation: false,
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    errorSpy.mockRestore();
  });

  async function run(args: string[]): Promise<void> {
    const program = new Command();
    program.option("--vault-dir <path>", "Path to vault directory");
    const secret = program.command("secret");
    registerSecretAllowCommand(secret);
    program.exitOverride();
    program.configureOutput({ writeErr: () => {} });
    await program.parseAsync(["node", "harpoc", "secret", "allow", ...args]);
  }

  it("--acknowledge-interpreter passes acknowledge_interpreters: true to the engine", async () => {
    await run(["secret://k", "--command", "python", "--acknowledge-interpreter"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ command_allowlist: ["python"] }),
      { acknowledge_interpreters: true },
    );
  });

  it("defaults acknowledge_interpreters to false when the flag is absent", async () => {
    await run(["secret://k", "--command", "gh"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ command_allowlist: ["gh"] }),
      { acknowledge_interpreters: false },
    );
  });
});

describe("secret allow command — network isolation flags", () => {
  let errorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockEngine.getInjectionPolicy.mockResolvedValue({
      url_allowlist: [],
      command_allowlist: ["gh"],
      env_allowlist: [],
      host_allowlist: [],
      response_mode: "filtered",
      response_header_allowlist: [],
      network_isolation: true,
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    errorSpy.mockRestore();
  });

  async function run(args: string[]): Promise<void> {
    const program = new Command();
    program.option("--vault-dir <path>", "Path to vault directory");
    const secret = program.command("secret");
    registerSecretAllowCommand(secret);
    program.exitOverride();
    program.configureOutput({ writeErr: () => {} });
    await program.parseAsync(["node", "harpoc", "secret", "allow", ...args]);
  }

  it("--network-isolation alone is a set (not a show) and lands as true", async () => {
    await run(["secret://k", "--network-isolation"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ network_isolation: true }),
      { acknowledge_interpreters: false },
    );
  });

  it("--no-network-isolation clears the stored requirement", async () => {
    await run(["secret://k", "--no-network-isolation"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ network_isolation: false }),
      { acknowledge_interpreters: false },
    );
  });

  it("keeps the stored true when neither spelling is passed (commander tri-state pin)", async () => {
    await run(["secret://k", "--url", "https://api.example.com/*"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ network_isolation: true }),
      { acknowledge_interpreters: false },
    );
  });
});
