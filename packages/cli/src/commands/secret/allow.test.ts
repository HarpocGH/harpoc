import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionConfig, InjectionPolicy } from "@harpoc/shared";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    getInjectionPolicy: vi.fn<() => Promise<InjectionPolicy>>(),
    setInjectionPolicy: vi.fn().mockResolvedValue(undefined),
    getConnectionConfig: vi.fn<() => Promise<ConnectionConfig | undefined>>(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { mergePolicy, registerSecretAllowCommand } from "./allow.js";
import { buildCli, spyCli, type CliSpies } from "../../__fixtures__/cli-harness.js";

const run = buildCli(
  (program) => registerSecretAllowCommand(program.command("secret")),
  ["secret", "allow"],
);

let spies: CliSpies;

beforeEach(() => {
  spies = spyCli();
});

afterEach(() => {
  spies.restore();
});

const STORED_POLICY: InjectionPolicy = {
  url_allowlist: [],
  command_allowlist: ["gh"],
  env_allowlist: [],
  host_allowlist: [],
  response_mode: "filtered",
  response_header_allowlist: [],
  network_isolation: false,
  fs_isolation: false,
  smtp_recipient_allowlist: [],
  imap_read_only: true,
  strict_tree_exit: false,
  proxy: false,
  ssh_agent_socket: false,
};

const current: InjectionPolicy = {
  url_allowlist: ["https://api.github.com/*"],
  command_allowlist: ["gh"],
  env_allowlist: ["HOME"],
  host_allowlist: ["db.example.com:5432"],
  response_mode: "status_only",
  response_header_allowlist: ["Content-Type"],
  network_isolation: true,
  fs_isolation: true,
  smtp_recipient_allowlist: [],
  imap_read_only: false,
  strict_tree_exit: false,
  proxy: false,
  ssh_agent_socket: false,
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

  it("keeps a stored fs_isolation when both flags are absent", () => {
    const merged = mergePolicy(current, { command: ["git"] });
    expect(merged.fs_isolation).toBe(true);
  });

  it("sets and clears fs_isolation via the tri-state option", () => {
    const off = mergePolicy(current, { fsIsolation: false });
    expect(off.fs_isolation).toBe(false);
    expect(off.network_isolation).toBe(true);
    expect(off.response_mode).toBe("status_only");

    const on = mergePolicy({ ...current, fs_isolation: false }, { fsIsolation: true });
    expect(on.fs_isolation).toBe(true);
  });

  it("the two isolation flags move independently", () => {
    const merged = mergePolicy({ ...current, fs_isolation: false }, { fsIsolation: true });
    expect(merged.fs_isolation).toBe(true);
    expect(merged.network_isolation).toBe(true);
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
      fs_isolation: false,
      smtp_recipient_allowlist: [],
      imap_read_only: false,
      strict_tree_exit: false,
      proxy: false,
      ssh_agent_socket: false,
    });
  });

  it("--clear alone yields the default policy", () => {
    const merged = mergePolicy(current, { clear: true });
    expect(merged.response_mode).toBe("filtered");
    expect(merged.url_allowlist).toEqual([]);
    expect(merged.response_header_allowlist).toEqual([]);
  });

  it("keeps a stored smtp_recipient_allowlist when --recipient is absent", () => {
    const merged = mergePolicy(
      { ...current, smtp_recipient_allowlist: ["a@b.c"] },
      { command: ["git"] },
    );
    expect(merged.smtp_recipient_allowlist).toEqual(["a@b.c"]);
  });

  it("--recipient adds to the stored allowlist instead of replacing it", () => {
    const merged = mergePolicy(
      { ...current, smtp_recipient_allowlist: ["a@b.c"] },
      { recipient: ["*@d.e"] },
    );
    expect(merged.smtp_recipient_allowlist).toEqual(["a@b.c", "*@d.e"]);
  });

  it("--recipient dedupes a pattern already present in the stored allowlist", () => {
    const merged = mergePolicy(
      { ...current, smtp_recipient_allowlist: ["a@b.c"] },
      { recipient: ["a@b.c"] },
    );
    expect(merged.smtp_recipient_allowlist).toEqual(["a@b.c"]);
  });

  it("--clear empties the recipient allowlist before a new --recipient is added", () => {
    const merged = mergePolicy(
      { ...current, smtp_recipient_allowlist: ["a@b.c"] },
      { clear: true, recipient: ["*@d.e"] },
    );
    expect(merged.smtp_recipient_allowlist).toEqual(["*@d.e"]);
  });

  it("keeps a stored imap_read_only when both flags are absent", () => {
    const merged = mergePolicy({ ...current, imap_read_only: true }, { command: ["git"] });
    expect(merged.imap_read_only).toBe(true);
  });

  it("sets and clears imap_read_only via the tri-state option", () => {
    const off = mergePolicy({ ...current, imap_read_only: true }, { imapReadOnly: false });
    expect(off.imap_read_only).toBe(false);

    const on = mergePolicy({ ...current, imap_read_only: false }, { imapReadOnly: true });
    expect(on.imap_read_only).toBe(true);
  });

  it("the recipient allowlist and imap_read_only move independently of the other groups", () => {
    const merged = mergePolicy(
      { ...current, smtp_recipient_allowlist: ["a@b.c"], imap_read_only: false },
      { recipient: ["*@d.e"], imapReadOnly: true },
    );
    expect(merged.smtp_recipient_allowlist).toEqual(["a@b.c", "*@d.e"]);
    expect(merged.imap_read_only).toBe(true);
    expect(merged.command_allowlist).toEqual(["gh"]);
  });
});

describe("secret allow command — interpreter acknowledgement pass-through", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockEngine.getInjectionPolicy.mockResolvedValue({ ...STORED_POLICY, command_allowlist: [] });
  });

  it("--acknowledge-interpreter passes acknowledge_interpreters: true to the engine", async () => {
    await run(["secret://k", "--command", "python", "--acknowledge-interpreter"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ command_allowlist: ["python"] }),
      { acknowledge_interpreters: true },
      undefined,
    );
  });

  it("defaults acknowledge_interpreters to false when the flag is absent", async () => {
    await run(["secret://k", "--command", "gh"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ command_allowlist: ["gh"] }),
      { acknowledge_interpreters: false },
      undefined,
    );
  });

  it("renders a schema refusal value-free through the shared renderer", async () => {
    await expect(run(["secret://k", "--response-mode", "bogus"])).rejects.toThrow("process.exit");
    expect(spies.errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("response_mode: must be one of full, filtered, status_only"),
    );
    expect(spies.errorSpy).not.toHaveBeenCalledWith(expect.stringContaining("bogus"));
    expect(mockEngine.setInjectionPolicy).not.toHaveBeenCalled();
  });
});

describe("secret allow command — network isolation flags", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockEngine.getInjectionPolicy.mockResolvedValue({ ...STORED_POLICY, network_isolation: true });
  });

  it("--network-isolation alone is a set (not a show) and lands as true", async () => {
    await run(["secret://k", "--network-isolation"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ network_isolation: true }),
      { acknowledge_interpreters: false },
      undefined,
    );
  });

  it("--no-network-isolation clears the stored requirement", async () => {
    await run(["secret://k", "--no-network-isolation"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ network_isolation: false }),
      { acknowledge_interpreters: false },
      undefined,
    );
  });

  it("keeps the stored true when neither spelling is passed (commander tri-state pin)", async () => {
    await run(["secret://k", "--url", "https://api.example.com/*"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ network_isolation: true }),
      { acknowledge_interpreters: false },
      undefined,
    );
  });
});

describe("secret allow command — filesystem isolation flags", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockEngine.getInjectionPolicy.mockResolvedValue({ ...STORED_POLICY, fs_isolation: true });
  });

  it("--fs-isolation alone is a set (not a show) and lands as true", async () => {
    mockEngine.getInjectionPolicy.mockResolvedValue({ ...STORED_POLICY });
    await run(["secret://k", "--fs-isolation"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ fs_isolation: true }),
      { acknowledge_interpreters: false },
      undefined,
    );
  });

  it("--no-fs-isolation clears the stored requirement", async () => {
    await run(["secret://k", "--no-fs-isolation"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ fs_isolation: false }),
      { acknowledge_interpreters: false },
      undefined,
    );
  });

  it("keeps the stored true when neither spelling is passed (commander tri-state pin)", async () => {
    await run(["secret://k", "--url", "https://api.example.com/*"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ fs_isolation: true }),
      { acknowledge_interpreters: false },
      undefined,
    );
  });

  it("--clear resets a stored fs_isolation to false", async () => {
    await run(["secret://k", "--clear"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ fs_isolation: false }),
      { acknowledge_interpreters: false },
      undefined,
    );
  });
});

describe("secret allow command — recipient allowlist flag (v1.3)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockEngine.getInjectionPolicy.mockResolvedValue({
      ...STORED_POLICY,
      smtp_recipient_allowlist: ["a@b.c"],
    });
  });

  it("--recipient is a set (not a show) and merges additively with the stored list", async () => {
    await run(["secret://k", "--recipient", "*@d.e"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ smtp_recipient_allowlist: ["a@b.c", "*@d.e"] }),
      { acknowledge_interpreters: false },
      undefined,
    );
  });

  it("--clear followed by --recipient starts from an empty allowlist", async () => {
    await run(["secret://k", "--clear", "--recipient", "*@d.e"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ smtp_recipient_allowlist: ["*@d.e"] }),
      { acknowledge_interpreters: false },
      undefined,
    );
  });
});

describe("secret allow command — imap read-only flag (v1.3)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockEngine.getInjectionPolicy.mockResolvedValue({ ...STORED_POLICY });
  });

  it("--imap-read-only alone is a set (not a show) and lands as true", async () => {
    mockEngine.getInjectionPolicy.mockResolvedValue({ ...STORED_POLICY, imap_read_only: false });
    await run(["secret://k", "--imap-read-only"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ imap_read_only: true }),
      { acknowledge_interpreters: false },
      undefined,
    );
  });

  it("--no-imap-read-only clears the stored requirement", async () => {
    await run(["secret://k", "--no-imap-read-only"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ imap_read_only: false }),
      { acknowledge_interpreters: false },
      undefined,
    );
  });

  it("keeps the stored true when neither spelling is passed (commander tri-state pin)", async () => {
    await run(["secret://k", "--url", "https://api.example.com/*"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ imap_read_only: true }),
      { acknowledge_interpreters: false },
      undefined,
    );
  });
});

describe("secret allow command — strict tree exit flag (2026-09-10)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockEngine.getInjectionPolicy.mockResolvedValue({ ...STORED_POLICY, strict_tree_exit: true });
  });

  it("--strict-tree-exit alone is a set (not a show) and lands as true", async () => {
    mockEngine.getInjectionPolicy.mockResolvedValue({ ...STORED_POLICY, strict_tree_exit: false });
    await run(["secret://k", "--strict-tree-exit"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ strict_tree_exit: true }),
      { acknowledge_interpreters: false },
      undefined,
    );
  });

  it("--no-strict-tree-exit clears the stored requirement", async () => {
    await run(["secret://k", "--no-strict-tree-exit"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ strict_tree_exit: false }),
      { acknowledge_interpreters: false },
      undefined,
    );
  });

  it("keeps the stored true when neither spelling is passed (commander tri-state pin)", async () => {
    await run(["secret://k", "--url", "https://api.example.com/*"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ strict_tree_exit: true }),
      { acknowledge_interpreters: false },
      undefined,
    );
  });

  it("mergePolicy: --clear resets it to false unless the flag re-asserts it", () => {
    expect(
      mergePolicy({ ...STORED_POLICY, strict_tree_exit: true }, { clear: true }).strict_tree_exit,
    ).toBe(false);
    expect(
      mergePolicy(
        { ...STORED_POLICY, strict_tree_exit: false },
        { clear: true, strictTreeExit: true },
      ).strict_tree_exit,
    ).toBe(true);
  });

  it("a bare `secret allow <handle>` is a show: the stored policy printed, nothing set (2026-09-12)", async () => {
    await run(["secret://k"]);
    expect(mockEngine.getInjectionPolicy).toHaveBeenCalledTimes(1);
    expect(mockEngine.setInjectionPolicy).not.toHaveBeenCalled();
    expect(spies.logSpy).toHaveBeenCalledWith(
      JSON.stringify({ ...STORED_POLICY, strict_tree_exit: true }, null, 2),
    );
  });
});

describe("secret allow command — egress proxy opt-in (B2)", () => {
  const GITHUB = ["https://api.github.com/*"];

  beforeEach(() => {
    vi.clearAllMocks();
    mockEngine.getInjectionPolicy.mockResolvedValue({ ...STORED_POLICY, url_allowlist: GITHUB });
  });

  it("--proxy alone is a set (not a show): the whole policy lands with proxy: true", async () => {
    await run(["secret://k", "--proxy"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      { ...STORED_POLICY, url_allowlist: GITHUB, proxy: true },
      { acknowledge_interpreters: false },
      undefined,
    );
    expect(spies.errorSpy.mock.calls).toEqual([["OK: Injection policy updated (secret://k)"]]);
  });

  it("--no-proxy clears a stored opt-in", async () => {
    mockEngine.getInjectionPolicy.mockResolvedValue({
      ...STORED_POLICY,
      url_allowlist: GITHUB,
      proxy: true,
    });
    await run(["secret://k", "--no-proxy"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      { ...STORED_POLICY, url_allowlist: GITHUB, proxy: false },
      { acknowledge_interpreters: false },
      undefined,
    );
  });

  it("keeps a stored opt-in when neither spelling is passed (commander tri-state pin)", async () => {
    mockEngine.getInjectionPolicy.mockResolvedValue({ ...STORED_POLICY, proxy: true });
    await run(["secret://k", "--url", "https://api.example.com/*"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      { ...STORED_POLICY, url_allowlist: ["https://api.example.com/*"], proxy: true },
      { acknowledge_interpreters: false },
      undefined,
    );
  });

  it("--proxy on a secret that allowlists no URL notes that the proxy brokers it to no origin", async () => {
    mockEngine.getInjectionPolicy.mockResolvedValue({ ...STORED_POLICY });
    await run(["secret://k", "--proxy"]);
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        "Note: secret://k is open to the egress proxy but allowlists no URL — the proxy brokers it to no origin until --url <pattern> adds one.",
      ],
      ["OK: Injection policy updated (secret://k)"],
    ]);
  });

  it("mergePolicy: --clear resets proxy to false unless --proxy re-asserts it", () => {
    expect(mergePolicy({ ...STORED_POLICY, proxy: true }, { clear: true }).proxy).toBe(false);
    expect(mergePolicy({ ...STORED_POLICY }, { clear: true, proxy: true }).proxy).toBe(true);
  });
});

describe("secret allow command — ssh-agent socket opt-in (B3)", () => {
  const PINNED: ConnectionConfig = {
    ssh: {
      known_hosts: [
        "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOCrwIj6+onGT6amn11WaE7DBDJU/Zcim3GZknGAAwyw",
      ],
    },
  };
  const HOST_NOTE =
    "Note: secret://k is open to the ssh-agent socket but allowlists no host — the socket signs with it for no host until --host <pattern> adds one.";
  const PIN_NOTE =
    "Note: secret://k is open to the ssh-agent socket but pins no host key — the socket signs with it for no host until secret connection secret://k --known-host <line> pins one.";

  beforeEach(() => {
    vi.clearAllMocks();
    mockEngine.getInjectionPolicy.mockResolvedValue({
      ...STORED_POLICY,
      host_allowlist: ["github.com"],
    });
    mockEngine.getConnectionConfig.mockResolvedValue(PINNED);
  });

  it("--ssh-agent-socket alone is a set (not a show): the whole policy lands with ssh_agent_socket: true", async () => {
    await run(["secret://k", "--ssh-agent-socket"]);
    expect(mockEngine.setInjectionPolicy.mock.calls).toEqual([
      [
        "secret://k",
        { ...STORED_POLICY, host_allowlist: ["github.com"], ssh_agent_socket: true },
        { acknowledge_interpreters: false },
        undefined,
      ],
    ]);
    // The pin is read with the merge read's caller, before the write.
    expect(mockEngine.getConnectionConfig.mock.calls).toEqual([["secret://k", undefined]]);
    const [read] = mockEngine.getConnectionConfig.mock.invocationCallOrder;
    const [write] = mockEngine.setInjectionPolicy.mock.invocationCallOrder;
    expect(read as number).toBeLessThan(write as number);
    expect(spies.errorSpy.mock.calls).toEqual([["OK: Injection policy updated (secret://k)"]]);
  });

  it("--no-ssh-agent-socket clears a stored opt-in and reads no connection config", async () => {
    mockEngine.getInjectionPolicy.mockResolvedValue({
      ...STORED_POLICY,
      host_allowlist: ["github.com"],
      ssh_agent_socket: true,
    });
    await run(["secret://k", "--no-ssh-agent-socket"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      { ...STORED_POLICY, host_allowlist: ["github.com"], ssh_agent_socket: false },
      { acknowledge_interpreters: false },
      undefined,
    );
    expect(mockEngine.getConnectionConfig).not.toHaveBeenCalled();
  });

  it("keeps a stored opt-in when neither spelling is passed (commander tri-state pin)", async () => {
    mockEngine.getInjectionPolicy.mockResolvedValue({ ...STORED_POLICY, ssh_agent_socket: true });
    await run(["secret://k", "--host", "gitlab.com"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      { ...STORED_POLICY, host_allowlist: ["gitlab.com"], ssh_agent_socket: true },
      { acknowledge_interpreters: false },
      undefined,
    );
    expect(mockEngine.getConnectionConfig).not.toHaveBeenCalled();
  });

  it("--ssh-agent-socket on a secret that allowlists no host notes that the socket signs for no host", async () => {
    mockEngine.getInjectionPolicy.mockResolvedValue({ ...STORED_POLICY });
    await run(["secret://k", "--ssh-agent-socket"]);
    expect(spies.errorSpy.mock.calls).toEqual([
      [HOST_NOTE],
      ["OK: Injection policy updated (secret://k)"],
    ]);
  });

  it("--ssh-agent-socket on a secret that pins no host key notes it, naming secret connection --known-host", async () => {
    mockEngine.getConnectionConfig.mockResolvedValue(undefined);
    await run(["secret://k", "--ssh-agent-socket"]);
    expect(spies.errorSpy.mock.calls).toEqual([
      [PIN_NOTE],
      ["OK: Injection policy updated (secret://k)"],
    ]);
  });

  it("--ssh-agent-socket with neither prints both notes, the allowlist's first", async () => {
    mockEngine.getInjectionPolicy.mockResolvedValue({ ...STORED_POLICY });
    mockEngine.getConnectionConfig.mockResolvedValue({ database: { tls_mode: "require" } });
    await run(["secret://k", "--ssh-agent-socket"]);
    expect(spies.errorSpy.mock.calls).toEqual([
      [HOST_NOTE],
      [PIN_NOTE],
      ["OK: Injection policy updated (secret://k)"],
    ]);
  });

  it("mergePolicy: --clear resets ssh_agent_socket to false unless --ssh-agent-socket re-asserts it", () => {
    expect(
      mergePolicy({ ...STORED_POLICY, ssh_agent_socket: true }, { clear: true }).ssh_agent_socket,
    ).toBe(false);
    expect(
      mergePolicy({ ...STORED_POLICY }, { clear: true, sshAgentSocket: true }).ssh_agent_socket,
    ).toBe(true);
  });
});

// I25 (test-review-2026-10-09): getting-started documents `--host <pattern>`
// and `--env <name>`; each parsed by the command lands in the engine call.
describe("secret allow command — host and env allowlist flags (I25)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockEngine.getInjectionPolicy.mockResolvedValue({ ...STORED_POLICY });
  });

  it("repeated --host replaces host_allowlist in the engine call, nothing else changed", async () => {
    await run(["secret://k", "--host", "127.0.0.1:5432", "--host", "localhost"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      { ...STORED_POLICY, host_allowlist: ["127.0.0.1:5432", "localhost"] },
      { acknowledge_interpreters: false },
      undefined,
    );
  });

  it("repeated --env replaces env_allowlist in the engine call, nothing else changed", async () => {
    await run(["secret://k", "--env", "HOME", "--env", "LANG"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      { ...STORED_POLICY, env_allowlist: ["HOME", "LANG"] },
      { acknowledge_interpreters: false },
      undefined,
    );
  });
});

describe("secret allow command — each of the 14 flag groups alone is a set (T5)", () => {
  const STORED: InjectionPolicy = { ...STORED_POLICY, imap_read_only: false };

  beforeEach(() => {
    vi.clearAllMocks();
    mockEngine.getInjectionPolicy.mockResolvedValue({ ...STORED });
    mockEngine.getConnectionConfig.mockResolvedValue(undefined);
  });

  it.each<{ flag: string; args: string[]; set: Partial<InjectionPolicy> }>([
    { flag: "--command", args: ["--command", "git"], set: { command_allowlist: ["git"] } },
    {
      flag: "--url",
      args: ["--url", "https://api.example.com/*"],
      set: { url_allowlist: ["https://api.example.com/*"] },
    },
    { flag: "--host", args: ["--host", "localhost"], set: { host_allowlist: ["localhost"] } },
    { flag: "--env", args: ["--env", "HOME"], set: { env_allowlist: ["HOME"] } },
    {
      flag: "--response-header",
      args: ["--response-header", "Content-Type"],
      set: { response_header_allowlist: ["Content-Type"] },
    },
    {
      flag: "--response-mode",
      args: ["--response-mode", "status_only"],
      set: { response_mode: "status_only" },
    },
    {
      flag: "--network-isolation",
      args: ["--network-isolation"],
      set: { network_isolation: true },
    },
    { flag: "--fs-isolation", args: ["--fs-isolation"], set: { fs_isolation: true } },
    {
      flag: "--recipient",
      args: ["--recipient", "*@d.e"],
      set: { smtp_recipient_allowlist: ["*@d.e"] },
    },
    { flag: "--imap-read-only", args: ["--imap-read-only"], set: { imap_read_only: true } },
    { flag: "--strict-tree-exit", args: ["--strict-tree-exit"], set: { strict_tree_exit: true } },
    { flag: "--proxy", args: ["--proxy"], set: { proxy: true } },
    { flag: "--ssh-agent-socket", args: ["--ssh-agent-socket"], set: { ssh_agent_socket: true } },
    { flag: "--clear", args: ["--clear"], set: { command_allowlist: [] } },
  ])("$flag alone is a set, not a show", async ({ args, set }) => {
    await run(["secret://k", ...args]);
    expect(mockEngine.setInjectionPolicy.mock.calls).toEqual([
      ["secret://k", { ...STORED, ...set }, { acknowledge_interpreters: false }, undefined],
    ]);
    expect(spies.stdout()).toBe("");
  });

  it("--acknowledge-interpreter alone is a show, not a set", async () => {
    await run(["secret://k", "--acknowledge-interpreter"]);
    expect(mockEngine.setInjectionPolicy).not.toHaveBeenCalled();
    expect(spies.stdout()).toBe(JSON.stringify(STORED, null, 2));
  });
});
