import { execFileSync, spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionConfig, GitAction, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { GitInjector } from "./git-injector.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";

vi.mock("./spawn-captured.js", () => ({ spawnCaptured: vi.fn() }));

const GIT = resolveExecutable("git", controlledPathDirs());
const SSH = resolveExecutable("ssh", controlledPathDirs());
const describeGit = GIT ? describe : describe.skip;
const describeGitSsh = GIT && SSH ? describe : describe.skip;

/** Redirect the temp dir os.tmpdir() reads (TEMP/TMP on win32, TMPDIR on POSIX). */
function overrideTempEnv(dir: string): { TMPDIR?: string; TMP?: string; TEMP?: string } {
  const saved = { TMPDIR: process.env.TMPDIR, TMP: process.env.TMP, TEMP: process.env.TEMP };
  process.env.TMPDIR = dir;
  process.env.TMP = dir;
  process.env.TEMP = dir;
  return saved;
}

function restoreTempEnv(saved: { TMPDIR?: string; TMP?: string; TEMP?: string }): void {
  if (saved.TMPDIR === undefined) delete process.env.TMPDIR;
  else process.env.TMPDIR = saved.TMPDIR;
  if (saved.TMP === undefined) delete process.env.TMP;
  else process.env.TMP = saved.TMP;
  if (saved.TEMP === undefined) delete process.env.TEMP;
  else process.env.TEMP = saved.TEMP;
}

/** The sh git would run GIT_SSH_COMMAND through: /bin/sh, or Git-for-Windows'. */
function findRoundtripSh(): string | null {
  if (process.platform !== "win32") return "/bin/sh";
  const candidates = [
    ...(GIT ? [join(dirname(dirname(GIT)), "usr", "bin", "sh.exe")] : []),
    "C:\\Program Files\\Git\\usr\\bin\\sh.exe",
    "C:\\Program Files\\Git\\bin\\sh.exe",
  ];
  return candidates.find((c) => existsSync(c)) ?? null;
}

const OK_RESULT: SpawnCapturedResult = {
  exit_code: 0,
  stdout: "",
  stderr: "",
  timed_out: false,
  truncated: false,
  signal: null,
  spawn_failed: false,
};

function policy(overrides: Partial<InjectionPolicy> = {}): InjectionPolicy {
  return {
    url_allowlist: [],
    command_allowlist: [],
    env_allowlist: [],
    host_allowlist: [],
    response_mode: "filtered",
    response_header_allowlist: [],
    network_isolation: false,
    ...overrides,
  };
}

type SpawnCall = [string, string[], { env: Record<string, string>; redact?: string[] }];

// Positive-path assertions on the spawned git command (code review 2026-07-07,
// M13): the credential must reach git via the vault-authored GIT_ASKPASS helper
// through the child environment — never argv — and the SSH transport must carry
// the hardening args in GIT_SSH_COMMAND.
describeGit("GitInjector HTTPS credential handling (git resolvable)", () => {
  const injector = new GitInjector(null);
  const spawnMock = vi.mocked(spawnCaptured);

  beforeEach(() => {
    spawnMock.mockReset();
    spawnMock.mockResolvedValue(OK_RESULT);
  });

  it("passes the credential via GIT_ASKPASS env vars, never argv", async () => {
    const action: GitAction = {
      type: "git",
      operation: "clone",
      repository: "https://8.8.8.8/org/repo.git",
    };
    const result = await injector.executeWithSecret(
      action,
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      policy({
        command_allowlist: [GIT as string],
        url_allowlist: ["https://8.8.8.8/*"],
      }),
      undefined,
    );

    expect(result.exit_code).toBe(0);
    expect(spawnMock).toHaveBeenCalledOnce();
    const [command, args, opts] = spawnMock.mock.calls[0] as SpawnCall;

    expect(command).toBe(GIT);
    expect(args).toEqual([
      "-c",
      "http.followRedirects=false",
      "clone",
      "https://8.8.8.8/org/repo.git",
    ]);

    expect(opts.env.GIT_ASKPASS).toBeTruthy();
    expect(opts.env.HARPOC_GIT_USERNAME).toBe("git-user");
    expect(opts.env.HARPOC_GIT_PASSWORD).toBe("s3cret-token-value");
    expect(opts.env.GIT_TERMINAL_PROMPT).toBe("0");

    // The credential appears in no argv element in any form.
    expect(args.every((a) => !a.includes("s3cret-token-value") && !a.includes("git-user"))).toBe(
      true,
    );
    // Both credential halves are redacted from any captured output.
    expect(opts.redact).toContain("s3cret-token-value");
    expect(opts.redact).toContain("git-user");
  });

  // T14: the child environment is built, not inherited (§4.5.3 layer 3). Both
  // git transports were unpinned here, so `{ ...process.env }` in either
  // initializer would have handed the vault process's whole environment —
  // proxy settings, operator-exported tokens, GIT_* overrides — to git.
  it("hands git a built environment, not the vault's own", async () => {
    process.env.HARPOC_T14_GIT_AMBIENT = "ambient-value";
    process.env.HARPOC_T14_GIT_ALLOWED = "allowed-value";
    try {
      await injector.executeWithSecret(
        { type: "git", operation: "clone", repository: "https://8.8.8.8/org/repo.git" },
        new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
        policy({
          command_allowlist: [GIT as string],
          url_allowlist: ["https://8.8.8.8/*"],
          env_allowlist: ["HARPOC_T14_GIT_ALLOWED"],
        }),
        undefined,
      );

      const [, , opts] = spawnMock.mock.calls[0] as SpawnCall;
      expect(opts.env.HARPOC_T14_GIT_AMBIENT).toBeUndefined();
      expect(opts.env.HARPOC_T14_GIT_ALLOWED).toBe("allowed-value");

      const expected = new Set([
        "PATH",
        "SystemRoot",
        "GIT_ASKPASS",
        "GIT_TERMINAL_PROMPT",
        "HARPOC_GIT_USERNAME",
        "HARPOC_GIT_PASSWORD",
        "HARPOC_GIT_HOST",
        "HARPOC_T14_GIT_ALLOWED",
      ]);
      expect(Object.keys(opts.env).filter((k) => !expected.has(k))).toEqual([]);
    } finally {
      delete process.env.HARPOC_T14_GIT_AMBIENT;
      delete process.env.HARPOC_T14_GIT_ALLOWED;
    }
  });

  it("skips a 1-2 char username in the redaction set (would shred output)", async () => {
    const action: GitAction = {
      type: "git",
      operation: "clone",
      repository: "https://8.8.8.8/org/repo.git",
    };
    await injector.executeWithSecret(
      action,
      new Uint8Array(Buffer.from("ab:s3cret-token-value")),
      policy({
        command_allowlist: [GIT as string],
        url_allowlist: ["https://8.8.8.8/*"],
      }),
      undefined,
    );

    const [, , opts] = vi.mocked(spawnCaptured).mock.calls[0] as SpawnCall;
    expect(opts.redact).toContain("s3cret-token-value");
    expect(opts.redact).not.toContain("ab");
  });
});

// H6: target control for Git-over-HTTPS must survive past the initially supplied
// URL string. git asks askpass for whatever host it ends up talking to (after a
// 3xx, or for a submodule URL the cloned repo chose), so the credential is bound
// to the validated host and redirect following is turned off.
describeGit("GitInjector HTTPS target control beyond the URL string (H6)", () => {
  const injector = new GitInjector(null);
  const spawnMock = vi.mocked(spawnCaptured);

  const REPO = "https://8.8.8.8/org/repo.git";

  function httpsPolicy(): InjectionPolicy {
    return policy({ command_allowlist: [GIT as string], url_allowlist: ["https://8.8.8.8/*"] });
  }

  /** Run the vault-authored askpass helper the way its launcher does. */
  function askpass(env: Record<string, string>, prompt: string): { out: string; status: number } {
    const helper = join(dirname(env.GIT_ASKPASS as string), "askpass.mjs");
    const r = spawnSync(process.execPath, [helper, prompt], { env, encoding: "utf8" });
    return { out: r.stdout ?? "", status: r.status ?? -1 };
  }

  beforeEach(() => {
    spawnMock.mockReset();
    spawnMock.mockResolvedValue(OK_RESULT);
  });

  it("forces http.followRedirects=false ahead of the subcommand", async () => {
    await injector.executeWithSecret(
      { type: "git", operation: "clone", repository: REPO },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      httpsPolicy(),
      undefined,
    );
    const [, args] = spawnMock.mock.calls[0] as SpawnCall;
    expect(args.slice(0, 2)).toEqual(["-c", "http.followRedirects=false"]);
    // The forced config must precede the subcommand or git ignores it.
    expect(args.indexOf("clone")).toBeGreaterThan(args.indexOf("http.followRedirects=false"));
  });

  it("binds the credential to the validated host", async () => {
    await injector.executeWithSecret(
      { type: "git", operation: "clone", repository: REPO },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      httpsPolicy(),
      undefined,
    );
    const [, , opts] = spawnMock.mock.calls[0] as SpawnCall;
    expect(opts.env.HARPOC_GIT_HOST).toBe("8.8.8.8");
  });

  it("the askpass helper answers for the validated host and refuses any other", async () => {
    let captured: Record<string, string> | undefined;
    let answered: { out: string; status: number } | undefined;
    let refused: { out: string; status: number } | undefined;
    let refusedNoUrl: { out: string; status: number } | undefined;

    // The launcher only exists for the duration of the spawn, so exercise it here.
    spawnMock.mockImplementation((_cmd, _args, opts) => {
      captured = (opts as { env: Record<string, string> }).env;
      answered = askpass(captured, "Password for 'https://git-user@8.8.8.8': ");
      refused = askpass(captured, "Password for 'https://8.8.8.8.attacker.tld/leak': ");
      refusedNoUrl = askpass(captured, "Password: ");
      return Promise.resolve(OK_RESULT);
    });

    await injector.executeWithSecret(
      { type: "git", operation: "clone", repository: REPO },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      httpsPolicy(),
      undefined,
    );

    expect(answered?.out.trim()).toBe("s3cret-token-value");
    expect(answered?.status).toBe(0);
    // A redirect or submodule target must get nothing, and the helper must fail.
    expect(refused?.out).not.toContain("s3cret-token-value");
    expect(refused?.out.trim()).toBe("");
    expect(refused?.status).toBe(1);
    // Fail closed when the prompt names no recognizable URL.
    expect(refusedNoUrl?.out.trim()).toBe("");
    expect(refusedNoUrl?.status).toBe(1);
  });

  it("answers the username prompt for the validated host too", async () => {
    let answered: { out: string; status: number } | undefined;
    spawnMock.mockImplementation((_cmd, _args, opts) => {
      answered = askpass(
        (opts as { env: Record<string, string> }).env,
        "Username for 'https://8.8.8.8': ",
      );
      return Promise.resolve(OK_RESULT);
    });
    await injector.executeWithSecret(
      { type: "git", operation: "clone", repository: REPO },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      httpsPolicy(),
      undefined,
    );
    expect(answered?.out.trim()).toBe("git-user");
  });

  it.each(["--recurse-submodules", "--recursive", "--recurse-sub"])(
    "refuses %s — submodule URLs come from the repository, not the vault",
    async (arg) => {
      await expect(
        injector.executeWithSecret(
          { type: "git", operation: "clone", repository: REPO, args: [arg] },
          new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
          httpsPolicy(),
          undefined,
        ),
      ).rejects.toMatchObject({ code: ErrorCode.INVALID_GIT_CONFIG });
      expect(spawnMock).not.toHaveBeenCalled();
    },
  );
});

describeGitSsh("GitInjector SSH transport hardening (git + ssh resolvable)", () => {
  const injector = new GitInjector(null);
  const spawnMock = vi.mocked(spawnCaptured);

  beforeEach(() => {
    spawnMock.mockReset();
    spawnMock.mockResolvedValue(OK_RESULT);
  });

  it("wires GIT_SSH_COMMAND with the hardening args and the agent socket", async () => {
    const { privateKey: keyPem } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const config: ConnectionConfig = {
      ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] },
    };
    const action: GitAction = {
      type: "git",
      operation: "clone",
      repository: "git@github.com:org/repo.git",
    };

    const result = await injector.executeWithSecret(
      action,
      new Uint8Array(Buffer.from(keyPem)),
      policy({
        command_allowlist: [GIT as string],
        host_allowlist: ["github.com"],
      }),
      config,
    );

    expect(result.exit_code).toBe(0);
    expect(spawnMock).toHaveBeenCalledOnce();
    const [command, args, opts] = spawnMock.mock.calls[0] as SpawnCall;

    expect(command).toBe(GIT);
    expect(args).toEqual(["clone", "git@github.com:org/repo.git"]);

    const sshCommand = opts.env.GIT_SSH_COMMAND ?? "";
    expect(sshCommand).toContain("StrictHostKeyChecking=yes");
    expect(sshCommand).toContain("BatchMode=yes");
    expect(sshCommand).toContain("UserKnownHostsFile=");
    expect(sshCommand).toContain("IdentitiesOnly=yes");
    // IdentitiesOnly restricts ssh to file-backed identities — the vault-written
    // .pub must ride along in GIT_SSH_COMMAND or the agent key is never offered.
    expect(sshCommand).toMatch(/ -i "?[^"]*identity\.pub"?/);
    expect(opts.env.SSH_AUTH_SOCK).toBeTruthy();
    expect(opts.env.GIT_TERMINAL_PROMPT).toBe("0");

    // The private key reaches ssh only through the ephemeral agent socket.
    expect(args.every((a) => !a.includes("PRIVATE KEY"))).toBe(true);
    expect(Object.values(opts.env).every((v) => !v.includes("PRIVATE KEY"))).toBe(true);
    expect(opts.redact).toContain(keyPem);
  });

  it("normalizes GIT_SSH_COMMAND to forward-slash paths git's bundled sh can exec", async () => {
    const { privateKey: keyPem } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const config: ConnectionConfig = {
      ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] },
    };
    const action: GitAction = {
      type: "git",
      operation: "clone",
      repository: "git@github.com:org/repo.git",
    };

    await injector.executeWithSecret(
      action,
      new Uint8Array(Buffer.from(keyPem)),
      policy({ command_allowlist: [GIT as string], host_allowlist: ["github.com"] }),
      config,
    );

    const [, , opts] = spawnMock.mock.calls[0] as SpawnCall;
    const sshCommand = opts.env.GIT_SSH_COMMAND ?? "";
    // Git-for-Windows runs GIT_SSH_COMMAND through sh, which treats a backslash
    // as an escape: on win32 the real ssh binary and the temp identity /
    // known_hosts paths are backslashed and must be normalized or the command
    // fails to exec (harness-discovered, Phase 2). POSIX paths have none, so the
    // assertion holds on every platform and guards the win32 fix from regressing.
    expect(sshCommand).not.toContain("\\");
    expect(sshCommand).toContain("UserKnownHostsFile=");
    expect(sshCommand).toMatch(/ -i "?'?[^"']*identity\.pub'?"?/);
  });

  // Review 2026-08-12: the win32 forward-slash fix still broke for paths sh or
  // ssh re-split — sh word-splits unquoted whitespace and expands `$`/backtick
  // even inside double quotes, and ssh's readconf re-tokenizes the
  // UserKnownHostsFile VALUE on whitespace after sh has built the argv. Parts
  // are now single-quoted for sh, the known_hosts value additionally
  // double-quoted for readconf.
  it("single-quotes GIT_SSH_COMMAND parts sh would split or expand; known_hosts value stays readconf-quoted", async () => {
    const spaced = mkdtempSync(join(tmpdir(), "harpoc sh $probe-"));
    const saved = overrideTempEnv(spaced);
    try {
      const { privateKey: keyPem } = generateKeyPairSync("rsa", {
        modulusLength: 2048,
        privateKeyEncoding: { type: "pkcs1", format: "pem" },
        publicKeyEncoding: { type: "spki", format: "pem" },
      });
      await injector.executeWithSecret(
        { type: "git", operation: "clone", repository: "git@github.com:org/repo.git" },
        new Uint8Array(Buffer.from(keyPem)),
        policy({ command_allowlist: [GIT as string], host_allowlist: ["github.com"] }),
        { ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] } },
      );

      const [, , opts] = spawnMock.mock.calls[0] as SpawnCall;
      const sshCommand = opts.env.GIT_SSH_COMMAND ?? "";
      const spacedFwd = spaced.replace(/\\/g, "/");

      // known_hosts part: single quotes for sh around a readconf-quoted value.
      const kh = /'UserKnownHostsFile="([^"]+)"'/.exec(sshCommand);
      expect(kh, sshCommand).toBeTruthy();
      expect((kh as RegExpExecArray)[1]).toContain(spacedFwd);
      // identity part: one single-quoted sh word after -i.
      const id = / -i '([^']+identity\.pub)'/.exec(sshCommand);
      expect(id, sshCommand).toBeTruthy();
      expect((id as RegExpExecArray)[1]).toContain(spacedFwd);
      // Nothing space-bearing or expandable survives outside single quotes.
      const outsideQuotes = sshCommand.replace(/'[^']*'/g, "");
      expect(outsideQuotes).not.toContain(spacedFwd);
      expect(outsideQuotes).not.toContain("$");
    } finally {
      restoreTempEnv(saved);
      rmSync(spaced, { recursive: true, force: true });
    }
  });

  // Real-sh round trip: the composed string must split back into exactly the
  // intended argv under the same shell git uses. POSIX always has /bin/sh; on
  // Windows the Git-for-Windows sh is probed (attempt-and-skip when absent).
  (findRoundtripSh() ? it : it.skip)(
    "composes a GIT_SSH_COMMAND real sh splits back into the intended argv",
    async () => {
      const sh = findRoundtripSh() as string;
      const spaced = mkdtempSync(join(tmpdir(), "harpoc sh $probe-"));
      const saved = overrideTempEnv(spaced);
      try {
        const { privateKey: keyPem } = generateKeyPairSync("rsa", {
          modulusLength: 2048,
          privateKeyEncoding: { type: "pkcs1", format: "pem" },
          publicKeyEncoding: { type: "spki", format: "pem" },
        });
        await injector.executeWithSecret(
          { type: "git", operation: "clone", repository: "git@github.com:org/repo.git" },
          new Uint8Array(Buffer.from(keyPem)),
          policy({ command_allowlist: [GIT as string], host_allowlist: ["github.com"] }),
          { ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] } },
        );

        const [, , opts] = spawnMock.mock.calls[0] as SpawnCall;
        const sshCommand = opts.env.GIT_SSH_COMMAND ?? "";
        const out = execFileSync(sh, ["-c", `printf '%s\n' ${sshCommand}`], {
          encoding: "utf8",
        });
        const words = out.split("\n").filter((l) => l.length > 0);
        const spacedFwd = spaced.replace(/\\/g, "/");

        // First word execs the ssh binary (forward-slashed on win32).
        expect(words[0]).toBe((SSH as string).replace(/\\/g, "/"));
        // The known_hosts option value survives as ONE argv element with its
        // readconf quotes intact, spaces and all.
        const khWord = words.find((w) => w.startsWith("UserKnownHostsFile="));
        expect(khWord, out).toMatch(/^UserKnownHostsFile="[^"]*known_hosts"$/);
        expect(khWord).toContain(spacedFwd);
        // The identity path survives as ONE argv element right after -i.
        const iIdx = words.indexOf("-i");
        expect(iIdx).toBeGreaterThan(-1);
        expect(words[iIdx + 1]).toMatch(/identity\.pub$/);
        expect(words[iIdx + 1]).toContain(spacedFwd);
        // sh performed no $-expansion: the literal $probe survives.
        expect(words[iIdx + 1]).toContain("$probe");
      } finally {
        restoreTempEnv(saved);
        rmSync(spaced, { recursive: true, force: true });
      }
    },
  );

  it("backs the agent identity with a vault-written .pub, removed after the invocation", async () => {
    const { privateKey: keyPem } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    let identityPath = "";
    let identityContentAtSpawn = "";
    spawnMock.mockImplementation((_cmd, _args, opts) => {
      const sshCommand = (opts as { env?: Record<string, string> }).env?.GIT_SSH_COMMAND ?? "";
      const m = / -i (?:"([^"]+)"|(\S+))/.exec(sshCommand);
      identityPath = (m?.[1] ?? m?.[2]) as string;
      identityContentAtSpawn = readFileSync(identityPath, "utf8");
      return Promise.resolve(OK_RESULT);
    });

    await injector.executeWithSecret(
      {
        type: "git",
        operation: "clone",
        repository: "git@github.com:org/repo.git",
      },
      new Uint8Array(Buffer.from(keyPem)),
      policy({
        command_allowlist: [GIT as string],
        host_allowlist: ["github.com"],
      }),
      { ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] } },
    );

    expect(identityContentAtSpawn).toMatch(/^ssh-rsa [A-Za-z0-9+/=]+ harpoc-ephemeral\n$/);
    expect(identityContentAtSpawn).not.toContain("PRIVATE KEY");
    expect(existsSync(identityPath)).toBe(false);
  });
});

describeGit("GitInjector network isolation (§4.5.3 layer 4)", () => {
  const spawnMock = vi.mocked(spawnCaptured);

  const cloneAction: GitAction = {
    type: "git",
    operation: "clone",
    repository: "https://8.8.8.8/org/repo.git",
  };

  const isolatedPolicy = () =>
    policy({
      command_allowlist: [GIT as string],
      url_allowlist: ["https://8.8.8.8/*"],
      network_isolation: true,
    });

  beforeEach(() => {
    spawnMock.mockReset();
  });

  it("passes the policy flag into the spawn seam and audits mechanism + state", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({ ...OK_RESULT, isolation_mechanism: "unshare" });
    await audited.executeWithSecret(
      cloneAction,
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      isolatedPolicy(),
      undefined,
      "secret-1",
    );
    const [, , opts] = spawnMock.mock.calls[0] as [
      string,
      string[],
      { networkIsolation?: boolean },
    ];
    expect(opts.networkIsolation).toBe(true);
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        detail: expect.objectContaining({
          transport: "https",
          network_isolation: true,
          isolation_mechanism: "unshare",
        }),
      }),
    );
  });

  it("audits and rethrows the fail-closed refusal from the seam", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockRejectedValue(VaultError.networkIsolationUnavailable("mocked"));
    await expect(
      audited.executeWithSecret(
        cloneAction,
        new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
        isolatedPolicy(),
        undefined,
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE });
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        detail: expect.objectContaining({
          error: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE,
          network_isolation: true,
        }),
      }),
    );
  });

  it("defaults to an un-isolated spawn and audits network_isolation: false", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue(OK_RESULT);
    await audited.executeWithSecret(
      cloneAction,
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      policy({ command_allowlist: [GIT as string], url_allowlist: ["https://8.8.8.8/*"] }),
      undefined,
      "secret-1",
    );
    const [, , opts] = spawnMock.mock.calls[0] as [
      string,
      string[],
      { networkIsolation?: boolean },
    ];
    expect(opts.networkIsolation).toBe(false);
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        detail: expect.objectContaining({ network_isolation: false }),
      }),
    );
  });
});

// The SSH transport has its own isolation wiring (flag hand-off, refusal
// catch, success/denial audit rows) — per-callsite, so it needs its own pin:
// pre-fix only 3 of the 4 spawnCaptured callsites were covered (review T1).
describeGitSsh("GitInjector SSH-transport network isolation (review fixes T1/F8)", () => {
  const spawnMock = vi.mocked(spawnCaptured);

  const { privateKey: sshKeyPem } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  const sshConfig: ConnectionConfig = {
    ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] },
  };
  const sshAction: GitAction = {
    type: "git",
    operation: "clone",
    repository: "git@github.com:org/repo.git",
  };
  const isolatedSshPolicy = () =>
    policy({
      command_allowlist: [GIT as string],
      host_allowlist: ["github.com"],
      network_isolation: true,
    });

  beforeEach(() => {
    spawnMock.mockReset();
  });

  it("passes the policy flag into the spawn seam and audits mechanism + state", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({ ...OK_RESULT, isolation_mechanism: "unshare" });
    await audited.executeWithSecret(
      sshAction,
      new Uint8Array(Buffer.from(sshKeyPem)),
      isolatedSshPolicy(),
      sshConfig,
      "secret-1",
    );
    const [, , opts] = spawnMock.mock.calls[0] as [
      string,
      string[],
      { networkIsolation?: boolean },
    ];
    expect(opts.networkIsolation).toBe(true);
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        detail: expect.objectContaining({
          transport: "ssh",
          network_isolation: true,
          isolation_mechanism: "unshare",
        }),
      }),
    );
  });

  it("audits and rethrows the fail-closed refusal from the seam (transport ssh)", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockRejectedValue(VaultError.networkIsolationUnavailable("mocked"));
    await expect(
      audited.executeWithSecret(
        sshAction,
        new Uint8Array(Buffer.from(sshKeyPem)),
        isolatedSshPolicy(),
        sshConfig,
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE });
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        detail: expect.objectContaining({
          transport: "ssh",
          error: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE,
          network_isolation: true,
        }),
      }),
    );
  });

  it("defaults to an un-isolated spawn and audits network_isolation: false", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue(OK_RESULT);
    await audited.executeWithSecret(
      sshAction,
      new Uint8Array(Buffer.from(sshKeyPem)),
      policy({ command_allowlist: [GIT as string], host_allowlist: ["github.com"] }),
      sshConfig,
      "secret-1",
    );
    const [, , opts] = spawnMock.mock.calls[0] as [
      string,
      string[],
      { networkIsolation?: boolean },
    ];
    expect(opts.networkIsolation).toBe(false);
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        detail: expect.objectContaining({ transport: "ssh", network_isolation: false }),
      }),
    );
  });

  it("the host-key-mismatch denial carries the isolation posture (review fix F8)", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({
      ...OK_RESULT,
      exit_code: 128,
      stderr: "Host key verification failed.",
    });
    await expect(
      audited.executeWithSecret(
        sshAction,
        new Uint8Array(Buffer.from(sshKeyPem)),
        isolatedSshPolicy(),
        sshConfig,
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.SSH_HOST_KEY_MISMATCH });
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        detail: expect.objectContaining({
          transport: "ssh",
          error: "SSH_HOST_KEY_MISMATCH",
          network_isolation: true,
        }),
      }),
    );
  });
});
