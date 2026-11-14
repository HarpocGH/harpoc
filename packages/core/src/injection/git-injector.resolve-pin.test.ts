import { execFileSync } from "node:child_process";
import type { ExecFileSyncOptions } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GitAction, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { GitInjector } from "./git-injector.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";
import { validateUrl } from "./url-validator.js";
import { expectVaultError } from "@harpoc/test-utils";

vi.mock("./spawn-captured.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./spawn-captured.js")>();
  return { ...actual, spawnCaptured: vi.fn() };
});
const DNS = vi.hoisted(() => ({ gitExample: ["93.184.216.34", "2606:2800:220:1::1"] }));
vi.mock("./url-validator.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./url-validator.js")>();
  return {
    ...actual,
    validateUrl: vi.fn(async (urlStr: string) => {
      const url = new URL(urlStr);
      if (url.hostname === "git.example" || url.hostname === "git.example.") {
        return { url, resolvedAddresses: [...DNS.gitExample] };
      }
      if (url.hostname === "harpoc-pin.invalid" || url.hostname === "harpoc-pin.invalid.") {
        return { url, resolvedAddresses: ["127.0.0.1"] };
      }
      if (url.hostname === "8.8.8.8") return actual.validateUrl(urlStr);
      throw new Error(`unexpected host ${url.hostname}`);
    }),
  };
});

const GIT = resolveExecutable("git", controlledPathDirs());
const NULL_GIT_CONFIG = process.platform === "win32" ? "NUL" : "/dev/null";
const SECRET = "git-user:s3cret-token-value";
const PIN_443 = "-c http.curloptResolve=git.example:443:93.184.216.34,[2606:2800:220:1::1]";
const PIN_443_DOT = "-c http.curloptResolve=git.example.:443:93.184.216.34,[2606:2800:220:1::1]";
const PIN_8443 = "-c http.curloptResolve=git.example:8443:93.184.216.34,[2606:2800:220:1::1]";
const PIN_V4 = "-c http.curloptResolve=git.example:443:93.184.216.34";
const BOTH_VERSIONS = ["93.184.216.34", "2606:2800:220:1::1"];
const MOCKED = ["ls-remote", "fetch", "push", "pull", "clone"];

const OK_RESULT: SpawnCapturedResult = {
  exit_code: 0,
  stdout: "",
  stderr: "",
  timed_out: false,
  truncated: false,
  signal: null,
  spawn_failed: false,
  redacted: false,
};

const { spawnCaptured: realSpawnCaptured } =
  await vi.importActual<typeof import("./spawn-captured.js")>("./spawn-captured.js");

/** Whether the resolved git is at least `major.minor` (git reads `http.curloptResolve` from 2.37). */
function gitAtLeast(major: number, minor: number): boolean {
  if (GIT === null) return false;
  const version = /(\d+)\.(\d+)/.exec(
    execFileSync(GIT, ["--version"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 20_000,
    }),
  );
  if (version === null) return false;
  const [have, sub] = [Number(version[1]), Number(version[2])];
  return have > major || (have === major && sub >= minor);
}

/** The first non-option token of a git argv, `-c`'s value skipped. */
function gitSubcommand(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i] as string;
    if (a === "-c") i++;
    else if (!a.startsWith("-")) return a;
  }
  return undefined;
}

/** A policy that allowlists the repository's origin and the resolved git. */
function policy(repository: string): InjectionPolicy {
  return {
    url_allowlist: [`${new URL(repository).origin}/*`],
    command_allowlist: [GIT as string],
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
  };
}

const PLANS = [
  ["clone", ["network", "network", "local"]],
  ["ls-remote", ["network"]],
  ["pull", ["local", "local", "network", "local"]],
  ["push", ["local", "local", "local", "network"]],
  ["fetch", ["local", "local", "local", "network", "local"]],
] as const;
const IP_PLANS = PLANS.filter(([operation]) => operation !== "ls-remote");

describe.skipIf(GIT === null)(
  "git over HTTPS is handed the judged addresses (P-1; skipped where git does not resolve)",
  () => {
    const injector = new GitInjector(null);
    const spawnMock = vi.mocked(spawnCaptured);
    let scratch: string;

    beforeEach(() => {
      scratch = mkdtempSync(join(tmpdir(), "harpoc-resolve-pin-"));
      DNS.gitExample = [...BOTH_VERSIONS];
      spawnMock.mockReset();
      spawnMock.mockImplementation((cmd, args, opts) =>
        MOCKED.includes(gitSubcommand(args) ?? "")
          ? Promise.resolve(OK_RESULT)
          : realSpawnCaptured(cmd, args, opts),
      );
    });

    afterEach(() => {
      spawnMock.mockReset();
      rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    /** The action of `operation` on `repository` with `args`, a working tree whose origin is `repository` made where the operation needs one. */
    function actionFor(
      operation: GitAction["operation"],
      repository: string,
      args: string[],
    ): GitAction {
      const tree = operation === "pull" || operation === "push" || operation === "fetch";
      const wd = join(scratch, "wd");
      if (tree) {
        const env = {
          ...process.env,
          GIT_CONFIG_NOSYSTEM: "1",
          GIT_CONFIG_GLOBAL: NULL_GIT_CONFIG,
        };
        const opts: ExecFileSyncOptions = {
          env,
          stdio: ["ignore", "pipe", "pipe"],
          timeout: 20_000,
        };
        execFileSync(GIT as string, ["init", "-q", wd], opts);
        execFileSync(GIT as string, ["-C", wd, "remote", "add", "origin", repository], opts);
      }
      return {
        type: "git",
        operation,
        repository,
        ...(args.length > 0 ? { args } : {}),
        ...(tree ? { working_directory: wd } : {}),
      };
    }

    /** Run `operation` on `repository` with `args` and list each step as its kind and the pins it carries. */
    async function stepsOf(
      operation: GitAction["operation"],
      repository: string,
      args: string[] = [],
    ): Promise<[string, string[]][]> {
      await injector.executeWithSecret(
        actionFor(operation, repository, args),
        new Uint8Array(Buffer.from(SECRET)),
        policy(repository),
        undefined,
      );
      return spawnMock.mock.calls.map(([, args]) => [
        args.some((a) => a.startsWith("--git-dir=")) ? "network" : "local",
        args.flatMap((a, i) => (a.includes("curloptResolve") ? [`${args[i - 1]} ${a}`] : [])),
      ]);
    }

    it.each(PLANS)(
      "%s: every network step holds exactly one pin of both judged addresses, IPv6 bracketed; every local step none",
      async (operation, plan) => {
        expect(await stepsOf(operation, "https://git.example/org/repo.git")).toEqual(
          plan.map((kind) => [kind, kind === "network" ? [PIN_443] : []]),
        );
      },
    );

    it.each(PLANS)(
      "%s: a host written with a trailing dot is pinned under both spellings, the dotted one first, on every network step; every local step none",
      async (operation, plan) => {
        expect(await stepsOf(operation, "https://git.example./org/repo.git")).toEqual(
          plan.map((kind) => [kind, kind === "network" ? [PIN_443_DOT, PIN_443] : []]),
        );
      },
    );

    it.each(PLANS)("%s: a :8443 URL pins git.example:8443", async (operation, plan) => {
      expect(await stepsOf(operation, "https://git.example:8443/org/repo.git")).toEqual(
        plan.map((kind) => [kind, kind === "network" ? [PIN_8443] : []]),
      );
    });

    it.each(PLANS)(
      "%s: an IP-literal URL, which the validator resolves to nothing, carries no pin",
      async (operation, plan) => {
        expect(await stepsOf(operation, "https://8.8.8.8/org/repo.git")).toEqual(
          plan.map((kind) => [kind, []]),
        );
      },
    );

    it.each(
      PLANS.flatMap(([operation]) =>
        ["https://-git.example/org/repo.git", "https://+git.example/org/repo.git"].map(
          (repository) => [operation, repository] as const,
        ),
      ),
    )(
      "%s: %s, a host http.curloptResolve would read as an instruction, is refused with one failed row before the validator and any spawn (K2-R2)",
      async (operation, repository) => {
        const log = vi.fn();
        const validateMock = vi.mocked(validateUrl);
        validateMock.mockClear();
        const err = await expectVaultError(
          () =>
            new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
              { type: "git", operation, repository },
              new Uint8Array(Buffer.from(SECRET)),
              policy(repository),
              undefined,
              "secret-1",
            ),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message === "HTTPS host of the repository must not begin with '-' or '+'").toBe(
          true,
        );
        expect(log.mock.calls).toEqual([
          [
            {
              eventType: "secret.use",
              secretId: "secret-1",
              detail: { context: "git", operation, error: "INVALID_GIT_CONFIG" },
              success: false,
            },
          ],
        ]);
        expect(validateMock).not.toHaveBeenCalled();
        expect(spawnMock).not.toHaveBeenCalled();
      },
    );

    it.each(IP_PLANS)(
      "%s: --ipv6 against a host the vault judged at IPv4 addresses alone is refused with one failed row before any spawn (K2-R6)",
      async (operation) => {
        DNS.gitExample = ["93.184.216.34"];
        const repository = "https://git.example/org/repo.git";
        const log = vi.fn();
        const err = await expectVaultError(
          () =>
            new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
              actionFor(operation, repository, ["--ipv6"]),
              new Uint8Array(Buffer.from(SECRET)),
              policy(repository),
              undefined,
              "secret-1",
            ),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message === "repository host has no address of the requested IP version").toBe(
          true,
        );
        expect(log.mock.calls).toEqual([
          [
            {
              eventType: "secret.use",
              secretId: "secret-1",
              detail: { context: "git", operation, error: "INVALID_GIT_CONFIG" },
              success: false,
            },
          ],
        ]);
        expect(spawnMock).not.toHaveBeenCalled();
      },
    );

    it.each(
      IP_PLANS.flatMap(([operation]) => [
        [operation, "-6", ["93.184.216.34"]] as const,
        [operation, "--ipv4", ["2606:2800:220:1::1"]] as const,
      ]),
    )(
      "%s: %s against a host the vault judged at %j alone is refused with one failed row before any spawn (K2-R6)",
      async (operation, option, addresses) => {
        DNS.gitExample = [...addresses];
        const repository = "https://git.example/org/repo.git";
        const log = vi.fn();
        const err = await expectVaultError(
          () =>
            new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
              actionFor(operation, repository, [option]),
              new Uint8Array(Buffer.from(SECRET)),
              policy(repository),
              undefined,
              "secret-1",
            ),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message === "repository host has no address of the requested IP version").toBe(
          true,
        );
        expect(log.mock.calls).toEqual([
          [
            {
              eventType: "secret.use",
              secretId: "secret-1",
              detail: { context: "git", operation, error: "INVALID_GIT_CONFIG" },
              success: false,
            },
          ],
        ]);
        expect(spawnMock).not.toHaveBeenCalled();
      },
    );

    it.each(
      IP_PLANS.flatMap(([operation, plan]) => [
        [operation, "--ipv4", ["93.184.216.34"], PIN_V4, plan] as const,
        [operation, "--ipv4", BOTH_VERSIONS, PIN_443, plan] as const,
        [operation, "--ipv6", BOTH_VERSIONS, PIN_443, plan] as const,
      ]),
    )(
      "%s: %s against a host judged at %j is dialled with the pin (K2-R6 control)",
      async (operation, option, addresses, pin, plan) => {
        DNS.gitExample = [...addresses];
        expect(await stepsOf(operation, "https://git.example/org/repo.git", [option])).toEqual(
          plan.map((kind) => [kind, kind === "network" ? [pin] : []]),
        );
        expect(
          spawnMock.mock.calls
            .filter(([, args]) => args.some((a) => a.startsWith("--git-dir=")))
            .some(([, args]) => args.includes(option)),
        ).toBe(true);
      },
    );

    it.each(["-4", "-6", "--ipv4", "--ipv6"])(
      "ls-remote refuses %s by the argument denylist, before the validator and any spawn (K2-R7)",
      async (option) => {
        const repository = "https://git.example/org/repo.git";
        const log = vi.fn();
        const validateMock = vi.mocked(validateUrl);
        validateMock.mockClear();
        const err = await expectVaultError(
          () =>
            new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
              { type: "git", operation: "ls-remote", repository, args: [option] },
              new Uint8Array(Buffer.from(SECRET)),
              policy(repository),
              undefined,
              "secret-1",
            ),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message === `disallowed git argument: ${option}`).toBe(true);
        expect(log.mock.calls).toEqual([
          [
            {
              eventType: "secret.use",
              secretId: "secret-1",
              detail: { context: "git", operation: "ls-remote", error: "INVALID_GIT_CONFIG" },
              success: false,
            },
          ],
        ]);
        expect(validateMock).not.toHaveBeenCalled();
        expect(spawnMock).not.toHaveBeenCalled();
      },
    );
  },
);

describe.skipIf(!gitAtLeast(2, 37))(
  "real git connects to the judged address (skipped where git does not resolve or is older than 2.37, which ignores http.curloptResolve)",
  () => {
    const spawnMock = vi.mocked(spawnCaptured);

    beforeEach(() => {
      spawnMock.mockReset();
      spawnMock.mockImplementation((cmd, args, opts) => realSpawnCaptured(cmd, args, opts));
    });

    afterEach(() => {
      spawnMock.mockReset();
    });

    it("an ls-remote of a name that resolves nowhere is refused at the connect to 127.0.0.1:1, not at a lookup", async () => {
      const repository = "https://harpoc-pin.invalid:1/x.git";
      const result = await new GitInjector(null).executeWithSecret(
        { type: "git", operation: "ls-remote", repository, timeout_ms: 20_000 },
        new Uint8Array(Buffer.from(SECRET)),
        policy(repository),
        undefined,
      );
      expect(result.timed_out).toBeUndefined();
      expect(result.exit_code).toBe(128);
      expect(result.stderr).toMatch(/unable to access/);
      expect(result.stderr).not.toMatch(/resolve host/i);
    });

    it("an ls-remote of a name written with a trailing dot that resolves nowhere is refused at the connect to 127.0.0.1:1, not at a lookup", async () => {
      const repository = "https://harpoc-pin.invalid.:1/x.git";
      const result = await new GitInjector(null).executeWithSecret(
        { type: "git", operation: "ls-remote", repository, timeout_ms: 20_000 },
        new Uint8Array(Buffer.from(SECRET)),
        policy(repository),
        undefined,
      );
      expect(result.timed_out).toBeUndefined();
      expect(result.exit_code).toBe(128);
      expect(result.stderr).toMatch(/unable to access/);
      expect(result.stderr).not.toMatch(/resolve host/i);
    });
  },
);
