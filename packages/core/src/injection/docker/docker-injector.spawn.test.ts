import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DockerRegistryAction, InjectionPolicy } from "@harpoc/shared";
import { VaultError, ErrorCode } from "@harpoc/shared";
import { spawnCaptured } from "../spawn-captured.js";
import type { SpawnCapturedOptions, SpawnCapturedResult } from "../spawn-captured.js";
import { executeDockerRegistryAction } from "./docker-injector.js";

vi.mock("../spawn-captured.js", () => ({ spawnCaptured: vi.fn() }));

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
    fs_isolation: false,
    ...overrides,
  };
}

const PULL_ACTION: DockerRegistryAction = {
  type: "docker_registry",
  operation: "pull",
  image: "registry.example.com/app:1.0",
  timeout_ms: 300_000,
};

const SECRET = new Uint8Array(Buffer.from("robot:s3cr3t-registry-pass-value"));

let binDir: string;
let dockerPath: string;
let savedPath: string | undefined;

beforeEach(() => {
  vi.mocked(spawnCaptured).mockReset();
  vi.mocked(spawnCaptured).mockResolvedValue(OK_RESULT);
  binDir = mkdtempSync(join(tmpdir(), "harpoc-docker-bin-"));
  const name = process.platform === "win32" ? "docker.exe" : "docker";
  dockerPath = join(binDir, name);
  writeFileSync(dockerPath, "", { mode: 0o755 });
  savedPath = process.env.PATH;
  process.env.PATH = binDir + delimiter + (savedPath ?? "");
});

afterEach(() => {
  if (savedPath === undefined) delete process.env.PATH;
  else process.env.PATH = savedPath;
  rmSync(binDir, { recursive: true, force: true });
});

function allowed(overrides: Partial<InjectionPolicy> = {}): InjectionPolicy {
  return policy({
    host_allowlist: ["registry.example.com"],
    command_allowlist: [dockerPath],
    ...overrides,
  });
}

type SpawnCall = [string, string[], SpawnCapturedOptions];

/** The helper dir is prepended to PATH so docker resolves docker-credential-harpoc. */
function helperDirFrom(env: Record<string, string>): string {
  return (env.PATH ?? "").split(delimiter)[0] as string;
}

describe("executeDockerRegistryAction spawn shape", () => {
  it("spawns the pinned docker binary with argv [docker, operation, image] and no shell", async () => {
    await executeDockerRegistryAction(PULL_ACTION, SECRET, allowed());

    expect(spawnCaptured).toHaveBeenCalledOnce();
    const [command, args] = vi.mocked(spawnCaptured).mock.calls[0] as SpawnCall;
    expect(command).toBe(dockerPath);
    expect(args).toEqual(["pull", "registry.example.com/app:1.0"]);
  });

  it("spawns with argv [docker, push, image] for a push", async () => {
    await executeDockerRegistryAction({ ...PULL_ACTION, operation: "push" }, SECRET, allowed());

    const [, args] = vi.mocked(spawnCaptured).mock.calls[0] as SpawnCall;
    expect(args).toEqual(["push", "registry.example.com/app:1.0"]);
  });

  it("passes DOCKER_CONFIG, the three HARPOC_DOCKER_* vars via env — never argv", async () => {
    await executeDockerRegistryAction(PULL_ACTION, SECRET, allowed());

    const [, args, opts] = vi.mocked(spawnCaptured).mock.calls[0] as SpawnCall;
    expect(opts.env.DOCKER_CONFIG).toBeTruthy();
    expect(opts.env.HARPOC_DOCKER_REGISTRY).toBe("registry.example.com");
    expect(opts.env.HARPOC_DOCKER_USER).toBe("robot");
    expect(opts.env.HARPOC_DOCKER_SECRET).toBe("s3cr3t-registry-pass-value");
    // The credential travels via env only — never on argv.
    expect(args.join(" ")).not.toContain("s3cr3t-registry-pass-value");
    expect(args.join(" ")).not.toContain("robot");
  });

  it("prepends the credential-helper dir to PATH", async () => {
    await executeDockerRegistryAction(PULL_ACTION, SECRET, allowed());

    const [, , opts] = vi.mocked(spawnCaptured).mock.calls[0] as SpawnCall;
    const helperDir = helperDirFrom(opts.env);
    expect(helperDir.length).toBeGreaterThan(0);
    // The helper dir sits ahead of the inherited PATH so docker finds
    // docker-credential-harpoc there first.
    expect(opts.env.PATH?.startsWith(helperDir + delimiter)).toBe(true);
  });

  it("registers the credential from the value's password half, redacted from output", async () => {
    const [, , opts] = await (async () => {
      await executeDockerRegistryAction(PULL_ACTION, SECRET, allowed());
      return vi.mocked(spawnCaptured).mock.calls[0] as SpawnCall;
    })();
    expect(opts.redact).toContain("s3cr3t-registry-pass-value");
  });

  it("writes the golden config.json — exactly credHelpers, NEVER an auths key", async () => {
    let raw = "";
    let parsed: Record<string, unknown> = {};
    vi.mocked(spawnCaptured).mockImplementation((_cmd, _args, opts) => {
      raw = readFileSync(join(opts.env.DOCKER_CONFIG as string, "config.json"), "utf8");
      parsed = JSON.parse(raw) as Record<string, unknown>;
      return Promise.resolve(OK_RESULT);
    });

    await executeDockerRegistryAction(PULL_ACTION, SECRET, allowed());

    expect(raw).toBe('{"credHelpers":{"registry.example.com":"harpoc"}}');
    // Security assertion: an `auths` entry would embed a base64 credential in
    // the file. There must be none — the credential lives only in the helper's
    // env, served on demand.
    expect(parsed).not.toHaveProperty("auths");
    expect(raw).not.toContain("auths");
    expect(parsed).toEqual({ credHelpers: { "registry.example.com": "harpoc" } });
  });

  it("keys credHelpers by the default registry for a bare image", async () => {
    let raw = "";
    vi.mocked(spawnCaptured).mockImplementation((_cmd, _args, opts) => {
      raw = readFileSync(join(opts.env.DOCKER_CONFIG as string, "config.json"), "utf8");
      return Promise.resolve(OK_RESULT);
    });

    await executeDockerRegistryAction(
      { ...PULL_ACTION, image: "nginx:latest" },
      SECRET,
      allowed({ host_allowlist: ["registry-1.docker.io"] }),
    );

    expect(raw).toBe('{"credHelpers":{"registry-1.docker.io":"harpoc"}}');
    expect(raw).not.toContain("auths");
  });

  it("does NOT wire network/fs isolation into the docker spawn (refused at the engine, not here)", async () => {
    await executeDockerRegistryAction(
      PULL_ACTION,
      SECRET,
      allowed({ network_isolation: true, fs_isolation: true }),
    );

    const [, , opts] = vi.mocked(spawnCaptured).mock.calls[0] as SpawnCall;
    // The docker×isolation refusal is architectural and lives at the engine,
    // before dispatch. The injector must never itself ask the spawn seam to
    // isolate — that would isolate the CLI messenger, not the daemon actor.
    expect(opts.networkIsolation).toBeUndefined();
    expect(opts.fsIsolation).toBeUndefined();
  });

  it("disposes BOTH temp dirs (DOCKER_CONFIG + helper) after a successful invocation", async () => {
    let configDir = "";
    let helperDir = "";
    vi.mocked(spawnCaptured).mockImplementation((_cmd, _args, opts) => {
      configDir = opts.env.DOCKER_CONFIG as string;
      helperDir = helperDirFrom(opts.env);
      expect(existsSync(configDir)).toBe(true);
      expect(existsSync(helperDir)).toBe(true);
      return Promise.resolve(OK_RESULT);
    });

    await executeDockerRegistryAction(PULL_ACTION, SECRET, allowed());

    expect(existsSync(configDir)).toBe(false);
    expect(existsSync(helperDir)).toBe(false);
  });

  it("disposes BOTH temp dirs even when the spawn seam throws (finally on the throw path)", async () => {
    let configDir = "";
    let helperDir = "";
    vi.mocked(spawnCaptured).mockImplementation((_cmd, _args, opts) => {
      configDir = opts.env.DOCKER_CONFIG as string;
      helperDir = helperDirFrom(opts.env);
      return Promise.reject(new Error("spawn boom"));
    });

    await expect(executeDockerRegistryAction(PULL_ACTION, SECRET, allowed())).rejects.toThrow(
      "spawn boom",
    );

    expect(configDir.length).toBeGreaterThan(0);
    expect(helperDir.length).toBeGreaterThan(0);
    expect(existsSync(configDir)).toBe(false);
    expect(existsSync(helperDir)).toBe(false);
  });

  it("disposes both temp dirs even when the operation fails (non-zero exit)", async () => {
    let configDir = "";
    let helperDir = "";
    vi.mocked(spawnCaptured).mockImplementation((_cmd, _args, opts) => {
      configDir = opts.env.DOCKER_CONFIG as string;
      helperDir = helperDirFrom(opts.env);
      return Promise.resolve({ ...OK_RESULT, exit_code: 7 });
    });

    await expect(executeDockerRegistryAction(PULL_ACTION, SECRET, allowed())).rejects.toMatchObject(
      { code: ErrorCode.DOCKER_OPERATION_FAILED },
    );

    expect(existsSync(configDir)).toBe(false);
    expect(existsSync(helperDir)).toBe(false);
  });

  it("passes the docker timeout_ms straight through to the spawn seam (up to the raised cap)", async () => {
    await executeDockerRegistryAction({ ...PULL_ACTION, timeout_ms: 1_800_000 }, SECRET, allowed());

    const [, , opts] = vi.mocked(spawnCaptured).mock.calls[0] as SpawnCall;
    expect(opts.timeoutMs).toBe(1_800_000);
  });

  it("writes an executable credential-helper launcher docker can resolve by name", async () => {
    let helperDir = "";
    vi.mocked(spawnCaptured).mockImplementation((_cmd, _args, opts) => {
      helperDir = helperDirFrom(opts.env);
      const launcherName =
        process.platform === "win32" ? "docker-credential-harpoc.cmd" : "docker-credential-harpoc";
      expect(existsSync(join(helperDir, launcherName))).toBe(true);
      return Promise.resolve(OK_RESULT);
    });

    await executeDockerRegistryAction(PULL_ACTION, SECRET, allowed());
    expect(helperDir.length).toBeGreaterThan(0);
  });
});

// A guard against a regression that would drop the redaction wrapper entirely.
it("surfaces a redacted VaultError, not a raw one, when the spawn rejects with the secret", async () => {
  const err = new VaultError(
    ErrorCode.DOCKER_OPERATION_FAILED,
    "daemon said s3cr3t-registry-pass-value",
  );
  vi.mocked(spawnCaptured).mockRejectedValue(err);

  const thrown = (await executeDockerRegistryAction(PULL_ACTION, SECRET, allowed()).catch(
    (e: unknown) => e,
  )) as VaultError;

  expect(thrown).toBeInstanceOf(VaultError);
  expect(thrown.message).not.toContain("s3cr3t-registry-pass-value");
});
