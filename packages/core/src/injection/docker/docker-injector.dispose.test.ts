import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DockerRegistryAction, InjectionPolicy } from "@harpoc/shared";
import { executeDockerRegistryAction } from "./docker-injector.js";

// The credential-helper dir is created by the SECOND `mkdtempSync` in
// `runDocker` (the DOCKER_CONFIG dir is the first). Fail only that second call
// so `writeCredentialHelper()` throws AFTER `writeDockerConfig()` created a real
// tmpdir — the exact ordering FIX 2 protects: config must dispose even when the
// helper write fails before the `try`. Config dirs the real `mkdtempSync`
// handed out are recorded so the test can prove they were removed.
const state = vi.hoisted(() => ({ configDirs: [] as string[] }));

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    mkdtempSync: ((prefix: string) => {
      const p = String(prefix);
      if (p.includes("harpoc-docker-helper-")) {
        throw new Error("mkdtemp helper boom");
      }
      const dir = actual.mkdtempSync(prefix);
      if (p.includes("harpoc-docker-config-")) state.configDirs.push(dir);
      return dir;
    }) as typeof actual.mkdtempSync,
  };
});

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
  state.configDirs.length = 0;
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

describe("executeDockerRegistryAction — config dir disposal when the helper write throws", () => {
  it("disposes the DOCKER_CONFIG tmpdir even though writeCredentialHelper() throws before the try", async () => {
    await expect(executeDockerRegistryAction(PULL_ACTION, SECRET, allowed())).rejects.toThrow(
      "mkdtemp helper boom",
    );

    // The config dir was created before the helper write threw...
    expect(state.configDirs).toHaveLength(1);
    const configDir = state.configDirs[0] as string;
    // ...and must not leak: FIX 2 moves the helper write inside the try, so the
    // finally disposes config on this pre-try throw path too.
    expect(existsSync(configDir)).toBe(false);
  });
});
