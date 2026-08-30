import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DockerRegistryAction, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode, VaultError, dockerRegistryActionSchema, sshActionSchema } from "@harpoc/shared";
import { spawnCaptured } from "../spawn-captured.js";
import type { SpawnCapturedResult } from "../spawn-captured.js";
import {
  buildDockerAuditDetails,
  executeDockerRegistryAction,
  parseImageReference,
} from "./docker-injector.js";

vi.mock("../spawn-captured.js", () => ({ spawnCaptured: vi.fn() }));

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
    smtp_recipient_allowlist: [],
    imap_read_only: false,
    ...overrides,
  };
}

const PULL_ACTION: DockerRegistryAction = {
  type: "docker_registry",
  operation: "pull",
  image: "registry.example.com/app:1.0",
  timeout_ms: 300_000,
};

// A fake `docker` binary on a temp PATH: it lets the command-allowlist
// resolution succeed on any host (docker need not be installed), while the
// mocked spawn seam guarantees it never actually runs.
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

const SECRET = new Uint8Array(Buffer.from("robot:s3cr3t-registry-pass-value"));

describe("executeDockerRegistryAction enforcement", () => {
  it("denies by default when the host allowlist is empty (fail-safe deny)", async () => {
    await expect(
      executeDockerRegistryAction(PULL_ACTION, SECRET, policy({ command_allowlist: [dockerPath] })),
    ).rejects.toMatchObject({ code: ErrorCode.HOST_NOT_ALLOWED });
    expect(spawnCaptured).not.toHaveBeenCalled();
  });

  it("denies a registry outside the allowlist", async () => {
    await expect(
      executeDockerRegistryAction(
        PULL_ACTION,
        SECRET,
        allowed({ host_allowlist: ["other-registry.example.com"] }),
      ),
    ).rejects.toMatchObject({ code: ErrorCode.HOST_NOT_ALLOWED });
    expect(spawnCaptured).not.toHaveBeenCalled();
  });

  it("requires the docker binary to be command-allowlisted (fail-safe deny)", async () => {
    await expect(
      executeDockerRegistryAction(
        PULL_ACTION,
        SECRET,
        policy({ host_allowlist: ["registry.example.com"] }),
      ),
    ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });
    expect(spawnCaptured).not.toHaveBeenCalled();
  });

  it("requires the default Docker Hub registry in the allowlist for a bare image (fail-safe)", async () => {
    // parseImageReference defaults a registry-less reference to
    // registry-1.docker.io — and that default host must still be present in
    // host_allowlist, so a bare image is not implicitly trusted.
    await expect(
      executeDockerRegistryAction(
        { ...PULL_ACTION, image: "library/nginx:latest" },
        SECRET,
        allowed(),
      ),
    ).rejects.toMatchObject({ code: ErrorCode.HOST_NOT_ALLOWED });
    expect(spawnCaptured).not.toHaveBeenCalled();
  });

  it("admits a bare image once its default registry is allowlisted", async () => {
    await executeDockerRegistryAction(
      { ...PULL_ACTION, image: "library/nginx:latest" },
      SECRET,
      allowed({ host_allowlist: ["registry-1.docker.io"] }),
    );
    expect(spawnCaptured).toHaveBeenCalledOnce();
  });

  it("refuses an image reference starting with '-' before any spawn (argv option smuggling)", async () => {
    await expect(
      executeDockerRegistryAction({ ...PULL_ACTION, image: "-oEvil" }, SECRET, allowed()),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_INPUT });
    expect(spawnCaptured).not.toHaveBeenCalled();
  });
});

describe("executeDockerRegistryAction result mapping", () => {
  it("returns a process-shaped success envelope on exit 0", async () => {
    vi.mocked(spawnCaptured).mockResolvedValue({
      ...OK_RESULT,
      stdout: "Pulled\n",
    });

    const result = await executeDockerRegistryAction(PULL_ACTION, SECRET, allowed());

    expect(result.result).toEqual({
      type: "docker_registry",
      operation: "pull",
      exit_code: 0,
      stdout: "Pulled\n",
      stderr: "",
      timed_out: undefined,
      truncated: undefined,
      signal: undefined,
      error: undefined,
    });
    expect(result.sanitized).toBe(false);
  });

  it("reports sanitized when the spawn seam's redaction changed the captured output", async () => {
    vi.mocked(spawnCaptured).mockResolvedValue({ ...OK_RESULT, redacted: true });

    const result = await executeDockerRegistryAction(PULL_ACTION, SECRET, allowed());

    expect(result.sanitized).toBe(true);
    // The flag rides the execution envelope only — the wire result is untouched.
    expect(result.result).not.toHaveProperty("sanitized");
  });

  it("maps a non-zero docker exit to DOCKER_OPERATION_FAILED", async () => {
    vi.mocked(spawnCaptured).mockResolvedValue({
      ...OK_RESULT,
      exit_code: 1,
      stderr: "manifest unknown",
    });

    await expect(executeDockerRegistryAction(PULL_ACTION, SECRET, allowed())).rejects.toMatchObject(
      { code: ErrorCode.DOCKER_OPERATION_FAILED },
    );
  });

  it("maps a spawn failure to DOCKER_OPERATION_FAILED", async () => {
    vi.mocked(spawnCaptured).mockResolvedValue({
      ...OK_RESULT,
      exit_code: null,
      spawn_failed: true,
    });

    await expect(executeDockerRegistryAction(PULL_ACTION, SECRET, allowed())).rejects.toMatchObject(
      { code: ErrorCode.DOCKER_OPERATION_FAILED },
    );
  });

  it("returns a graceful PROCESS_TIMEOUT result (not a throw) on timeout", async () => {
    vi.mocked(spawnCaptured).mockResolvedValue({
      ...OK_RESULT,
      exit_code: null,
      timed_out: true,
      signal: "SIGKILL",
    });

    const result = await executeDockerRegistryAction(PULL_ACTION, SECRET, allowed());

    expect(result.result).toMatchObject({
      type: "docker_registry",
      operation: "pull",
      timed_out: true,
      error: ErrorCode.PROCESS_TIMEOUT,
    });
  });

  it("redacts the credential from any thrown VaultError message (defense in depth)", async () => {
    // A driver/daemon message could quote the injected secret; every throw out
    // of the injector passes redactErrorMessage.
    vi.mocked(spawnCaptured).mockRejectedValue(
      new VaultError(ErrorCode.DOCKER_OPERATION_FAILED, "boom s3cr3t-registry-pass-value boom"),
    );

    const err = (await executeDockerRegistryAction(PULL_ACTION, SECRET, allowed()).catch(
      (e: unknown) => e,
    )) as VaultError;

    expect(err.message).not.toContain("s3cr3t-registry-pass-value");
  });

  it("redacts a username at the shared floor (MIN_REDACTABLE_FRAGMENT)", async () => {
    await executeDockerRegistryAction(
      PULL_ACTION,
      new Uint8Array(Buffer.from("abc:s3cr3t-registry-pass-value")),
      allowed(),
    );

    const opts = vi.mocked(spawnCaptured).mock.calls[0]?.[2];
    expect(opts?.redact).toContain("s3cr3t-registry-pass-value");
    expect(opts?.redact).toContain("abc");
  });

  it("leaves a 1-2 char username out of the redaction set (would shred output)", async () => {
    await executeDockerRegistryAction(
      PULL_ACTION,
      new Uint8Array(Buffer.from("ab:s3cr3t-registry-pass-value")),
      allowed(),
    );

    const opts = vi.mocked(spawnCaptured).mock.calls[0]?.[2];
    expect(opts?.redact).toContain("s3cr3t-registry-pass-value");
    expect(opts?.redact).not.toContain("ab");
  });
});

describe("parseImageReference", () => {
  it("extracts a registry host from a fully qualified reference", () => {
    expect(parseImageReference("registry.example.com/team/app:1.0")).toEqual({
      registry: "registry.example.com",
      repository: "team/app:1.0",
    });
  });

  it("keeps a host:port registry authority intact", () => {
    expect(parseImageReference("localhost:5000/app:dev")).toEqual({
      registry: "localhost:5000",
      repository: "app:dev",
    });
  });

  it("defaults a registry-less reference to registry-1.docker.io", () => {
    expect(parseImageReference("nginx:latest")).toEqual({
      registry: "registry-1.docker.io",
      repository: "nginx:latest",
    });
  });

  it("treats a user/repo first segment (no dot/colon) as Docker Hub, not a registry", () => {
    expect(parseImageReference("myuser/myapp:1.0")).toEqual({
      registry: "registry-1.docker.io",
      repository: "myuser/myapp:1.0",
    });
  });

  it("recognizes localhost as a registry host", () => {
    expect(parseImageReference("localhost/app")).toEqual({
      registry: "localhost",
      repository: "app",
    });
  });
});

describe("buildDockerAuditDetails", () => {
  it("names registry (parsed), image and operation (spec §7.2)", () => {
    expect(buildDockerAuditDetails(PULL_ACTION)).toEqual({
      registry: "registry.example.com",
      image: "registry.example.com/app:1.0",
      operation: "pull",
    });
  });

  it("reports the default registry for a bare image", () => {
    expect(
      buildDockerAuditDetails({ ...PULL_ACTION, operation: "push", image: "nginx:latest" }),
    ).toEqual({
      registry: "registry-1.docker.io",
      image: "nginx:latest",
      operation: "push",
    });
  });
});

describe("timeout_ms cap cross-check", () => {
  it("accepts timeout_ms up to 1_800_000 for a docker_registry action", () => {
    const parsed = dockerRegistryActionSchema.safeParse({
      type: "docker_registry",
      operation: "pull",
      image: "registry.example.com/app:1.0",
      timeout_ms: 1_800_000,
    });
    expect(parsed.success).toBe(true);
  });

  it("rejects timeout_ms at 300_001 for an ssh action (the 5-minute norm)", () => {
    const parsed = sshActionSchema.safeParse({
      type: "ssh",
      host: "host.example.com",
      user: "deploy",
      command: "uptime",
      timeout_ms: 300_001,
    });
    expect(parsed.success).toBe(false);
  });
});
