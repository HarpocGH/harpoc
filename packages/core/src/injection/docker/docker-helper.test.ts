import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DOCKER_CREDENTIAL_HELPER_SRC } from "./docker-injector.js";

// The credential helper is the security crux: docker invokes it as a real
// subprocess (`docker-credential-harpoc get`) with the requested server URL on
// stdin. These tests run it exactly as docker would — the embedded source
// written to a temp `.mjs`, spawned through `process.execPath` — so they
// observe the helper's actual runtime behaviour, not a re-implementation.

const REGISTRY = "registry.example.com";
const USER = "robot";
const SECRET = "s3cr3t-registry-pass-value";

interface HelperRun {
  stdout: string;
  stderr: string;
  code: number | null;
}

let dir: string;
let helperFile: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "harpoc-docker-helper-test-"));
  helperFile = join(dir, "docker-credential-harpoc.mjs");
  writeFileSync(helperFile, DOCKER_CREDENTIAL_HELPER_SRC, { mode: 0o700 });
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

/**
 * Run the helper exactly as docker's credential-helper protocol does: argv is
 * `[helper, <action>]`, the requested server URL arrives on stdin. `endStdin`
 * defaults to true; a test passes `endStdin: false` to prove an action exits
 * WITHOUT reading stdin — if it tried to read, the unclosed pipe would block
 * and the test would time out.
 */
function runHelper(
  action: string,
  opts: { stdin?: string; endStdin?: boolean; env?: Record<string, string | undefined> } = {},
): Promise<HelperRun> {
  const env: Record<string, string | undefined> = {
    HARPOC_DOCKER_REGISTRY: REGISTRY,
    HARPOC_DOCKER_USER: USER,
    HARPOC_DOCKER_SECRET: SECRET,
    ...opts.env,
  };
  const cleanEnv: Record<string, string> = {};
  for (const [k, v] of Object.entries(env)) {
    if (v !== undefined) cleanEnv[k] = v;
  }
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [helperFile, action], {
      shell: false,
      env: cleanEnv,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c: Buffer) => (stdout += c.toString("utf8")));
    child.stderr.on("data", (c: Buffer) => (stderr += c.toString("utf8")));
    child.on("error", reject);
    child.on("close", (code) => resolvePromise({ stdout, stderr, code }));
    if (opts.stdin !== undefined) child.stdin.write(opts.stdin);
    if (opts.endStdin !== false) child.stdin.end();
  });
}

describe("docker credential helper (real subprocess)", () => {
  it("get for the bound registry prints the exact credential JSON and exits 0", async () => {
    const { stdout, stderr, code } = await runHelper("get", { stdin: REGISTRY });

    expect(code).toBe(0);
    expect(stderr).toBe("");
    // The exact docker credential-helper `get` response shape — key order and
    // all. This is the one path where the secret is meant to reach stdout.
    expect(stdout.trimEnd()).toBe(
      `{"Username":"${USER}","Secret":"${SECRET}","ServerURL":"${REGISTRY}"}`,
    );
    expect(JSON.parse(stdout)).toEqual({
      Username: USER,
      Secret: SECRET,
      ServerURL: REGISTRY,
    });
  });

  it("get tolerates a trailing newline on the requested server URL", async () => {
    const { stdout, code } = await runHelper("get", { stdin: `${REGISTRY}\n` });

    expect(code).toBe(0);
    expect(JSON.parse(stdout)).toMatchObject({ Secret: SECRET, ServerURL: REGISTRY });
  });

  it("get matches the bound registry case-insensitively", async () => {
    const { stdout, code } = await runHelper("get", { stdin: REGISTRY.toUpperCase() });

    expect(code).toBe(0);
    expect(JSON.parse(stdout)).toMatchObject({ Secret: SECRET });
  });

  it("get for a FOREIGN host prints docker's miss signal, exits 1, and leaks NO secret bytes", async () => {
    const { stdout, stderr, code } = await runHelper("get", { stdin: "evil.example.com" });

    expect(code).toBe(1);
    // docker's recognized "no credentials" signal — treated as anonymous, not
    // a hard error, so a foreign registry simply gets no credential.
    expect(stdout.trimEnd()).toBe("credentials not found in native keychain");
    // The crux assertion: the bound secret never reaches ANY output channel for
    // a host the vault did not bind the credential to.
    expect(stdout).not.toContain(SECRET);
    expect(stderr).not.toContain(SECRET);
    expect(stdout).not.toContain(USER);
  });

  it("get fails closed (miss) when no registry is bound", async () => {
    const { stdout, code } = await runHelper("get", {
      stdin: REGISTRY,
      env: { HARPOC_DOCKER_REGISTRY: "" },
    });

    expect(code).toBe(1);
    expect(stdout.trimEnd()).toBe("credentials not found in native keychain");
    expect(stdout).not.toContain(SECRET);
  });

  it("store exits 1 immediately WITHOUT reading stdin", async () => {
    // stdin is deliberately left open. A helper that tried to read it would
    // block on the unclosed pipe and this test would time out; a prompt exit
    // proves store never touches stdin (so it can never persist a credential).
    const { stdout, code } = await runHelper("store", { endStdin: false });

    expect(code).toBe(1);
    expect(stdout).not.toContain(SECRET);
  });

  it("erase exits 1 immediately WITHOUT reading stdin", async () => {
    const { stdout, code } = await runHelper("erase", { endStdin: false });

    expect(code).toBe(1);
    expect(stdout).not.toContain(SECRET);
  });

  it("list exits 1 immediately WITHOUT reading stdin", async () => {
    const { stdout, code } = await runHelper("list", { endStdin: false });

    expect(code).toBe(1);
    expect(stdout).not.toContain(SECRET);
  });
});
