import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildSshEnv } from "./ssh-common.js";
import { buildCleanEnv } from "./clean-env.js";

/**
 * T14: §4.5.3 layer 3 (a child inherits nothing but PATH, the credential and
 * the explicitly allowlisted variables) is double-pinned for the process
 * context and asserted nowhere for Git and SSH — replacing either initializer's
 * body with `{ ...process.env }` kept the suite green, while handing every
 * ambient variable of the vault process (proxy settings, tokens exported by the
 * operator's shell, `GIT_*`/`SSH_*` overrides) to the spawned binary.
 */

const AMBIENT = {
  HARPOC_T14_AMBIENT_TOKEN: "ambient-secret-value",
  HARPOC_T14_ALLOWED: "allowed-value",
  GIT_SSH_COMMAND: "ssh -o ProxyCommand=curl-evil",
  SSH_AUTH_SOCK: "/tmp/attacker-agent.sock",
  LD_PRELOAD: "/tmp/evil.so",
} as const;

beforeEach(() => {
  for (const [name, value] of Object.entries(AMBIENT)) process.env[name] = value;
});

afterEach(() => {
  for (const name of Object.keys(AMBIENT)) Reflect.deleteProperty(process.env, name);
});

describe("SSH child environment is built, not inherited (T14)", () => {
  it("carries only the agent socket, PATH and the allowlist", () => {
    const env = buildSshEnv("/tmp/harpoc-agent.sock", []);

    expect(env.SSH_AUTH_SOCK).toBe("/tmp/harpoc-agent.sock");
    expect(env.HARPOC_T14_AMBIENT_TOKEN).toBeUndefined();
    expect(env.LD_PRELOAD).toBeUndefined();
    expect(env.GIT_SSH_COMMAND).toBeUndefined();

    const allowedKeys = new Set(["PATH", "SSH_AUTH_SOCK", "SystemRoot", "ProgramData"]);
    expect(Object.keys(env).filter((k) => !allowedKeys.has(k))).toEqual([]);
  });

  it("the vault's agent socket wins over an ambient SSH_AUTH_SOCK", () => {
    const env = buildSshEnv("/tmp/harpoc-agent.sock", ["SSH_AUTH_SOCK"]);
    expect(env.SSH_AUTH_SOCK).toBe("/tmp/harpoc-agent.sock");
  });

  it("control: an explicitly allowlisted variable is passed through", () => {
    const env = buildSshEnv("/tmp/harpoc-agent.sock", ["HARPOC_T14_ALLOWED"]);
    expect(env.HARPOC_T14_ALLOWED).toBe("allowed-value");
    expect(env.HARPOC_T14_AMBIENT_TOKEN).toBeUndefined();
  });

  it("keeps PATH so the pinned binary's dependencies resolve", () => {
    const env = buildSshEnv("/tmp/harpoc-agent.sock", []);
    expect(env.PATH).toBeTruthy();
  });

  it.runIf(process.platform === "win32")(
    "passes ProgramData and SystemRoot on Windows (Win32-OpenSSH needs both)",
    () => {
      const env = buildSshEnv("\\\\.\\pipe\\harpoc", []);
      expect(env.SystemRoot).toBeTruthy();
      expect(env.ProgramData).toBeTruthy();
    },
  );
});

describe("process/MCP child environment (T14 control group)", () => {
  it("buildCleanEnv drops ambient variables the same way", () => {
    const env = buildCleanEnv("TOKEN", "value", []);
    expect(env.TOKEN).toBe("value");
    expect(env.HARPOC_T14_AMBIENT_TOKEN).toBeUndefined();
    expect(Object.keys(env).filter((k) => k !== "PATH" && k !== "TOKEN")).toEqual([]);
  });

  it("an allowlist entry cannot shadow the injected credential", () => {
    process.env.TOKEN = "ambient-token";
    try {
      const env = buildCleanEnv("TOKEN", "vault-value", ["TOKEN"]);
      expect(env.TOKEN).toBe("vault-value");
    } finally {
      delete process.env.TOKEN;
    }
  });
});
