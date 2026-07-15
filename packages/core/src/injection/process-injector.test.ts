import { afterEach, describe, expect, it, vi } from "vitest";
import type { ProcessAction, ProcessResult } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { forceNetworkIsolationUnavailableForTests } from "./network-isolation.js";
import { ProcessInjector } from "./process-injector.js";

const NODE = process.execPath;
const SECRET = "sk-supersecret-abcdef123456";

const injector = new ProcessInjector(null);

function nodeAction(script: string, overrides: Partial<ProcessAction> = {}): ProcessAction {
  return {
    type: "process",
    command: NODE,
    args: ["-e", script],
    env_var: "SECRET",
    ...overrides,
  };
}

function run(
  action: ProcessAction,
  policy: { command_allowlist: string[]; env_allowlist: string[] } = {
    command_allowlist: [NODE],
    env_allowlist: [],
  },
  secret = SECRET,
): Promise<ProcessResult> {
  return injector.executeWithSecret(action, new Uint8Array(Buffer.from(secret, "utf8")), policy);
}

describe("ProcessInjector — env injection & output", () => {
  it("injects the credential as an environment variable", async () => {
    // Child writes a marker proving the env var is set (without echoing the value).
    const result = await run(
      nodeAction(`process.stdout.write(process.env.SECRET ? "SET" : "UNSET")`),
    );
    expect(result.type).toBe("process");
    expect(result.exit_code).toBe(0);
    expect(result.stdout).toBe("SET");
  });

  it("captures stdout and returns the exit code", async () => {
    const result = await run(nodeAction(`process.stdout.write("hello"); process.exit(3)`));
    expect(result.stdout).toBe("hello");
    expect(result.exit_code).toBe(3);
  });

  it("captures stderr", async () => {
    const result = await run(nodeAction(`process.stderr.write("oops")`));
    expect(result.stderr).toBe("oops");
  });
});

describe("ProcessInjector — output sanitization", () => {
  it("redacts the raw credential echoed to stdout", async () => {
    const result = await run(nodeAction(`process.stdout.write(process.env.SECRET)`));
    expect(result.stdout).not.toContain(SECRET);
    expect(result.stdout).toContain("[REDACTED]");
  });

  it("redacts a base64-encoded echo of the exact value (raises to L3)", async () => {
    const result = await run(
      nodeAction(`process.stdout.write(Buffer.from(process.env.SECRET).toString("base64"))`),
    );
    const b64 = Buffer.from(SECRET, "utf8").toString("base64");
    expect(result.stdout).not.toContain(b64);
    expect(result.stdout).toContain("[REDACTED]");
  });
});

describe("ProcessInjector — no shell (L2/L3 separation)", () => {
  it("passes args as data, never through a shell", async () => {
    // If a shell ran, $(...) would expand. With shell:false it stays literal.
    const result = await run(
      nodeAction(`process.stdout.write(process.argv[process.argv.length - 1])`, {
        args: [
          "-e",
          `process.stdout.write(process.argv[process.argv.length - 1])`,
          "$(echo pwned)",
        ],
      }),
    );
    expect(result.stdout).toBe("$(echo pwned)");
  });
});

describe("ProcessInjector — clean environment", () => {
  const MARKER = "HARPOC_LEAK_MARKER";

  afterEach(() => {
    Reflect.deleteProperty(process.env, MARKER);
  });

  it("does not inherit non-allowlisted vault environment variables", async () => {
    process.env[MARKER] = "LEAKED";
    const result = await run(
      nodeAction(`process.stdout.write(process.env.${MARKER} ? "PRESENT" : "ABSENT")`),
    );
    expect(result.stdout).toBe("ABSENT");
  });

  it("passes through allowlisted environment variables", async () => {
    process.env[MARKER] = "OK";
    const result = await run(
      nodeAction(`process.stdout.write(process.env.${MARKER} || "ABSENT")`),
      { command_allowlist: [NODE], env_allowlist: [MARKER] },
    );
    expect(result.stdout).toBe("OK");
  });

  it("always provides PATH for command resolution", async () => {
    const result = await run(
      nodeAction(`process.stdout.write(process.env.PATH ? "HASPATH" : "NOPATH")`),
    );
    expect(result.stdout).toBe("HASPATH");
  });
});

describe("ProcessInjector — command allowlist", () => {
  it("denies by default when the allowlist is empty", async () => {
    await expect(
      run(nodeAction(`process.stdout.write("x")`), { command_allowlist: [], env_allowlist: [] }),
    ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });
  });

  it("denies a command not in the allowlist", async () => {
    await expect(
      run(nodeAction(`process.stdout.write("x")`), {
        command_allowlist: ["some-other-binary"],
        env_allowlist: [],
      }),
    ).rejects.toBeInstanceOf(VaultError);
  });
});

describe("ProcessInjector — resource bounds", () => {
  it("kills a process that exceeds the timeout", async () => {
    const result = await run(nodeAction(`setTimeout(() => {}, 60000)`, { timeout_ms: 200 }));
    expect(result.timed_out).toBe(true);
    expect(result.error).toBe(ErrorCode.PROCESS_TIMEOUT);
    expect(result.exit_code).toBeNull();
  });

  it("truncates output that exceeds the cap", async () => {
    const result = await run(
      nodeAction(`process.stdout.write(Buffer.alloc(1200000, 65).toString())`),
    );
    expect(result.truncated).toBe(true);
  });
});

describe("ProcessInjector — config validation", () => {
  it("rejects a non-existent working_directory", async () => {
    await expect(
      run(nodeAction(`process.stdout.write("x")`, { working_directory: "/no/such/dir/xyz123" })),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_PROCESS_CONFIG });
  });
});

describe("ProcessInjector — network isolation (§4.5.3 layer 4)", () => {
  afterEach(() => forceNetworkIsolationUnavailableForTests(null));

  it("refuses fail-closed and audits when the platform cannot deliver isolation", async () => {
    forceNetworkIsolationUnavailableForTests("forced for test");
    const log = vi.fn();
    const audited = new ProcessInjector({ log } as unknown as AuditLogger);
    await expect(
      audited.executeWithSecret(
        nodeAction(`process.stdout.write("ran")`),
        new Uint8Array(Buffer.from(SECRET, "utf8")),
        { command_allowlist: [NODE], env_allowlist: [], network_isolation: true },
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE });
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: "secret.use",
        success: false,
        detail: expect.objectContaining({
          error: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE,
          network_isolation: true,
        }),
      }),
    );
  });

  it("audits network_isolation: false on an ordinary spawn", async () => {
    const log = vi.fn();
    const audited = new ProcessInjector({ log } as unknown as AuditLogger);
    const result = await audited.executeWithSecret(
      nodeAction(`process.exit(0)`),
      new Uint8Array(Buffer.from(SECRET, "utf8")),
      { command_allowlist: [NODE], env_allowlist: [] },
      "secret-1",
    );
    expect(result.exit_code).toBe(0);
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        detail: expect.objectContaining({ network_isolation: false }),
      }),
    );
  });
});
