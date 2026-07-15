import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType } from "@harpoc/shared";
import { Command } from "commander";
import { createEngine, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { registerOAuthConnectCommand } from "./connect.js";

// Mock argon2 for speed (same approach as core/oauth-proxy tests)
vi.mock("argon2", () => ({
  hash: async (password: Buffer | string, opts: { salt: Buffer | Uint8Array }) => {
    const { createHash } = await import("node:crypto");
    const salt = opts.salt instanceof Uint8Array ? Buffer.from(opts.salt) : opts.salt;
    return createHash("sha256")
      .update(typeof password === "string" ? password : Buffer.from(password))
      .update(salt)
      .digest();
  },
}));

// Only defaultOpenBrowser is replaced (F9 tests); everything else stays real.
const openBrowserMock = vi.hoisted(() => vi.fn());
vi.mock("@harpoc/oauth-proxy", async (importOriginal) => {
  const original = await importOriginal<typeof import("@harpoc/oauth-proxy")>();
  return { ...original, defaultOpenBrowser: openBrowserMock };
});

let tempDir: string;
let tokenServer: Server;
let tokenServerUrl: string;
let tokenHandler: (req: IncomingMessage, res: ServerResponse) => void;
let deviceServer: Server;
let deviceServerUrl: string;
let deviceHandler: (req: IncomingMessage, res: ServerResponse) => void;

beforeAll(async () => {
  tokenServer = createServer((req, res) => {
    tokenHandler(req, res);
  });
  await new Promise<void>((resolve) => {
    tokenServer.listen(0, "127.0.0.1", () => resolve());
  });
  const tokenAddr = tokenServer.address() as { port: number };
  tokenServerUrl = `http://127.0.0.1:${tokenAddr.port}`;

  deviceServer = createServer((req, res) => {
    deviceHandler(req, res);
  });
  await new Promise<void>((resolve) => {
    deviceServer.listen(0, "127.0.0.1", () => resolve());
  });
  const deviceAddr = deviceServer.address() as { port: number };
  deviceServerUrl = `http://127.0.0.1:${deviceAddr.port}`;

  tempDir = join(tmpdir(), `harpoc-oauth-e2e-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  const engine = createEngine(tempDir);
  await engine.initVault("password-e2e-123");
  await engine.destroy();
});

afterAll(() => {
  tokenServer.close();
  deviceServer.close();
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

async function run(args: string[]): Promise<void> {
  const program = new Command();
  program.option("--vault-dir <path>", "Path to vault directory");
  const oauth = program.command("oauth").description("OAuth");
  registerOAuthConnectCommand(oauth);
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  await program.parseAsync(["node", "harpoc", "--vault-dir", tempDir, "oauth", "connect", ...args]);
}

describe("oauth connect e2e (real engine, real OAuthManager, loopback fake provider)", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  const savedEnv = process.env.HARPOC_OAUTH_CLIENT_SECRET;

  beforeEach(() => {
    openBrowserMock.mockReset();
    process.env.HARPOC_OAUTH_CLIENT_SECRET = "e2e-client-secret";
    tokenHandler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          access_token: "e2e-access-token",
          refresh_token: "e2e-refresh-token",
          expires_in: 3600,
        }),
      );
    };
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    // The "browser": watch stderr for the printed authorization URL and hit
    // the loopback callback with the code + state, exactly like a user would.
    errorSpy = vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
      const text = args.map(String).join(" ");
      const match = /https:\/\/example\.com\/auth\?[^\s]+/.exec(text);
      if (match) {
        const authUrl = new URL(match[0]);
        const state = authUrl.searchParams.get("state");
        const redirectUri = authUrl.searchParams.get("redirect_uri");
        if (state && redirectUri) {
          setTimeout(() => {
            void fetch(`${redirectUri}?code=e2e-auth-code&state=${state}`);
          }, 50);
        }
      }
    });
  });

  afterEach(() => {
    if (savedEnv === undefined) {
      delete process.env.HARPOC_OAUTH_CLIENT_SECRET;
    } else {
      process.env.HARPOC_OAUTH_CLIENT_SECRET = savedEnv;
    }
    exitSpy.mockRestore();
    errorSpy.mockRestore();
    logSpy.mockRestore();
  });

  it("authorization_code end-to-end: the printed URL drives the callback and the secret goes ACTIVE", async () => {
    await run([
      "e2e-auth",
      "--provider",
      "custom",
      "--client-id",
      "e2e-client",
      "--token-endpoint",
      tokenServerUrl,
      "--auth-endpoint",
      "https://example.com/auth",
      "--callback-port",
      "0",
      "--json",
    ]);

    const printed = JSON.parse(logSpy.mock.calls[0]?.[0] as string) as Record<string, unknown>;
    expect(printed.status).toBe("authorized");
    expect(printed.handle).toBe("secret://e2e-auth");

    const verify = await loadUnlockedEngine(tempDir);
    try {
      const info = await verify.getSecretInfo("secret://e2e-auth");
      expect(info.status).toBe("active");
      expect(info.type).toBe("oauth_token");
      const authorize = verify.queryAudit({ eventType: AuditEventType.OAUTH_AUTHORIZE });
      const callback = verify.queryAudit({ eventType: AuditEventType.OAUTH_CALLBACK });
      expect(authorize.length).toBeGreaterThanOrEqual(1);
      expect(callback.length).toBeGreaterThanOrEqual(1);
    } finally {
      await verify.destroy();
    }
  });

  it("device flow with an immediate grant: prints the user code, waits, secret ACTIVE", async () => {
    deviceHandler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          device_code: "e2e-device-code",
          user_code: "E2E-1234",
          verification_uri: "https://example.com/device",
          expires_in: 60,
          interval: 0,
        }),
      );
    };

    await run([
      "e2e-device",
      "--provider",
      "custom",
      "--client-id",
      "e2e-client",
      "--token-endpoint",
      tokenServerUrl,
      "--device-endpoint",
      deviceServerUrl,
      "--device",
    ]);

    const stderrText = errorSpy.mock.calls.map((call) => call.map(String).join(" ")).join("\n");
    expect(stderrText).toContain("E2E-1234");
    expect(stderrText).toContain("OK: OAuth secret connected");

    const verify = await loadUnlockedEngine(tempDir);
    try {
      const info = await verify.getSecretInfo("secret://e2e-device");
      expect(info.status).toBe("active");
    } finally {
      await verify.destroy();
    }
  });

  it("client_credentials end-to-end via HARPOC_OAUTH_CLIENT_SECRET (no prompt)", async () => {
    await run([
      "e2e-cc",
      "--provider",
      "custom",
      "--client-id",
      "e2e-client",
      "--token-endpoint",
      tokenServerUrl,
      "--client-credentials",
      "--json",
    ]);

    const printed = JSON.parse(logSpy.mock.calls[0]?.[0] as string) as Record<string, unknown>;
    expect(printed.status).toBe("authorized");

    const verify = await loadUnlockedEngine(tempDir);
    try {
      const info = await verify.getSecretInfo("secret://e2e-cc");
      expect(info.status).toBe("active");
    } finally {
      await verify.destroy();
    }
  });

  it("token endpoint failure: exit 1, error rendered, secret stays PENDING (negative control)", async () => {
    tokenHandler = (_req, res) => {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_client" }));
    };

    await expect(
      run([
        "e2e-fail",
        "--provider",
        "custom",
        "--client-id",
        "e2e-client",
        "--token-endpoint",
        tokenServerUrl,
        "--client-credentials",
      ]),
    ).rejects.toThrow("process.exit");

    expect(exitSpy).toHaveBeenCalledWith(1);
    const stderrText = errorSpy.mock.calls.map((call) => call.map(String).join(" ")).join("\n");
    expect(stderrText).toContain("OAUTH_TOKEN_EXCHANGE_FAILED");

    const verify = await loadUnlockedEngine(tempDir);
    try {
      const info = await verify.getSecretInfo("secret://e2e-fail");
      expect(info.status).toBe("pending");
    } finally {
      await verify.destroy();
    }
  });

  it("no browser callback within --timeout: OAUTH_CALLBACK_TIMEOUT (negative control)", async () => {
    await expect(
      run([
        "e2e-timeout",
        "--provider",
        "custom",
        "--client-id",
        "e2e-client",
        "--token-endpoint",
        tokenServerUrl,
        "--auth-endpoint",
        "https://example.com/no-callback",
        "--callback-port",
        "0",
        "--timeout",
        "1",
      ]),
    ).rejects.toThrow("process.exit");

    expect(exitSpy).toHaveBeenCalledWith(1);
    const stderrText = errorSpy.mock.calls.map((call) => call.map(String).join(" ")).join("\n");
    expect(stderrText).toContain("OAUTH_CALLBACK_TIMEOUT");
  });

  it("re-running connect after a failed flow resumes the PENDING secret (review fix F6)", async () => {
    tokenHandler = (_req, res) => {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_client" }));
    };
    await expect(
      run([
        "e2e-resume",
        "--provider",
        "custom",
        "--client-id",
        "e2e-client",
        "--token-endpoint",
        tokenServerUrl,
        "--client-credentials",
      ]),
    ).rejects.toThrow("process.exit");

    // Pre-fix, this re-run died on DUPLICATE_SECRET before any flow started.
    tokenHandler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ access_token: "resumed-access-token", expires_in: 3600 }));
    };
    await run([
      "e2e-resume",
      "--provider",
      "custom",
      "--client-id",
      "e2e-client",
      "--token-endpoint",
      tokenServerUrl,
      "--client-credentials",
      "--json",
    ]);

    const printed = JSON.parse(logSpy.mock.calls.at(-1)?.[0] as string) as Record<string, unknown>;
    expect(printed.status).toBe("authorized");
    expect(printed.handle).toBe("secret://e2e-resume");

    const verify = await loadUnlockedEngine(tempDir);
    try {
      const info = await verify.getSecretInfo("secret://e2e-resume");
      expect(info.status).toBe("active");
    } finally {
      await verify.destroy();
    }
  });

  it("--timeout bounds the device wait: exit 1, poll cancelled, secret PENDING (review fix F7)", async () => {
    deviceHandler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          device_code: "e2e-hang-code",
          user_code: "E2E-HANG",
          verification_uri: "https://example.com/device",
          expires_in: 900,
          interval: 0,
        }),
      );
    };
    let polls = 0;
    tokenHandler = (_req, res) => {
      polls++;
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "authorization_pending" }));
    };

    // Pre-fix this hung until the provider's expires_in (900 s here) — the
    // user's --timeout only fed the auth-code callback server.
    await expect(
      run([
        "e2e-device-timeout",
        "--provider",
        "custom",
        "--client-id",
        "e2e-client",
        "--token-endpoint",
        tokenServerUrl,
        "--device-endpoint",
        deviceServerUrl,
        "--device",
        "--timeout",
        "1",
      ]),
    ).rejects.toThrow("process.exit");

    expect(exitSpy).toHaveBeenCalledWith(1);
    const stderrText = errorSpy.mock.calls.map((call) => call.map(String).join(" ")).join("\n");
    expect(stderrText).toContain("OAUTH_CALLBACK_TIMEOUT");

    // The background poll was cancelled: the endpoint hit count settles.
    // A request dispatched before the abort may still land, so wait for
    // quiescence — a full zero-hit window (the cancelFlow suite's pattern).
    await vi.waitFor(
      async () => {
        const before = polls;
        await new Promise((resolve) => setTimeout(resolve, 200));
        expect(polls).toBe(before);
      },
      { timeout: 5_000, interval: 10 },
    );

    const verify = await loadUnlockedEngine(tempDir);
    try {
      const info = await verify.getSecretInfo("secret://e2e-device-timeout");
      expect(info.status).toBe("pending");
    } finally {
      await verify.destroy();
    }
  }, 15_000);

  it("--open browser failure warns and the flow still completes (review fix F9)", async () => {
    openBrowserMock.mockRejectedValue(new Error("xdg-open missing"));

    await run([
      "e2e-open-fail",
      "--provider",
      "custom",
      "--client-id",
      "e2e-client",
      "--token-endpoint",
      tokenServerUrl,
      "--auth-endpoint",
      "https://example.com/auth",
      "--callback-port",
      "0",
      "--open",
      "--json",
    ]);

    expect(openBrowserMock).toHaveBeenCalledOnce();
    const stderrText = errorSpy.mock.calls.map((call) => call.map(String).join(" ")).join("\n");
    expect(stderrText).toContain("could not open a browser automatically");

    const printed = JSON.parse(logSpy.mock.calls.at(-1)?.[0] as string) as Record<string, unknown>;
    expect(printed.status).toBe("authorized");
  });

  it("control: a successful --open launch prints no warning", async () => {
    openBrowserMock.mockResolvedValue(undefined);

    await run([
      "e2e-open-ok",
      "--provider",
      "custom",
      "--client-id",
      "e2e-client",
      "--token-endpoint",
      tokenServerUrl,
      "--auth-endpoint",
      "https://example.com/auth",
      "--callback-port",
      "0",
      "--open",
      "--json",
    ]);

    expect(openBrowserMock).toHaveBeenCalledOnce();
    const stderrText = errorSpy.mock.calls.map((call) => call.map(String).join(" ")).join("\n");
    expect(stderrText).not.toContain("could not open a browser");

    const printed = JSON.parse(logSpy.mock.calls.at(-1)?.[0] as string) as Record<string, unknown>;
    expect(printed.status).toBe("authorized");
  });
});
