import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { startGitSmartHttp } from "./git-smart-http.js";
import type { Listener } from "./git-smart-http.js";

const USER = "fixture-user";
const TOKEN = "fixture-token";
const BASIC = `Basic ${Buffer.from(`${USER}:${TOKEN}`).toString("base64")}`;

const HANG_PRELOAD =
  'require("node:fs").writeFileSync(process.env.HARPOC_CGI_PID_FILE, String(process.pid));\n' +
  "Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10_000);\n" +
  'require("node:fs").writeFileSync(process.env.HARPOC_CGI_ENDED_FILE, "ended");\n';

const TERM_LATE_PRELOAD =
  'const fs = require("node:fs");\n' +
  'process.on("uncaughtException", () => {});\n' +
  'process.on("SIGTERM", () => {\n' +
  '  fs.writeFileSync(process.env.HARPOC_CGI_TERM_FILE, "term");\n' +
  "  setTimeout(() => process.exit(0), 1_000);\n" +
  "});\n" +
  'setTimeout(() => fs.writeFileSync(process.env.HARPOC_CGI_ENDED_FILE, "ended"), 10_000);\n' +
  "fs.writeFileSync(process.env.HARPOC_CGI_PID_FILE, String(process.pid));\n";

let scratch = "";
let pidFile = "";
let endedFile = "";
let termFile = "";
let server: Listener | undefined;

function hangingEnv(preloadFile = "hang.cjs"): NodeJS.ProcessEnv {
  const preload = join(scratch, preloadFile).replaceAll("\\", "/");
  return {
    ...process.env,
    NODE_OPTIONS: `--require="${preload}"`,
    HARPOC_CGI_PID_FILE: pidFile,
    HARPOC_CGI_ENDED_FILE: endedFile,
    HARPOC_CGI_TERM_FILE: termFile,
  };
}

function isGone(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return false;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ESRCH";
  }
}

beforeEach(() => {
  scratch = mkdtempSync(join(tmpdir(), "harpoc-git-cgi-"));
  pidFile = join(scratch, "cgi.pid");
  endedFile = join(scratch, "cgi.ended");
  termFile = join(scratch, "cgi.term");
  writeFileSync(join(scratch, "hang.cjs"), HANG_PRELOAD);
  writeFileSync(join(scratch, "term-late.cjs"), TERM_LATE_PRELOAD);
});

afterEach(async () => {
  if (server) {
    await server.close();
    server = undefined;
  }
  rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("git-smart-http fixture CGI child", () => {
  it("answers 502 when the CGI child outlives cgiTimeoutMs", async () => {
    server = await startGitSmartHttp({
      git: process.execPath,
      projectRoot: scratch,
      user: USER,
      token: TOKEN,
      env: hangingEnv(),
      cgiTimeoutMs: 500,
    });
    const response = await fetch(`http://127.0.0.1:${server.port}/repo.git/info/refs`, {
      headers: { authorization: BASIC },
      signal: AbortSignal.timeout(5000),
    });
    expect(response.status).toBe(502);
  });

  it("close() kills a live CGI child and resolves", async () => {
    server = await startGitSmartHttp({
      git: process.execPath,
      projectRoot: scratch,
      user: USER,
      token: TOKEN,
      env: hangingEnv(),
    });
    const pending = fetch(`http://127.0.0.1:${server.port}/repo.git/info/refs`, {
      headers: { authorization: BASIC },
      signal: AbortSignal.timeout(15_000),
    }).catch(() => undefined);
    await vi.waitFor(() => expect(existsSync(pidFile)).toBe(true), { timeout: 8000 });
    await vi.waitFor(() => expect(readFileSync(pidFile, "utf8")).not.toBe(""), { timeout: 8000 });
    const pid = Number.parseInt(readFileSync(pidFile, "utf8"), 10);
    await server.close();
    server = undefined;
    expect(isGone(pid)).toBe(true);
    expect(existsSync(endedFile)).toBe(false);
    await pending;
  });

  // Skipped on win32: a terminated process reads as gone at once there.
  it.skipIf(process.platform === "win32")(
    "close() returns only when a CGI child that outlives SIGTERM is gone",
    async () => {
      server = await startGitSmartHttp({
        git: process.execPath,
        projectRoot: scratch,
        user: USER,
        token: TOKEN,
        env: hangingEnv("term-late.cjs"),
      });
      const pending = fetch(`http://127.0.0.1:${server.port}/repo.git/info/refs`, {
        headers: { authorization: BASIC },
        signal: AbortSignal.timeout(15_000),
      }).catch(() => undefined);
      await vi.waitFor(() => expect(existsSync(pidFile)).toBe(true), { timeout: 8000 });
      await vi.waitFor(() => expect(readFileSync(pidFile, "utf8")).not.toBe(""), { timeout: 8000 });
      const pid = Number.parseInt(readFileSync(pidFile, "utf8"), 10);
      await server.close();
      server = undefined;
      expect(isGone(pid)).toBe(true);
      expect(existsSync(termFile)).toBe(true);
      expect(existsSync(endedFile)).toBe(false);
      await pending;
    },
  );
});
