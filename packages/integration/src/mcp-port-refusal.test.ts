import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

const MCP_ENTRY = join(
  dirname(createRequire(import.meta.url).resolve("@harpoc/mcp-server/package.json")),
  "dist",
  "index.js",
);

function runMcp(args: string[]): Promise<{ code: number | null; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [MCP_ENTRY, ...args], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString()));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stderr }));
  });
}

describe("harpoc-mcp --http --port (spawned binary)", () => {
  it("refuses a non-decimal port before touching any vault", async () => {
    const result = await runMcp(["--http", "--port", "0x10"]);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('Invalid port "0x10". Must be 1-65535.');
    expect(result.stderr).not.toContain("Vault is locked");
  }, 30_000);
});

describe("harpoc-mcp --token-file and the removed --token (spawned binary)", () => {
  it("refuses an unreadable token file before touching any vault", async () => {
    const missing = join(tmpdir(), `harpoc-no-such-token-${String(process.pid)}`);
    const result = await runMcp(["--token-file", missing]);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain(`Cannot read --token-file ${missing}`);
    expect(result.stderr).not.toContain("Vault is locked");
  }, 30_000);

  it("refuses the removed --token flag, never echoing its value", async () => {
    const result = await runMcp(["--token", "not.a.jwt"]);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("--token was removed");
    expect(result.stderr).toContain("--token-file <path>");
    expect(result.stderr).not.toContain("not.a.jwt");
    expect(result.stderr).not.toContain("Vault is locked");
  }, 30_000);
});

describe("harpoc-mcp --http --allowed-host (spawned binary)", () => {
  it("refuses a non-loopback bind without --allowed-host before touching any vault", async () => {
    const result = await runMcp(["--http", "--host", "0.0.0.0"]);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("requires --allowed-host");
    expect(result.stderr).not.toContain("Vault is locked");
  }, 30_000);

  it("refuses an entry carrying a port, naming it", async () => {
    const result = await runMcp(["--http", "--allowed-host", "vault.example:3000"]);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('Invalid --allowed-host "vault.example:3000"');
    expect(result.stderr).not.toContain("Vault is locked");
  }, 30_000);

  it("refuses --allowed-host without --http", async () => {
    const result = await runMcp(["--allowed-host", "vault.example"]);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("--allowed-host requires --http");
  }, 30_000);
});
