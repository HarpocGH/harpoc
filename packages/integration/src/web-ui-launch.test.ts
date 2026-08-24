import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { VaultEngine } from "@harpoc/core";
import { SESSION_FILE_NAME, VAULT_DB_NAME } from "@harpoc/shared";
import { freePort, runCli, startCliServer } from "./helpers/spawn-cli.js";

const PASSWORD = "launch-flow-pw-1";
const LAUNCH_LINE = /\[harpoc\] Web UI: (http:\/\/[^#\s?]+)#token=(\S+)/;

function jwtPayload(token: string): Record<string, unknown> {
  const segment = token.split(".")[1] as string;
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as Record<string, unknown>;
}

describe("web-ui launch flow (spawned CLI)", () => {
  let vaultDir: string;

  beforeAll(async () => {
    vaultDir = mkdtempSync(join(tmpdir(), "harpoc-launch-"));
    // Init in-process (mocked-free real engine), then let the real CLI write
    // the session the spawned server will read — the piped hidden prompt is
    // itself pinned behavior (2026-07-06).
    const engine = new VaultEngine({
      dbPath: join(vaultDir, VAULT_DB_NAME),
      sessionPath: join(vaultDir, SESSION_FILE_NAME),
    });
    await engine.initVault(PASSWORD);
    await engine.destroy();
    const unlock = await runCli(["unlock"], {
      vaultDir,
      stdin: `${PASSWORD}\n`,
    });
    expect(unlock.code).toBe(0);
  }, 120_000);

  afterAll(() => {
    rmSync(vaultDir, { recursive: true, force: true });
  });

  it("serves the UI and a working fragment launch token", async () => {
    const port = await freePort();
    const server = startCliServer(["server", "start", "--rest", "--ui", "--port", String(port)], {
      vaultDir,
    });
    try {
      const [, base, token] = await server.waitForStderr(LAUNCH_LINE);
      expect(base).toBe(`http://127.0.0.1:${String(port)}/ui`);

      const payload = jwtPayload(token as string);
      expect(payload["scope"]).toEqual(["admin"]);
      expect(payload["principal_type"]).toBe("user");

      const origin = `http://127.0.0.1:${String(port)}`;
      const auth = { Authorization: `Bearer ${token as string}` };

      // The token authenticates an admin route; its label lives in the registry.
      const tokens = await fetch(`${origin}/api/v1/tokens`, { headers: auth });
      expect(tokens.status).toBe(200);
      const rows = (
        (await tokens.json()) as {
          data: { jti: string; label: string | null }[];
        }
      ).data;
      expect(rows.find((row) => row.jti === payload["jti"])?.label).toBe("web-ui launch");

      // /ui: index, CSP + nosniff, SPA fallback, traversal + unknown-extension 404.
      const index = await fetch(`${origin}/ui`);
      expect(index.status).toBe(200);
      expect(index.headers.get("content-security-policy")).toContain("default-src 'self'");
      expect(index.headers.get("x-content-type-options")).toBe("nosniff");
      const html = await index.text();

      const spa = await fetch(`${origin}/ui/agents`);
      expect(spa.status).toBe(200);
      expect(spa.headers.get("content-type")).toContain("text/html");

      // %2e%2e collapses client-side (WHATWG URL parser normalizes it before the
      // request is sent, so the wire path is never traversal); ..%2f survives intact
      // and is what actually exercises the handler's decoded-containment guard.
      expect((await fetch(`${origin}/ui/..%2f..%2fpackage.json`)).status).toBe(404);
      expect((await fetch(`${origin}/ui/anything.xyz`)).status).toBe(404);

      const assetMatch = html.match(/\/ui\/(assets\/[^"']+\.js)/);
      expect(assetMatch).not.toBeNull();
      const asset = await fetch(`${origin}/ui/${(assetMatch as RegExpMatchArray)[1] as string}`);
      expect(asset.status).toBe(200);
      expect(asset.headers.get("cache-control")).toContain("immutable");
    } finally {
      await server.stop();
    }
  }, 120_000);

  it("--ui-token-ttl shortens the launch token to the minute", async () => {
    const port = await freePort();
    const server = startCliServer(
      ["server", "start", "--rest", "--ui", "--port", String(port), "--ui-token-ttl", "5"],
      { vaultDir },
    );
    try {
      const [, , token] = await server.waitForStderr(LAUNCH_LINE);
      const payload = jwtPayload(token as string);
      expect((payload["exp"] as number) - (payload["iat"] as number)).toBe(5 * 60);
    } finally {
      await server.stop();
    }
  }, 120_000);

  it("refuses the three invalid flag combinations before binding anything", async () => {
    const noRest = await runCli(["server", "start", "--ui"], { vaultDir });
    expect(noRest.code).toBe(1);
    expect(noRest.stderr).toContain("Error: --ui requires --rest.");

    const noUi = await runCli(["server", "start", "--rest", "--ui-token-ttl", "10"], { vaultDir });
    expect(noUi.code).toBe(1);
    expect(noUi.stderr).toContain("Error: --ui-token-ttl requires --ui.");

    const overCap = await runCli(["server", "start", "--rest", "--ui", "--ui-token-ttl", "1441"], {
      vaultDir,
    });
    expect(overCap.code).toBe(1);
    expect(overCap.stderr).toContain("Error: --ui-token-ttl exceeds the 24 h token cap (1440).");
  }, 120_000);
});
