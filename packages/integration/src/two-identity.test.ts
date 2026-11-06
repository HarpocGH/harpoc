import { readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  AuditEventType,
  ErrorCode,
  SESSION_FILE_NAME,
  VAULT_DB_NAME,
  sessionFileSchema,
} from "@harpoc/shared";
import { assertTierAvailable } from "./helpers/platform-tiers.js";
import {
  CLI_ENTRY,
  runAs,
  runCliAs,
  startCliServerOnFreePort,
  type CliServer,
} from "./helpers/spawn-cli.js";

/**
 * Deployment model B on a real kernel (design M3 § Tests): the vault runs as one
 * OS user, the agent is another and holds a use-only token. Every vault step is
 * the built CLI run as the vault user through `sudo -n -u`, every agent probe a
 * child run as the agent user the same way; the negative controls repeat the
 * read as the vault user — the same-UID case model A is.
 *
 * Linux only: `sudo -u`, `/proc/<pid>/environ` and POSIX ownership. The users
 * come from HARPOC_TWO_UID_VAULT_USER and HARPOC_TWO_UID_AGENT_USER (the ci.yml
 * ubuntu legs and the dev container create them with
 * deploy/linux/install-two-identity.sh); where the `two-uid` tier of
 * HARPOC_REQUIRE_PLATFORM_TESTS is required, a missing user or a refused sudo
 * fails instead of skipping. The vault directory is a `mktemp -d` of the vault
 * user (0700, like /var/lib/harpoc); the runner cannot remove another user's
 * directory, so the teardown removes it through sudo.
 */

const VAULT_USER = process.env["HARPOC_TWO_UID_VAULT_USER"];
const AGENT_USER = process.env["HARPOC_TWO_UID_AGENT_USER"];
const PASSWORD = "two-uid-master-pw-1";
const SECRET_VALUE = "two-uid-environ-value-5c1e";
const AGENT = "agent-b";
const ARGON2_TIMEOUT_MS = 110_000;

// The agent user's HTTP client: the token arrives on stdin, never in argv.
const AGENT_REQUEST = [
  "let input = '';",
  "process.stdin.on('data', (c) => (input += c));",
  "process.stdin.on('end', () => {",
  "  const { url, method, token, body } = JSON.parse(input);",
  "  const headers = { authorization: 'Bearer ' + token, 'content-type': 'application/json' };",
  "  fetch(url, { method, headers, body })",
  "    .then(async (res) => process.stdout.write(JSON.stringify({ status: res.status, body: await res.text() })))",
  "    .catch((err) => { process.stderr.write(String(err)); process.exitCode = 1; });",
  "});",
].join("\n");

interface AuditRow {
  event_type: string;
  principal_id: string | null;
  detail: Record<string, unknown> | null;
}

describe.skipIf(process.platform !== "linux")(
  "two-identity deployment (Linux only: sudo -n -u, /proc and POSIX ownership)",
  () => {
    let available = false;
    let vault = "";
    let agent = "";
    let vaultDir: string | undefined;
    let daemon: CliServer | undefined;
    let origin = "";
    let useToken = "";

    const asVault = (args: string[], opts: { stdin?: string; timeoutMs?: number } = {}) =>
      runCliAs(vault, args, { vaultDir: vaultDir as string, ...opts });

    async function agentRequest(
      method: "GET" | "POST",
      path: string,
      body?: unknown,
      timeoutMs?: number,
    ): Promise<{ status: number; body: string }> {
      const run = await runAs(agent, [process.execPath, "-e", AGENT_REQUEST], {
        stdin: JSON.stringify({
          url: `${origin}${path}`,
          method,
          token: useToken,
          body: body === undefined ? undefined : JSON.stringify(body),
        }),
        timeoutMs,
      });
      expect(run.code, run.stderr).toBe(0);
      return JSON.parse(run.stdout) as { status: number; body: string };
    }

    beforeAll(async () => {
      let probeError: unknown;
      try {
        if (VAULT_USER === undefined || AGENT_USER === undefined) {
          throw new Error("HARPOC_TWO_UID_VAULT_USER and HARPOC_TWO_UID_AGENT_USER are not set");
        }
        for (const user of [VAULT_USER, AGENT_USER]) {
          const probe = await runAs(user, [process.execPath, CLI_ENTRY, "--version"]);
          if (probe.code !== 0) {
            throw new Error(`sudo -n -u ${user} cannot run the built CLI: ${probe.stderr.trim()}`);
          }
        }
        available = true;
      } catch (err) {
        probeError = err;
      }
      assertTierAvailable("two-uid", available, probeError);
      if (!available) return;
      vault = VAULT_USER as string;
      agent = AGENT_USER as string;

      const made = await runAs(vault, ["mktemp", "-d", join(tmpdir(), "harpoc-two-uid-XXXXXX")]);
      expect(made.code, made.stderr).toBe(0);
      vaultDir = made.stdout.trim();

      // init leaves the vault unlocked with a session file; no unlock follows.
      const init = await asVault(["init"], {
        stdin: `${PASSWORD}\n${PASSWORD}\n`,
        timeoutMs: ARGON2_TIMEOUT_MS,
      });
      expect(init.code, init.stderr).toBe(0);
      const steps: { args: string[]; stdin?: string }[] = [
        { args: ["agent", "register", AGENT] },
        { args: ["secret", "set", "api-key"], stdin: `${SECRET_VALUE}\n` },
        { args: ["secret", "allow", "secret://api-key", "--command", "sleep"] },
        {
          args: [
            "policy",
            "grant",
            "secret://api-key",
            "--principal-type",
            "agent",
            "--principal-id",
            AGENT,
            "--permissions",
            "use",
          ],
        },
      ];
      for (const step of steps) {
        const run = await asVault(step.args, { stdin: step.stdin });
        expect(run.code, `${step.args.join(" ")}: ${run.stderr}`).toBe(0);
      }
      const minted = await asVault([
        "auth",
        "token",
        "--agent",
        AGENT,
        "--scope",
        "use",
        "--ttl",
        "60",
        "--json",
      ]);
      expect(minted.code, minted.stderr).toBe(0);
      useToken = (JSON.parse(minted.stdout) as { token: string }).token;

      const started = await startCliServerOnFreePort(
        (port) => ["server", "start", "--rest", "--port", String(port)],
        { vaultDir, user: vault },
      );
      daemon = started.server;
      origin = `http://127.0.0.1:${String(started.port)}`;
    }, 180_000);

    afterEach(async () => {
      if (!available) return;
      const swept = await runAs(vault, ["pkill", "-u", vault, "-x", "sleep"]);
      expect([0, 1]).toContain(swept.code);
    });

    afterAll(async () => {
      if (!available || vaultDir === undefined) return;
      try {
        await daemon?.stop();
      } finally {
        const leftovers = [
          await runAs(vault, ["pkill", "-KILL", "-u", vault, "-f", vaultDir]),
          await runAs(vault, ["pkill", "-KILL", "-u", vault, "-x", "sleep"]),
        ];
        const removed = await runAs(vault, ["rm", "-rf", "--", vaultDir]);
        expect(
          leftovers.map((r) => r.code),
          "a process of the vault user outlived the suite",
        ).toEqual([1, 1]);
        expect(removed.code, removed.stderr).toBe(0);
      }
    });

    it("(a) the agent user can neither list the 0700 vault directory nor read the database; the vault user reads its SQLite header", async (ctx) => {
      if (!available) return ctx.skip();
      const dir = vaultDir as string;
      const db = join(dir, VAULT_DB_NAME);
      const mode = await runAs(vault, ["stat", "-c", "%a %U", dir]);
      expect(mode.stdout.trim()).toBe(`700 ${vault}`);

      const listing = await runAs(agent, ["ls", dir]);
      expect(listing.code).not.toBe(0);
      expect(listing.stderr).toMatch(/Permission denied/);
      const read = await runAs(agent, ["cat", db]);
      expect(read.code).not.toBe(0);
      expect(read.stderr).toMatch(/Permission denied/);
      expect(read.stdout.length).toBe(0);
      let thrown: unknown;
      try {
        readdirSync(dir);
      } catch (err) {
        thrown = err;
      }
      expect((thrown as NodeJS.ErrnoException | undefined)?.code).toBe("EACCES");

      const header = await runAs(vault, ["head", "-c", "16", db]);
      expect(header.code).toBe(0);
      expect(header.stdout).toBe("SQLite format 3\0");
    }, 30_000);

    it("(b) the agent's use-only token: GET …/value is 403 ACCESS_DENIED at the scope check with one access.denied row; POST …/use runs (positive control)", async (ctx) => {
      if (!available) return ctx.skip();
      const value = await agentRequest("GET", "/api/v1/secrets/api-key/value");
      expect(value.status).toBe(403);
      expect(JSON.parse(value.body)).toEqual({
        error: ErrorCode.ACCESS_DENIED,
        message: "Access denied: Token lacks permission: read",
      });
      const audit = await asVault(["audit", "--event", AuditEventType.ACCESS_DENIED, "--json"]);
      expect(audit.code, audit.stderr).toBe(0);
      const rows = (JSON.parse(audit.stdout) as AuditRow[]).filter(
        (r) => r.detail?.["operation"] === "GET /api/v1/secrets/api-key/value",
      );
      expect(rows).toHaveLength(1);
      expect(rows[0]?.principal_id).toBe(AGENT);
      expect(rows[0]?.detail).toEqual({
        operation: "GET /api/v1/secrets/api-key/value",
        error: ErrorCode.ACCESS_DENIED,
        reason: "permission",
        interface: "rest",
      });

      const used = await agentRequest("POST", "/api/v1/secrets/api-key/use", {
        action: { type: "process", command: "sleep", args: ["0"], env_var: "API_KEY" },
      });
      expect(used.status).toBe(200);
      expect(JSON.parse(used.body)).toMatchObject({ data: { type: "process", exit_code: 0 } });
    }, 60_000);

    it("(c) /proc/<pid>/environ of a vault-owned process-context child is unreadable to the agent user and to the runner; the vault user reads the credential in it (same-UID negative control)", async (ctx) => {
      if (!available) return ctx.skip();
      const pending = agentRequest(
        "POST",
        "/api/v1/secrets/api-key/use",
        {
          action: {
            type: "process",
            command: "sleep",
            args: ["120"],
            env_var: "API_KEY",
            timeout_ms: 60_000,
          },
        },
        90_000,
      );
      const pid = await vi.waitFor(
        async () => {
          const listed = await runAs(vault, ["pgrep", "-u", vault, "-x", "sleep"]);
          const pids = listed.stdout.split("\n").filter((line) => line !== "");
          expect(pids).toHaveLength(1);
          return Number(pids[0]);
        },
        { timeout: 20_000, interval: 250 },
      );
      const environ = `/proc/${String(pid)}/environ`;

      const agentRead = await runAs(agent, ["cat", environ]);
      expect(agentRead.code).not.toBe(0);
      expect(agentRead.stderr).toMatch(/Permission denied|No such file or directory/);
      expect(agentRead.stdout.includes(SECRET_VALUE)).toBe(false);
      let thrown: unknown;
      try {
        readFileSync(environ);
      } catch (err) {
        thrown = err;
      }
      expect(["EACCES", "ENOENT"]).toContain((thrown as NodeJS.ErrnoException | undefined)?.code);

      const vaultRead = await runAs(vault, ["cat", environ]);
      expect(vaultRead.code).toBe(0);
      expect(vaultRead.stdout.split("\0").includes(`API_KEY=${SECRET_VALUE}`)).toBe(true);

      const killed = await runAs(vault, ["kill", "-s", "TERM", String(pid)]);
      expect(killed.code).toBe(0);
      const answer = await pending;
      expect(answer.status).toBe(200);
      expect(answer.body.includes(SECRET_VALUE)).toBe(false);
      expect(JSON.parse(answer.body)).toMatchObject({
        data: { type: "process", exit_code: null, signal: "SIGTERM" },
      });
    }, 120_000);

    it("(d) the 0600 session file: the agent user cannot read it; the vault user reads a complete session (model A's exposure, inside the vault's UID)", async (ctx) => {
      if (!available) return ctx.skip();
      const session = join(vaultDir as string, SESSION_FILE_NAME);
      const agentRead = await runAs(agent, ["cat", session]);
      expect(agentRead.code).not.toBe(0);
      expect(agentRead.stderr).toMatch(/Permission denied/);
      expect(agentRead.stdout.length).toBe(0);

      const mode = await runAs(vault, ["stat", "-c", "%a %U", session]);
      expect(mode.stdout.trim()).toBe(`600 ${vault}`);
      const vaultRead = await runAs(vault, ["cat", session]);
      expect(vaultRead.code).toBe(0);
      expect(sessionFileSchema.safeParse(JSON.parse(vaultRead.stdout)).success).toBe(true);
    }, 30_000);

    it("(e) the daemon stops on SIGTERM delivered as the vault user and writes its server.stop row", async (ctx) => {
      if (!available) return ctx.skip();
      const server = daemon as CliServer;
      await server.stop();
      expect(server.child.exitCode).toBe(0);
      const audit = await asVault(["audit", "--event", AuditEventType.SERVER_STOP, "--json"]);
      expect(audit.code, audit.stderr).toBe(0);
      const rows = JSON.parse(audit.stdout) as AuditRow[];
      expect(rows).toHaveLength(1);
      expect(rows[0]?.detail).toMatchObject({ transport: "rest", trigger: "SIGTERM" });
    }, 60_000);
  },
);
