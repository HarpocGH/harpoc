import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  AuditEventType,
  ErrorCode,
  SESSION_CLEANUP_INTERVAL_MS,
  SESSION_FILE_NAME,
  VaultState,
} from "@harpoc/shared";
import {
  CLI_ENTRY,
  runCli,
  runCommand,
  startCliServer,
  startCliServerOnFreePort,
} from "./helpers/spawn-cli.js";
import type { CliServer } from "./helpers/spawn-cli.js";

/**
 * The memory session on the built CLI (design M2, tranche B5): `server start --session
 * memory` keeps the keys of its unlock in the daemon alone — it writes no session file, a
 * session it loads at start is read once and left to the administrator, and its lock is
 * `POST /api/v1/vault/lock` or SIGTERM, while `harpoc lock` as the vault user reaches only
 * the administrator's own session (design § 3 M3 "Administration in B"). Every deployment
 * model B flag without it is refused `SESSION_MODE_CONFLICT` before the vault opens. With
 * `--issue-token` the daemon mints a consumer's token into a file at start and again at half
 * its TTL; the consumer's REST mode reads the file per command, so it follows the rotation
 * with no restart, and a revoked token is never re-minted. A one-minute TTL keeps the
 * rotation rows at thirty seconds a re-mint; their exact instants under fake timers are
 * core's `token-rotation.test.ts`. The two-UID rows (the consumer's group reading the file)
 * are B6's.
 */

const PASSWORD = "memory-session-master-pw-1";
const ARGON2_TIMEOUT_MS = 110_000;
const AGENT = "agent-m";
const SECRET_VALUE = "memory-session-fixture-value-5b2c";
const CREDENTIAL_ID = "harpoc-unlock";
/** The token file `auth token --out` writes and the rotator matches: the JWT and a newline. */
const TOKEN_FILE_FORM = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\n$/;
const REVOKED_WARNING = new RegExp(`Warning: --issue-token agent=${AGENT}: TOKEN_REVOKED`, "g");

interface AuditRow {
  event_type: string;
  success: boolean;
  detail: Record<string, unknown> | null;
}

interface Exit {
  code: number | null;
  stdout: string;
  stderr: string;
}

/** A token's `jti` and `exp` (seconds), read from its payload segment — never printed. */
function claimsOf(token: string): { jti: string; exp: number } {
  const payload = token.trim().split(".")[1] ?? "";
  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as {
    jti: string;
    exp: number;
  };
}

describe("the memory session on the built CLI (server start --session memory, the conflict check, --issue-token)", () => {
  let root = "";
  let vaultDir = "";
  let sessionPath = "";
  let credentials = "";
  let keyPath = "";
  let adminTokenFile = "";
  let adminToken = "";
  let tokenDir = "";
  let tokenFile = "";
  let stolenFile = "";
  let firstToken = "";
  let adminLockedAt = 0;
  let loaded: { server: CliServer; port: number } | undefined;
  let credentialed: { server: CliServer; port: number } | undefined;
  let rotating: { server: CliServer; port: number } | undefined;
  const issued: string[] = [];
  const outputs: string[] = [];

  const originOf = (daemon: { port: number } | undefined): string => {
    if (daemon === undefined) throw new Error("no live daemon for this row");
    return `http://127.0.0.1:${String(daemon.port)}`;
  };
  const admin = (): Record<string, string> => ({ authorization: `Bearer ${adminToken}` });
  const spec = (file: string): string =>
    `agent=${AGENT},file=${file},scope=use+list,secrets=*,ttl=1`;

  async function cli(args: string[], stdin?: string, timeoutMs?: number): Promise<string> {
    const run = await runCli(args, { vaultDir, stdin, timeoutMs });
    outputs.push(run.stdout, run.stderr);
    expect(run.code, `${args.join(" ")}: ${run.stderr}`).toBe(0);
    return run.stdout;
  }

  function withoutCredentialsDirectory(): NodeJS.ProcessEnv {
    const env = { ...process.env };
    delete env["CREDENTIALS_DIRECTORY"];
    return env;
  }

  /** The CLI's REST mode, the bearer read from `file` by this command alone (no HARPOC_TOKEN). */
  async function rest(origin: string, file: string, args: string[]): Promise<Exit> {
    const env = { ...process.env };
    delete env["HARPOC_TOKEN"];
    const run = await runCommand(
      process.execPath,
      [CLI_ENTRY, "--url", origin, "--token-file", file, ...args],
      { env },
    );
    outputs.push(run.stdout, run.stderr);
    return run;
  }

  /** A start that must fail: the child's exit and output, with `env` as its whole environment. */
  async function failedStart(args: string[], env: NodeJS.ProcessEnv, dir: string): Promise<Exit> {
    const server = startCliServer(args, { vaultDir: dir, env });
    const closed = await server.closed();
    outputs.push(server.stdoutSoFar(), server.stderrSoFar());
    return { code: closed.code, stdout: server.stdoutSoFar(), stderr: server.stderrSoFar() };
  }

  /** The memory-mode daemon unlocked from the fake credentials directory, `extra` appended. */
  function startFromCredential(extra: string[]): Promise<{ server: CliServer; port: number }> {
    return startCliServerOnFreePort(
      (port) => [
        "server",
        "start",
        "--rest",
        "--port",
        String(port),
        "--session",
        "memory",
        "--unlock-credential",
        CREDENTIAL_ID,
        ...extra,
      ],
      { vaultDir, env: { ...process.env, CREDENTIALS_DIRECTORY: credentials } },
    );
  }

  async function restAudit(origin: string, event: string, success?: boolean): Promise<AuditRow[]> {
    const query = new URLSearchParams({ event_type: event, limit: "500" });
    if (success !== undefined) query.set("success", String(success));
    const res = await fetch(`${origin}/api/v1/audit?${query.toString()}`, { headers: admin() });
    expect(res.status).toBe(200);
    return ((await res.json()) as { data: AuditRow[] }).data;
  }

  async function secretsStatus(origin: string): Promise<number> {
    const res = await fetch(`${origin}/api/v1/secrets`, { headers: admin() });
    await res.text();
    return res.status;
  }

  async function stop(daemon: { server: CliServer } | undefined): Promise<void> {
    if (daemon === undefined) return;
    await daemon.server.stop();
    outputs.push(daemon.server.stdoutSoFar(), daemon.server.stderrSoFar());
  }

  beforeAll(async () => {
    root = mkdtempSync(join(tmpdir(), "harpoc-msess-"));
    vaultDir = join(root, "vault");
    mkdirSync(vaultDir);
    sessionPath = join(vaultDir, SESSION_FILE_NAME);
    keyPath = join(root, "unlock.key");
    adminTokenFile = join(root, "admin.jwt");
    stolenFile = join(root, "stolen.jwt");
    // The deployment recipe's runtime directory and set-group-ID consumer directory.
    tokenDir = join(root, "run", AGENT);
    mkdirSync(tokenDir, { recursive: true });
    chmodSync(join(root, "run"), 0o750);
    chmodSync(tokenDir, 0o2750);
    tokenFile = join(tokenDir, "token.jwt");

    // init leaves the vault unlocked with the administrator's session file.
    await cli(["init"], `${PASSWORD}\n${PASSWORD}\n`, ARGON2_TIMEOUT_MS);
    await cli(["agent", "register", AGENT]);
    await cli(["secret", "set", "api-key"], `${SECRET_VALUE}\n`);
    await cli([
      "policy",
      "grant",
      "secret://api-key",
      "--principal-type",
      "agent",
      "--principal-id",
      AGENT,
      "--permissions",
      "list,use",
    ]);
    // The administrator's REST bearer, minted while the session is theirs (no REST mint exists).
    await cli([
      "auth",
      "token",
      "--scope",
      "admin",
      "--principal-type",
      "user",
      "--label",
      "memory-session admin",
      "--ttl",
      "60",
      "--out",
      adminTokenFile,
    ]);
    adminToken = readFileSync(adminTokenFile, "utf8").trim();
    issued.push(adminToken);
    // One password unlock in the CLI's own process; its session file stays the administrator's.
    await cli(["unlock-key", "enroll", "--out", keyPath], `${PASSWORD}\n`, ARGON2_TIMEOUT_MS);

    credentials = join(root, "credentials");
    mkdirSync(credentials, { mode: 0o700 });
    chmodSync(credentials, 0o700);
    copyFileSync(keyPath, join(credentials, CREDENTIAL_ID));
    chmodSync(join(credentials, CREDENTIAL_ID), 0o400);
  }, 240_000);

  afterAll(async () => {
    try {
      await stop(rotating);
    } finally {
      try {
        await stop(credentialed);
      } finally {
        try {
          await stop(loaded);
        } finally {
          if (root !== "") {
            rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
          }
        }
      }
    }
  });

  it.each([
    ["--issue-token", (): string[] => ["--issue-token", spec(join(root, "token.jwt"))]],
    ["--unlock-credential", (): string[] => ["--unlock-credential", CREDENTIAL_ID]],
    ["--unlock-key-file", (): string[] => ["--unlock-key-file", keyPath]],
    ["--proxy", (): string[] => ["--proxy"]],
    ["--ssh-agent", (): string[] => ["--ssh-agent"]],
  ])(
    "server start %s without --session memory is refused SESSION_MODE_CONFLICT naming the flag, before the vault opens",
    async (flag, tail) => {
      const noVault = join(root, "no-vault-here");
      const run = await failedStart(
        ["server", "start", "--rest", ...tail()],
        withoutCredentialsDirectory(),
        noVault,
      );
      expect(run.code).toBe(1);
      expect(run.stderr).toContain(`[${ErrorCode.SESSION_MODE_CONFLICT}]`);
      expect(run.stderr).toContain(`${flag} requires --session memory`);
      expect(existsSync(noVault)).toBe(false);
    },
    60_000,
  );

  it("an explicit --session file is refused the same way: --proxy --session file", async () => {
    const noVault = join(root, "no-vault-here");
    const run = await failedStart(
      ["server", "start", "--rest", "--proxy", "--session", "file"],
      withoutCredentialsDirectory(),
      noVault,
    );
    expect(run.code).toBe(1);
    expect(run.stderr).toContain(`[${ErrorCode.SESSION_MODE_CONFLICT}]`);
    expect(run.stderr).toContain("--proxy requires --session memory");
    expect(existsSync(noVault)).toBe(false);
  }, 60_000);

  // The token file's access list on Windows is B7's (RA-B5-4): the option is refused there.
  it.runIf(process.platform === "win32")(
    "--issue-token on Windows is refused INVALID_INPUT naming the option, before the vault opens",
    async () => {
      const noVault = join(root, "no-vault-here");
      const run = await failedStart(
        ["server", "start", "--rest", "--session", "memory", "--issue-token", spec(tokenFile)],
        withoutCredentialsDirectory(),
        noVault,
      );
      expect(run.code).toBe(1);
      expect(run.stderr).toContain(`[${ErrorCode.INVALID_INPUT}]`);
      expect(run.stderr).toContain("--issue-token");
      expect(existsSync(noVault)).toBe(false);
    },
    60_000,
  );

  it("a memory-mode daemon loaded from the administrator's session keeps no tie to it: POST /api/v1/vault/lock seals the daemon and leaves the session file byte for byte, and the administrator's commands still run on it", async () => {
    const before = readFileSync(sessionPath);
    loaded = await startCliServerOnFreePort(
      (port) => ["server", "start", "--rest", "--port", String(port), "--session", "memory"],
      { vaultDir },
    );
    const origin = originOf(loaded);
    expect(await secretsStatus(origin)).toBe(200);

    const res = await fetch(`${origin}/api/v1/vault/lock`, { method: "POST", headers: admin() });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ data: { locked: true } });

    const after = await fetch(`${origin}/api/v1/secrets`, { headers: admin() });
    expect(after.status).toBe(503);
    expect(((await after.json()) as { error: string }).error).toBe(ErrorCode.VAULT_LOCKED);
    const health = await fetch(`${origin}/api/v1/health`);
    expect(((await health.json()) as { data: { state: string } }).data.state).toBe(
      VaultState.SEALED,
    );
    // Neither the daemon's requests (no slide) nor its lock (no erase) touched the file.
    expect(readFileSync(sessionPath).equals(before)).toBe(true);
    const names = (JSON.parse(await cli(["secret", "list", "--json"])) as { name: string }[]).map(
      (s) => s.name,
    );
    expect(names).toContain("api-key");
    await stop(loaded);
    loaded = undefined;
  }, 60_000);

  it("a memory-mode daemon unlocked from the credential writes no session: health unlocked, the administrator's session file byte for byte, the vault.unlock row with method credential", async () => {
    const before = readFileSync(sessionPath);
    credentialed = await startFromCredential([]);
    const origin = originOf(credentialed);
    const health = await fetch(`${origin}/api/v1/health`);
    expect(((await health.json()) as { data: { state: string } }).data.state).toBe(
      VaultState.UNLOCKED,
    );
    expect(await secretsStatus(origin)).toBe(200);
    expect(readFileSync(sessionPath).equals(before)).toBe(true);
    const unlocks = (await restAudit(origin, AuditEventType.VAULT_UNLOCK)).filter(
      (r) => r.detail?.["method"] === "credential",
    );
    expect(unlocks).toHaveLength(1);
  }, 60_000);

  it("harpoc lock as the vault user erases only the administrator's session: the file is gone, the administrator's commands are locked out, and the memory-mode daemon keeps serving", async () => {
    await cli(["lock"]);
    adminLockedAt = Date.now();
    expect(existsSync(sessionPath)).toBe(false);
    const locked = await runCli(["secret", "list"], { vaultDir });
    outputs.push(locked.stdout, locked.stderr);
    expect(locked.code).toBe(1);
    expect(locked.stderr).toContain("Vault is locked");
    expect(await secretsStatus(originOf(credentialed))).toBe(200);
  }, 60_000);

  // --issue-token is refused on Windows (RA-B5-4): the rotation rows run on the POSIX legs.
  it.skipIf(process.platform === "win32")(
    "--issue-token: the token file is in place, 0640, before the first request; the consumer's per-command read observes the re-mint at half the TTL with no restart, and the earlier token still verifies",
    async () => {
      rotating = await startFromCredential(["--issue-token", spec(tokenFile)]);
      const startedAt = Date.now();
      const origin = originOf(rotating);
      expect(existsSync(tokenFile)).toBe(true);
      expect((statSync(tokenFile).mode & 0o777).toString(8)).toBe("640");
      // The set-group-ID directory's group; that the group is the consumer's is B6's two-UID row.
      expect(statSync(tokenFile).gid).toBe(statSync(tokenDir).gid);
      firstToken = readFileSync(tokenFile, "utf8");
      issued.push(firstToken);
      expect(TOKEN_FILE_FORM.test(firstToken)).toBe(true);
      writeFileSync(stolenFile, firstToken, { mode: 0o600 });

      const listed = await rest(origin, tokenFile, ["secret", "list", "--json"]);
      expect(listed.code, listed.stderr).toBe(0);
      expect((JSON.parse(listed.stdout) as { name: string }[]).map((s) => s.name)).toContain(
        "api-key",
      );

      // A reader loop across the rename: every read is a whole token, the old or the new.
      let torn = 0;
      await vi.waitFor(
        () => {
          const now = readFileSync(tokenFile, "utf8");
          if (!TOKEN_FILE_FORM.test(now)) torn += 1;
          expect(now !== firstToken).toBe(true);
        },
        { timeout: 45_000, interval: 50 },
      );
      expect(torn).toBe(0);
      // Half the TTL, not at once (the instant itself is core's fake-timer row).
      expect(Date.now() - startedAt).toBeGreaterThanOrEqual(20_000);
      const second = readFileSync(tokenFile, "utf8");
      issued.push(second);
      expect(TOKEN_FILE_FORM.test(second)).toBe(true);
      expect(claimsOf(second).jti).not.toBe(claimsOf(firstToken).jti);

      const again = await rest(origin, tokenFile, ["secret", "list", "--json"]);
      expect(again.code, again.stderr).toBe(0);
      // Rotation revokes nothing: a copy of the first token verifies until its exp.
      const stolen = await rest(origin, stolenFile, ["secret", "list", "--json"]);
      expect(stolen.code, stolen.stderr).toBe(0);

      const rotations = (await restAudit(origin, AuditEventType.TOKEN_CREATE, true)).filter(
        (r) => r.detail?.["rotation"] === true,
      );
      expect(rotations.map((r) => r.detail?.["jti"]).sort()).toEqual(
        [claimsOf(firstToken).jti, claimsOf(second).jti].sort(),
      );
      for (const row of rotations) {
        expect(row.detail).toMatchObject({ subject: AGENT, scope: ["use", "list"] });
      }
      const trail = JSON.stringify(rotations);
      expect(trail.includes(firstToken.trim()) || trail.includes(second.trim())).toBe(false);
    },
    90_000,
  );

  it.skipIf(process.platform === "win32")(
    "a revoked token is not re-minted: auth revoke through another daemon reaches the rotating one at once — the consumer's next call is refused TOKEN_REVOKED, the next re-mint instant writes a failed token.create row and leaves the file as it was, and the rotator warns once",
    async () => {
      const origin = originOf(rotating);
      const live = readFileSync(tokenFile, "utf8");
      // The administrator's REST mode against the other daemon: a revocation another process
      // commits is in the rotating daemon's store at once.
      const revoked = await rest(originOf(credentialed), adminTokenFile, [
        "auth",
        "revoke",
        claimsOf(live).jti,
      ]);
      expect(revoked.code, revoked.stderr).toBe(0);

      const refused = await rest(origin, tokenFile, ["secret", "list"]);
      expect(refused.code).toBe(1);
      expect(refused.stderr).toContain(`[${ErrorCode.TOKEN_REVOKED}]`);

      await vi.waitFor(
        async () => {
          const failed = (await restAudit(origin, AuditEventType.TOKEN_CREATE, false)).filter(
            (r) => r.detail?.["rotation"] === true,
          );
          expect(failed).toHaveLength(1);
          expect(failed[0]?.detail).toMatchObject({
            subject: AGENT,
            rotation: true,
            error: ErrorCode.TOKEN_REVOKED,
          });
        },
        { timeout: 45_000, interval: 1_000 },
      );
      expect(readFileSync(tokenFile, "utf8") === live).toBe(true);
      const rotations = (await restAudit(origin, AuditEventType.TOKEN_CREATE, true)).filter(
        (r) => r.detail?.["rotation"] === true,
      );
      expect(rotations).toHaveLength(2);
      expect(rotating?.server.stderrSoFar().match(REVOKED_WARNING)).toHaveLength(1);
    },
    90_000,
  );

  it.skipIf(process.platform === "win32")(
    "a copy of an earlier token still dies at its exp: TOKEN_EXPIRED once its TTL has passed",
    async () => {
      const origin = originOf(rotating);
      await vi.waitFor(
        async () => {
          const run = await rest(origin, stolenFile, ["secret", "list"]);
          expect(run.stderr.includes(`[${ErrorCode.TOKEN_EXPIRED}]`)).toBe(true);
        },
        { timeout: 45_000, interval: 2_000 },
      );
      expect(Date.now() >= claimsOf(firstToken).exp * 1000).toBe(true);
    },
    60_000,
  );

  // Windows delivers no SIGTERM: kill() ends the child there without its shutdown path.
  it.skipIf(process.platform === "win32")(
    "SIGTERM stops a memory-mode daemon still serving a monitor interval after the administrator's lock: exit 0 and its server.stop row, and the vault opens again only by a new unlock",
    async () => {
      // No product event exists for a seal that must not happen: a file-mode monitor would have
      // sealed within one interval of the erase, so the daemon is judged after one has passed.
      const settle = adminLockedAt + SESSION_CLEANUP_INTERVAL_MS + 2_000 - Date.now();
      if (settle > 0) await new Promise<void>((resolve) => setTimeout(resolve, settle));
      expect(await secretsStatus(originOf(credentialed))).toBe(200);

      const daemon = credentialed as { server: CliServer; port: number };
      await stop(daemon);
      expect(daemon.server.child.exitCode).toBe(0);
      const locked = await runCli(["secret", "list"], { vaultDir });
      outputs.push(locked.stdout, locked.stderr);
      expect(locked.code).toBe(1);
      expect(locked.stderr).toContain("Vault is locked");
      expect(existsSync(sessionPath)).toBe(false);
      const stops = (await restAudit(originOf(rotating), AuditEventType.SERVER_STOP)).filter(
        (r) => r.detail?.["transport"] === "rest" && r.detail["port"] === daemon.port,
      );
      expect(stops).toHaveLength(1);
      expect(stops[0]?.detail).toMatchObject({ trigger: "SIGTERM" });
    },
    90_000,
  );

  it("no token reaches the daemons' output, the CLI's output or the audit trail", async () => {
    const reader = [rotating, credentialed].find((d) => d !== undefined && !d.server.exited());
    const trail = JSON.stringify(await restAudit(originOf(reader), AuditEventType.TOKEN_CREATE));
    const swept = [
      trail,
      ...[loaded, credentialed, rotating].flatMap((d) =>
        d === undefined ? [] : [d.server.stdoutSoFar(), d.server.stderrSoFar()],
      ),
      ...outputs,
    ];
    expect(issued.length).toBeGreaterThan(0);
    for (const text of swept) {
      for (const token of issued) expect(text.includes(token.trim())).toBe(false);
    }
  }, 60_000);
});
