import { randomBytes } from "node:crypto";
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
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AuditEventType, ErrorCode, SESSION_FILE_NAME, VaultState } from "@harpoc/shared";
import { canon } from "./helpers/key-needles.js";
import { runCli, startCliServer, startCliServerOnFreePort } from "./helpers/spawn-cli.js";
import type { CliServer } from "./helpers/spawn-cli.js";

/**
 * The headless start on the built CLI (design M1, tranche B4): `unlock-key enroll`
 * writes the unlock key under a password unlock, and `server start --unlock-credential
 * <id>` unlocks its own engine from `$CREDENTIALS_DIRECTORY/<id>` — here a directory the
 * suite fills the way systemd's `LoadCredentialEncrypted=` does (DB-1: the fake directory
 * on every leg; the real systemd delivery is `systemd-credential.test.ts`, Linux only) —
 * with no prompt and no session file before it, then serves an authenticated request.
 * The daemon runs in the memory session (tranche B5) and writes no session file, so the
 * administrator unlocks again for their own commands, which the daemon serves through.
 * `--unlock-key-file` is the sealer-agnostic input. The refusals: the variable unset, a
 * credential the directory lacks, a group- or world-readable key file, and a wrong key,
 * which counts against the lockout the password path shares.
 */

const PASSWORD = "unlock-key-master-pw-1";
const ARGON2_TIMEOUT_MS = 110_000;
const AGENT = "agent-k";
const SECRET_VALUE = "unlock-key-fixture-value-3e9a";
const CREDENTIAL_ID = "harpoc-unlock";
const STANDING_WARNING = /a password file by another name/g;

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

describe("the headless start on the built CLI (unlock-key enroll, server start --unlock-credential, --unlock-key-file)", () => {
  let root = "";
  let vaultDir = "";
  let credentials = "";
  let keyPath = "";
  let key = Buffer.alloc(0);
  let daemon: CliServer | undefined;
  let origin = "";
  let sessionFileBeforeStart = true;
  let sessionFileAfterStart = true;
  let enrollOutput = "";
  const outputs: string[] = [];

  async function cli(args: string[], stdin?: string, timeoutMs?: number): Promise<string> {
    const run = await runCli(args, { vaultDir, stdin, timeoutMs });
    outputs.push(run.stdout, run.stderr);
    expect(run.code, `${args.join(" ")}: ${run.stderr}`).toBe(0);
    return run.stdout;
  }

  async function auditRows(event: string): Promise<AuditRow[]> {
    return JSON.parse(
      await cli(["audit", "--event", event, "--limit", "500", "--json"]),
    ) as AuditRow[];
  }

  /** A start that must fail: the child's exit and output, with `env` as its whole environment. */
  async function failedStart(
    args: string[],
    env: NodeJS.ProcessEnv,
    dir = vaultDir,
  ): Promise<Exit> {
    const server = startCliServer(args, { vaultDir: dir, env });
    const closed = await server.closed();
    outputs.push(server.stdoutSoFar(), server.stderrSoFar());
    return { code: closed.code, stdout: server.stdoutSoFar(), stderr: server.stderrSoFar() };
  }

  function withoutCredentialsDirectory(): NodeJS.ProcessEnv {
    const env = { ...process.env };
    delete env["CREDENTIALS_DIRECTORY"];
    return env;
  }

  /** A credentials directory as systemd hands one over: the unit's user alone, the file read-only. */
  function credentialsDirectory(name: string, bytes: Buffer): string {
    const dir = join(root, name);
    mkdirSync(dir, { mode: 0o700 });
    chmodSync(dir, 0o700);
    writeFileSync(join(dir, CREDENTIAL_ID), bytes, { mode: 0o400 });
    chmodSync(join(dir, CREDENTIAL_ID), 0o400);
    return dir;
  }

  beforeAll(async () => {
    root = mkdtempSync(join(tmpdir(), "harpoc-ukey-"));
    vaultDir = join(root, "vault");
    mkdirSync(vaultDir);
    keyPath = join(root, "unlock.key");

    // init leaves the vault unlocked with a session file.
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
      "read",
    ]);
    // One password unlock (one Argon2id) in the CLI's own process, then the key on disk.
    await cli(["unlock-key", "enroll", "--out", keyPath], `${PASSWORD}\n`, ARGON2_TIMEOUT_MS);
    enrollOutput = outputs.at(-1) ?? "";
    key = readFileSync(keyPath);
    // No session survives the administrator's work: the daemon must unlock from the key.
    await cli(["lock"]);
    sessionFileBeforeStart = existsSync(join(vaultDir, SESSION_FILE_NAME));

    credentials = join(root, "credentials");
    mkdirSync(credentials, { mode: 0o700 });
    chmodSync(credentials, 0o700);
    copyFileSync(keyPath, join(credentials, CREDENTIAL_ID));
    chmodSync(join(credentials, CREDENTIAL_ID), 0o400);

    const started = await startCliServerOnFreePort(
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
      ],
      { vaultDir, env: { ...process.env, CREDENTIALS_DIRECTORY: credentials } },
    );
    daemon = started.server;
    origin = `http://127.0.0.1:${String(started.port)}`;
    sessionFileAfterStart = existsSync(join(vaultDir, SESSION_FILE_NAME));
    // The administrator's own session for the commands below (a third Argon2id): the daemon
    // holds none, so this unlock neither feeds nor seals it.
    await cli(["unlock"], `${PASSWORD}\n`, ARGON2_TIMEOUT_MS);
  }, 360_000);

  afterAll(async () => {
    try {
      await daemon?.stop();
    } finally {
      if (root !== "") {
        rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      }
    }
  });

  it("unlock-key enroll writes the 32-byte key to --out and names the file, never the key", () => {
    expect(key.length).toBe(32);
    expect(enrollOutput.includes(keyPath)).toBe(true);
  });

  // POSIX modes; on win32 the key file's owner-only ACL is the CLI's own icacls step.
  it.skipIf(process.platform === "win32")("unlock-key enroll writes the key file 0400", () => {
    expect((statSync(keyPath).mode & 0o777).toString(8)).toBe("400");
  });

  it("the daemon starts from the credentials directory with no prompt, no session file before it and none after it: health reports the vault unlocked", async () => {
    expect(sessionFileBeforeStart).toBe(false);
    expect(sessionFileAfterStart).toBe(false);
    const res = await fetch(`${origin}/api/v1/health`);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { data: { state: string } }).data.state).toBe(
      VaultState.UNLOCKED,
    );
  }, 60_000);

  it("the first authenticated request needs no person: a read-scoped token the administrator mints through their own session reads the secret the daemon decrypts", async () => {
    const tokenFile = join(root, "token.jwt");
    await cli([
      "auth",
      "token",
      "--agent",
      AGENT,
      "--scope",
      "read",
      "--ttl",
      "60",
      "--out",
      tokenFile,
    ]);
    const token = readFileSync(tokenFile, "utf8").trim();
    const res = await fetch(`${origin}/api/v1/secrets/api-key/value`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: { value: string } };
    expect(Buffer.from(body.data.value, "base64").toString("utf8") === SECRET_VALUE).toBe(true);
  }, 60_000);

  it("unlock-key status reports the slot enrolled, with its date", async () => {
    const status = JSON.parse(await cli(["unlock-key", "status", "--json"])) as {
      enrolled: boolean;
      enrolledAt?: string;
    };
    expect(status.enrolled).toBe(true);
    expect(Number.isNaN(Date.parse(status.enrolledAt ?? ""))).toBe(false);
  }, 60_000);

  it("the audit trail: one vault.unlock_key.enroll row, the daemon's vault.unlock row with method credential, the password unlock's row without a detail", async () => {
    const enrolled = await auditRows(AuditEventType.VAULT_UNLOCK_KEY_ENROLL);
    expect(enrolled).toHaveLength(1);
    expect(enrolled[0]?.success).toBe(true);
    const unlocks = await auditRows(AuditEventType.VAULT_UNLOCK);
    expect(unlocks.filter((r) => r.detail?.["method"] === "credential")).toHaveLength(1);
    expect(unlocks.filter((r) => r.detail?.["method"] === "credential")[0]?.detail).toEqual({
      method: "credential",
    });
    expect(unlocks.filter((r) => r.detail === null).length).toBeGreaterThanOrEqual(1);
    expect(unlocks.filter((r) => r.detail !== null && r.detail["method"] !== "credential")).toEqual(
      [],
    );
  }, 60_000);

  // Windows delivers no SIGTERM: kill() ends the child there without its shutdown path.
  it.skipIf(process.platform === "win32")(
    "the daemon stops on SIGTERM with its server.stop row",
    async () => {
      const server = daemon as CliServer;
      await server.stop();
      expect(server.child.exitCode).toBe(0);
      const rows = (await auditRows(AuditEventType.SERVER_STOP)).filter(
        (r) => r.detail?.["transport"] === "rest",
      );
      expect(rows).toHaveLength(1);
      expect(rows[0]?.detail).toMatchObject({ trigger: "SIGTERM" });
    },
    60_000,
  );

  it("--unlock-credential with CREDENTIALS_DIRECTORY unset is refused INVALID_INPUT naming the variable, before any vault is opened", async () => {
    const noVault = join(root, "no-vault-here");
    const run = await failedStart(
      ["server", "start", "--rest", "--session", "memory", "--unlock-credential", CREDENTIAL_ID],
      withoutCredentialsDirectory(),
      noVault,
    );
    expect(run.code).toBe(1);
    expect(run.stderr).toContain(`[${ErrorCode.INVALID_INPUT}]`);
    expect(run.stderr).toContain("CREDENTIALS_DIRECTORY");
    expect(existsSync(noVault)).toBe(false);
  }, 60_000);

  it("a credential the directory does not hold is refused INVALID_INPUT naming it, and opens no session", async () => {
    const before = (await auditRows(AuditEventType.VAULT_UNLOCK)).length;
    const run = await failedStart(
      ["server", "start", "--rest", "--session", "memory", "--unlock-credential", "harpoc-absent"],
      { ...process.env, CREDENTIALS_DIRECTORY: credentials },
    );
    expect(run.code).toBe(1);
    expect(run.stderr).toContain(`[${ErrorCode.INVALID_INPUT}]`);
    expect(run.stderr).toContain("harpoc-absent");
    expect((await auditRows(AuditEventType.VAULT_UNLOCK)).length).toBe(before);
  }, 60_000);

  // POSIX modes: on win32 a file's mode bits do not carry its ACL.
  it.skipIf(process.platform === "win32")(
    "--unlock-key-file with a 0644 key is refused UNLOCK_KEY_SOURCE_UNSAFE naming the mode, before any vault is opened",
    async () => {
      const lax = join(root, "lax.key");
      copyFileSync(keyPath, lax);
      chmodSync(lax, 0o644);
      const noVault = join(root, "no-vault-here");
      const run = await failedStart(
        ["server", "start", "--rest", "--session", "memory", "--unlock-key-file", lax],
        withoutCredentialsDirectory(),
        noVault,
      );
      expect(run.code).toBe(1);
      expect(run.stderr.includes(`[${ErrorCode.UNLOCK_KEY_SOURCE_UNSAFE}]`)).toBe(true);
      expect(run.stderr.includes("644")).toBe(true);
      expect(existsSync(noVault)).toBe(false);
    },
    60_000,
  );

  it("--unlock-key-file with the owner-only key unlocks the daemon and prints the standing warning once", async () => {
    const started = await startCliServerOnFreePort(
      (port) => [
        "server",
        "start",
        "--rest",
        "--port",
        String(port),
        "--session",
        "memory",
        "--unlock-key-file",
        keyPath,
      ],
      { vaultDir, env: withoutCredentialsDirectory() },
    );
    try {
      const res = await fetch(`http://127.0.0.1:${String(started.port)}/api/v1/health`);
      expect(((await res.json()) as { data: { state: string } }).data.state).toBe(
        VaultState.UNLOCKED,
      );
      expect(started.server.stderrSoFar().match(STANDING_WARNING)).toHaveLength(1);
    } finally {
      await started.server.stop();
      outputs.push(started.server.stdoutSoFar(), started.server.stderrSoFar());
    }
  }, 60_000);

  it("a wrong key is refused INVALID_UNLOCK_KEY and counts against the lockout the password shares: after five, the password is refused too", async () => {
    const wrong = credentialsDirectory("credentials-wrong", randomBytes(32));
    const unlocksBefore = (await auditRows(AuditEventType.VAULT_UNLOCK)).length;
    for (let attempt = 1; attempt <= 5; attempt++) {
      const run = await failedStart(
        ["server", "start", "--rest", "--session", "memory", "--unlock-credential", CREDENTIAL_ID],
        { ...process.env, CREDENTIALS_DIRECTORY: wrong },
      );
      expect(run.code, `attempt ${String(attempt)}`).toBe(1);
      expect(run.stderr.includes(`[${ErrorCode.INVALID_UNLOCK_KEY}]`)).toBe(true);
    }
    // LOCKOUT_ACTIVE is checked before the key derivation: no Argon2id runs here.
    const unlock = await runCli(["unlock"], { vaultDir, stdin: `${PASSWORD}\n` });
    outputs.push(unlock.stdout, unlock.stderr);
    expect(unlock.code).toBe(1);
    expect(unlock.stderr).toMatch(/Account locked\. Try again in \d+s\./);
    expect((await auditRows(AuditEventType.VAULT_UNLOCK)).length).toBe(unlocksBefore);
  }, 120_000);

  it("no byte of the key reaches any output the suite captured or the audit trail", async () => {
    const trail = await cli(["audit", "--limit", "500", "--json"]);
    const needles = [key.toString("hex"), key.toString("base64"), key.toString("base64url")];
    const strippedForms: [form: string, needle: string][] = [
      ["a decimal list", Array.from(key).join(",")],
      ["a JSON object", JSON.stringify(new Uint8Array(key))],
    ];
    const swept = [trail, daemon?.stdoutSoFar() ?? "", daemon?.stderrSoFar() ?? "", ...outputs];
    for (const text of swept) {
      for (const needle of needles) expect(canon(text).includes(needle)).toBe(false);
      const stripped = text.replace(/\s+/g, "");
      for (const [form, needle] of strippedForms) {
        expect(stripped.includes(needle), `an output carries the key as ${form}`).toBe(false);
      }
    }
  }, 60_000);
});
