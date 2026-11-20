import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createCa } from "@harpoc/cert-manager";
import { BackupScheduler, VaultEngine, writeUnlockKeyFile } from "@harpoc/core";
import {
  AuditEventType,
  ErrorCode,
  SESSION_FILE_NAME,
  VAULT_DB_NAME,
  VaultState,
} from "@harpoc/shared";
import type { AccessPolicy } from "@harpoc/shared";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";
import { grantOn } from "./helpers/engine-factory.js";
import { freePort, runCli, startCliServer, startCliServerOnFreePort } from "./helpers/spawn-cli.js";
import type { CliServer } from "./helpers/spawn-cli.js";

const PASSWORD = "backup-restore-master-pw-1";
const ARGON2_TIMEOUT_MS = 110_000;
const AGENT = "restore-agent";
const SECRET_VALUE = "backup-restore-fixture-value-5c2e";
const CA_HOST = "127.0.0.1";
const DAY_MS = 86_400_000;
const COPY_NAME = /^harpoc-\d{8}T\d{6}Z\.db$/;
const SLOT_KEYS = [
  "wrapped_kek_uk",
  "wrapped_kek_uk_iv",
  "wrapped_kek_uk_tag",
  "unlock_key_enrolled_at",
] as const;

interface AuditRow {
  event_type: string;
  success: boolean;
  detail: Record<string, unknown> | null;
}

interface MetaHandle {
  prepare(sql: string): { get(...params: unknown[]): unknown };
}

function slotValues(engine: VaultEngine): string[] {
  const { db } = (engine as unknown as { store: { db: MetaHandle } }).store;
  const read = db.prepare("SELECT value FROM vault_meta WHERE key = ?");
  return SLOT_KEYS.map((key) => (read.get(key) as { value: string } | undefined)?.value ?? "");
}

function withoutCredentialsDirectory(): NodeJS.ProcessEnv {
  const env = { ...process.env };
  delete env["CREDENTIALS_DIRECTORY"];
  return env;
}

describe("a scheduled copy taken under load, restored on a fresh install by the documented steps", () => {
  let root = "";
  let sourceDir = "";
  let backupDir = "";
  let restoredDir = "";
  let oldKeyFile = "";
  let oldKey: Uint8Array = new Uint8Array(0);
  let source: VaultEngine | undefined;
  let second: VaultEngine | undefined;
  let scheduler: BackupScheduler | undefined;
  let scheduledCopy = "";
  let sourceHandles: string[] = [];
  let sourcePolicies: AccessPolicy[] = [];
  let sourceRoot = "";
  let sourceSlot: string[] = [];
  let writtenWhileCopying = 0;
  let secondWrittenWhileCopying = 0;
  const schedulerErrors: unknown[] = [];
  const daemons: CliServer[] = [];

  async function cli(
    vaultDir: string,
    args: string[],
    stdin?: string,
    timeoutMs?: number,
  ): Promise<string> {
    const run = await runCli(args, { vaultDir, stdin, timeoutMs });
    expect(run.code, `${args.join(" ")}: ${run.stderr}`).toBe(0);
    return run.stdout;
  }

  function ownDirectory(name: string): string {
    const dir = join(root, name);
    mkdirSync(dir, { mode: 0o700 });
    chmodSync(dir, 0o700);
    return dir;
  }

  function placeCopy(copy: string, name: string): string {
    const dir = ownDirectory(name);
    const db = join(dir, VAULT_DB_NAME);
    copyFileSync(copy, db);
    chmodSync(db, 0o600);
    return dir;
  }

  function expectNoSlotValue(copy: string): void {
    const bytes = readFileSync(copy).toString("latin1");
    SLOT_KEYS.forEach((key, index) => {
      expectAbsent(bytes, sourceSlot[index] as string, `the copy's bytes (${key})`);
    });
  }

  async function takeScheduledCopyUnderLoad(
    engine: VaultEngine,
    writer: VaultEngine,
  ): Promise<string> {
    let copying = false;
    let reportRun: (run: { settled: Promise<{ file: string }> }) => void = () => undefined;
    const firstRun = new Promise<{ settled: Promise<{ file: string }> }>((resolve) => {
      reportRun = resolve;
    });
    const observed: Pick<VaultEngine, "backupToDirectory"> = {
      backupToDirectory: (dir, options) => {
        const run = engine.backupToDirectory(dir, options);
        copying = true;
        reportRun({
          settled: run.finally(() => {
            copying = false;
          }),
        });
        return run;
      },
    };
    const running = new BackupScheduler(observed, {
      dir: backupDir,
      intervalMs: DAY_MS,
      keep: 7,
      label: "--backup-dir",
      onError: (err) => schedulerErrors.push(err),
    });
    scheduler = running;
    let loading = true;
    const load = (async () => {
      while (loading) {
        engine.listSecrets();
        if (copying) writtenWhileCopying += 1;
        writer.listSecrets();
        if (copying) secondWrittenWhileCopying += 1;
        await new Promise<void>((resolve) => setImmediate(resolve));
      }
    })();
    try {
      running.start();
      const { settled } = await firstRun;
      return (await settled).file;
    } finally {
      loading = false;
      await load;
      await running.stop();
    }
  }

  beforeAll(async () => {
    root = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-backup-restore-")));
    chmodSync(root, 0o700);
    sourceDir = ownDirectory("source");
    backupDir = ownDirectory("backups");
    const dbPath = join(sourceDir, VAULT_DB_NAME);
    const sessionPath = join(sourceDir, SESSION_FILE_NAME);
    const engine = new VaultEngine({ dbPath, sessionPath });
    source = engine;
    await engine.initVault(PASSWORD);
    engine.registerAgent({ name: AGENT });
    const created = await engine.createSecret({
      name: "restore-api-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from(SECRET_VALUE, "utf8")),
    });
    await grantOn(engine, created.handle, AGENT, ["read"]);
    const ca = createCa({ permittedHosts: [CA_HOST], validityDays: 30 });
    await engine.createProxyCa({
      certPem: ca.certPem,
      keyPem: ca.keyPem,
      rootPem: ca.rootPem,
      hosts: [CA_HOST],
    });
    oldKey = await engine.enrollUnlockKey();
    oldKeyFile = join(root, "old-machine.key");
    await writeUnlockKeyFile(oldKeyFile, oldKey);

    sourceHandles = engine
      .listSecrets()
      .map((secret) => secret.handle)
      .sort();
    sourcePolicies = engine.listPolicies();
    sourceRoot = (await engine.proxyCaCertificate())?.certPem ?? "";
    sourceSlot = slotValues(engine);

    const writer = new VaultEngine({ dbPath, sessionPath });
    second = writer;
    await writer.loadSession();
    scheduledCopy = await takeScheduledCopyUnderLoad(engine, writer);
  }, 180_000);

  afterAll(async () => {
    try {
      for (const daemon of daemons) await daemon.stop();
      await scheduler?.stop();
      await second?.destroy();
      await source?.destroy();
    } finally {
      oldKey.fill(0);
      if (root !== "") {
        rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      }
    }
  });

  it("the source holds what a restore must bring back: two handles, a grant, the CA's root and an enrolled unlock key", () => {
    expect(sourceHandles).toEqual(["secret://harpoc-ca", "secret://restore-api-key"]);
    expect(sourcePolicies.map((p) => [p.principal_type, p.principal_id, p.permissions])).toEqual([
      ["agent", AGENT, ["read"]],
    ]);
    expect(sourceRoot.startsWith("-----BEGIN CERTIFICATE-----")).toBe(true);
    expect(sourceSlot.every((value) => value.length > 0)).toBe(true);
  });

  it("the scheduler's copy, taken while the engine and a second engine on the same file keep writing, finishes as one harpoc-<stamp>.db with no temporary file beside it, and the engine answered during the copy", () => {
    expect(schedulerErrors).toEqual([]);
    expect(dirname(scheduledCopy)).toBe(backupDir);
    expect(basename(scheduledCopy)).toMatch(COPY_NAME);
    expect(readdirSync(backupDir)).toEqual([basename(scheduledCopy)]);
    expect(writtenWhileCopying).toBeGreaterThan(0);
    expect(secondWrittenWhileCopying).toBeGreaterThan(1);
    expect((source as VaultEngine).verifyAuditChain().valid).toBe(true);
  });

  it.skipIf(process.platform === "win32")(
    "the copy is 0600 in its 0700 directory (POSIX modes; on win32 the access list is the copy's own step)",
    () => {
      expect((statSync(scheduledCopy).mode & 0o777).toString(8)).toBe("600");
      expect((statSync(backupDir).mode & 0o777).toString(8)).toBe("700");
    },
  );

  it("the copy's bytes hold none of the four values of the source's unlock-key slot", () => {
    expectNoSlotValue(scheduledCopy);
  });

  it("placed as the database of a fresh vault directory, the copy opens by the password alone: harpoc unlock exits 0", async () => {
    restoredDir = placeCopy(scheduledCopy, "restored");
    await cli(restoredDir, ["unlock"], `${PASSWORD}\n`, ARGON2_TIMEOUT_MS);
  }, 180_000);

  it("harpoc unlock-key status reports no key", async () => {
    const status = JSON.parse(await cli(restoredDir, ["unlock-key", "status", "--json"])) as {
      enrolled: boolean;
    };
    expect(status).toEqual({ enrolled: false });
  });

  it("server start --unlock-key-file with the old machine's key is refused UNLOCK_KEY_NOT_ENROLLED", async () => {
    const port = await freePort();
    const server = startCliServer(
      [
        "server",
        "start",
        "--rest",
        "--port",
        String(port),
        "--session",
        "memory",
        "--unlock-key-file",
        oldKeyFile,
      ],
      { vaultDir: restoredDir, env: withoutCredentialsDirectory() },
    );
    daemons.push(server);
    const closed = await server.closed();
    expect(closed.code).toBe(1);
    expect(server.stderrSoFar()).toContain(`[${ErrorCode.UNLOCK_KEY_NOT_ENROLLED}]`);
  });

  it("secret list and policy list name what the source had", async () => {
    const secrets = JSON.parse(await cli(restoredDir, ["secret", "list", "--json"])) as {
      handle: string;
    }[];
    expect(secrets.map((secret) => secret.handle).sort()).toEqual(sourceHandles);
    const policies = JSON.parse(await cli(restoredDir, ["policy", "list", "--json"])) as unknown;
    expect(policies).toEqual(JSON.parse(JSON.stringify(sourcePolicies)));
  });

  it("audit verify exits 0, and the trail holds the copy's own vault.backup row", async () => {
    const report = JSON.parse(await cli(restoredDir, ["audit", "verify", "--json"])) as {
      valid: boolean;
    };
    expect(report.valid).toBe(true);
    const rows = JSON.parse(
      await cli(restoredDir, ["audit", "--event", AuditEventType.VAULT_BACKUP, "--json"]),
    ) as AuditRow[];
    expect(rows.map(({ success, detail }) => ({ success, detail }))).toEqual([
      { success: true, detail: { trigger: "schedule", file: basename(scheduledCopy) } },
    ]);
  });

  it("proxy ca export prints the source's root, byte for byte", async () => {
    const exported = await cli(restoredDir, ["proxy", "ca", "export"]);
    expect(exported).toBe(sourceRoot);
  });

  it("unlock-key enroll writes a new key, and a start with it serves GET /api/v1/health", async () => {
    const newKeyFile = join(root, "new-machine.key");
    await cli(
      restoredDir,
      ["unlock-key", "enroll", "--out", newKeyFile],
      `${PASSWORD}\n`,
      ARGON2_TIMEOUT_MS,
    );
    expect(statSync(newKeyFile).size).toBe(32);
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
        newKeyFile,
      ],
      { vaultDir: restoredDir, env: withoutCredentialsDirectory() },
    );
    daemons.push(started.server);
    try {
      const res = await fetch(`http://127.0.0.1:${String(started.port)}/api/v1/health`);
      expect(res.status).toBe(200);
      expect(((await res.json()) as { data: { state: string } }).data.state).toBe(
        VaultState.UNLOCKED,
      );
    } finally {
      await started.server.stop();
    }
  }, 180_000);

  describe("harpoc backup <file>", () => {
    let attendedFile = "";

    it("writes a file with the same properties: it opens by password alone, lists the same handles and policies, verifies its chain with its own vault.backup row, holds no unlock-key slot and keeps the CA", async () => {
      attendedFile = join(ownDirectory("attended"), "vault-copy.db");
      const written = JSON.parse(await cli(sourceDir, ["backup", attendedFile, "--json"])) as {
        backup_file: string;
      };
      expect(written.backup_file).toBe(attendedFile);
      expectNoSlotValue(attendedFile);

      const placed = placeCopy(attendedFile, "restored-attended");
      const engine = new VaultEngine({
        dbPath: join(placed, VAULT_DB_NAME),
        sessionPath: join(placed, SESSION_FILE_NAME),
        sessionMode: "memory",
      });
      try {
        await expectVaultError(
          () => engine.unlockWithKey(new Uint8Array(oldKey)),
          ErrorCode.UNLOCK_KEY_NOT_ENROLLED,
        );
        await engine.unlock(PASSWORD);
        expect(await engine.unlockKeyStatus()).toEqual({ enrolled: false });
        expect(
          engine
            .listSecrets()
            .map((secret) => secret.handle)
            .sort(),
        ).toEqual(sourceHandles);
        expect(engine.listPolicies()).toEqual(sourcePolicies);
        expect(engine.verifyAuditChain().valid).toBe(true);
        const commandRows = engine
          .queryAudit({ eventType: AuditEventType.VAULT_BACKUP })
          .filter((row) => row.detail?.["trigger"] === "command");
        expect(commandRows.map(({ success, detail }) => ({ success, detail }))).toEqual([
          { success: true, detail: { trigger: "command", file: basename(attendedFile) } },
        ]);
        expect((await engine.proxyCaCertificate())?.certPem).toBe(sourceRoot);
      } finally {
        await engine.destroy();
      }
    }, 180_000);

    it("a second call on that file is refused before the vault opens and leaves the file as it was", async () => {
      const before = readFileSync(attendedFile);
      const run = await runCli(["backup", attendedFile], { vaultDir: sourceDir });
      expect(run.code).toBe(1);
      expect(run.stderr.trim()).toBe(
        `Error: [${ErrorCode.INVALID_INPUT}] <file>: ${attendedFile} exists; a backup is written to a new file only`,
      );
      expect(readFileSync(attendedFile).equals(before)).toBe(true);
    });
  });
});
