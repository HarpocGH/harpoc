import { createHash, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AuditEventType, VaultState } from "@harpoc/shared";
import { getPkgRoot } from "@harpoc/test-utils";
import { assertTierAvailable } from "./helpers/platform-tiers.js";
import { CLI_ENTRY, freePort, runAs, runCliAs, runCommand } from "./helpers/spawn-cli.js";

/**
 * The reference sealer on a real systemd (design M1, tranche B4 — DB-1's host-mode
 * round trip): a credential encrypted with `systemd-creds encrypt --with-key=host` and
 * handed to a transient unit through `LoadCredentialEncrypted=` reaches the unit's
 * `$CREDENTIALS_DIRECTORY` as the bytes that were sealed, readable by the unit's user;
 * and the built CLI under such a unit, as the vault user, unlocks from it with
 * `server start --unlock-credential` — the one row that hands the CLI's credential reader
 * a file systemd itself wrote (the fake directory of `unlock-key.test.ts` holds a file the
 * suite wrote). `${CREDENTIALS_DIRECTORY}` in a command is expanded by the service manager
 * (systemd-run(1), systemd.exec(5) § Credentials): no shell runs in any unit.
 *
 * Linux with systemd as PID 1 only (`/run/systemd/system`, sd_booted(3)), `systemd-creds`
 * of systemd 254 or later (systemd-run's command expansion), passwordless `sudo -n` and
 * the vault user of the `two-uid` tier; where the `systemd-creds` tier of
 * HARPOC_REQUIRE_PLATFORM_TESTS is required (the ubuntu legs) a missing prerequisite fails
 * instead of skipping. The dev container has no PID 1 systemd and skips.
 */

const VAULT_USER = process.env["HARPOC_TWO_UID_VAULT_USER"];
const PASSWORD = "systemd-creds-master-pw-1";
const ARGON2_TIMEOUT_MS = 110_000;
const MIN_SYSTEMD = 254;
const UNIT = resolve(
  getPkgRoot(import.meta.url),
  "..",
  "..",
  "deploy",
  "systemd",
  "harpoc.service",
);

/**
 * The [Service] directives of deploy/systemd/harpoc.service the transient unit takes over,
 * so the daemon runs under the unit's own sandbox. Left out: what the test sets itself (the
 * user, the command, the credential, the environment), what a transient unit does not need
 * (the restart policy, the type it sets), and what the runner's layout forbids — the
 * checkout lives under /home (ProtectHome=) and the vault directory under /tmp (PrivateTmp=),
 * which the test makes writable in place of the unit's StateDirectory= and ReadWritePaths=.
 */
const NOT_TAKEN_OVER = new Set([
  "Type",
  "User",
  "Group",
  "LoadCredentialEncrypted",
  "Environment",
  "ExecStart",
  "StateDirectory",
  "StateDirectoryMode",
  "ReadWritePaths",
  "Restart",
  "RestartSec",
  "ProtectHome",
  "PrivateTmp",
]);

function unitSandbox(): string[] {
  const lines = readFileSync(UNIT, "utf8").split("\n");
  const service = lines.slice(lines.indexOf("[Service]") + 1, lines.indexOf("[Install]"));
  return service
    .filter((l) => /^[A-Za-z]+=/.test(l) && !NOT_TAKEN_OVER.has(l.slice(0, l.indexOf("="))))
    .map((l) => `--property=${l}`);
}

interface AuditRow {
  event_type: string;
  detail: Record<string, unknown> | null;
}

describe.skipIf(process.platform !== "linux")(
  "the systemd credential on a real systemd (Linux only: systemd-creds, systemd-run, sudo -n)",
  () => {
    let available = false;
    let vault = "";
    let root = "";
    let vaultDir: string | undefined;
    let unit: string | undefined;

    const asRoot = (argv: string[]) => runAs("root", argv);
    const asVault = (args: string[], opts: { stdin?: string; timeoutMs?: number } = {}) =>
      runCliAs(vault, args, { vaultDir: vaultDir as string, ...opts });

    /** `argv` in a transient service as `user` with one encrypted credential, waited for. */
    function runInUnit(credential: string, argv: string[]) {
      return asRoot([
        "systemd-run",
        "--quiet",
        "--wait",
        "--pipe",
        "--collect",
        "--property=Type=exec",
        `--uid=${vault}`,
        `--property=LoadCredentialEncrypted=${credential}`,
        "--",
        ...argv,
      ]);
    }

    async function seal(name: string, plain: string, sealed: string): Promise<void> {
      const encrypted = await asRoot([
        "systemd-creds",
        "encrypt",
        `--name=${name}`,
        "--with-key=host",
        "--",
        plain,
        sealed,
      ]);
      expect(encrypted.code, encrypted.stderr).toBe(0);
    }

    beforeAll(async () => {
      let probeError: unknown;
      try {
        if (!existsSync("/run/systemd/system")) {
          throw new Error("systemd is not PID 1 (no /run/systemd/system)");
        }
        const version = await runCommand("systemd-creds", ["--version"]);
        const major = Number(/^systemd (\d+)/.exec(version.stdout)?.[1]);
        if (version.code !== 0 || !(major >= MIN_SYSTEMD)) {
          throw new Error(
            `systemd-creds --version: exit ${String(version.code)}, "${version.stdout.split("\n")[0] ?? ""}" (systemd ${String(MIN_SYSTEMD)} or later needed)`,
          );
        }
        const sudo = await runCommand("sudo", ["-n", "true"]);
        if (sudo.code !== 0) throw new Error(`sudo -n true: ${sudo.stderr.trim()}`);
        if (VAULT_USER === undefined) throw new Error("HARPOC_TWO_UID_VAULT_USER is not set");
        const probe = await runAs(VAULT_USER, [process.execPath, CLI_ENTRY, "--version"]);
        if (probe.code !== 0) {
          throw new Error(
            `sudo -n -u ${VAULT_USER} cannot run the built CLI: ${probe.stderr.trim()}`,
          );
        }
        available = true;
      } catch (err) {
        probeError = err;
      }
      assertTierAvailable("systemd-creds", available, probeError);
      if (!available) return;
      vault = VAULT_USER as string;
      root = mkdtempSync(join(tmpdir(), "harpoc-sdc-"));
    }, 60_000);

    afterAll(async () => {
      if (!available) return;
      try {
        if (unit !== undefined) {
          const active = await asRoot(["systemctl", "is-active", "--quiet", `${unit}.service`]);
          if (active.code === 0) {
            const stopped = await asRoot(["systemctl", "stop", `${unit}.service`]);
            expect(stopped.code, stopped.stderr).toBe(0);
          }
        }
      } finally {
        if (vaultDir !== undefined) {
          const leftover = await runAs(vault, ["pkill", "-KILL", "-u", vault, "-f", vaultDir]);
          const removed = await runAs(vault, ["rm", "-rf", "--", vaultDir]);
          expect(leftover.code, "a process of the vault user outlived the suite").toBe(1);
          expect(removed.code, removed.stderr).toBe(0);
        }
        rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      }
    });

    it("a host-key credential reaches the unit's $CREDENTIALS_DIRECTORY as the sealed bytes, readable by the unit's user and by no other", async (ctx) => {
      if (!available) return ctx.skip();
      const id = `harpoc-ci-${randomBytes(4).toString("hex")}`;
      const plain = join(root, "plain.bin");
      const sealed = join(root, `${id}.cred`);
      const bytes = randomBytes(32);
      writeFileSync(plain, bytes, { mode: 0o400 });
      chmodSync(plain, 0o400);
      await seal(id, plain, sealed);

      const digest = await runInUnit(`${id}:${sealed}`, [
        "/usr/bin/sha256sum",
        "--",
        `\${CREDENTIALS_DIRECTORY}/${id}`,
      ]);
      expect(digest.code, digest.stderr).toBe(0);
      const sum = createHash("sha256").update(bytes).digest("hex");
      expect(digest.stdout.split(" ")[0] === sum).toBe(true);

      const stat = await runInUnit(`${id}:${sealed}`, [
        "/usr/bin/stat",
        "-L",
        "--",
        `\${CREDENTIALS_DIRECTORY}/${id}`,
      ]);
      expect(stat.code, stat.stderr).toBe(0);
      const access = /Access: \(0(\d{3})\/[^)]*\)\s+Uid: \(\s*(\d+)\//.exec(stat.stdout);
      expect(access, stat.stdout).not.toBeNull();
      const mode = parseInt(access?.[1] ?? "777", 8);
      console.log(
        `[systemd-creds] the credential file systemd hands the unit: mode ${(access?.[1] ?? "?").padStart(4, "0")}, uid ${access?.[2] ?? "?"}`,
      );
      expect(mode & 0o007).toBe(0);
      expect(mode & 0o222).toBe(0);
    }, 60_000);

    it("the built CLI under a transient unit with the unit's sandbox, as the vault user, unlocks from the sealed unlock key with no person: health unlocked, the vault.unlock row method credential, SIGTERM through systemctl stop", async (ctx) => {
      if (!available) return ctx.skip();
      const made = await runAs(vault, ["mktemp", "-d", join(tmpdir(), "harpoc-sdc-vault-XXXXXX")]);
      expect(made.code, made.stderr).toBe(0);
      vaultDir = made.stdout.trim();
      const init = await asVault(["init"], {
        stdin: `${PASSWORD}\n${PASSWORD}\n`,
        timeoutMs: ARGON2_TIMEOUT_MS,
      });
      expect(init.code, init.stderr).toBe(0);
      const keyFile = join(vaultDir, "unlock.key");
      const enrolled = await asVault(["unlock-key", "enroll", "--out", keyFile], {
        stdin: `${PASSWORD}\n`,
        timeoutMs: ARGON2_TIMEOUT_MS,
      });
      expect(enrolled.code, enrolled.stderr).toBe(0);
      const locked = await asVault(["lock"]);
      expect(locked.code, locked.stderr).toBe(0);
      // The recipe's encrypt line (deploy/linux/enroll-unlock-key.sh) with --with-key=host and
      // a scratch path: the recipe's own paths are the host's /etc/credstore.encrypted.
      const sealed = join(root, "harpoc-unlock.cred");
      await seal("harpoc-unlock", keyFile, sealed);

      const port = await freePort();
      unit = `harpoc-sdc-${randomBytes(4).toString("hex")}`;
      const started = await asRoot([
        "systemd-run",
        "--quiet",
        `--unit=${unit}`,
        "--collect",
        "--property=Type=exec",
        `--uid=${vault}`,
        `--property=LoadCredentialEncrypted=harpoc-unlock:${sealed}`,
        "--setenv=HARPOC_SESSION_KEYSTORE=off",
        ...unitSandbox(),
        `--property=ReadWritePaths=${vaultDir}`,
        "--",
        process.execPath,
        CLI_ENTRY,
        "--vault-dir",
        vaultDir,
        "server",
        "start",
        "--rest",
        "--port",
        String(port),
        "--unlock-credential",
        "harpoc-unlock",
      ]);
      expect(started.code, started.stderr).toBe(0);

      const deadline = Date.now() + 30_000;
      let state = "";
      while (state !== VaultState.UNLOCKED) {
        const res = await fetch(`http://127.0.0.1:${String(port)}/api/v1/health`, {
          signal: AbortSignal.timeout(2_000),
        }).catch(() => undefined);
        if (res?.ok) state = ((await res.json()) as { data: { state: string } }).data.state;
        if (state === VaultState.UNLOCKED) break;
        if (Date.now() > deadline) {
          const journal = await asRoot([
            "journalctl",
            "--no-pager",
            "-o",
            "cat",
            "-u",
            `${unit}.service`,
          ]);
          throw new Error(
            `the unit did not serve an unlocked vault within 30 s:\n${journal.stdout}`,
          );
        }
        await new Promise<void>((resolve) => setTimeout(resolve, 250));
      }

      const audit = await asVault(["audit", "--event", AuditEventType.VAULT_UNLOCK, "--json"]);
      expect(audit.code, audit.stderr).toBe(0);
      const rows = (JSON.parse(audit.stdout) as AuditRow[]).filter(
        (r) => r.detail?.["method"] === "credential",
      );
      expect(rows).toHaveLength(1);

      const stopped = await asRoot(["systemctl", "stop", `${unit}.service`]);
      expect(stopped.code, stopped.stderr).toBe(0);
      const stops = await asVault(["audit", "--event", AuditEventType.SERVER_STOP, "--json"]);
      expect(stops.code, stops.stderr).toBe(0);
      expect((JSON.parse(stops.stdout) as AuditRow[])[0]?.detail).toMatchObject({
        transport: "rest",
        trigger: "SIGTERM",
      });
    }, 300_000);
  },
);
