import { createPrivateKey, randomBytes } from "node:crypto";
import type { Stats } from "node:fs";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, delimiter, join } from "node:path";
import { format } from "node:util";
import ssh2 from "ssh2";
import type { ParsedKey } from "ssh2";
import type { MockInstance } from "vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  CallerContext,
  InjectionPolicyInput,
  RenderEntry,
  UseSecretAction,
} from "@harpoc/shared";
import {
  AuditEventType,
  ErrorCode,
  isRenderTempName,
  PrincipalType,
  SecretType,
  VaultError,
} from "@harpoc/shared";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";
import { registerAgents } from "../__fixtures__/engine-seams.js";
import { VaultEngine } from "../vault-engine.js";
import { system32Path } from "../win32-paths.js";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { resolveNativeSshClient } from "./__fixtures__/native-ssh-client.js";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { generateEd25519HostKeys } from "./__fixtures__/ssh2-host-keys.js";
import { hostAddress, startSftpSshServer } from "./__fixtures__/ssh2-sftp-server.js";
import type { SftpServer, SftpServerOptions } from "./__fixtures__/ssh2-sftp-server.js";
import { renderEntryDigest } from "./render-entry-digest.js";

vi.mock("../crypto/argon2.js", async (importOriginal) =>
  (await import("../__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

const { utils } = ssh2;

// The render resolves `ssh` as the product does; on Windows only the native Win32-OpenSSH
// client is accepted, so its directory leads the PATH.
if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}

const SSH =
  process.platform === "win32"
    ? (resolveExecutable(
        join(process.env.SystemRoot ?? "C:\\Windows", "System32", "OpenSSH", "ssh.exe"),
        [],
      ) ?? resolveNativeSshClient("ssh"))
    : resolveNativeSshClient("ssh");
const SFTP = resolveNativeSshClient("sftp");
const HOST = hostAddress();

const USER = "deploy";
const ENTRY = "app-env";
const REMOTE_PATH = "/srv/app/app.env";
const KEY = "secret://deploy-key";
const BOT = "secret://bot-token";
const API = "secret://api-key";
const DB = "secret://db-password";
const SLOTS = [BOT, API, DB];
const AGENT = "operator";
const CALLER: CallerContext = { principal_type: "agent", principal_id: AGENT, interface: "mcp" };
const RENDER = { type: "sftp", operation: "render", entry: ENTRY } as UseSecretAction;
const WRITTEN = { type: "sftp_render", status: "written" };
const ROW_TIMEOUT_MS = 60_000;
const TEMPLATE = [
  "# app.env, rendered by harpoc",
  "BOT_TOKEN={{secret://bot-token}}",
  "API_KEY={{secret://api-key}}",
  "DATABASE_URL=postgres://app:{{secret://db-password}}@db.internal:5432/app",
  "BOT_TOKEN_AGAIN={{secret://bot-token}}",
  "",
].join("\n");
const ISO = { network_isolation: false, fs_isolation: false };
const MCP = { interface: "mcp" };
// On win32 every spawn runs inside the job wrapper; off win32 a render's spawn adds no field.
const SPAWN = process.platform === "win32" ? { tree_kill: "job" } : {};
const FAILED_TEXT = VaultError.renderFailed().message;
// What a render's run creates in the temporary directory: `writeKnownHosts`, `writeIdentityFile`
// (`harpoc-ssh-id-`) and, off win32, the ephemeral agent's socket directory.
const PRODUCT_PREFIXES = ["harpoc-ssh-", "harpoc-agent-"];

it("ssh-live tier: required legs fail instead of skipping when ssh or a non-loopback address is unresolvable", () => {
  if ((SSH === null || HOST === null) && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no ssh client or no non-loopback IPv4 address resolves',
    );
  }
});

// Skipped where no ssh client or no non-loopback IPv4 address of this host resolves: an
// entry's host may not be the vault host's loopback.
describe.skipIf(SSH === null || HOST === null)(
  "the sftp render under the leg's OpenSSH client against the ssh2 SFTP server fixture",
  () => {
    const host = HOST as string;
    let vaultDir: string;
    let fxBase: string;
    let fxRoot: string;
    let password: string;
    let engine: VaultEngine;
    let engines: VaultEngine[];
    let servers: SftpServer[];
    let keyId: string;
    let ids: Record<string, string>;
    let values: Record<string, string>;
    let authorizedKey: string;
    let earlier: Set<string>;

    function draw(): string {
      return randomBytes(18).toString("base64url");
    }

    function bytes(text: string): Uint8Array {
      return new Uint8Array(Buffer.from(text, "utf8"));
    }

    function quiet<T>(promise: Promise<T>): Promise<T> {
      promise.catch(() => undefined);
      return promise;
    }

    function harpocEntries(): string[] {
      return readdirSync(tmpdir()).filter((name) => name.startsWith("harpoc-"));
    }

    /** The forms of the key's private part a leak would take: its PEM, the PEM's body lines, the scalar. */
    function keyNeedles(pem: string): string[] {
      const lines = pem
        .split(/\r?\n/)
        .filter((line) => line.length >= 16 && !line.startsWith("-----"));
      const parsed = utils.parseKey(pem) as ParsedKey;
      const jwk = createPrivateKey(parsed.getPrivatePEM()).export({ format: "jwk" });
      const scalar = Buffer.from(jwk.d as string, "base64url");
      return [
        pem,
        ...lines,
        scalar.toString("base64url"),
        scalar.toString("base64"),
        scalar.toString("hex"),
      ];
    }

    function needles(): { label: string; value: string }[] {
      return [
        ...keyNeedles(values[KEY] as string).map((value) => ({ label: KEY, value })),
        ...SLOTS.map((handle) => ({ label: handle, value: values[handle] as string })),
      ];
    }

    /**
     * A vanished entry is skipped, on win32 also one whose delete is pending (EPERM). Another
     * suite's entry may be unreadable (a vault in a write transaction answers EBUSY on win32, a
     * directory of mode 000 EACCES): `foreign` skips those too; the product's own never.
     */
    function filesUnder(path: string, foreign = false): { path: string; text: string }[] {
      const skipped = (err: unknown): boolean => {
        const code = (err as NodeJS.ErrnoException).code;
        if (code === "ENOENT" || (process.platform === "win32" && code === "EPERM")) return true;
        return foreign && (code === "EBUSY" || code === "EACCES" || code === "EPERM");
      };
      let stat: Stats;
      try {
        stat = lstatSync(path);
      } catch (err) {
        if (skipped(err)) return [];
        throw err;
      }
      if (stat.isDirectory()) {
        let names: string[];
        try {
          names = readdirSync(path);
        } catch (err) {
          if (skipped(err)) return [];
          throw err;
        }
        return names.flatMap((name) => filesUnder(join(path, name), foreign));
      }
      if (!stat.isFile()) return [];
      try {
        return [{ path, text: readFileSync(path, "latin1") }];
      } catch (err) {
        if (skipped(err)) return [];
        throw err;
      }
    }

    function newTemporaryFiles(): { path: string; text: string }[] {
      const own = new Set([basename(vaultDir), basename(fxBase)]);
      return harpocEntries()
        .filter((name) => !earlier.has(name) && !own.has(name))
        .flatMap((name) =>
          filesUnder(
            join(tmpdir(), name),
            !PRODUCT_PREFIXES.some((prefix) => name.startsWith(prefix)),
          ),
        );
    }

    function content(api = values[API] as string): Buffer {
      return Buffer.from(
        TEMPLATE.replaceAll("{{secret://bot-token}}", values[BOT] as string)
          .replaceAll("{{secret://api-key}}", api)
          .replaceAll("{{secret://db-password}}", values[DB] as string),
        "utf8",
      );
    }

    const appDir = (): string => join(fxRoot, "srv", "app");
    const rendered = (): string => join(appDir(), "app.env");

    async function start(options: Partial<SftpServerOptions> = {}): Promise<SftpServer> {
      const server = await startSftpSshServer({
        user: USER,
        authorizedKey,
        root: fxRoot,
        host,
        ...options,
      });
      servers.push(server);
      return server;
    }

    /** The connection config pins the server's real host key, which a render must never read. */
    async function arrange(
      server: SftpServer,
      overrides: Partial<RenderEntry> = {},
      approving: string[] = SLOTS,
      policy: InjectionPolicyInput = {},
    ): Promise<RenderEntry> {
      const entry: RenderEntry = {
        name: ENTRY,
        host,
        port: server.port,
        user: USER,
        path: REMOTE_PATH,
        host_keys: [server.hostKeyLine],
        template: TEMPLATE,
        ...overrides,
      };
      await engine.setInjectionPolicy(KEY, {
        command_allowlist: [SSH as string],
        host_allowlist: [host],
        ...policy,
        render: { entries: [entry], approvals: [] },
      });
      await engine.setConnectionConfig(KEY, {
        ssh: { known_hosts: [`[${host}]:${String(server.port)} ${server.hostKeyLine}`] },
      });
      for (const handle of approving) {
        await engine.setInjectionPolicy(handle, {
          render: {
            entries: [],
            approvals: [{ key: keyId, entry: ENTRY, digest: renderEntryDigest(entry) }],
          },
        });
      }
      return entry;
    }

    function useRows() {
      return engine
        .queryAudit({ eventType: AuditEventType.SECRET_USE })
        .reverse()
        .map((row) => ({
          secret: row.secret_id,
          success: row.success,
          principal: [row.principal_type, row.principal_id],
          detail: row.detail,
        }));
    }

    function keyRow(server: SftpServer, extra: Record<string, unknown>): Record<string, unknown> {
      return {
        context: "sftp",
        host,
        port: server.port,
        user: USER,
        operation: "render",
        entry: ENTRY,
        remote_path: REMOTE_PATH,
        slots: SLOTS,
        written: "no",
        ...ISO,
        ...MCP,
        ...extra,
      };
    }

    function slotRow(server: SftpServer, extra: Record<string, unknown> = {}) {
      return {
        context: "sftp",
        operation: "render",
        entry: ENTRY,
        key: KEY,
        host,
        port: server.port,
        user: USER,
        remote_path: REMOTE_PATH,
        ...ISO,
        ...MCP,
        ...extra,
      };
    }

    function callRows(
      server: SftpServer,
      success: boolean,
      key: Record<string, unknown>,
      slot: Record<string, unknown> = {},
    ) {
      const principal = [PrincipalType.AGENT, AGENT];
      return [
        { secret: keyId, success, principal, detail: keyRow(server, key) },
        ...SLOTS.map((handle) => ({
          secret: ids[handle],
          success,
          principal,
          detail: slotRow(server, slot),
        })),
      ];
    }

    beforeEach(async () => {
      earlier = new Set(harpocEntries());
      vaultDir = mkdtempSync(join(tmpdir(), "harpoc-srl-"));
      password = randomBytes(12).toString("hex");
      engine = new VaultEngine({
        dbPath: join(vaultDir, "vault.db"),
        sessionPath: join(vaultDir, "session.json"),
      });
      engines = [engine];
      servers = [];
      await engine.initVault(password);
      registerAgents(engine, AGENT);
      const userKey = generateEd25519HostKeys();
      authorizedKey = userKey.public.split(/\s+/).slice(0, 2).join(" ");
      values = { [KEY]: userKey.private, [BOT]: draw(), [API]: draw(), [DB]: draw() };
      ids = {};
      for (const handle of [KEY, ...SLOTS]) {
        await engine.createSecret({
          name: handle.slice("secret://".length),
          type: SecretType.API_KEY,
          value: bytes(values[handle] as string),
        });
        ids[handle] = await engine.resolveSecretId(handle);
        engine.grantPolicy(
          {
            secretId: ids[handle] as string,
            principalType: PrincipalType.AGENT,
            principalId: AGENT,
            permissions: ["use"],
          },
          "test-admin",
        );
      }
      keyId = ids[KEY] as string;
      await engine.setInjectionPolicy(KEY, {
        command_allowlist: [SSH as string],
        host_allowlist: [host],
      });
      const made = mkdtempSync(join(tmpdir(), "harpoc-sftp-fx-"));
      fxBase = process.platform === "win32" ? made : realpathSync(made);
      fxRoot = join(fxBase, "root");
      mkdirSync(join(fxRoot, "srv", "app"), { recursive: true });
    });

    afterEach(async () => {
      vi.restoreAllMocks();
      await Promise.all(servers.map((server) => server.close()));
      for (const each of engines) await each.destroy();
      rmSync(vaultDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      rmSync(fxBase, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    it(
      "the gap file's closing row: three handles rendered, the file's bytes and mode, a written status and no value anywhere",
      async () => {
        const printed: MockInstance[] = [
          vi.spyOn(console, "log"),
          vi.spyOn(console, "warn"),
          vi.spyOn(console, "error"),
        ];
        const server = await start();
        await arrange(server);
        const held = server.pause("posix-rename@openssh.com");

        const call = quiet(engine.useSecret(KEY, RENDER, CALLER));
        await Promise.race([held.reached, call]);
        const walked = newTemporaryFiles();
        held.release();
        const result = await call;

        const answer = JSON.stringify(result);
        const trail = JSON.stringify(engine.queryAudit());
        const printedText = printed
          .flatMap((spy) => spy.mock.calls)
          .map((args) => format(...(args as unknown[])))
          .join("\n");
        const vaultFiles = filesUnder(vaultDir);
        for (const { label, value } of needles()) {
          expectAbsent(answer, value, `the answer, for ${label}`);
          expectAbsent(trail, value, `the audit trail, for ${label}`);
          expectAbsent(printedText, value, `the console, for ${label}`);
          for (const file of vaultFiles) {
            expectAbsent(file.text, value, `${basename(file.path)} of the vault, for ${label}`);
          }
          for (const file of walked) {
            expectAbsent(file.text, value, `${basename(file.path)} under the pause, for ${label}`);
          }
        }

        expect(result).toStrictEqual(WRITTEN);
        expect(readFileSync(rendered()).equals(content())).toBe(true);
        expect(server.permissions(REMOTE_PATH)).toBe(0o600);
        expect(readdirSync(appDir())).toStrictEqual(["app.env"]);
        expect(server.seen.requests).not.toContain("READ");
        const walkedOwn = (name: string, holds: string): boolean =>
          walked.some((file) => basename(file.path) === name && file.text.includes(holds));
        expect(walkedOwn("known_hosts", server.hostKeyLine.split(" ")[1] as string)).toBe(true);
        expect(walkedOwn("identity.pub", authorizedKey.split(" ")[1] as string)).toBe(true);
        expect(vaultFiles.some((file) => basename(file.path) === "vault.db")).toBe(true);
        expect(useRows()).toStrictEqual(callRows(server, true, { written: "yes", ...SPAWN }));
      },
      ROW_TIMEOUT_MS,
    );

    // win32 keeps no POSIX mode bits: the rendered file's mode on disk is judged off win32 alone.
    it.skipIf(process.platform === "win32")(
      "the rendered file's mode on disk is 0600",
      async () => {
        const server = await start();
        await arrange(server);

        await expect(engine.useSecret(KEY, RENDER, CALLER)).resolves.toStrictEqual(WRITTEN);

        expect(statSync(rendered()).mode & 0o777).toBe(0o600);
      },
      ROW_TIMEOUT_MS,
    );

    it(
      "an entry one slot has not approved: RENDER_SLOT_REFUSED, one failed row on that slot, nothing connected or written",
      async () => {
        const server = await start();
        await arrange(server, {}, [BOT, API]);

        const err = await expectVaultError(
          () => engine.useSecret(KEY, RENDER, CALLER),
          ErrorCode.RENDER_SLOT_REFUSED,
        );

        expect(err.message).toBe(VaultError.renderSlotRefused().message);
        expect(useRows()).toStrictEqual([
          {
            secret: ids[DB],
            success: false,
            principal: [PrincipalType.AGENT, AGENT],
            detail: {
              handle: DB,
              context: "sftp",
              operation: "render",
              entry: ENTRY,
              key: KEY,
              error: ErrorCode.RENDER_NOT_APPROVED,
              ...MCP,
            },
          },
        ]);
        expect(server.seen.connections).toBe(0);
        expect(existsSync(rendered())).toBe(false);
      },
      ROW_TIMEOUT_MS,
    );

    it.each<{
      what: string;
      context: string;
      action: (server: SftpServer, local: string) => UseSecretAction;
    }>([
      {
        what: "the ssh context",
        context: "ssh",
        action: (server) => ({
          type: "ssh",
          host,
          port: server.port,
          user: USER,
          command: "id",
        }),
      },
      {
        what: "an sftp download",
        context: "sftp",
        action: (server, local) => ({
          type: "sftp",
          operation: "download",
          host,
          port: server.port,
          user: USER,
          remote_path: REMOTE_PATH,
          local_path: join(local, "app.env"),
        }),
      },
    ])(
      "a delivering key serves no other action — $what",
      async ({ context, action }) => {
        const local = join(fxBase, "local");
        mkdirSync(local);
        const server = await start();
        await arrange(server, {}, SLOTS, {
          command_allowlist: [SSH as string, ...(SFTP === null ? [] : [SFTP])],
          local_dirs: [local],
        });

        await expectVaultError(
          () => engine.useSecret(KEY, action(server, local), CALLER),
          ErrorCode.RENDER_ONLY_KEY,
        );

        expect(useRows()).toStrictEqual([
          {
            secret: keyId,
            success: false,
            principal: [PrincipalType.AGENT, AGENT],
            detail: { handle: KEY, context, error: ErrorCode.RENDER_ONLY_KEY, ...MCP },
          },
        ]);
        expect(server.seen.connections).toBe(0);
      },
      ROW_TIMEOUT_MS,
    );

    it(
      "a server without posix-rename: nothing is opened, RENDER_FAILED, the key's row says no_rename",
      async () => {
        const server = await start({ extensions: { posixRename: false } });
        await arrange(server);

        const err = await expectVaultError(
          () => engine.useSecret(KEY, RENDER, CALLER),
          ErrorCode.RENDER_FAILED,
        );

        expect(err.message).toBe(FAILED_TEXT);
        expect(useRows()).toStrictEqual(
          callRows(server, false, {
            written: "no",
            reason: "no_rename",
            error: ErrorCode.RENDER_FAILED,
            ...SPAWN,
          }),
        );
        expect(server.seen.requests).toStrictEqual(["INIT"]);
        expect(existsSync(rendered())).toBe(false);
      },
      ROW_TIMEOUT_MS,
    );

    it(
      "a stale temporary file of this path is removed, and nothing else",
      async () => {
        const stale = `.app.env.harpoc-${randomBytes(16).toString("hex")}.tmp`;
        const kept = {
          [`.app.env.harpoc-${randomBytes(16).toString("hex").slice(1)}.tmp`]: randomBytes(24),
          [`.other.env.harpoc-${randomBytes(16).toString("hex")}.tmp`]: randomBytes(24),
          "app.env.bak": randomBytes(24),
        };
        writeFileSync(join(appDir(), stale), "stale\n");
        for (const [name, keptBytes] of Object.entries(kept)) {
          writeFileSync(join(appDir(), name), keptBytes);
        }
        const server = await start();
        await arrange(server);

        await expect(engine.useSecret(KEY, RENDER, CALLER)).resolves.toStrictEqual(WRITTEN);

        expect(isRenderTempName(stale, "app.env")).toBe(true);
        expect(Object.keys(kept).map((name) => isRenderTempName(name, "app.env"))).toStrictEqual([
          false,
          false,
          false,
        ]);
        expect(existsSync(join(appDir(), stale))).toBe(false);
        for (const [name, keptBytes] of Object.entries(kept)) {
          expect(readFileSync(join(appDir(), name)).equals(keptBytes)).toBe(true);
        }
        expect(readFileSync(rendered()).equals(content())).toBe(true);
        expect(readdirSync(appDir()).sort()).toStrictEqual(
          [...Object.keys(kept), "app.env"].sort(),
        );
      },
      ROW_TIMEOUT_MS,
    );

    it(
      "an existing temporary name ends the render: nothing removed, nothing opened again",
      async () => {
        const server = await start({ collideOnOpen: true });
        await arrange(server);

        await expectVaultError(
          () => engine.useSecret(KEY, RENDER, CALLER),
          ErrorCode.RENDER_FAILED,
        );

        expect(useRows()[0]?.detail).toStrictEqual(
          keyRow(server, {
            written: "no",
            reason: "open",
            error: ErrorCode.RENDER_FAILED,
            ...SPAWN,
          }),
        );
        const opened = server.seen.requests.indexOf("OPEN");
        expect(server.seen.requests.filter((name) => name === "OPEN")).toHaveLength(1);
        expect(server.seen.requests.slice(opened)).not.toContain("REMOVE");
        const names = readdirSync(appDir());
        expect(names).toHaveLength(1);
        expect(isRenderTempName(names[0] as string, "app.env")).toBe(true);
        expect(readFileSync(join(appDir(), names[0] as string), "utf8")).toBe("planted\n");
        expect(existsSync(rendered())).toBe(false);
      },
      ROW_TIMEOUT_MS,
    );

    it(
      "a forged host-key line on the remote's error stream changes nothing",
      async () => {
        const server = await start({ stderr: "Host key verification failed.\r\n" });
        await arrange(server);

        await expect(engine.useSecret(KEY, RENDER, CALLER)).resolves.toStrictEqual(WRITTEN);

        expect(useRows()[0]?.detail).toStrictEqual(keyRow(server, { written: "yes", ...SPAWN }));
        expect(readFileSync(rendered()).equals(content())).toBe(true);
      },
      ROW_TIMEOUT_MS,
    );

    it(
      "a host key the entry does not hold: RENDER_FAILED, the key's row says host_key, no authentication",
      async () => {
        const server = await start();
        const other = generateEd25519HostKeys().public.split(/\s+/).slice(0, 2).join(" ");
        await arrange(server, { host_keys: [other] });

        const err = await expectVaultError(
          () => engine.useSecret(KEY, RENDER, CALLER),
          ErrorCode.RENDER_FAILED,
        );

        expect(err.message).toBe(FAILED_TEXT);
        expect(useRows()).toStrictEqual(
          callRows(server, false, {
            written: "no",
            reason: "host_key",
            error: ErrorCode.RENDER_FAILED,
            ...SPAWN,
          }),
        );
        expect(server.seen.methods).toStrictEqual([]);
        expect(existsSync(rendered())).toBe(false);
      },
      ROW_TIMEOUT_MS,
    );

    it(
      "a path in a directory the server does not have: RENDER_FAILED, the key's row says open, the directory unchanged",
      async () => {
        const path = "/srv/missing/app.env";
        const tree = (): string[] => filesUnder(fxRoot).map((file) => file.path);
        writeFileSync(join(appDir(), "app.env.bak"), randomBytes(24));
        const before = tree();
        const server = await start();
        await arrange(server, { path });

        await expectVaultError(
          () => engine.useSecret(KEY, RENDER, CALLER),
          ErrorCode.RENDER_FAILED,
        );

        expect(useRows()[0]?.detail).toStrictEqual(
          keyRow(server, {
            remote_path: path,
            written: "no",
            reason: "open",
            error: ErrorCode.RENDER_FAILED,
            ...SPAWN,
          }),
        );
        expect(tree()).toStrictEqual(before);
        expect(readdirSync(join(fxRoot, "srv"))).toStrictEqual(["app"]);
      },
      ROW_TIMEOUT_MS,
    );

    it(
      "two engines on one vault render to one path: the file is one engine's whole content",
      async () => {
        const server = await start();
        await arrange(server);
        const second = new VaultEngine({
          dbPath: join(vaultDir, "vault.db"),
          sessionPath: join(vaultDir, "session-b.json"),
        });
        engines.push(second);
        await second.unlock(password);
        const firstApi = values[API] as string;
        const secondApi = draw();
        const held = server.pause("WRITE");

        const first = quiet(engine.useSecret(KEY, RENDER, CALLER));
        await Promise.race([held.reached, first]);
        await second.rotateSecret(API, bytes(secondApi));
        await expect(second.useSecret(KEY, RENDER, CALLER)).resolves.toStrictEqual(WRITTEN);
        held.release();
        await expectVaultError(() => first, ErrorCode.RENDER_FAILED);

        const file = readFileSync(rendered(), "utf8");
        expectAbsent(file, firstApi, "the rendered file, for the first api-key value");
        expect(Buffer.from(file, "utf8").equals(content(secondApi))).toBe(true);
        expect(readdirSync(appDir())).toStrictEqual(["app.env"]);
        const failed = useRows().filter((row) => row.secret === keyId && !row.success);
        expect(failed).toHaveLength(1);
        expect(failed[0]?.detail?.["written"]).toBe("no");
        expect(["write", "rename"]).toContain(failed[0]?.detail?.["reason"]);
      },
      ROW_TIMEOUT_MS,
    );

    it(
      "a lock under a render aborts the child, writes the rows and publishes nothing; the next render removes the temporary file",
      async () => {
        const server = await start();
        await arrange(server);
        const held = server.pause("WRITE");

        const call = quiet(engine.useSecret(KEY, RENDER, CALLER));
        await Promise.race([held.reached, call]);
        await engine.lock();
        await expectVaultError(() => call, ErrorCode.VAULT_LOCKED);
        held.release();
        await engine.unlock(password);

        expect(useRows()).toStrictEqual(
          callRows(
            server,
            false,
            { written: "no", error: ErrorCode.VAULT_LOCKED },
            { error: ErrorCode.VAULT_LOCKED },
          ),
        );
        expect(engine.verifyAuditChain().valid).toBe(true);
        const left = readdirSync(appDir());
        expect(left).toHaveLength(1);
        expect(isRenderTempName(left[0] as string, "app.env")).toBe(true);
        expect(server.permissions(`/srv/app/${left[0] as string}`)).toBe(0o600);

        await expect(engine.useSecret(KEY, RENDER, CALLER)).resolves.toStrictEqual(WRITTEN);
        expect(readdirSync(appDir())).toStrictEqual(["app.env"]);
      },
      ROW_TIMEOUT_MS,
    );
  },
);
