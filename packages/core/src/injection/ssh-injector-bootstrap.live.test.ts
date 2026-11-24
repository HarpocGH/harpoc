import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { InjectionPolicy } from "@harpoc/shared";
import { ErrorCode, SSH_HOST_KEY_TYPES, SSH_INSTALL_KEY_TYPES } from "@harpoc/shared";
import { expectAbsent } from "@harpoc/test-utils";
import {
  type BootstrapStandIns,
  makeBootstrapStandIns,
} from "./__fixtures__/bootstrap-standins.js";
import { resolveNativeSshClient } from "./__fixtures__/native-ssh-client.js";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { serialized } from "./__fixtures__/serialized.js";
import { generateEd25519HostKeys } from "./__fixtures__/ssh2-host-keys.js";
import {
  type PasswordServer,
  type PasswordServerAuth,
  type PasswordServerExec,
  startPasswordSshServer,
} from "./__fixtures__/ssh2-password-server.js";
import { baseSshEnv } from "./ssh-common.js";
import { parseSshPublicKey, type SshPublicKey } from "./ssh-common-keys.js";
import {
  readSshVersion,
  SSH_PASSWORD_LOGIN_MIN_VERSION,
  type SshVersion,
  sshVersionAtLeast,
} from "./ssh-common-version.js";
import { type BootstrapOutcome, runBootstrap } from "./ssh-injector-bootstrap.js";
import { BOOTSTRAP_REMOTE_COMMAND } from "./ssh-injector-bootstrap-script.js";

const SSH = resolveNativeSshClient("ssh");

const USER = "deploy";
const RULE = "#1000 ALL=(ALL:ALL) NOPASSWD: ALL\n";
const BUDGET_MS = 30_000;
const ROW_TIMEOUT_MS = 60_000;

function policy(overrides: Partial<InjectionPolicy> = {}): InjectionPolicy {
  return {
    url_allowlist: [],
    command_allowlist: [],
    env_allowlist: [],
    host_allowlist: [],
    response_mode: "filtered",
    response_header_allowlist: [],
    network_isolation: false,
    fs_isolation: false,
    smtp_recipient_allowlist: [],
    imap_read_only: false,
    strict_tree_exit: false,
    proxy: false,
    ssh_agent_socket: false,
    local_dirs: [],
    ssh_bootstrap: null,
    ...overrides,
  };
}

function keyOf(line: string, types: readonly string[]): SshPublicKey {
  const key = parseSshPublicKey(line, types);
  if (key === null) throw new Error("the key reader refuses a line ssh2 generated");
  return key;
}

function generatedLine(): string {
  return generateEd25519HostKeys().public.split(/\s+/).slice(0, 2).join(" ");
}

function codeOf(outcome: BootstrapOutcome): ErrorCode | null {
  return outcome.kind === "refused" ? outcome.error.code : null;
}

// win32: the bootstrap is refused on a Windows vault host, so no row of this file runs there.
it.skipIf(process.platform === "win32")(
  "ssh-live tier: required legs fail instead of skipping when ssh is unresolvable",
  () => {
    if (SSH === null && tierRequired("ssh-live")) {
      throw new Error(
        'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no ssh client resolves',
      );
    }
  },
);

// Skipped on win32, where the bootstrap is refused on a Windows vault host before any spawn (that
// row is the engine's), and where no native ssh client resolves.
describe.skipIf(process.platform === "win32" || SSH === null)(
  "the ssh bootstrap through the leg's own OpenSSH client against an ssh2 password server",
  () => {
    let s: BootstrapStandIns;
    let password: string;
    let installKey: SshPublicKey;
    const servers: PasswordServer[] = [];

    beforeEach(() => {
      s = makeBootstrapStandIns();
      password = randomBytes(18).toString("base64url");
      s.set("sudo.password", password);
      installKey = keyOf(generatedLine(), SSH_INSTALL_KEY_TYPES);
    });

    afterEach(async () => {
      await Promise.all(servers.splice(0).map((server) => server.close()));
      s.dispose();
    });

    const sshDir = (): string => join(s.home, ".ssh");
    const keysFile = (): string => join(s.home, ".ssh", "authorized_keys");
    const dropIn = (): string => join(s.sudoersDir, "harpoc-1000");

    function standInExec(startup = ""): (command: string) => PasswordServerExec | null {
      return (command) =>
        command === BOOTSTRAP_REMOTE_COMMAND
          ? {
              file: "/bin/sh",
              args: ["-c", startup + s.command],
              env: { HOME: s.home, PATH: "/nonexistent" },
            }
          : null;
    }

    async function serve(
      auth: PasswordServerAuth = "password",
      exec: (command: string) => PasswordServerExec | null = standInExec(),
    ): Promise<PasswordServer> {
      const server = await startPasswordSshServer({ user: USER, password, auth, exec });
      servers.push(server);
      return server;
    }

    async function bootstrap(
      server: PasswordServer,
      options: { sudoers?: boolean; hostKeyLine?: string; budgetMs?: number } = {},
    ): Promise<BootstrapOutcome> {
      const outcome = await runBootstrap({
        sshPath: SSH as string,
        host: "127.0.0.1",
        port: server.port,
        user: USER,
        hostKeys: [keyOf(options.hostKeyLine ?? server.hostKeyLine, SSH_HOST_KEY_TYPES)],
        installKey,
        sudoers: options.sudoers ?? false,
        password: Buffer.from(password),
        policy: policy(),
        budgetMs: options.budgetMs ?? BUDGET_MS,
      });
      expectAbsent(serialized(outcome), password, "the outcome, its error's message included");
      expectAbsent(s.log().join("\n"), password, "the stand-ins' log");
      return outcome;
    }

    it("the leg's client is at least 8.4", async () => {
      const version = await readSshVersion(SSH as string, baseSshEnv([]));
      expect(version).not.toBeNull();
      expect(sshVersionAtLeast(version as SshVersion, SSH_PASSWORD_LOGIN_MIN_VERSION)).toBe(true);
    });

    it(
      "the key is installed through a password login",
      async () => {
        const server = await serve();
        const outcome = await bootstrap(server);
        expect(outcome).toMatchObject({ kind: "done", key: "installed", sudoers: "not_asked" });
        expect(server.seen.commands).toEqual([BOOTSTRAP_REMOTE_COMMAND]);
        expect(server.seen.passwords).toBe(1);
        expect(readFileSync(keysFile(), "utf8")).toBe(`${installKey.line}\n`);
      },
      ROW_TIMEOUT_MS,
    );

    it(
      "with the flag the drop-in is written, then the key",
      async () => {
        const outcome = await bootstrap(await serve(), { sudoers: true });
        expect(outcome).toMatchObject({ kind: "done", key: "installed", sudoers: "written" });
        expect(s.log()).toEqual([
          "id -u stdin=0",
          `sudo read=${String(password.length)}`,
          `visudo -c -f ${s.dir}/sudoers.d/harpoc-1000.tmp stdin=0`,
          `visudo -c -f ${s.dir}/sudoers stdin=0`,
        ]);
        expect(readFileSync(dropIn(), "utf8")).toBe(RULE);
        expect(statSync(dropIn()).mode & 0o777).toBe(0o440);
        expect(readFileSync(keysFile(), "utf8")).toBe(`${installKey.line}\n`);
      },
      ROW_TIMEOUT_MS,
    );

    it(
      "a second call finds both",
      async () => {
        const server = await serve();
        await bootstrap(server, { sudoers: true });
        const outcome = await bootstrap(server, { sudoers: true });
        expect(outcome).toMatchObject({ kind: "done", key: "present", sudoers: "present" });
        expect(readFileSync(keysFile(), "utf8")).toBe(`${installKey.line}\n`);
      },
      ROW_TIMEOUT_MS,
    );

    it(
      "the sudoers step refused: nothing is installed",
      async () => {
        s.set("sudo.mode", "outside-before");
        const outcome = await bootstrap(await serve(), { sudoers: true });
        expect(codeOf(outcome)).toBe(ErrorCode.SSH_BOOTSTRAP_STEP_FAILED);
        expect(outcome).toMatchObject({
          kind: "refused",
          status: { dropIn: "refused", key: "not_attempted" },
        });
        expect(existsSync(sshDir())).toBe(false);
      },
      ROW_TIMEOUT_MS,
    );

    it(
      "a refused password",
      async () => {
        const server = await serve("refuse");
        const outcome = await bootstrap(server);
        expect(server.seen.passwords).toBe(1);
        expect(server.seen.commands).toEqual([]);
        expect(outcome.kind).toBe("refused");
        expect(codeOf(outcome)).toBe(ErrorCode.SSH_PASSWORD_REFUSED);
      },
      ROW_TIMEOUT_MS,
    );

    it(
      "no password method offered",
      async () => {
        const server = await serve("no-password");
        const outcome = await bootstrap(server);
        expect(outcome.kind).toBe("refused");
        expect(codeOf(outcome)).toBe(ErrorCode.SSH_PASSWORD_NOT_OFFERED);
        expect(server.seen.passwords).toBe(0);
      },
      ROW_TIMEOUT_MS,
    );

    it(
      "an account accepted without a password",
      async () => {
        const server = await serve("open");
        const outcome = await bootstrap(server, { sudoers: true });
        expect(outcome).toMatchObject({ kind: "done", key: "installed", sudoers: "written" });
        expect(server.seen.passwords).toBe(0);
        expect(s.log()[1]).toBe(`sudo read=${String(password.length)}`);
      },
      ROW_TIMEOUT_MS,
    );

    it(
      "nothing answered until the budget",
      async () => {
        const server = await serve("silent");
        const outcome = await bootstrap(server, { budgetMs: 2_000 });
        expect(outcome.kind).toBe("refused");
        expect(codeOf(outcome)).toBe(ErrorCode.SSH_CONNECT_FAILED);
        expect(outcome.spawn).toMatchObject({ timed_out: true, exit_code: null });
        expect(server.seen.commands).toEqual([]);
      },
      ROW_TIMEOUT_MS,
    );

    it(
      "another host key",
      async () => {
        const server = await serve();
        const outcome = await bootstrap(server, { hostKeyLine: generatedLine() });
        expect(outcome.kind).toBe("refused");
        expect(codeOf(outcome)).toBe(ErrorCode.SSH_HOST_KEY_MISMATCH);
        expect(server.seen.methods).toEqual([]);
      },
      ROW_TIMEOUT_MS,
    );

    it(
      "a start-up file that took a line",
      async () => {
        const server = await serve("password", standInExec("IFS= read -r x; "));
        const outcome = await bootstrap(server, { sudoers: true });
        expect(outcome).toEqual({ kind: "unconfirmed", spawn: outcome.spawn });
        expect(existsSync(sshDir())).toBe(false);
        expect(s.log().some((line) => line.startsWith("sudo"))).toBe(false);
      },
      ROW_TIMEOUT_MS,
    );

    it(
      "text a start-up file printed without a line feed",
      async () => {
        const server = await serve("password", standInExec('printf "Welcome to host"; '));
        const outcome = await bootstrap(server);
        expect(outcome).toMatchObject({ kind: "done", key: "installed", sudoers: "not_asked" });
      },
      ROW_TIMEOUT_MS,
    );

    it(
      "a session that ends without a status line",
      async () => {
        const server = await serve("password", (command) =>
          command === BOOTSTRAP_REMOTE_COMMAND
            ? {
                file: "/bin/sh",
                args: ["-c", "echo partial"],
                env: { HOME: s.home, PATH: "/nonexistent" },
              }
            : null,
        );
        const outcome = await bootstrap(server);
        expect(outcome).toEqual({ kind: "unconfirmed", spawn: outcome.spawn });
        expect(server.seen.commands).toEqual([BOOTSTRAP_REMOTE_COMMAND]);
      },
      ROW_TIMEOUT_MS,
    );

    // § 19's limit: text the account prints after the script's status line ends the secret, although the key is installed.
    it(
      "text after the status line ends the secret",
      async () => {
        const server = await serve("password", standInExec('trap "echo bye" 0; '));
        const outcome = await bootstrap(server);
        expect(outcome).toEqual({ kind: "unconfirmed", spawn: outcome.spawn });
        expect(server.seen.commands).toEqual([BOOTSTRAP_REMOTE_COMMAND]);
        expect(server.seen.passwords).toBe(1);
        expect(readFileSync(keysFile(), "utf8")).toBe(`${installKey.line}\n`);
      },
      ROW_TIMEOUT_MS,
    );
  },
);
