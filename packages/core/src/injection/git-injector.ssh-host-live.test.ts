/**
 * E-24, live: the vault's ssh reaches the host the allowlist judged. One
 * address git reads otherwise than the vault (a destination on 127.0.0.2 and
 * the listener's port) and two it reads alike reach the listener; the rest are
 * refused first. The listener is on 127.0.0.1 alone, pinned as `[127.0.0.1]:<port>`,
 * so a session on it shows ssh dialled the judged host and checked the host
 * key under it. The listener answers every `exec` with exit status 1: git's
 * own failure is the expected result, the listener's record is the assertion.
 */
import { readFileSync } from "node:fs";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import ssh2 from "ssh2";
import type { ParsedKey, Server as SshServer } from "ssh2";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionConfig, GitAction, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import type { AuditLogger, AuditLogOptions } from "../audit/audit-logger.js";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { resolveNativeSshClient } from "./__fixtures__/native-ssh-client.js";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { GitInjector } from "./git-injector.js";
import { EphemeralSshAgent } from "./ssh-agent/index.js";
import { system32Path } from "../win32-paths.js";
import { expectVaultError } from "@harpoc/test-utils";

const { Server, utils } = ssh2;

// The injector resolves ssh for GIT_SSH_COMMAND against the process PATH; on
// Windows only the native Win32-OpenSSH client reaches the agent's named pipe,
// so its directory leads the PATH (as in git-injector.spawn.test.ts).
if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}

const GIT = resolveExecutable("git", controlledPathDirs());
const SSH = resolveNativeSshClient("ssh");

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "__fixtures__", "ssh");
const USER_KEY_PEM = readFileSync(join(FIXTURES, "ed25519_openssh"), "utf8");

// A leg that exports the ssh-live tier ships git and ssh: where either does not resolve there,
// this guard fails the file instead of letting the suite below skip silently.
it("ssh-live tier: required legs fail instead of skipping when git or ssh is unresolvable", () => {
  if ((GIT === null || SSH === null) && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but git or ssh does not resolve',
    );
  }
});

const describeLive = describe.skipIf(GIT === null || SSH === null);

interface Session {
  username: string;
  command: string;
}

// [title, the address for the listener's port, the user the listener sees]
const ADDRESSES: ReadonlyArray<readonly [string, (port: number) => string, string]> = [
  [
    "a # in the URL authority behind a named user",
    (port) => `ssh://git@127.0.0.1#@127.0.0.2:${String(port)}/p`,
    "git",
  ],
  [
    "control: ssh:// with a port",
    (port) => `ssh://git@127.0.0.1:${String(port)}/org/repo.git`,
    "git",
  ],
  [
    "control: the bracketed scp form with a port",
    (port) => `[git@127.0.0.1:${String(port)}]:org/repo.git`,
    "git",
  ],
];

const USER_NOT_A_NAME: ReadonlyArray<readonly [string, (port: number) => string]> = [
  ["a # in the URL authority", (port) => `ssh://127.0.0.1#@127.0.0.2:${String(port)}/p`],
  ["@[ in the URL path with a port", (port) => `ssh://127.0.0.1/@[127.0.0.2]:${String(port)}/p`],
  [
    "a bracketed URL userinfo with a port",
    (port) => `ssh://[127.0.0.2:${String(port)}]@127.0.0.1/p`,
  ],
  [
    "a percent-encoded port and / in the URL userinfo",
    (port) => `ssh://127.0.0.2%3A${String(port)}%2F@127.0.0.1/p`,
  ],
  [
    "a percent-encoded :// in a bracketed URL userinfo",
    (port) => `ssh://ssh%3A%2F%2Fx@[127.0.0.2:${String(port)}]@127.0.0.1/p`,
  ],
];

describeLive("E-24, live: the vault's ssh reaches the judged host, whatever git reads", () => {
  let server: SshServer | undefined;
  let port = 0;
  let hostPubLine = "";
  let agentPub: ParsedKey;
  const sessions: Session[] = [];

  beforeAll(async () => {
    const hostKeys = utils.generateKeyPairSync("ed25519");
    hostPubLine = hostKeys.public.split(/\s+/).slice(0, 2).join(" ");

    const probeAgent = await EphemeralSshAgent.start(USER_KEY_PEM);
    const parsed = utils.parseKey(probeAgent.publicKeyOpenssh);
    probeAgent.dispose();
    if (parsed instanceof Error) throw parsed;
    agentPub = parsed;

    const srv = new Server({ hostKeys: [hostKeys.private] }, (client) => {
      let username = "";
      client
        .on("authentication", (ctx) => {
          username = ctx.username;
          if (ctx.method !== "publickey") {
            ctx.reject(["publickey"]);
            return;
          }
          const matches =
            ctx.key.algo === agentPub.type && ctx.key.data.equals(agentPub.getPublicSSH());
          if (!matches) {
            ctx.reject(["publickey"]);
            return;
          }
          if (!ctx.signature) {
            ctx.accept();
            return;
          }
          const verified = agentPub.verify(
            ctx.blob as Buffer,
            ctx.signature,
            (ctx as unknown as { hashAlgo?: string }).hashAlgo,
          );
          if (verified) ctx.accept();
          else ctx.reject(["publickey"]);
        })
        .on("ready", () => {
          client.on("session", (accept) => {
            accept().on("exec", (acceptExec, _reject, info) => {
              sessions.push({ username, command: info.command });
              const stream = acceptExec();
              stream.exit(1);
              stream.end();
            });
          });
        })
        .on("error", () => {
          /* a client that leaves after the refused exec is expected here */
        });
    });

    server = srv;
    await new Promise<void>((resolve) => {
      srv.listen(0, "127.0.0.1", () => {
        port = (srv.address() as { port: number }).port;
        resolve();
      });
    });
  });

  afterAll(() => {
    server?.close();
  });

  beforeEach(() => {
    sessions.length = 0;
  });

  const policy = (): InjectionPolicy => ({
    url_allowlist: [],
    command_allowlist: [GIT as string],
    env_allowlist: [],
    host_allowlist: ["127.0.0.1"],
    response_mode: "filtered",
    response_header_allowlist: [],
    network_isolation: false,
    fs_isolation: false,
    smtp_recipient_allowlist: [],
    imap_read_only: false,
    strict_tree_exit: false,
    proxy: false,
    ssh_agent_socket: false,
  });

  it.each(ADDRESSES)(
    "%s: one session on 127.0.0.1, the row names 127.0.0.1",
    async (_title, address, user) => {
      const log = vi.fn();
      const injector = new GitInjector({ log } as unknown as AuditLogger);
      const config: ConnectionConfig = {
        ssh: { known_hosts: [`[127.0.0.1]:${String(port)} ${hostPubLine}`] },
      };
      const action: GitAction = {
        type: "git",
        operation: "ls-remote",
        repository: address(port),
        timeout_ms: 20_000,
      };

      const result = await injector.executeWithSecret(
        action,
        new Uint8Array(Buffer.from(USER_KEY_PEM)),
        policy(),
        config,
        "secret-1",
      );

      // The listener refuses the exec: git reports its own failure, no timeout, no host-key refusal.
      expect(result.exit_code === 0).toBe(false);
      expect(result.timed_out === true).toBe(false);
      expect(sessions.length).toBe(1);
      expect(sessions[0]?.command.startsWith("git-upload-pack ")).toBe(true);
      expect(sessions[0]?.username === user).toBe(true);
      const rows = log.mock.calls.map((c) => c[0] as AuditLogOptions);
      expect(rows.length).toBe(1);
      expect(rows[0]?.detail?.transport).toBe("ssh");
      expect(rows[0]?.detail?.host).toBe("127.0.0.1");
      expect("error" in (rows[0]?.detail ?? {})).toBe(false);
    },
    30_000,
  );

  it.each(USER_NOT_A_NAME)(
    "%s: refused for its user part, INVALID_GIT_CONFIG, one row without a host, no session",
    async (_title, address) => {
      const log = vi.fn();
      const injector = new GitInjector({ log } as unknown as AuditLogger);
      const config: ConnectionConfig = {
        ssh: { known_hosts: [`[127.0.0.1]:${String(port)} ${hostPubLine}`] },
      };
      const err = await expectVaultError(
        () =>
          injector.executeWithSecret(
            { type: "git", operation: "ls-remote", repository: address(port), timeout_ms: 20_000 },
            new Uint8Array(Buffer.from(USER_KEY_PEM)),
            policy(),
            config,
            "secret-1",
          ),
        ErrorCode.INVALID_GIT_CONFIG,
      );
      expect(
        err.message ===
          "SSH user of the repository must be a name of letters, digits, '.', '_' and '-' that begins with a letter or a digit",
      ).toBe(true);
      expect(sessions.length).toBe(0);
      expect(log.mock.calls).toEqual([
        [
          {
            eventType: "secret.use",
            secretId: "secret-1",
            detail: { context: "git", operation: "ls-remote", error: "INVALID_GIT_CONFIG" },
            success: false,
          },
        ],
      ]);
    },
    30_000,
  );
});
