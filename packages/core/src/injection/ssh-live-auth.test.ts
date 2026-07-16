import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import ssh2 from "ssh2";
import type { ParsedKey, Server as SshServer } from "ssh2";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { EphemeralSshAgent } from "./ssh-agent/index.js";
import { buildSshEnv, sshHardeningArgs, writeIdentityFile, writeKnownHosts } from "./ssh-common.js";

/**
 * Live SSH authentication e2e (thesis §4.5.7): the real OpenSSH client, driven
 * with the exact production hardening argv and clean environment, authenticates
 * against a real SSH server with the key held ONLY by the in-process ephemeral
 * agent. The M13 spawn suites pin the argv the injectors assemble; this suite
 * pins that the argv actually authenticates — the two failure modes it exists
 * for (IdentitiesOnly=yes starving an agent-only identity; ssh.exe dying
 * without ProgramData) were invisible to every argv-level assertion.
 *
 * The server side is the `ssh2` package — a test-only counterparty simulating
 * the remote host; no third-party crypto enters the vault's runtime dependency
 * set. The `-p <port>` flag is harness-only: SshAction has no port field, and
 * an unprivileged test cannot bind 22.
 */

const { Server, utils } = ssh2;

// On Windows the ephemeral agent listens on a named pipe, which only the native
// Win32-OpenSSH client consumes through SSH_AUTH_SOCK — an MSYS build (e.g. the
// Git-bundled ssh, which a Git-Bash PATH resolves first) treats the value as a
// filesystem path and silently finds no agent. Production pins the client via
// the per-secret command allowlist; the suite pins the native one the same way.
const SSH =
  process.platform === "win32"
    ? (resolveExecutable(
        join(process.env.SystemRoot ?? "C:\\Windows", "System32", "OpenSSH", "ssh.exe"),
        [],
      ) ?? resolveExecutable("ssh", controlledPathDirs()))
    : resolveExecutable("ssh", controlledPathDirs());

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "__fixtures__", "ssh");
const USER_KEY_PEM = readFileSync(join(FIXTURES, "ed25519_openssh"), "utf8");

// A CI leg that provisions an ssh client exports HARPOC_REQUIRE_PLATFORM_TESTS
// including "ssh-live": the client going missing is then a FAILURE, not a skip
// (review T3 pattern). Local dev without ssh on PATH skips.
function tierRequired(tier: string): boolean {
  return (process.env["HARPOC_REQUIRE_PLATFORM_TESTS"] ?? "")
    .split(",")
    .map((t) => t.trim())
    .includes(tier);
}

it("ssh-live tier: required legs fail instead of skipping when ssh is unresolvable", () => {
  if (SSH === null && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no ssh client resolves',
    );
  }
});

const describeSsh = SSH ? describe : describe.skip;

interface AuthEvent {
  method: string;
  matchesEphemeral?: boolean;
  signed?: boolean;
  verified?: boolean;
}

describeSsh("live SSH authentication through the ephemeral agent", () => {
  let server: SshServer | undefined;
  let port = 0;
  let hostPubLine = "";
  let agentPub: ParsedKey;
  const events: AuthEvent[] = [];

  beforeAll(async () => {
    const hostKeys = utils.generateKeyPairSync("ed25519");
    hostPubLine = hostKeys.public.split(/\s+/).slice(0, 2).join(" ");

    const probeAgent = await EphemeralSshAgent.start(USER_KEY_PEM);
    const parsed = utils.parseKey(probeAgent.publicKeyOpenssh);
    probeAgent.dispose();
    if (parsed instanceof Error) throw parsed;
    agentPub = parsed;

    const srv = new Server({ hostKeys: [hostKeys.private] }, (client) => {
      client
        .on("authentication", (ctx) => {
          if (ctx.method !== "publickey") {
            events.push({ method: ctx.method });
            ctx.reject(["publickey"]);
            return;
          }
          const matches =
            ctx.key.algo === agentPub.type && ctx.key.data.equals(agentPub.getPublicSSH());
          if (!matches || !ctx.signature) {
            events.push({ method: ctx.method, matchesEphemeral: matches, signed: false });
            if (matches) ctx.accept();
            else ctx.reject(["publickey"]);
            return;
          }
          const verified = agentPub.verify(
            ctx.blob as Buffer,
            ctx.signature,
            (ctx as unknown as { hashAlgo?: string }).hashAlgo,
          );
          events.push({ method: ctx.method, matchesEphemeral: matches, signed: true, verified });
          if (verified) ctx.accept();
          else ctx.reject(["publickey"]);
        })
        .on("ready", () => {
          client.on("session", (accept) => {
            accept().on("exec", (acceptExec) => {
              const stream = acceptExec();
              stream.write("live-ok\n");
              stream.exit(0);
              stream.end();
            });
          });
        })
        .on("error", () => {
          /* client-side disconnects after failed auth are expected here */
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
    events.length = 0;
  });

  function runSsh(
    args: string[],
    authSock: string,
  ): Promise<{ exit: number | null; stdout: string; stderr: string }> {
    return new Promise((resolve, reject) => {
      const child = spawn(SSH as string, args, {
        env: buildSshEnv(authSock, []),
        stdio: ["ignore", "pipe", "pipe"],
      });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (d: Buffer) => {
        stdout += d.toString();
      });
      child.stderr.on("data", (d: Buffer) => {
        stderr += d.toString();
      });
      child.on("error", reject);
      child.on("close", (code) => {
        // Let the server's auth events land before the test inspects them.
        setTimeout(() => resolve({ exit: code, stdout, stderr }), 250);
      });
    });
  }

  const tail = (p: number) => ["-p", String(p), "-l", "testuser", "--", "127.0.0.1", "whoami"];

  it("authenticates with the agent-held key via the vault-written IdentityFile and runs the command", async () => {
    const agent = await EphemeralSshAgent.start(USER_KEY_PEM);
    const kh = writeKnownHosts([`[127.0.0.1]:${port} ${hostPubLine}`]);
    const identity = writeIdentityFile(agent.publicKeyOpenssh);
    try {
      const r = await runSsh(
        [...sshHardeningArgs(kh.file, identity.file, 10), ...tail(port)],
        agent.authSock,
      );

      expect(r.exit, r.stderr).toBe(0);
      expect(r.stdout.trim()).toBe("live-ok");
      // The server verified a signature from the ephemeral identity…
      expect(events.some((e) => e.matchesEphemeral && e.signed && e.verified)).toBe(true);
      // …and, IdentityFile being explicit, ssh offered no other identity: the
      // default ~/.ssh/id_* candidates are dropped, not merely deprioritized.
      expect(events.filter((e) => e.method === "publickey").every((e) => e.matchesEphemeral)).toBe(
        true,
      );
    } finally {
      agent.dispose();
      kh.dispose();
      identity.dispose();
    }
  }, 30_000);

  it("pins the vulnerability: without the IdentityFile, IdentitiesOnly=yes starves the agent-only key", async () => {
    const agent = await EphemeralSshAgent.start(USER_KEY_PEM);
    const kh = writeKnownHosts([`[127.0.0.1]:${port} ${hostPubLine}`]);
    const identity = writeIdentityFile(agent.publicKeyOpenssh);
    try {
      // The pre-fix argv: identical except the `-i <identity.pub>` pair.
      const full = sshHardeningArgs(kh.file, identity.file, 10);
      const preFix = full.filter((a, i) => a !== "-i" && full[i - 1] !== "-i");

      const r = await runSsh([...preFix, ...tail(port)], agent.authSock);

      // Authentication fails although the agent held a key the server accepts:
      // ssh never offers the ephemeral identity because no configured identity
      // file backs it (ssh_config(5), IdentitiesOnly).
      expect(r.exit).not.toBe(0);
      expect(events.some((e) => e.method === "publickey" && e.matchesEphemeral === true)).toBe(
        false,
      );
    } finally {
      agent.dispose();
      kh.dispose();
      identity.dispose();
    }
  }, 30_000);
});
