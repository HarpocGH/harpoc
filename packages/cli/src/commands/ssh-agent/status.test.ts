import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn(),
}));

// The real probe, spied: a row on every platform answers for it (a fake agent can listen only on a
// pipe on win32, never at <runtime-dir>/<consumer>/ssh-agent.sock); the POSIX row runs it whole.
vi.mock("../../utils/agent-probe.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../utils/agent-probe.js")>();
  return { ...actual, probeAgentSocket: vi.fn(actual.probeAgentSocket) };
});

import { probeAgentSocket } from "../../utils/agent-probe.js";
import { loadUnlockedEngine } from "../../utils/vault-loader.js";
import { registerSshAgentStatusCommand } from "./status.js";
import { buildCli, spyCli, type CliSpies } from "../../__fixtures__/cli-harness.js";

const run = buildCli(
  (program) => registerSshAgentStatusCommand(program.command("ssh-agent")),
  ["ssh-agent", "status"],
);

// The public halves of core's fixture keys (core/src/injection/__fixtures__/ssh/*.pub) and what
// `ssh-keygen -lf` (C:\Windows\System32\OpenSSH, OpenSSH_for_Windows_9.5p2) printed for them.
const ED25519 = {
  keyType: "ssh-ed25519",
  blob: "AAAAC3NzaC1lZDI1NTE5AAAAIOCrwIj6+onGT6amn11WaE7DBDJU/Zcim3GZknGAAwyw",
  fingerprint: "SHA256:vKqyAVTrbMF3MHOKboGKqIW51KxwLjApBtP/N48OLeo",
};
const ECDSA256 = {
  keyType: "ecdsa-sha2-nistp256",
  blob: "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ/QFP3G4F4xZlD/T+Aj459FydBO+OMsgSEEE9ej/ZvkUP4KagQHcySSRBY2bJFIRP4uL6ijgcG2OIZHow14hxc=",
  fingerprint: "SHA256:7dcaydo930fNrjtVUaiof/9VYG5XTSIZsm5+Q+F96ag",
};

function listed(key: typeof ED25519, comment: string) {
  return {
    keyType: key.keyType,
    fingerprint: key.fingerprint,
    comment,
    publicKey: `${key.keyType} ${key.blob} ${comment}`,
  };
}

let spies: CliSpies;
let dir: string;

beforeEach(() => {
  vi.clearAllMocks();
  spies = spyCli();
  dir = mkdtempSync(join(tmpdir(), "harpoc-sas-"));
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.mocked(probeAgentSocket).mockReset();
  spies.restore();
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

/** Consumer directories under the runtime directory, and the probe's answer for each socket. */
function consumers(answers: Record<string, Awaited<ReturnType<typeof probeAgentSocket>>>): void {
  for (const name of Object.keys(answers)) mkdirSync(join(dir, name));
  vi.mocked(probeAgentSocket).mockImplementation(async (socketPath) => {
    const name = Object.keys(answers).find(
      (consumer) => join(dir, consumer, "ssh-agent.sock") === socketPath,
    );
    if (name === undefined) throw new Error(`unexpected probe of ${socketPath}`);
    return answers[name] as Awaited<ReturnType<typeof probeAgentSocket>>;
  });
}

describe("ssh-agent status — each consumer's socket, as ssh-add -l reads it", () => {
  it("lists each consumer's identities: key type, SHA256 fingerprint, the handle; opens no vault", async () => {
    consumers({
      bob: { listening: false, reason: "no_socket" },
      alice: {
        listening: true,
        identities: [listed(ED25519, "secret://deploy-key"), listed(ECDSA256, "secret://ci/build")],
      },
    });

    await run(["--runtime-dir", dir]);

    expect(spies.stdout()).toBe(
      [
        `consumer alice: listening — 2 identities (${join(dir, "alice", "ssh-agent.sock")})`,
        `  ssh-ed25519 ${ED25519.fingerprint} secret://deploy-key`,
        `  ecdsa-sha2-nistp256 ${ECDSA256.fingerprint} secret://ci/build`,
        `consumer bob: not listening — no socket (${join(dir, "bob", "ssh-agent.sock")})`,
      ].join("\n"),
    );
    expect(vi.mocked(probeAgentSocket).mock.calls).toEqual([
      [join(dir, "alice", "ssh-agent.sock"), 2_000],
      [join(dir, "bob", "ssh-agent.sock"), 2_000],
    ]);
    expect(spies.stderr()).toBe("");
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
    expect(spies.exitSpy).not.toHaveBeenCalled();
  });

  it("--consumer probes that consumer alone and lists no directory", async () => {
    const runtimeDir = join(dir, "not-listed");
    vi.mocked(probeAgentSocket).mockResolvedValue({ listening: true, identities: [] });

    await run(["--consumer", "alice", "--runtime-dir", runtimeDir]);

    expect(vi.mocked(probeAgentSocket).mock.calls).toEqual([
      [join(runtimeDir, "alice", "ssh-agent.sock"), 2_000],
    ]);
    expect(spies.stdout()).toBe(
      `consumer alice: listening — no identities (${join(runtimeDir, "alice", "ssh-agent.sock")})`,
    );
  });

  it("--json prints the same facts as one object", async () => {
    consumers({
      alice: { listening: true, identities: [listed(ED25519, "secret://deploy-key")] },
      bob: { listening: false, reason: "timeout" },
    });

    await run(["--runtime-dir", dir, "--json"]);

    expect(JSON.parse(spies.stdout())).toEqual({
      runtimeDir: dir,
      consumers: [
        {
          consumer: "alice",
          socketPath: join(dir, "alice", "ssh-agent.sock"),
          listening: true,
          identities: [listed(ED25519, "secret://deploy-key")],
        },
        {
          consumer: "bob",
          socketPath: join(dir, "bob", "ssh-agent.sock"),
          listening: false,
          reason: "timeout",
        },
      ],
    });
  });

  it("names every reason a socket is not listening, and an agent that refuses to list", async () => {
    consumers({
      a: { listening: false, reason: "not_a_socket" },
      b: { listening: false, reason: "refused" },
      c: { listening: false, reason: "permission_denied" },
      d: { listening: false, reason: "timeout" },
      e: { listening: false, reason: "not_an_agent" },
      f: { listening: false, reason: "unreachable" },
      g: { listening: true, identities: null },
    });

    await run(["--runtime-dir", dir]);

    const socket = (name: string): string => `(${join(dir, name, "ssh-agent.sock")})`;
    expect(spies.stdout().split("\n")).toEqual([
      `consumer a: not listening — not a socket ${socket("a")}`,
      `consumer b: not listening — connection refused ${socket("b")}`,
      `consumer c: not listening — permission denied ${socket("c")}`,
      `consumer d: not listening — no answer within 2 s ${socket("d")}`,
      `consumer e: not listening — not an ssh-agent answer ${socket("e")}`,
      `consumer f: not listening — unreachable ${socket("f")}`,
      `consumer g: listening — the identities request was refused (a locked vault refuses it) ${socket("g")}`,
    ]);
  });

  it("shows every control character an identity carries as ?, so no escape sequence reaches the terminal", async () => {
    consumers({
      alice: {
        listening: true,
        identities: [
          {
            keyType: "ssh-ed25519\u0007",
            fingerprint: ED25519.fingerprint,
            comment: "secret://k\u001b[31m\u009b0m\u007f",
            publicKey: `ssh-ed25519 ${ED25519.blob} secret://k`,
          },
        ],
      },
    });

    await run(["--runtime-dir", dir]);

    expect(spies.stdout()).toBe(
      [
        `consumer alice: listening — 1 identity (${join(dir, "alice", "ssh-agent.sock")})`,
        `  ssh-ed25519? ${ED25519.fingerprint} secret://k?[31m?0m?`,
      ].join("\n"),
    );
    const controls = spies.logSpy.mock.calls
      .flat()
      .flatMap((line) => Array.from(String(line)))
      .filter((char) => {
        const code = char.charCodeAt(0);
        return code < 0x20 || (code >= 0x7f && code <= 0x9f);
      });
    expect(controls).toEqual([]);
  });

  it("a runtime directory holding no consumer directory says so and exits 0; a file is no consumer", async () => {
    writeFileSync(join(dir, "token.jwt"), "");

    await run(["--runtime-dir", dir]);

    expect(spies.stdout()).toBe(`No consumer directory under ${dir}.`);
    expect(probeAgentSocket).not.toHaveBeenCalled();
    expect(spies.exitSpy).not.toHaveBeenCalled();
  });

  // The command runs in the consumer's context, where a unit's $RUNTIME_DIRECTORY is that unit's
  // own directory, not the daemon's (RA-10): the path is taken from --runtime-dir alone.
  it("reads no ambient RUNTIME_DIRECTORY: without --runtime-dir it is refused", async () => {
    vi.stubEnv("RUNTIME_DIRECTORY", dir);

    await expect(run([])).rejects.toThrow("process.exit");
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        "Error: [INVALID_INPUT] --runtime-dir <path> is required: the daemon's runtime directory (no $RUNTIME_DIRECTORY is read)",
      ],
    ]);
    expect(probeAgentSocket).not.toHaveBeenCalled();
  });
});

describe("ssh-agent status — refusals, before anything is probed", () => {
  it.each([
    {
      label: "an empty --runtime-dir",
      argv: ["--runtime-dir", ""],
      line: "Error: [INVALID_INPUT] --runtime-dir: empty path",
    },
    {
      label: "a flag taken as the --runtime-dir path",
      argv: ["--runtime-dir", "--json"],
      line: "Error: [INVALID_INPUT] --runtime-dir: a flag, not a path (give a path that starts with a dash as ./-name)",
    },
    {
      label: "a --consumer that is not a consumer name",
      argv: ["--consumer", "Alice", "--runtime-dir", "<dir>"],
      line: 'Error: [INVALID_INPUT] consumer "Alice": not a directory name (lowercase letters, digits, _ and -, not starting with -; at most 255)',
    },
    {
      label: "a runtime directory that does not exist",
      argv: ["--runtime-dir", "<missing>"],
      line: "Error: [INVALID_INPUT] --runtime-dir: no such directory: <missing>",
    },
    {
      label: "a regular file given as the runtime directory",
      argv: ["--runtime-dir", "<file>"],
      line: "Error: [INVALID_INPUT] --runtime-dir: not a directory: <file>",
    },
  ])("refuses $label", async ({ argv, line }) => {
    const missing = join(dir, "missing");
    const file = join(dir, "plain-file");
    writeFileSync(file, "");
    const resolve = (text: string): string =>
      text.replace("<missing>", missing).replace("<file>", file).replace("<dir>", dir);

    await expect(run(argv.map(resolve))).rejects.toThrow("process.exit");

    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy.mock.calls).toEqual([[resolve(line)]]);
    expect(spies.logSpy).not.toHaveBeenCalled();
    expect(probeAgentSocket).not.toHaveBeenCalled();
  });

  it("a directory under the runtime directory that is not a consumer name refuses the report", async () => {
    mkdirSync(join(dir, "alice"));
    mkdirSync(join(dir, "-x"));

    await expect(run(["--runtime-dir", dir])).rejects.toThrow("process.exit");
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        'Error: [INVALID_INPUT] consumer "-x": not a directory name (lowercase letters, digits, _ and -, not starting with -; at most 255)',
      ],
    ]);
    expect(probeAgentSocket).not.toHaveBeenCalled();
  });

  it("renders a refusal through the --json envelope", async () => {
    await expect(run(["--consumer", "Alice", "--runtime-dir", dir, "--json"])).rejects.toThrow(
      "process.exit",
    );

    expect(JSON.parse(spies.stderr())).toEqual({
      error: "INVALID_INPUT",
      message:
        'consumer "Alice": not a directory name (lowercase letters, digits, _ and -, not starting with -; at most 255)',
    });
    expect(spies.logSpy).not.toHaveBeenCalled();
  });
});

// The real probe against a stand-in agent at the consumer's socket path: a Unix socket — Node
// listens on a pipe only on win32, never at a filesystem path (measured: EACCES). The short
// prefix keeps the path inside darwin's 104-byte sun_path under its long $TMPDIR.
describe.skipIf(process.platform === "win32")(
  "ssh-agent status — the real probe through a stand-in agent socket (POSIX)",
  () => {
    let server: Server | undefined;

    afterEach(async () => {
      await new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve()));
      server = undefined;
    });

    it("prints the identities a socket at <runtime-dir>/<consumer>/ssh-agent.sock answers", async () => {
      mkdirSync(join(dir, "alice"));
      const blob = Buffer.from(ED25519.blob, "base64");
      const comment = Buffer.from("secret://deploy-key");
      const u32 = (n: number): Buffer => {
        const b = Buffer.alloc(4);
        b.writeUInt32BE(n);
        return b;
      };
      const body = Buffer.concat([
        Buffer.from([12]),
        u32(1),
        u32(blob.length),
        blob,
        u32(comment.length),
        comment,
      ]);
      server = createServer((socket) => {
        socket.on("error", () => undefined);
        socket.on("data", () => socket.end(Buffer.concat([u32(body.length), body])));
      });
      const socketPath = join(dir, "alice", "ssh-agent.sock");
      await new Promise<void>((resolve) => server?.listen(socketPath, () => resolve()));

      await run(["--runtime-dir", dir]);

      expect(spies.stdout()).toBe(
        [
          `consumer alice: listening — 1 identity (${socketPath})`,
          `  ssh-ed25519 ${ED25519.fingerprint} secret://deploy-key`,
        ].join("\n"),
      );
    });
  },
);
