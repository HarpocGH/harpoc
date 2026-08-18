import { spawn } from "node:child_process";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Arm, CallOutcome } from "./arm.js";
import { textOf } from "../harness/surfaces/mcp-http.js";
import { resolveGit, resolveSsh } from "../harness/fixtures.js";

const SERVER = fileURLToPath(new URL("../../fixtures/baseline-mcp/server.mjs", import.meta.url));
const STARTUP_TIMEOUT_MS = 30_000;

/**
 * The git and ssh the HARNESS resolved, handed to the baseline rather than
 * re-resolved inside it, so both arms drive the same binary (F-6). Resolution
 * failures are tolerated: a host without ssh must still be able to run the
 * http and process arms, and the ssh arms fail on their own terms when they
 * spawn a binary that is not there.
 */
function resolvedBinaries(): Record<string, string> {
  const env: Record<string, string> = {};
  try {
    env.E2E_GIT_PATH = resolveGit();
  } catch {
    /* the git arms will report it */
  }
  try {
    env.E2E_SSH_PATH = resolveSsh();
  } catch {
    /* the ssh arms will report it */
  }
  return env;
}

/**
 * Wait for the child's port handshake. A fixed port would race across the
 * sequence of arms; port 0 plus a stdout line is deterministic.
 */
function awaitPort(child: ChildProcessWithoutNullStreams): Promise<number> {
  return new Promise((resolve, reject) => {
    let buffered = "";
    let settled = false;
    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };
    const timer = setTimeout(() => {
      settle(() =>
        reject(new Error(`baseline-mcp did not announce a port within ${STARTUP_TIMEOUT_MS} ms`)),
      );
    }, STARTUP_TIMEOUT_MS);

    child.stdout.on("data", (chunk: Buffer) => {
      buffered += chunk.toString("utf8");
      const match = /LISTENING (\d+)/.exec(buffered);
      if (match) settle(() => resolve(Number(match[1])));
    });
    child.on("error", (err) => settle(() => reject(err)));
    child.on("exit", (code) =>
      settle(() => reject(new Error(`baseline-mcp exited early with code ${String(code)}`))),
    );
  });
}

/** A running baseline fixture with a connected MCP client. */
export interface BaselineServer {
  client: Client;
  child: ChildProcessWithoutNullStreams;
  port: number;
  /** Everything the child has written to stderr so far, read at call time. */
  stderr(): string;
  stop(): Promise<void>;
}

/**
 * The §2.3 baseline fixture, running: a real MCP server holding the credential
 * in its launch environment, with no vault in the path (D2, D5).
 *
 * Spawned rather than containerised because it is the analogue of the vault's
 * own MCP server, which the Harpoc arm runs in-process — a container would put
 * a network boundary on one side of the comparison and not the other. That also
 * makes it fleet-free, which is what lets the behavioural pin on the fixture's
 * own injection dispatch run on a host without Docker.
 */
export async function startBaselineServer(opts: {
  credential: string;
  secretName?: string;
}): Promise<BaselineServer> {
  const child = spawn(process.execPath, [SERVER], {
    env: {
      ...process.env,
      ...resolvedBinaries(),
      // The credential enters exactly as Listing 2.1 delivers it.
      API_TOKEN: opts.credential,
      SECRET_NAME: opts.secretName ?? "baseline-secret",
      PORT: "0",
    },
    shell: false,
  }) as ChildProcessWithoutNullStreams;

  let stderr = "";
  child.stderr.on("data", (chunk: Buffer) => {
    // Capped from the front: an unread pipe blocks the child once the OS
    // buffer fills, and the stream is a channel assertOpaque covers.
    if (stderr.length < 256 * 1024) stderr += chunk.toString("utf8");
  });

  const port = await awaitPort(child);
  const transport = new StreamableHTTPClientTransport(
    new URL(`http://127.0.0.1:${String(port)}/mcp`),
  );
  const client = new Client({ name: "harpoc-e2e-baseline-client", version: "1.0.0" });
  await client.connect(transport);

  return {
    client,
    child,
    port,
    stderr: () => stderr,
    async stop() {
      await client.close();
      child.kill();
    },
  };
}

/**
 * The §2.3 baseline arm: the fixture above, wrapped in the `Arm` contract the
 * paired scenarios drive.
 */
export async function startBaselineArm(credential: string, secretName?: string): Promise<Arm> {
  const server = await startBaselineServer({ credential, secretName });
  const client = server.client;

  const call = async (name: string, args: Record<string, unknown>): Promise<CallOutcome> => {
    try {
      const raw = (await client.callTool({ name, arguments: args })) as {
        isError?: boolean;
        content?: unknown;
      };
      const text = textOf(raw);
      const stderr = server.stderr();
      if (raw.isError === true) return { ok: false, result: raw, text, errorText: text, stderr };
      return { ok: true, result: raw, text, stderr };
    } catch (err) {
      const text = err instanceof Error ? err.message : String(err);
      return { ok: false, result: err, text, errorText: text, stderr: server.stderr() };
    }
  };

  return {
    name: "baseline",
    invoke: (handle, action) => call("use_secret", { handle, action }),
    async probeMetadata(): Promise<CallOutcome> {
      // The whole agent-visible metadata surface at once — §6.2.1's claim is
      // about the surface, not about any single tool.
      const list = await call("list_secrets", {});
      const info = await call("get_secret_info", {});
      const failing = await call("failing_request", {});
      const resource = await client
        .readResource({ uri: "credentials://env" })
        .then((r) => r as unknown)
        .catch((err: unknown) => err);

      const parts = [list, info, failing];
      return {
        ok: true,
        result: {
          list: list.result,
          info: info.result,
          failing: failing.errorText ?? failing.result,
          resource,
        },
        text: parts.map((p) => p.text).join("\n"),
        stderr: server.stderr(),
      };
    },
    close() {
      return server.stop();
    },
  };
}
