import { readFileSync } from "node:fs";
import { Server } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { MockInstance } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { EphemeralSshAgent } from "./index.js";
import { connectAgent, parseIdentities, requestIdentities } from "../__fixtures__/agent-client.js";
import type { AgentClient } from "../__fixtures__/agent-client.js";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "__fixtures__", "ssh");
const KEY_PEM = readFileSync(join(FIXTURES, "ed25519_openssh"), "utf8");
const NODE_TEXT_MARKER = "node-text-marker-of-the-bind";
const BIND_REFUSAL = "Ephemeral ssh-agent failed: the agent's socket could not be bound";

function failNextBind(listen: MockInstance<Server["listen"]>, err: Error): void {
  listen.mockImplementationOnce(function (this: Server) {
    process.nextTick(() => this.emit("error", err));
    return this;
  });
}

describe("EphemeralSshAgent.start — the bind", () => {
  let listen: MockInstance<Server["listen"]>;

  beforeEach(() => {
    listen = vi.spyOn(Server.prototype, "listen");
  });

  afterEach(() => {
    listen.mockRestore();
  });

  it("a failed bind (EMFILE) is refused SSH_AGENT_FAILED naming the errno, never node's text", async () => {
    failNextBind(
      listen,
      Object.assign(new Error(`listen EMFILE: too many open files ${NODE_TEXT_MARKER}`), {
        code: "EMFILE",
      }),
    );

    const err = await expectVaultError(
      () => EphemeralSshAgent.start(KEY_PEM),
      ErrorCode.SSH_AGENT_FAILED,
    );
    expectAbsent(err.message, NODE_TEXT_MARKER);
    expect(err.message).toBe(`${BIND_REFUSAL} (EMFILE)`);
    expect(listen).toHaveBeenCalledTimes(1);
  });

  it("a failed bind whose error carries no code is refused SSH_AGENT_FAILED (unknown error), never node's text", async () => {
    failNextBind(listen, new Error(`listen ${NODE_TEXT_MARKER}`));

    const err = await expectVaultError(
      () => EphemeralSshAgent.start(KEY_PEM),
      ErrorCode.SSH_AGENT_FAILED,
    );
    expectAbsent(err.message, NODE_TEXT_MARKER);
    expect(err.message).toBe(`${BIND_REFUSAL} (unknown error)`);
    expect(listen).toHaveBeenCalledTimes(1);
  });

  it("a failed bind whose error is null is refused SSH_AGENT_FAILED (unknown error)", async () => {
    failNextBind(listen, null as unknown as Error);

    const err = await expectVaultError(
      () => EphemeralSshAgent.start(KEY_PEM),
      ErrorCode.SSH_AGENT_FAILED,
    );
    expect(err.message).toBe(`${BIND_REFUSAL} (unknown error)`);
    expect(listen).toHaveBeenCalledTimes(1);
  });

  it("an error emitted on the bound server throws nothing, and the agent still answers REQUEST_IDENTITIES", async () => {
    const agent = await EphemeralSshAgent.start(KEY_PEM);
    let client: AgentClient | undefined;
    try {
      expect(listen).toHaveBeenCalledTimes(1);
      const server = listen.mock.contexts[0] as Server;
      expect(() =>
        server.emit("error", Object.assign(new Error("accept EMFILE"), { code: "EMFILE" })),
      ).not.toThrow();

      client = await connectAgent(agent.authSock);
      expect(parseIdentities(await requestIdentities(client))).toHaveLength(1);
    } finally {
      client?.close();
      agent.dispose();
    }
  });
});
