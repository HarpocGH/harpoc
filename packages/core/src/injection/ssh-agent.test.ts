import { generateKeyPairSync } from "node:crypto";
import { existsSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import ssh2 from "ssh2";
import type { ParsedKey } from "ssh2";
import { EphemeralSshAgent } from "./ssh-agent.js";

const { createAgent, utils } = ssh2;

function makeKeyPem(): string {
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return privateKey;
}

const KEY_PEM = makeKeyPem();

describe("EphemeralSshAgent", () => {
  it("serves the identity and signs over the agent socket", async () => {
    const agent = await EphemeralSshAgent.start(KEY_PEM);
    try {
      const client = createAgent(agent.authSock);

      const keys = await new Promise<ParsedKey[]>((resolve, reject) => {
        client.getIdentities((err, k) => (err ? reject(err) : resolve(k ?? [])));
      });
      expect(keys.length).toBe(1);

      const data = Buffer.from("challenge-bytes");
      const sig = await new Promise<Buffer>((resolve, reject) => {
        client.sign(keys[0], data, {}, (err, signature) =>
          err ? reject(err) : resolve(signature as Buffer),
        );
      });
      expect(Buffer.isBuffer(sig)).toBe(true);
      expect(sig.length).toBeGreaterThan(0);

      const parsed = utils.parseKey(KEY_PEM);
      if (!(parsed instanceof Error)) {
        expect(parsed.verify(data, sig)).toBe(true);
      }
    } finally {
      agent.dispose();
    }
  });

  it("rejects an invalid private key", async () => {
    await expect(EphemeralSshAgent.start("not a private key")).rejects.toMatchObject({
      code: ErrorCode.SSH_AGENT_FAILED,
    });
  });

  it("removes the socket directory on dispose (POSIX)", async () => {
    const agent = await EphemeralSshAgent.start(KEY_PEM);
    const sock = agent.authSock;
    agent.dispose();
    if (process.platform !== "win32") {
      expect(existsSync(sock)).toBe(false);
    }
  });
});
