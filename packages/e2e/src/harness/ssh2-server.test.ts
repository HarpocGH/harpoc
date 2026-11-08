import { readFileSync } from "node:fs";
import { join } from "node:path";
import ssh2 from "ssh2";
import type { ParsedKey } from "ssh2";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { KEYS_DIR, clientKeyPem, knownHostPinOnPort } from "./ssh.js";
import { SSH2_EXEC_REPLY, privateKeyNeedles, startSsh2Server } from "./ssh2-server.js";
import type { Ssh2Server } from "./ssh2-server.js";

const { Client, utils } = ssh2;
const OUT = join(KEYS_DIR, "out");

function publicBlob(file: string): Buffer {
  return (utils.parseKey(readFileSync(join(OUT, file))) as ParsedKey).getPublicSSH();
}

/** One exec over a real ssh2 client: the host key checked against the pinned fixture's. */
function execOnce(
  server: Ssh2Server,
  privateKey: string,
): Promise<{ stdout: string; code: number | null }> {
  const pinned = publicBlob("hostkey_pinned_ed25519.pub");
  return new Promise((resolve, reject) => {
    const conn = new Client();
    conn
      .on("ready", () => {
        conn.exec("true", (err, stream) => {
          if (err) {
            conn.end();
            reject(err);
            return;
          }
          let stdout = "";
          stream.on("data", (chunk: Buffer) => (stdout += chunk.toString("utf8")));
          stream.on("exit", (code: number | null) => {
            stream.on("close", () => {
              conn.end();
              resolve({ stdout, code });
            });
          });
        });
      })
      .on("error", reject)
      .connect({
        host: "127.0.0.1",
        port: server.port,
        username: "harpoc-b6",
        privateKey,
        hostVerifier: (key: Buffer) => key.equals(pinned),
        readyTimeout: 10_000,
      });
  });
}

/**
 * The in-process SSH server the agent-socket row authenticates against
 * (RD-B6-3): the fixture `hostkey_pinned_ed25519` host key, the fixture client
 * key's public half the one it accepts — signature verified — and an exec
 * answered with a fixed line, held when a row asks.
 */
describe("the in-process ssh2 server", () => {
  let server: Ssh2Server;

  beforeAll(async () => {
    server = await startSsh2Server();
  });

  afterAll(async () => {
    await server?.close();
  });

  it("accepts the fixture client key by a verified signature and answers the exec", async () => {
    const before = server.events.length;
    expect(await execOnce(server, clientKeyPem())).toEqual({
      stdout: `${SSH2_EXEC_REPLY}\n`,
      code: 0,
    });
    expect(
      server.events
        .slice(before)
        .some((e) => e.method === "publickey" && e.signed && e.verified && e.user === "harpoc-b6"),
    ).toBe(true);
  });

  it("refuses a key it does not authorize", async () => {
    const stranger = readFileSync(join(OUT, "hostkey_rogue_ed25519"), "utf8");
    await expect(execOnce(server, stranger)).rejects.toThrow(/authentication methods failed/);
  });

  it("close() ends a live client connection instead of waiting for it", async () => {
    const own = await startSsh2Server();
    const pinned = publicBlob("hostkey_pinned_ed25519.pub");
    const conn = new Client();
    let closing: Promise<void> | undefined;
    try {
      await new Promise<void>((resolve, reject) => {
        conn
          .once("ready", () => resolve())
          .on("error", reject)
          .connect({
            host: "127.0.0.1",
            port: own.port,
            username: "harpoc-b6",
            privateKey: clientKeyPem(),
            hostVerifier: (key: Buffer) => key.equals(pinned),
            readyTimeout: 10_000,
          });
      });
      const clientClosed = new Promise<string>((resolve) => {
        conn.once("close", () => resolve("closed"));
      });
      closing = own.close();
      const result = await Promise.race([
        closing.then(() => "closed"),
        new Promise((resolve) => setTimeout(resolve, 2_000, "timed out")),
      ]);
      expect(result).toBe("closed");
      expect(
        await Promise.race([
          clientClosed,
          new Promise((resolve) => setTimeout(resolve, 2_000, "timed out")),
        ]),
      ).toBe("closed");
    } finally {
      conn.end();
      await (closing ?? own.close());
    }
  });

  it("holds an exec until released", async () => {
    const hold = server.hold();
    let answered = false;
    const pending = execOnce(server, clientKeyPem()).then((run) => {
      answered = true;
      return run;
    });
    await hold.arrived;
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(answered).toBe(false);
    hold.release();
    expect((await pending).code).toBe(0);
  });

  it("names its pin in the bracketed known_hosts form on its bound port", () => {
    expect(server.knownHostLine).toBe(knownHostPinOnPort("127.0.0.1", server.port));
  });

  it("derives the private key's needles: the PEM, its body lines, the unwrapped body and the scalar — none of them a part of the public line", () => {
    const pem = clientKeyPem();
    const needles = privateKeyNeedles(pem);
    const body = pem.split(/\r?\n/).filter((line) => line.length > 0 && !line.startsWith("-----"));
    // Boolean-shaped throughout: a failing assertion never prints key material.
    expect(needles.includes(pem)).toBe(true);
    expect(needles.includes(body.join(""))).toBe(true);
    expect(body.filter((l) => l.length >= 16).every((line) => needles.includes(line))).toBe(true);
    expect(needles.length).toBe(2 + body.filter((l) => l.length >= 16).length + 3);
    const publicLine = readFileSync(join(OUT, "client_ed25519.pub"), "utf8");
    expect(needles.some((needle) => publicLine.includes(needle))).toBe(false);
  });
});
