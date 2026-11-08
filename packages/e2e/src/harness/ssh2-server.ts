import { createPrivateKey } from "node:crypto";
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import ssh2 from "ssh2";
import type { Connection, Server as SshServer } from "ssh2";
import { KEYS_DIR, keysReady, knownHostPinOnPort } from "./ssh.js";

const { Server, utils } = ssh2;

/** The line every exec is answered with. */
export const SSH2_EXEC_REPLY = "b6-ok";

export interface SshAuthEvent {
  user: string;
  method: string;
  signed: boolean;
  verified: boolean;
}

/** A gate on the next exec: answered only after `release()`. */
export interface ExecHold {
  arrived: Promise<void>;
  release(): void;
}

export interface Ssh2Server {
  port: number;
  /** `[127.0.0.1]:<port> ssh-ed25519 <base64>` — the vault's pin and the agent's known_hosts line. */
  knownHostLine: string;
  events: SshAuthEvent[];
  hold(): ExecHold;
  close(): Promise<void>;
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve: () => void = () => undefined;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

/**
 * The fleet's `sshd-pinned` in process (RD-B6-3), as core's
 * `agent-socket-live.test.ts` builds it: an `ssh2` server with the fixture
 * `hostkey_pinned_ed25519` host key on a free loopback port, accepting the
 * fixture client key's public half alone and only by a signature it verifies,
 * answering every exec with `SSH2_EXEC_REPLY`. It runs in the harness's
 * process, never in the vault's.
 */
export async function startSsh2Server(): Promise<Ssh2Server> {
  if (!keysReady())
    throw new Error("fixture ssh keys missing — run: pnpm --filter @harpoc/e2e keys");
  const out = join(KEYS_DIR, "out");
  const authorized = utils.parseKey(readFileSync(join(out, "client_ed25519.pub")));
  if (authorized instanceof Error)
    throw new Error("client_ed25519.pub does not parse as a public key");
  const events: SshAuthEvent[] = [];
  let armed: { arrive: () => void; released: Promise<void> } | undefined;
  const releases: Array<() => void> = [];
  const clients = new Set<Connection>();

  const server: SshServer = new Server(
    { hostKeys: [readFileSync(join(out, "hostkey_pinned_ed25519"))] },
    (client) => {
      clients.add(client);
      client.once("close", () => clients.delete(client));
      client
        .on("authentication", (ctx) => {
          if (ctx.method !== "publickey") {
            events.push({ user: ctx.username, method: ctx.method, signed: false, verified: false });
            ctx.reject(["publickey"]);
            return;
          }
          const offered =
            ctx.key.algo === authorized.type && ctx.key.data.equals(authorized.getPublicSSH());
          if (!offered) {
            events.push({ user: ctx.username, method: ctx.method, signed: false, verified: false });
            ctx.reject(["publickey"]);
            return;
          }
          if (ctx.signature === undefined || ctx.blob === undefined) {
            events.push({ user: ctx.username, method: ctx.method, signed: false, verified: false });
            ctx.accept();
            return;
          }
          const verified = authorized.verify(ctx.blob, ctx.signature, ctx.hashAlgo);
          events.push({ user: ctx.username, method: ctx.method, signed: true, verified });
          if (verified) ctx.accept();
          else ctx.reject(["publickey"]);
        })
        .on("ready", () => {
          client.on("session", (accept) => {
            accept().on("exec", (acceptExec) => {
              const gate = armed;
              const stream = acceptExec();
              void (async () => {
                if (gate !== undefined) {
                  gate.arrive();
                  await gate.released;
                }
                stream.write(`${SSH2_EXEC_REPLY}\n`);
                stream.exit(0);
                stream.end();
              })();
            });
          });
        })
        .on("error", () => {
          // A client that disconnects after a refused key ends here.
        });
    },
  );
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const { port } = server.address() as AddressInfo;

  return {
    port,
    knownHostLine: knownHostPinOnPort("127.0.0.1", port),
    events,
    hold(): ExecHold {
      const arrival = deferred();
      const releasing = deferred();
      const gate = { arrive: arrival.resolve, released: releasing.promise };
      armed = gate;
      const release = (): void => {
        releasing.resolve();
        if (armed === gate) armed = undefined;
      };
      releases.push(release);
      return { arrived: arrival.promise, release };
    },
    async close(): Promise<void> {
      for (const release of releases) release();
      for (const client of clients) client.end();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/**
 * A private key's forms a leak would take, as core's live suite derives them:
 * the PEM whole, each body line of 16 characters or more, the unwrapped body,
 * and the private scalar in base64url, base64 and hex.
 */
export function privateKeyNeedles(pem: string): string[] {
  const body = pem.split(/\r?\n/).filter((line) => line.length > 0 && !line.startsWith("-----"));
  const parsed = utils.parseKey(pem);
  if (parsed instanceof Error) throw new Error("the private key fixture does not parse");
  const jwk = createPrivateKey(parsed.getPrivatePEM()).export({ format: "jwk" });
  const scalar = Buffer.from(String(jwk.d), "base64url");
  return [
    pem,
    ...body.filter((line) => line.length >= 16),
    body.join(""),
    scalar.toString("base64url"),
    scalar.toString("base64"),
    scalar.toString("hex"),
  ];
}
