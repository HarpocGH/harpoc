import { readFileSync } from "node:fs";
import { createServer } from "node:net";
import type { AddressInfo, Server, Socket } from "node:net";
import { dirname, join } from "node:path";
import { createSecureContext, TLSSocket } from "node:tls";
import type { SecureContext } from "node:tls";
import { fileURLToPath } from "node:url";

/**
 * Scripted fake SMTP server for the in-house client's wire-level tests.
 *
 * It records every byte received BEFORE the TLS upgrade into `plaintext` and
 * every (decrypted) byte received AFTER into `postTls`, so a test can prove the
 * load-bearing invariant directly: AUTH bytes never cross the plaintext leg.
 * STARTTLS and implicit-TLS both upgrade the same accepted socket to a
 * server-side `TLSSocket`, presenting the reused RSA fixture certificate
 * (`packages/core/src/__fixtures__/certs`, CN/SAN `fixture.example.com`).
 */

const CERT_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "__fixtures__",
  "certs",
);
// This file is not a `.test.ts`, so it compiles into `dist`; a top-level
// `readFileSync`/`createSecureContext` would run the fs read on import. Both are
// deferred to first use and memoized, keeping module load side-effect-free — the
// fixture is only ever touched from a test's `startFakeSmtp` (or the pinned CA).
let fixtureCache: { cert: string; context: SecureContext } | undefined;

function loadFixture(): { cert: string; context: SecureContext } {
  if (!fixtureCache) {
    const key = readFileSync(join(CERT_DIR, "rsa-key.pem"), "utf8");
    const cert = readFileSync(join(CERT_DIR, "rsa-cert.pem"), "utf8");
    fixtureCache = { cert, context: createSecureContext({ key, cert }) };
  }
  return fixtureCache;
}

/** The server-side TLS context, built (and cached) on first use. */
function getSecureContext(): SecureContext {
  return loadFixture().context;
}

/** The self-signed fixture certificate, usable as a pinned CA by the client. */
export function getFixtureCaPem(): string {
  return loadFixture().cert;
}
/** The logical host the fixture certificate is valid for. */
export const FIXTURE_HOST = "fixture.example.com";

export interface SmtpScript {
  /** Advertise STARTTLS and honor the upgrade. */
  starttls: boolean;
  /** Mechanisms advertised once the connection is secure (e.g. `["PLAIN"]`). */
  authMechanisms: string[];
  /** Present TLS from the first byte (for `security: "tls"`). */
  implicitTls?: boolean;
  /** Answer AUTH with 535 instead of 235. */
  auth?: "ok" | "fail";
  /** Answer RCPT TO with 550 instead of 250. */
  rcpt?: "ok" | "fail";
  /** `flood` = a multi-megabyte bannerless line; `silent` = never greet. */
  banner?: "normal" | "flood" | "silent";
}

export interface RecordedWire {
  plaintext: Buffer;
  postTls: Buffer;
}

export interface FakeSmtp {
  port: number;
  wire(): RecordedWire;
  close(): Promise<void>;
}

class Connection {
  private secure = false;
  private stream: Socket | TLSSocket;
  private lineBuf = "";
  private inData = false;
  private authState: "none" | "user" | "pass" = "none";
  private readonly plaintext: Buffer[] = [];
  private readonly postTls: Buffer[] = [];
  private readonly dataHandler = (chunk: Buffer): void => this.onChunk(chunk);

  constructor(
    private readonly raw: Socket,
    private readonly script: SmtpScript,
  ) {
    this.stream = raw;
    raw.on("error", () => undefined);
    if (script.implicitTls) {
      this.upgrade(true);
    } else {
      raw.on("data", this.dataHandler);
      this.sendBanner();
    }
  }

  wire(): RecordedWire {
    return { plaintext: Buffer.concat(this.plaintext), postTls: Buffer.concat(this.postTls) };
  }

  private onChunk(chunk: Buffer): void {
    (this.secure ? this.postTls : this.plaintext).push(Buffer.from(chunk));
    this.lineBuf += chunk.toString("latin1");
    let idx = this.lineBuf.indexOf("\r\n");
    while (idx !== -1) {
      const line = this.lineBuf.slice(0, idx);
      this.lineBuf = this.lineBuf.slice(idx + 2);
      this.handleLine(line);
      idx = this.lineBuf.indexOf("\r\n");
    }
  }

  private handleLine(line: string): void {
    if (this.inData) {
      if (line === ".") {
        this.inData = false;
        this.send("250 2.0.0 Ok: queued\r\n");
      }
      return;
    }
    if (this.authState === "user") {
      this.authState = "pass";
      this.send("334 UGFzc3dvcmQ6\r\n");
      return;
    }
    if (this.authState === "pass") {
      this.authState = "none";
      this.finishAuth();
      return;
    }
    const upper = line.toUpperCase();
    if (upper.startsWith("EHLO") || upper.startsWith("HELO")) {
      this.sendEhlo();
      return;
    }
    if (upper === "STARTTLS") {
      if (!this.script.starttls) {
        this.send("502 5.5.1 Command not implemented\r\n");
        return;
      }
      this.send("220 2.0.0 Ready to start TLS\r\n");
      this.upgrade(false);
      return;
    }
    if (upper.startsWith("AUTH ")) {
      this.handleAuth(line);
      return;
    }
    if (upper.startsWith("MAIL FROM")) {
      this.send("250 2.1.0 Ok\r\n");
      return;
    }
    if (upper.startsWith("RCPT TO")) {
      this.send(this.script.rcpt === "fail" ? "550 5.1.1 No such user\r\n" : "250 2.1.5 Ok\r\n");
      return;
    }
    if (upper === "DATA") {
      this.inData = true;
      this.send("354 End data with <CR><LF>.<CR><LF>\r\n");
      return;
    }
    if (upper === "QUIT") {
      this.send("221 2.0.0 Bye\r\n");
      this.stream.end();
      return;
    }
    if (upper === "RSET" || upper === "NOOP") {
      this.send("250 2.0.0 Ok\r\n");
      return;
    }
    this.send("500 5.5.2 Command unrecognized\r\n");
  }

  private handleAuth(line: string): void {
    const mech = (line.split(" ")[1] ?? "").toUpperCase();
    if (mech === "PLAIN" || mech === "XOAUTH2") {
      // Credentials arrive inline (base64) — the fake never inspects them.
      this.finishAuth();
      return;
    }
    if (mech === "LOGIN") {
      this.authState = "user";
      this.send("334 VXNlcm5hbWU6\r\n");
      return;
    }
    this.send("504 5.7.4 Unrecognized authentication type\r\n");
  }

  private finishAuth(): void {
    this.send(
      this.script.auth === "fail"
        ? "535 5.7.8 Authentication credentials invalid\r\n"
        : "235 2.7.0 Authentication successful\r\n",
    );
  }

  private sendEhlo(): void {
    const lines = ["fake.harpoc.local greets you", "PIPELINING", "8BITMIME"];
    if (this.script.starttls && !this.secure) {
      lines.push("STARTTLS");
    }
    if (this.secure && this.script.authMechanisms.length > 0) {
      lines.push(`AUTH ${this.script.authMechanisms.join(" ")}`);
    }
    const out = lines
      .map((text, i) => `250${i === lines.length - 1 ? " " : "-"}${text}\r\n`)
      .join("");
    this.send(out);
  }

  private sendBanner(): void {
    if (this.script.banner === "silent") {
      return;
    }
    if (this.script.banner === "flood") {
      // A single bannerless line far past the client's per-line cap.
      this.stream.write(Buffer.concat([Buffer.from("220 "), Buffer.alloc(10 * 1024 * 1024, 0x78)]));
      return;
    }
    this.send("220 fake.harpoc.local ESMTP\r\n");
  }

  private upgrade(sendBannerAfter: boolean): void {
    this.raw.removeListener("data", this.dataHandler);
    this.lineBuf = "";
    this.secure = true;
    const tls = new TLSSocket(this.raw, { isServer: true, secureContext: getSecureContext() });
    tls.on("error", () => undefined);
    tls.on("data", this.dataHandler);
    this.stream = tls;
    if (sendBannerAfter) {
      tls.on("secure", () => this.sendBanner());
    }
  }

  private send(text: string): void {
    this.stream.write(Buffer.from(text, "latin1"));
  }
}

export async function startFakeSmtp(script: SmtpScript): Promise<FakeSmtp> {
  let latest: Connection | null = null;
  const server: Server = createServer((raw: Socket) => {
    latest = new Connection(raw, script);
  });
  server.on("error", () => undefined);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const port = (server.address() as AddressInfo).port;
  return {
    port,
    wire: () => (latest ? latest.wire() : { plaintext: Buffer.alloc(0), postTls: Buffer.alloc(0) }),
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
