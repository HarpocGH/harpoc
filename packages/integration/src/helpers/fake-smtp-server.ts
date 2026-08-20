import { createServer } from "node:net";
import type { AddressInfo, Server, Socket } from "node:net";
import { createSecureContext, TLSSocket } from "node:tls";
import { LOOPBACK_CERT_PEM, LOOPBACK_KEY_PEM } from "./loopback-cert.js";

/**
 * Scripted fake SMTP server, a local copy of core's
 * `packages/core/src/injection/mail/__fixtures__/fake-smtp-server.ts` — the
 * integration package cannot import a module out of core's `src/` (the
 * `rootDir: "src"` cross-package tripwire the typecheck gate enforces; core's
 * cert PEMs are reached only by a runtime `readFileSync`, never a module
 * import), and core does not export the fake, so the brief permits a local
 * copy. The one change from the original is the presented certificate: this
 * copy serves the loopback pair (CN `harpoc-loopback`, SAN
 * `DNS:localhost, IP:127.0.0.1`) so the real `VaultEngine` can dial it through
 * the SSRF floor with TLS identity intact.
 */

const SECURE_CONTEXT = createSecureContext({ key: LOOPBACK_KEY_PEM, cert: LOOPBACK_CERT_PEM });

/** The self-signed loopback certificate, usable as a pinned CA by the client. */
export const FIXTURE_CA_PEM = LOOPBACK_CERT_PEM;
/** The logical host the fixture certificate is valid for. */
export const FIXTURE_HOST = "localhost";

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
    this.send("220 fake.harpoc.local ESMTP\r\n");
  }

  private upgrade(sendBannerAfter: boolean): void {
    this.raw.removeListener("data", this.dataHandler);
    this.lineBuf = "";
    this.secure = true;
    const tls = new TLSSocket(this.raw, { isServer: true, secureContext: SECURE_CONTEXT });
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
