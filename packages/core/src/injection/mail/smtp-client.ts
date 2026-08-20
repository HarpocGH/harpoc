import { connect as netConnect } from "node:net";
import type { Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";
import type { ConnectionOptions, TLSSocket } from "node:tls";
import { VaultError } from "@harpoc/shared";
import { identityCheckerFor } from "../db-adapters.js";

/**
 * In-house SMTP submission client (node:net / node:tls only — no third-party
 * mail library in the vault process). It carries the vault credential to the
 * mail server, so the load-bearing invariant is that AUTH bytes NEVER cross a
 * plaintext leg: `starttls` upgrades the same socket and only then authenticates,
 * and a server that fails to advertise STARTTLS is refused before any credential
 * byte is written. The MIME body is assembled elsewhere (`mail/mime.ts`);
 * dot-stuffing and the wire framing are this module's job.
 */

export type SmtpAuth =
  | { kind: "password"; username: string; password: string }
  | { kind: "xoauth2"; username: string; accessToken: string };

export interface SmtpSendOptions {
  host: string;
  port: number;
  /** SSRF-pinned address to dial; TLS identity is verified against `host`. */
  address: string;
  security: "tls" | "starttls";
  auth: SmtpAuth;
  envelope: { from: string; recipients: string[] };
  /** Assembled RFC 5322 text (CRLF line endings). */
  message: string;
  timeoutMs: number;
  /** `false` is an audited plaintext opt-out for implicit-TLS mode only. */
  tls?: { ca?: string } | false;
}

// Capped-output discipline (see injection/capped-output.ts): bound what a
// hostile or malfunctioning server can make the client buffer.
const MAX_LINE_BYTES = 8 * 1024;
const MAX_SESSION_BYTES = 1024 * 1024;
// A fixed, non-identifying HELO/EHLO name — the client's own identity leaks
// nothing about the host it runs on.
const CLIENT_NAME = "harpoc.local";

interface SmtpResponse {
  code: number;
  lines: string[];
}

interface Capabilities {
  starttls: boolean;
  mechanisms: Set<string>;
}

/**
 * A single-socket SMTP read/write channel. It assembles multi-line responses
 * (`250-` continuation, `250 ` terminator), enforces the per-line and
 * per-session byte caps, and can be rebound onto the upgraded TLS socket after
 * STARTTLS. Every failure surfaces as {@link VaultError.smtpDeliveryFailed} so
 * no lower-level detail (or credential) reaches the caller.
 */
class SmtpChannel {
  private stream: Socket | TLSSocket | null = null;
  private secure = false;
  private pending = "";
  private accum: string[] = [];
  private completed: SmtpResponse[] = [];
  private resolver: ((r: SmtpResponse) => void) | null = null;
  private rejecter: ((e: Error) => void) | null = null;
  private failure: Error | null = null;
  private sessionBytes = 0;

  private readonly dataHandler = (chunk: Buffer): void => this.onData(chunk);
  private readonly errorHandler = (): void => this.fail(this.deliveryError());
  private readonly closeHandler = (): void => this.fail(this.deliveryError());
  private readonly timeoutHandler = (): void => {
    this.stream?.destroy();
    this.fail(this.deliveryError());
  };

  constructor(
    private readonly origin: string,
    private readonly timeoutMs: number,
  ) {}

  get isSecure(): boolean {
    return this.secure;
  }

  bind(stream: Socket | TLSSocket, secure: boolean): void {
    this.unbind();
    this.stream = stream;
    this.secure = secure;
    this.pending = "";
    this.accum = [];
    this.completed = [];
    this.failure = null;
    stream.setTimeout(this.timeoutMs);
    stream.on("data", this.dataHandler);
    stream.on("error", this.errorHandler);
    stream.on("close", this.closeHandler);
    stream.on("timeout", this.timeoutHandler);
  }

  unbind(): void {
    const s = this.stream;
    if (!s) {
      return;
    }
    s.removeListener("data", this.dataHandler);
    s.removeListener("error", this.errorHandler);
    s.removeListener("close", this.closeHandler);
    s.removeListener("timeout", this.timeoutHandler);
    this.stream = null;
  }

  write(data: string): void {
    this.stream?.write(Buffer.from(data, "utf8"));
  }

  readResponse(): Promise<SmtpResponse> {
    if (this.failure) {
      return Promise.reject(this.failure);
    }
    const next = this.completed.shift();
    if (next) {
      return Promise.resolve(next);
    }
    return new Promise<SmtpResponse>((resolve, reject) => {
      this.resolver = resolve;
      this.rejecter = reject;
    });
  }

  private deliveryError(): VaultError {
    return VaultError.smtpDeliveryFailed(this.origin);
  }

  private onData(chunk: Buffer): void {
    this.sessionBytes += chunk.length;
    if (this.sessionBytes > MAX_SESSION_BYTES) {
      this.fail(this.deliveryError());
      return;
    }
    this.pending += chunk.toString("latin1");
    let idx = this.pending.indexOf("\r\n");
    while (idx !== -1) {
      const line = this.pending.slice(0, idx);
      this.pending = this.pending.slice(idx + 2);
      if (line.length > MAX_LINE_BYTES) {
        this.fail(this.deliveryError());
        return;
      }
      this.consumeLine(line);
      if (this.failure) {
        return;
      }
      idx = this.pending.indexOf("\r\n");
    }
    // A line still in flight that already exceeds the cap (e.g. a flooding
    // banner with no CRLF) is refused without waiting for a terminator.
    if (this.pending.length > MAX_LINE_BYTES) {
      this.fail(this.deliveryError());
    }
  }

  private consumeLine(line: string): void {
    const match = /^(\d{3})([ -]?)(.*)$/.exec(line);
    if (!match) {
      this.fail(this.deliveryError());
      return;
    }
    const [, codeStr = "", sep = "", text = ""] = match;
    this.accum.push(text);
    if (sep === "-") {
      return;
    }
    const response: SmtpResponse = { code: Number(codeStr), lines: this.accum };
    this.accum = [];
    this.deliver(response);
  }

  private deliver(response: SmtpResponse): void {
    const resolve = this.resolver;
    if (resolve) {
      this.resolver = null;
      this.rejecter = null;
      resolve(response);
      return;
    }
    this.completed.push(response);
  }

  private fail(error: Error): void {
    if (this.failure) {
      return;
    }
    this.failure = error;
    const reject = this.rejecter;
    if (reject) {
      this.resolver = null;
      this.rejecter = null;
      reject(error);
    }
  }
}

function tlsOptions(opts: SmtpSendOptions): ConnectionOptions {
  const ca = opts.tls ? opts.tls.ca : undefined;
  return {
    servername: opts.host,
    checkServerIdentity: identityCheckerFor(opts.host),
    rejectUnauthorized: true,
    ...(ca !== undefined ? { ca } : {}),
  };
}

function openImplicitTls(opts: SmtpSendOptions): TLSSocket {
  const socket = tlsConnect({ host: opts.address, port: opts.port, ...tlsOptions(opts) });
  socket.setNoDelay(true);
  return socket;
}

function openPlain(opts: SmtpSendOptions): Socket {
  const socket = netConnect(opts.port, opts.address);
  socket.setNoDelay(true);
  // Node derives the TLS name to verify as `servername || _host || "localhost"`;
  // pin the logical host so a later STARTTLS upgrade over an IP-literal dial
  // still verifies against the intended name (mirrors db-adapters' dialPinned).
  (socket as Socket & { _host?: string })._host = opts.host;
  return socket;
}

function upgradeTls(base: Socket, opts: SmtpSendOptions): TLSSocket {
  return tlsConnect({ socket: base, ...tlsOptions(opts) });
}

function awaitEvent(
  socket: Socket | TLSSocket,
  event: string,
  timeoutMs: number,
  origin: string,
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    socket.setTimeout(timeoutMs);
    const cleanup = (): void => {
      socket.removeListener(event, onOk);
      socket.removeListener("error", onErr);
      socket.removeListener("timeout", onTimeout);
    };
    const onOk = (): void => {
      cleanup();
      resolve();
    };
    const onErr = (): void => {
      cleanup();
      reject(VaultError.smtpDeliveryFailed(origin));
    };
    const onTimeout = (): void => {
      cleanup();
      socket.destroy();
      reject(VaultError.smtpDeliveryFailed(origin));
    };
    socket.once(event, onOk);
    socket.once("error", onErr);
    socket.once("timeout", onTimeout);
  });
}

async function expectCode(
  channel: SmtpChannel,
  code: number,
  origin: string,
): Promise<SmtpResponse> {
  const response = await channel.readResponse();
  if (response.code !== code) {
    throw VaultError.smtpDeliveryFailed(origin);
  }
  return response;
}

async function ehlo(channel: SmtpChannel, origin: string): Promise<Capabilities> {
  channel.write(`EHLO ${CLIENT_NAME}\r\n`);
  const response = await channel.readResponse();
  if (response.code !== 250) {
    throw VaultError.smtpDeliveryFailed(origin);
  }
  const mechanisms = new Set<string>();
  let starttls = false;
  for (const line of response.lines) {
    const upper = line.toUpperCase().trim();
    if (upper === "STARTTLS") {
      starttls = true;
    } else if (upper.startsWith("AUTH ")) {
      for (const mech of upper.slice(5).split(/\s+/)) {
        if (mech.length > 0) {
          mechanisms.add(mech);
        }
      }
    }
  }
  return { starttls, mechanisms };
}

async function authenticate(
  channel: SmtpChannel,
  opts: SmtpSendOptions,
  caps: Capabilities,
  origin: string,
  allowPlaintext: boolean,
): Promise<void> {
  // The invariant, enforced fail-closed: a credential byte is written only over
  // a secured socket, unless the caller explicitly opted into an
  // implicit-TLS-disabled plaintext relay (`security: "tls"`, `tls: false`).
  if (!channel.isSecure && !allowPlaintext) {
    throw VaultError.smtpDeliveryFailed(origin);
  }

  const auth = opts.auth;
  if (auth.kind === "xoauth2") {
    if (!caps.mechanisms.has("XOAUTH2")) {
      throw VaultError.smtpDeliveryFailed(origin);
    }
    const blob = Buffer.from(
      `user=${auth.username}\x01auth=Bearer ${auth.accessToken}\x01\x01`,
      "utf8",
    ).toString("base64");
    channel.write(`AUTH XOAUTH2 ${blob}\r\n`);
    const response = await channel.readResponse();
    if (response.code === 235) {
      return;
    }
    if (response.code === 334) {
      // Server returned a base64 error challenge; an empty line elicits the
      // final status (a 5xx), which folds to delivery-failed below.
      channel.write("\r\n");
      const settled = await channel.readResponse();
      if (settled.code === 235) {
        return;
      }
    }
    throw VaultError.smtpDeliveryFailed(origin);
  }

  if (caps.mechanisms.has("PLAIN")) {
    const cred = Buffer.from(`\0${auth.username}\0${auth.password}`, "utf8").toString("base64");
    channel.write(`AUTH PLAIN ${cred}\r\n`);
    await expectCode(channel, 235, origin);
    return;
  }
  if (caps.mechanisms.has("LOGIN")) {
    channel.write("AUTH LOGIN\r\n");
    await expectCode(channel, 334, origin);
    channel.write(`${Buffer.from(auth.username, "utf8").toString("base64")}\r\n`);
    await expectCode(channel, 334, origin);
    channel.write(`${Buffer.from(auth.password, "utf8").toString("base64")}\r\n`);
    await expectCode(channel, 235, origin);
    return;
  }
  throw VaultError.smtpDeliveryFailed(origin);
}

/** Neutralize CR/LF so an envelope address cannot smuggle an extra command. */
function smtpAddress(address: string): string {
  return address.replace(/[\r\n]/g, "");
}

/**
 * Dot-stuff the DATA payload (RFC 5321 §4.5.2): any line beginning with `.`
 * gets a doubled leading dot, and the payload is terminated with the lone-dot
 * sequence. mime.ts deliberately leaves this to the SMTP client.
 */
function dotStuff(message: string): string {
  let body = message.replace(/\r\n\./g, "\r\n..");
  if (body.startsWith(".")) {
    body = `.${body}`;
  }
  if (!body.endsWith("\r\n")) {
    body += "\r\n";
  }
  return `${body}.\r\n`;
}

export async function sendSmtp(
  opts: SmtpSendOptions,
): Promise<{ accepted: number; messageId: null }> {
  const origin = `${opts.host}:${opts.port}`;
  const allowPlaintext = opts.security === "tls" && opts.tls === false;
  const channel = new SmtpChannel(origin, opts.timeoutMs);
  let rawSocket: Socket | null = null;
  let tlsSocket: TLSSocket | null = null;

  try {
    if (opts.security === "tls" && opts.tls !== false) {
      tlsSocket = openImplicitTls(opts);
      await awaitEvent(tlsSocket, "secureConnect", opts.timeoutMs, origin);
      channel.bind(tlsSocket, true);
    } else {
      rawSocket = openPlain(opts);
      await awaitEvent(rawSocket, "connect", opts.timeoutMs, origin);
      channel.bind(rawSocket, false);
    }

    await expectCode(channel, 220, origin);
    let caps = await ehlo(channel, origin);

    if (opts.security === "starttls" && !channel.isSecure) {
      if (!caps.starttls) {
        // Refused BEFORE any credential byte is written.
        throw VaultError.smtpStarttlsUnavailable(opts.host);
      }
      channel.write("STARTTLS\r\n");
      await expectCode(channel, 220, origin);
      const base = rawSocket;
      if (!base) {
        throw VaultError.smtpDeliveryFailed(origin);
      }
      channel.unbind();
      tlsSocket = upgradeTls(base, opts);
      await awaitEvent(tlsSocket, "secureConnect", opts.timeoutMs, origin);
      channel.bind(tlsSocket, true);
      caps = await ehlo(channel, origin);
    }

    await authenticate(channel, opts, caps, origin, allowPlaintext);

    channel.write(`MAIL FROM:<${smtpAddress(opts.envelope.from)}>\r\n`);
    await expectCode(channel, 250, origin);

    let accepted = 0;
    for (const recipient of opts.envelope.recipients) {
      channel.write(`RCPT TO:<${smtpAddress(recipient)}>\r\n`);
      const response = await channel.readResponse();
      if (response.code >= 200 && response.code < 300) {
        accepted += 1;
      } else {
        throw VaultError.smtpDeliveryFailed(origin);
      }
    }

    channel.write("DATA\r\n");
    await expectCode(channel, 354, origin);
    channel.write(dotStuff(opts.message));
    await expectCode(channel, 250, origin);

    channel.write("QUIT\r\n");
    await channel.readResponse().catch(() => undefined);

    return { accepted, messageId: null };
  } finally {
    channel.unbind();
    tlsSocket?.destroy();
    rawSocket?.destroy();
  }
}
