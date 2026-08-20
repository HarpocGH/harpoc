import { createServer } from "node:net";
import type { AddressInfo, Server, Socket } from "node:net";
import { createSecureContext, TLSSocket } from "node:tls";
import { LOOPBACK_CERT_PEM, LOOPBACK_KEY_PEM } from "./loopback-cert.js";

/**
 * Scripted fake IMAP server, a local copy of core's
 * `packages/core/src/injection/mail/__fixtures__/fake-imap-server.ts` (see the
 * SMTP fake's header for why integration copies rather than imports the core
 * fixture). IMAP is implicit-TLS only, so this server presents TLS from the
 * first byte — here the loopback pair (SAN `DNS:localhost, IP:127.0.0.1`)
 * rather than the original's `fixture.example.com`, so the real `VaultEngine`
 * can reach it through the SSRF floor. It is a proper IMAP literal reader: a
 * command line ending in `{n}` is answered with a `+` continuation and the next
 * `n` octets consumed as literal content, never re-parsed as a command.
 */

const SECURE_CONTEXT = createSecureContext({ key: LOOPBACK_KEY_PEM, cert: LOOPBACK_CERT_PEM });

/** The self-signed loopback certificate, usable as a pinned CA by the client. */
export const FIXTURE_CA_PEM = LOOPBACK_CERT_PEM;
/** The logical host the fixture certificate is valid for. */
export const FIXTURE_HOST = "localhost";

export interface UidFetchMessageSpec {
  uid: number;
  /** Rendered as `FLAGS (...)` when present. */
  flags?: string[];
  /** Raw ENVELOPE list text. */
  envelope?: string;
  /** Sent as a genuine `{n}\r\n<bytes>` literal for `BODY[HEADER]`. */
  header?: string;
  /** Sent as a genuine `{n}\r\n<bytes>` literal for `BODY[TEXT]`. */
  text?: string;
}

export interface ImapScript {
  /** Advertised capabilities (default `["IMAP4rev1"]`). */
  capabilities?: string[];
  /** Answer LOGIN / AUTHENTICATE with a tagged NO instead of OK. */
  auth?: "ok" | "fail";
  /** Greeting shape: normal `* OK`, never greet, or a hostile `* BYE`. */
  greeting?: "normal" | "silent" | "bye";
  /** SELECT/EXAMINE tagged result (default `ok`). */
  selectStatus?: "ok" | "no";
  /** `* <n> EXISTS` reported on SELECT/EXAMINE (default 3). */
  existsOnSelect?: number;
  /** UIDs reported on `* SEARCH ...` for UID SEARCH (default none). */
  searchResults?: number[];
  /** Per-message UID FETCH response content, in order. */
  uidFetch?: UidFetchMessageSpec[];
  /** Number of `* n EXPUNGE` untagged lines EXPUNGE reports (default 0). */
  expungeCount?: number;
}

export interface RecordedCommand {
  tag: string;
  name: string;
  /** The reconstructed command text (literal octets excluded). */
  text: string;
  literals: Buffer[];
}

export interface FakeImap {
  port: number;
  commands(): RecordedCommand[];
  raw(): Buffer;
  close(): Promise<void>;
}

class Connection {
  private readonly tls: TLSSocket;
  private buf = Buffer.alloc(0);
  private mode: "line" | "literal" = "line";
  private litRemaining = 0;
  private litParts: Buffer[] = [];
  private curTextChunks: string[] = [];
  private curLiterals: Buffer[] = [];
  private awaitingSaslTag: string | null = null;
  private readonly received: Buffer[] = [];
  private readonly recorded: RecordedCommand[] = [];

  constructor(
    raw: Socket,
    private readonly script: ImapScript,
  ) {
    raw.on("error", () => undefined);
    this.tls = new TLSSocket(raw, { isServer: true, secureContext: SECURE_CONTEXT });
    this.tls.on("error", () => undefined);
    this.tls.on("data", (chunk: Buffer) => this.onData(chunk));
    this.tls.on("secure", () => this.greet());
  }

  commands(): RecordedCommand[] {
    return this.recorded;
  }

  rawBytes(): Buffer {
    return Buffer.concat(this.received);
  }

  private send(text: string): void {
    this.tls.write(Buffer.from(text, "latin1"));
  }

  private greet(): void {
    const greeting = this.script.greeting ?? "normal";
    if (greeting === "silent") {
      return;
    }
    if (greeting === "bye") {
      this.send("* BYE fake declines service\r\n");
      return;
    }
    this.send(`* OK [CAPABILITY ${this.capabilityList()}] fake IMAP ready\r\n`);
  }

  private capabilityList(): string {
    const caps = this.script.capabilities ?? ["IMAP4rev1"];
    return caps.join(" ");
  }

  private onData(chunk: Buffer): void {
    this.received.push(Buffer.from(chunk));
    this.buf = Buffer.concat([this.buf, chunk]);
    this.drain();
  }

  private drain(): void {
    for (;;) {
      if (this.mode === "literal") {
        if (this.buf.length === 0) {
          return;
        }
        const take = Math.min(this.litRemaining, this.buf.length);
        this.litParts.push(this.buf.subarray(0, take));
        this.buf = this.buf.subarray(take);
        this.litRemaining -= take;
        if (this.litRemaining === 0) {
          this.curLiterals.push(Buffer.concat(this.litParts));
          this.litParts = [];
          this.mode = "line";
        }
        continue;
      }
      const idx = this.buf.indexOf("\r\n", 0, "latin1");
      if (idx === -1) {
        return;
      }
      const line = this.buf.subarray(0, idx).toString("latin1");
      this.buf = this.buf.subarray(idx + 2);
      this.onLine(line);
    }
  }

  private onLine(line: string): void {
    if (this.awaitingSaslTag !== null) {
      const tag = this.awaitingSaslTag;
      this.awaitingSaslTag = null;
      this.finishTagged(tag, "authenticate");
      return;
    }
    const match = /\{(\d+)(\+?)\}$/.exec(line);
    if (match) {
      const n = Number(match[1]);
      const nonSync = match[2] === "+";
      this.curTextChunks.push(line.slice(0, line.length - match[0].length));
      this.mode = "literal";
      this.litRemaining = n;
      this.litParts = [];
      if (!nonSync) {
        this.send("+ OK literal\r\n");
      }
      return;
    }
    this.curTextChunks.push(line);
    this.finalizeCommand();
  }

  private finalizeCommand(): void {
    const text = this.curTextChunks.join("");
    const literals = this.curLiterals;
    this.curTextChunks = [];
    this.curLiterals = [];
    const tokens = text.split(/\s+/).filter((t) => t.length > 0);
    const tag = tokens[0] ?? "";
    const first = (tokens[1] ?? "").toUpperCase();
    const name = first === "UID" ? `UID ${(tokens[2] ?? "").toUpperCase()}` : first;
    this.recorded.push({ tag, name, text, literals });
    this.dispatch(tag, name, tokens, literals);
  }

  private dispatch(tag: string, name: string, tokens: string[], literals: Buffer[]): void {
    switch (name) {
      case "CAPABILITY":
        this.send(`* CAPABILITY ${this.capabilityList()}\r\n`);
        this.finishTagged(tag, "capability");
        return;
      case "LOGIN":
        this.finishTagged(tag, "login");
        return;
      case "AUTHENTICATE":
        this.send("+ \r\n");
        this.awaitingSaslTag = tag;
        return;
      case "SELECT":
      case "EXAMINE":
        this.handleSelect(tag);
        return;
      case "FETCH":
        this.handleFetch(tag, literals);
        return;
      case "UID SEARCH":
        this.handleUidSearch(tag);
        return;
      case "UID FETCH":
        this.handleUidFetch(tag);
        return;
      case "EXPUNGE":
        this.handleExpunge(tag);
        return;
      case "UID EXPUNGE":
        this.handleUidExpunge(tag);
        return;
      case "LOGOUT":
        this.send("* BYE fake signing off\r\n");
        this.send(`${tag} OK LOGOUT completed\r\n`);
        this.tls.end();
        return;
      case "DELETE":
        this.send(`${tag} OK DELETE completed\r\n`);
        return;
      case "NOOP":
        this.send(`${tag} OK NOOP completed\r\n`);
        return;
      default:
        void tokens;
        this.send(`${tag} OK ${name || "command"} completed\r\n`);
        return;
    }
  }

  private finishTagged(tag: string, op: string): void {
    if (this.script.auth === "fail" && (op === "login" || op === "authenticate")) {
      this.send(`${tag} NO [AUTHENTICATIONFAILED] credentials rejected\r\n`);
      return;
    }
    this.send(`${tag} OK ${op} completed\r\n`);
  }

  private handleSelect(tag: string): void {
    const exists = this.script.existsOnSelect ?? 3;
    this.send("* FLAGS (\\Seen \\Deleted)\r\n");
    this.send(`* ${exists} EXISTS\r\n`);
    this.send("* 0 RECENT\r\n");
    if (this.script.selectStatus === "no") {
      this.send(`${tag} NO SELECT failed\r\n`);
      return;
    }
    this.send(`${tag} OK [READ-WRITE] SELECT completed\r\n`);
  }

  private handleFetch(tag: string, literals: Buffer[]): void {
    void literals;
    this.send(`${tag} OK FETCH completed\r\n`);
  }

  private handleUidSearch(tag: string): void {
    const uids = this.script.searchResults ?? [];
    const suffix = uids.length > 0 ? ` ${uids.join(" ")}` : "";
    this.send(`* SEARCH${suffix}\r\n`);
    this.send(`${tag} OK UID SEARCH completed\r\n`);
  }

  private handleUidFetch(tag: string): void {
    for (const msg of this.script.uidFetch ?? []) {
      const items: string[] = [`UID ${msg.uid}`];
      if (msg.flags) {
        items.push(`FLAGS (${msg.flags.join(" ")})`);
      }
      if (msg.envelope !== undefined) {
        items.push(`ENVELOPE ${msg.envelope}`);
      }
      this.send(`* ${msg.uid} FETCH (${items.join(" ")}`);
      if (msg.header !== undefined) {
        const bytes = Buffer.from(msg.header, "utf8");
        this.send(` BODY[HEADER] {${bytes.length}}\r\n`);
        this.tls.write(bytes);
      }
      if (msg.text !== undefined) {
        const bytes = Buffer.from(msg.text, "utf8");
        this.send(` BODY[TEXT] {${bytes.length}}\r\n`);
        this.tls.write(bytes);
      }
      this.send(")\r\n");
    }
    this.send(`${tag} OK UID FETCH completed\r\n`);
  }

  private handleExpunge(tag: string): void {
    this.sendExpungeReplies(tag, "EXPUNGE");
  }

  private handleUidExpunge(tag: string): void {
    this.sendExpungeReplies(tag, "UID EXPUNGE");
  }

  private sendExpungeReplies(tag: string, op: string): void {
    const count = this.script.expungeCount ?? 0;
    for (let i = 0; i < count; i += 1) {
      this.send("* 1 EXPUNGE\r\n");
    }
    this.send(`${tag} OK ${op} completed\r\n`);
  }
}

export async function startFakeImap(script: ImapScript): Promise<FakeImap> {
  let latest: Connection | null = null;
  const server: Server = createServer((raw: Socket) => {
    latest = new Connection(raw, script);
  });
  server.on("error", () => undefined);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const port = (server.address() as AddressInfo).port;
  return {
    port,
    commands: () => (latest ? latest.commands() : []),
    raw: () => (latest ? latest.rawBytes() : Buffer.alloc(0)),
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
