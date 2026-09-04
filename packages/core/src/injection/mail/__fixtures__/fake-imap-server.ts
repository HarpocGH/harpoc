import { readFileSync } from "node:fs";
import { createServer } from "node:net";
import type { AddressInfo, Server, Socket } from "node:net";
import { dirname, join } from "node:path";
import { createSecureContext, TLSSocket } from "node:tls";
import type { SecureContext } from "node:tls";
import { fileURLToPath } from "node:url";

/**
 * Scripted fake IMAP server for the in-house client's wire-level tests.
 *
 * IMAP is implicit-TLS only (spec §4.2), so this server presents TLS from the
 * first byte — the reused RSA fixture certificate (`packages/core/src/__fixtures__/certs`,
 * CN/SAN `fixture.example.com`). It is a *proper* IMAP literal reader: a client
 * command whose line ends in `{n}` (a synchronizing literal) is answered with a
 * `+` continuation and the next `n` octets are consumed as literal content, NOT
 * re-parsed as a command line. That is exactly what lets a test prove the
 * injection defense: a CRLF-bearing payload delivered inside an announced
 * `{n}` literal arrives as ONE recorded command, never a second one.
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
// fixture is only ever touched from a test's `startFakeImap` (or the pinned CA).
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

export interface UidFetchMessageSpec {
  uid: number;
  /** Rendered as `FLAGS (...)` when present. */
  flags?: string[];
  /** Raw ENVELOPE list text, e.g. `("date" "subj" ((NIL NIL "a" "b")) NIL NIL NIL NIL NIL NIL NIL)`. */
  envelope?: string;
  /** Sent as a genuine `{n}\r\n<bytes>` literal for `BODY[HEADER]`. */
  header?: string;
  /** Sent as a genuine `{n}\r\n<bytes>` literal for `BODY[TEXT]`. */
  text?: string;
}

export interface ImapScript {
  /** Advertised capabilities (default `["IMAP4rev1"]`). */
  capabilities?: string[];
  /**
   * Capabilities advertised once LOGIN/AUTHENTICATE has succeeded, i.e. the
   * set a client re-reading CAPABILITY after authentication sees (RFC 3501
   * 6.1.1 lets the set change; Gmail advertises MOVE and UIDPLUS only once
   * authenticated). Absent, the authenticated set equals `capabilities`.
   */
  postLoginCapabilities?: string[];
  /** Answer LOGIN / AUTHENTICATE with a tagged NO instead of OK. */
  auth?: "ok" | "fail";
  /** Greeting shape: normal `* OK`, never greet, or a hostile `* BYE`. */
  greeting?: "normal" | "silent" | "bye";
  /** SELECT/EXAMINE tagged result (default `ok`). */
  selectStatus?: "ok" | "no";
  /** `* <n> EXISTS` reported on SELECT/EXAMINE (default 3). */
  existsOnSelect?: number;
  /** FETCH replies with a single BODY literal carrying this text. */
  fetchLiteral?: string;
  /** FETCH announces a literal of this many octets and sends nothing more. */
  fetchOversizedLiteral?: number;
  /** FETCH floods the client with more than its session cap of untagged data. */
  flood?: boolean;
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
  private authenticated = false;
  private readonly received: Buffer[] = [];
  private readonly recorded: RecordedCommand[] = [];

  constructor(
    raw: Socket,
    private readonly script: ImapScript,
  ) {
    raw.on("error", () => undefined);
    this.tls = new TLSSocket(raw, { isServer: true, secureContext: getSecureContext() });
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
    const post = this.script.postLoginCapabilities;
    const caps =
      this.authenticated && post !== undefined ? post : (this.script.capabilities ?? ["IMAP4rev1"]);
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
    // `UID SEARCH` / `UID FETCH` / `UID STORE` / `UID MOVE` / `UID COPY`
    // recorded and dispatched as one two-word name, distinct from their
    // non-UID counterparts.
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
    if (op === "login" || op === "authenticate") {
      this.authenticated = true;
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
    if (this.script.flood) {
      // Nine sub-cap literals (each under the 1 MiB per-literal cap) whose sum
      // blows past the 8 MiB session cap — this exercises the session cap, not
      // the literal cap.
      const chunk = Buffer.alloc(1_000_000, 0x78);
      for (let i = 0; i < 9; i += 1) {
        this.send(`* 1 FETCH (BODY[TEXT] {${chunk.length}}\r\n`);
        this.tls.write(chunk);
        this.send(")\r\n");
      }
      this.send(`${tag} OK FETCH completed\r\n`);
      return;
    }
    if (typeof this.script.fetchOversizedLiteral === "number") {
      this.send(`* 1 FETCH (BODY[TEXT] {${this.script.fetchOversizedLiteral}}\r\n`);
      return;
    }
    if (typeof this.script.fetchLiteral === "string") {
      const bytes = Buffer.from(this.script.fetchLiteral, "utf8");
      this.send(`* 1 FETCH (BODY[TEXT] {${bytes.length}}\r\n`);
      this.tls.write(bytes);
      this.send(")\r\n");
      this.send(`${tag} OK FETCH completed\r\n`);
      return;
    }
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
