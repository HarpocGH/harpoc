import { connect as tlsConnect } from "node:tls";
import type { ConnectionOptions, TLSSocket } from "node:tls";
import { VaultError } from "@harpoc/shared";
import { identityCheckerFor } from "../db-adapters.js";
import type { SmtpAuth } from "./smtp-client.js";

/**
 * In-house IMAP client (node:tls only — no third-party IMAP library in the
 * vault process). It carries the vault credential to the mail server, so its
 * load-bearing property is that IMAP command injection is impossible *by
 * construction*: user data (mailbox names, search terms) only ever reaches the
 * wire through {@link ImapArg} `string` encoding, which emits a quoted string
 * when the value is short and clean and otherwise a `{n}\r\n` synchronizing
 * literal. A CRLF-bearing payload can never terminate the command line and start
 * a second command — it is delivered as counted literal octets. `atom` is for
 * client-authored tokens (command names, flags) only and is refused if it
 * carries whitespace or control bytes.
 *
 * IMAP is implicit-TLS only (spec §4.2): the socket is TLS from the first byte,
 * dialing the SSRF-pinned `address` while verifying the certificate against the
 * logical `host`. The reader is a state machine toggling between line mode and
 * literal-countdown mode; per-line, per-literal and per-session byte caps bound
 * what a hostile or malfunctioning server can make the client buffer, and an
 * oversized literal is refused at its announcement, before a byte is buffered.
 * Every failure surfaces as {@link VaultError.imapOperationFailed}, which names
 * the origin (host:port) and operation only — never the credential.
 */

export type ImapAuth = SmtpAuth;

export interface ImapConnectOptions {
  host: string;
  port: number;
  /** SSRF-pinned address to dial; TLS identity is verified against `host`. */
  address: string;
  auth: ImapAuth;
  timeoutMs: number;
  tls?: { ca?: string };
}

export type ImapArg =
  | { kind: "atom"; value: string }
  | { kind: "string"; value: string }
  | { kind: "list"; items: ImapArg[] };

// `raw` is the logical line's reconstructed text with any server literals
// elided (their bytes live in `literals`, in encounter order) — needed by the
// FETCH parser below because a naive whitespace split (`atoms`) breaks on the
// parenthesized, unspaced structure of an ENVELOPE response.
export type UntaggedLine = { atoms: string[]; literals: Buffer[]; raw: string };

export interface ImapResponse {
  tagged: { status: "OK" | "NO" | "BAD"; text: string };
  untagged: UntaggedLine[];
}

export interface ImapSearchCriteria {
  unseen?: boolean;
  since?: string;
  from?: string;
  subject?: string;
  text?: string;
}

export type ImapFetchParts = "envelope" | "headers" | "text" | "full";

export interface ImapMessage {
  uid: number;
  flags: string[];
  envelope?: ImapEnvelope;
  headers?: string;
  text?: string;
}

export interface ImapEnvelope {
  date: string | null;
  subject: string | null;
  from: string[];
  to: string[];
}

// Capped-output discipline (see injection/capped-output.ts): bound what a
// hostile or malfunctioning server can make the client buffer.
const MAX_LINE_BYTES = 8 * 1024;
const MAX_LITERAL_BYTES = 1024 * 1024;
const MAX_SESSION_BYTES = 8 * 1024 * 1024;
// An IMAP quoted string may hold any 7-bit char but `"`, `\`, CR, LF and NUL;
// beyond this length (or with any excluded byte) the value goes as a literal.
const MAX_QUOTED_BYTES = 1024;

type Segment = { kind: "inline"; text: string } | { kind: "literal"; bytes: Buffer };

/** A fully-assembled server response line, with any literals reattached. */
interface LogicalLine {
  text: string;
  literals: Buffer[];
}

function isQuotable(value: string): boolean {
  if (Buffer.byteLength(value, "utf8") > MAX_QUOTED_BYTES) {
    return false;
  }
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code > 0x7e || code === 0x22 || code === 0x5c) {
      return false;
    }
  }
  return true;
}

/**
 * Encode one argument into wire segments. This is the injection defense: user
 * data flows only through `string` (quoted or literal), never onto the command
 * line as raw bytes. `atom` is validated to be a single client-authored token.
 */
function encodeArg(arg: ImapArg): Segment[] {
  if (arg.kind === "atom") {
    // IMAP system flags (`\Seen`, `\Deleted`, ...) are client-authored atoms
    // that carry exactly one leading backslash — RFC 3501's generic atom-char
    // class excludes backslash, but the `flag` production allows it as the
    // first character. Strip at most one before validating the rest, so a
    // stray/embedded backslash (never legitimate) still fails closed.
    const bare = arg.value.startsWith("\\") ? arg.value.slice(1) : arg.value;
    if (/[\s\r\n\0(){%*"\\]/.test(bare) || bare.length === 0) {
      // A programming error, not user data — atoms are always client-authored.
      throw new Error("invalid IMAP atom");
    }
    return [{ kind: "inline", text: arg.value }];
  }
  if (arg.kind === "string") {
    if (isQuotable(arg.value)) {
      return [{ kind: "inline", text: `"${arg.value}"` }];
    }
    return [{ kind: "literal", bytes: Buffer.from(arg.value, "utf8") }];
  }
  const segments: Segment[] = [{ kind: "inline", text: "(" }];
  arg.items.forEach((item, index) => {
    if (index > 0) {
      segments.push({ kind: "inline", text: " " });
    }
    segments.push(...encodeArg(item));
  });
  segments.push({ kind: "inline", text: ")" });
  return segments;
}

/**
 * A single implicit-TLS IMAP read/write channel. It delivers complete logical
 * response lines (untagged `*`, continuation `+`, tagged `<tag> STATUS`) one at
 * a time, reassembling `{n}` server literals, and enforces the byte caps. Every
 * failure resolves to {@link VaultError.imapOperationFailed}.
 */
class ImapChannel {
  private buf = Buffer.alloc(0);
  private mode: "line" | "literal" = "line";
  private literalRemaining = 0;
  private literalParts: Buffer[] = [];
  private curTextChunks: string[] = [];
  private curLiterals: Buffer[] = [];
  private readonly queue: LogicalLine[] = [];
  private waiter: { resolve: (l: LogicalLine) => void; reject: (e: Error) => void } | null = null;
  private failure: Error | null = null;
  private sessionBytes = 0;

  private readonly dataHandler = (chunk: Buffer): void => this.onData(chunk);
  private readonly errorHandler = (): void => this.fail(this.opError());
  private readonly closeHandler = (): void => this.fail(this.opError());
  private readonly timeoutHandler = (): void => {
    this.stream.destroy();
    this.fail(this.opError());
  };

  constructor(
    private readonly stream: TLSSocket,
    private readonly origin: string,
    private readonly timeoutMs: number,
  ) {
    stream.setTimeout(timeoutMs);
    stream.on("data", this.dataHandler);
    stream.on("error", this.errorHandler);
    stream.on("close", this.closeHandler);
    stream.on("timeout", this.timeoutHandler);
  }

  write(text: string): void {
    this.stream.write(Buffer.from(text, "latin1"));
  }

  writeBytes(bytes: Buffer): void {
    this.stream.write(bytes);
  }

  destroy(): void {
    this.detach();
    this.stream.destroy();
  }

  private detach(): void {
    this.stream.removeListener("data", this.dataHandler);
    this.stream.removeListener("error", this.errorHandler);
    this.stream.removeListener("close", this.closeHandler);
    this.stream.removeListener("timeout", this.timeoutHandler);
  }

  private opError(): VaultError {
    return VaultError.imapOperationFailed(this.origin, "read");
  }

  nextLine(): Promise<LogicalLine> {
    if (this.failure) {
      return Promise.reject(this.failure);
    }
    const queued = this.queue.shift();
    if (queued) {
      return Promise.resolve(queued);
    }
    return new Promise<LogicalLine>((resolve, reject) => {
      this.waiter = { resolve, reject };
    });
  }

  private onData(chunk: Buffer): void {
    if (this.failure) {
      return;
    }
    this.sessionBytes += chunk.length;
    if (this.sessionBytes > MAX_SESSION_BYTES) {
      this.fail(this.opError());
      return;
    }
    this.buf = this.buf.length === 0 ? Buffer.from(chunk) : Buffer.concat([this.buf, chunk]);
    this.drain();
  }

  private drain(): void {
    for (;;) {
      if (this.failure) {
        return;
      }
      if (this.mode === "literal") {
        if (this.buf.length === 0) {
          return;
        }
        const take = Math.min(this.literalRemaining, this.buf.length);
        this.literalParts.push(this.buf.subarray(0, take));
        this.buf = this.buf.subarray(take);
        this.literalRemaining -= take;
        if (this.literalRemaining === 0) {
          this.curLiterals.push(Buffer.concat(this.literalParts));
          this.literalParts = [];
          this.mode = "line";
        }
        continue;
      }
      const idx = this.buf.indexOf("\r\n", 0, "latin1");
      if (idx === -1) {
        // A partial line that already exceeds the per-line cap is refused
        // without waiting for its terminator (a flooding, CRLF-less line).
        if (this.buf.length > MAX_LINE_BYTES) {
          this.fail(this.opError());
        }
        return;
      }
      if (idx > MAX_LINE_BYTES) {
        this.fail(this.opError());
        return;
      }
      const line = this.buf.subarray(0, idx).toString("latin1");
      this.buf = this.buf.subarray(idx + 2);
      this.onLine(line);
    }
  }

  private onLine(line: string): void {
    const match = /\{(\d+)\}$/.exec(line);
    if (match) {
      const n = Number(match[1]);
      if (n > MAX_LITERAL_BYTES) {
        // Refused at the announcement — before a single literal octet is read.
        this.fail(VaultError.imapOperationFailed(this.origin, "read"));
        return;
      }
      this.curTextChunks.push(line.slice(0, line.length - match[0].length));
      this.mode = "literal";
      this.literalRemaining = n;
      this.literalParts = [];
      return;
    }
    this.curTextChunks.push(line);
    const logical: LogicalLine = {
      text: this.curTextChunks.join(""),
      literals: this.curLiterals,
    };
    this.curTextChunks = [];
    this.curLiterals = [];
    this.deliver(logical);
  }

  private deliver(line: LogicalLine): void {
    const waiter = this.waiter;
    if (waiter) {
      this.waiter = null;
      waiter.resolve(line);
      return;
    }
    this.queue.push(line);
  }

  private fail(error: Error): void {
    if (this.failure) {
      return;
    }
    this.failure = error;
    const waiter = this.waiter;
    if (waiter) {
      this.waiter = null;
      waiter.reject(error);
    }
  }
}

function tlsOptions(opts: ImapConnectOptions): ConnectionOptions {
  const ca = opts.tls?.ca;
  return {
    servername: opts.host,
    checkServerIdentity: identityCheckerFor(opts.host),
    rejectUnauthorized: true,
    ...(ca !== undefined ? { ca } : {}),
  };
}

function awaitSecure(socket: TLSSocket, timeoutMs: number, origin: string): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    socket.setTimeout(timeoutMs);
    const cleanup = (): void => {
      socket.removeListener("secureConnect", onOk);
      socket.removeListener("error", onErr);
      socket.removeListener("timeout", onTimeout);
    };
    const onOk = (): void => {
      cleanup();
      resolve();
    };
    const onErr = (): void => {
      cleanup();
      reject(VaultError.imapOperationFailed(origin, "connect"));
    };
    const onTimeout = (): void => {
      cleanup();
      socket.destroy();
      reject(VaultError.imapOperationFailed(origin, "connect"));
    };
    socket.once("secureConnect", onOk);
    socket.once("error", onErr);
    socket.once("timeout", onTimeout);
  });
}

function parseTagged(text: string): { status: "OK" | "NO" | "BAD"; text: string } | null {
  const match = /^(\S+)\s+(OK|NO|BAD)\b\s*(.*)$/.exec(text);
  if (!match) {
    return null;
  }
  return { status: match[2] as "OK" | "NO" | "BAD", text: match[3] ?? "" };
}

function parseCapabilities(atoms: string[]): string[] {
  const idx = atoms.findIndex((a) => a.toUpperCase() === "CAPABILITY");
  if (idx === -1) {
    return [];
  }
  return atoms.slice(idx + 1).filter((a) => a.length > 0);
}

const IMAP_MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
] as const;

/** ISO date -> IMAP SEARCH date-text (`SINCE 1-Aug-2026`) — client-computed
 * from validated numeric components, never the raw input string. */
function formatImapDate(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    throw VaultError.invalidInput(`invalid IMAP SEARCH date: ${iso}`);
  }
  const month = IMAP_MONTHS[date.getUTCMonth()] ?? "Jan";
  return `${date.getUTCDate()}-${month}-${date.getUTCFullYear()}`;
}

/** number[] -> IMAP sequence-set atom ("3,5,8") — numbers only, never
 * free text; the format is why this is safe to send as a bare atom. */
function formatUidSet(uids: number[]): string {
  if (uids.length === 0) {
    throw VaultError.invalidInput("at least one UID is required");
  }
  return uids
    .map((uid) => {
      if (!Number.isSafeInteger(uid) || uid <= 0) {
        throw VaultError.invalidInput(`invalid IMAP UID: ${uid}`);
      }
      return String(uid);
    })
    .join(",");
}

function flagArg(flag: string): ImapArg {
  return { kind: "atom", value: flag };
}

// Mirrors encodeArg's atom char-class check exactly (including the one
// leading backslash IMAP system flags carry), but fails as VaultError instead
// of the plain Error encodeArg throws for what should never happen there
// (atoms are documented as always client-authored — a caller-supplied flag
// is not). Validate-before-send, same pattern as formatUidSet: called before
// command(), so a malformed flag never reaches the wire.
const ATOM_FORBIDDEN_CHARS = /[\s\r\n\0(){%*"\\]/;

function validateFlags(flags: string[]): void {
  for (const flag of flags) {
    const bare = flag.startsWith("\\") ? flag.slice(1) : flag;
    if (ATOM_FORBIDDEN_CHARS.test(bare) || bare.length === 0) {
      throw VaultError.invalidInput(`invalid IMAP flag: ${flag}`);
    }
  }
}

const FETCH_HEADER_ITEM: ImapArg = { kind: "atom", value: "BODY.PEEK[HEADER]" };
const FETCH_TEXT_ITEM: ImapArg = { kind: "atom", value: "BODY.PEEK[TEXT]" };

function envelopeFetchList(extra: ImapArg[]): ImapArg {
  return {
    kind: "list",
    items: [
      { kind: "atom", value: "UID" },
      { kind: "atom", value: "FLAGS" },
      { kind: "atom", value: "ENVELOPE" },
      ...extra,
    ],
  };
}

/** `.PEEK` everywhere so a FETCH never implicitly sets `\Seen`. */
function fetchItemsArg(parts: ImapFetchParts): ImapArg {
  switch (parts) {
    case "envelope":
      return envelopeFetchList([]);
    case "headers":
      return FETCH_HEADER_ITEM;
    case "text":
      return FETCH_TEXT_ITEM;
    case "full":
      return envelopeFetchList([FETCH_HEADER_ITEM, FETCH_TEXT_ITEM]);
    default: {
      const exhaustive: never = parts;
      throw VaultError.invalidInput(`unsupported IMAP fetch parts: ${String(exhaustive)}`);
    }
  }
}

/** Minimal parenthesized-list / quoted-string / NIL parser for IMAP ENVELOPE
 * structures. Envelope fields are short header values the server always
 * sends inline (never as literals), so this never has to reconcile against
 * the literal queue the way FETCH's BODY[...] sections do. */
type SExpr = string | null | SExpr[];

class SExprParser {
  constructor(
    private readonly text: string,
    private pos: number = 0,
  ) {}

  parseOne(): SExpr {
    this.skipSpace();
    const ch = this.text[this.pos];
    if (ch === "(") {
      this.pos += 1;
      const items: SExpr[] = [];
      this.skipSpace();
      while (this.pos < this.text.length && this.text[this.pos] !== ")") {
        items.push(this.parseOne());
        this.skipSpace();
      }
      this.pos += 1;
      return items;
    }
    if (ch === '"') {
      return this.parseQuoted();
    }
    return this.parseAtom();
  }

  private skipSpace(): void {
    while (this.text[this.pos] === " ") {
      this.pos += 1;
    }
  }

  private parseQuoted(): string {
    this.pos += 1;
    let out = "";
    while (this.pos < this.text.length && this.text[this.pos] !== '"') {
      const c = this.text[this.pos];
      if (c === "\\") {
        this.pos += 1;
        out += this.text[this.pos] ?? "";
      } else {
        out += c ?? "";
      }
      this.pos += 1;
    }
    this.pos += 1;
    return out;
  }

  private parseAtom(): string | null {
    const start = this.pos;
    while (this.pos < this.text.length && !"() ".includes(this.text[this.pos] ?? "")) {
      this.pos += 1;
    }
    const token = this.text.slice(start, this.pos);
    return token.toUpperCase() === "NIL" ? null : token;
  }
}

function asString(value: SExpr | undefined): string | null {
  return typeof value === "string" ? value : null;
}

/** One address-structure is `(name adl mailbox host)`; render as
 * `"name" <mailbox@host>` when a display name is present, else bare. */
function asAddressList(value: SExpr | undefined): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const result: string[] = [];
  for (const entry of value) {
    if (!Array.isArray(entry)) {
      continue;
    }
    const name = entry[0];
    const mailbox = entry[2];
    const host = entry[3];
    const mb = typeof mailbox === "string" ? mailbox : "";
    const hostStr = typeof host === "string" ? host : "";
    const addr = mb.length > 0 && hostStr.length > 0 ? `${mb}@${hostStr}` : mb || hostStr;
    result.push(typeof name === "string" && name.length > 0 ? `${name} <${addr}>` : addr);
  }
  return result;
}

function toEnvelope(parsed: SExpr): ImapEnvelope {
  const fields = Array.isArray(parsed) ? parsed : [];
  return {
    date: asString(fields[0]),
    subject: asString(fields[1]),
    from: asAddressList(fields[2]),
    to: asAddressList(fields[5]),
  };
}

/** FETCH response parser: UID/FLAGS come off the naive `atoms` split (they
 * never contain nested structure), ENVELOPE is parsed from `raw` via
 * {@link SExprParser}, and BODY[HEADER]/BODY[TEXT] content is matched to the
 * per-line `literals` queue in the order both appear in `raw` — the queue is
 * FIFO because the server necessarily wrote them in that order on the wire. */
function parseFetchMessages(untagged: UntaggedLine[]): ImapMessage[] {
  const messages: ImapMessage[] = [];
  for (const line of untagged) {
    if (!/^\*\s+\d+\s+FETCH\s+\(/i.test(line.raw)) {
      continue;
    }
    const uidMatch = /\bUID\s+(\d+)\b/.exec(line.raw);
    const uid = uidMatch?.[1] !== undefined ? Number(uidMatch[1]) : NaN;
    if (!Number.isFinite(uid)) {
      continue;
    }
    const flagsMatch = /\bFLAGS\s*\(([^)]*)\)/.exec(line.raw);
    const flags = (flagsMatch?.[1] ?? "").split(/\s+/).filter((f) => f.length > 0);

    const message: ImapMessage = { uid, flags };

    const envIdx = line.raw.indexOf("ENVELOPE");
    if (envIdx !== -1) {
      const parser = new SExprParser(line.raw, envIdx + "ENVELOPE".length);
      message.envelope = toEnvelope(parser.parseOne());
    }

    const literalQueue = [...line.literals];
    const markers: Array<{ idx: number; kind: "headers" | "text" }> = [];
    const headerIdx = line.raw.indexOf("BODY[HEADER]");
    if (headerIdx !== -1) {
      markers.push({ idx: headerIdx, kind: "headers" });
    }
    const textIdx = line.raw.indexOf("BODY[TEXT]");
    if (textIdx !== -1) {
      markers.push({ idx: textIdx, kind: "text" });
    }
    markers.sort((a, b) => a.idx - b.idx);
    for (const marker of markers) {
      const buf = literalQueue.shift();
      if (buf) {
        if (marker.kind === "headers") {
          message.headers = buf.toString("utf8");
        } else {
          message.text = buf.toString("utf8");
        }
      }
    }

    messages.push(message);
  }
  return messages;
}

/** `* <n> EXPUNGE` count — shared by plain and UID-scoped EXPUNGE. */
function countExpungeLines(untagged: UntaggedLine[]): number {
  let count = 0;
  for (const line of untagged) {
    if (
      line.atoms.length >= 3 &&
      line.atoms[0] === "*" &&
      line.atoms[2]?.toUpperCase() === "EXPUNGE"
    ) {
      count += 1;
    }
  }
  return count;
}

export class ImapClient {
  private tagCounter = 0;
  private readonly caps = new Set<string>();

  private constructor(
    private readonly channel: ImapChannel,
    private readonly origin: string,
    private readonly host: string,
  ) {}

  /**
   * Dials, greets, reads CAPABILITY, authenticates — and then clears the
   * capability set and reads CAPABILITY a second time. RFC 3501 6.1.1 lets a
   * server's capability set change once the session is authenticated (Gmail
   * advertises MOVE and UIDPLUS only post-login), so the pre-authentication
   * set is not the set `move` may decide on: E83's refusal would otherwise
   * claim a server "advertises neither" on evidence it had already
   * superseded. The cost is one extra round trip per connection; parsing the
   * `[CAPABILITY ...]` response code of the tagged LOGIN/AUTHENTICATE OK
   * would remove it and is a documented follow-up.
   */
  static async connect(opts: ImapConnectOptions): Promise<ImapClient> {
    const origin = `${opts.host}:${opts.port}`;
    const socket = tlsConnect({ host: opts.address, port: opts.port, ...tlsOptions(opts) });
    socket.setNoDelay(true);
    try {
      await awaitSecure(socket, opts.timeoutMs, origin);
    } catch (error) {
      socket.destroy();
      throw error;
    }
    const channel = new ImapChannel(socket, origin, opts.timeoutMs);
    const client = new ImapClient(channel, origin, opts.host);
    try {
      await client.readGreeting();
      await client.loadCapabilities();
      await client.authenticate(opts.auth);
      client.caps.clear();
      await client.loadCapabilities();
      return client;
    } catch (error) {
      channel.destroy();
      throw error;
    }
  }

  capabilities(): ReadonlySet<string> {
    return this.caps;
  }

  async select(mailbox: string, readOnly: boolean): Promise<{ exists: number }> {
    const verb = readOnly ? "EXAMINE" : "SELECT";
    const response = await this.command(verb, [{ kind: "string", value: mailbox }]);
    if (response.tagged.status !== "OK") {
      throw VaultError.imapOperationFailed(this.origin, verb.toLowerCase());
    }
    let exists = 0;
    for (const line of response.untagged) {
      // `* <n> EXISTS`
      if (line.atoms.length >= 3 && line.atoms[2]?.toUpperCase() === "EXISTS") {
        const n = Number(line.atoms[1]);
        if (Number.isFinite(n)) {
          exists = n;
        }
      }
    }
    return { exists };
  }

  async searchUids(criteria: ImapSearchCriteria): Promise<number[]> {
    const args: ImapArg[] = [];
    if (criteria.unseen) {
      args.push({ kind: "atom", value: "UNSEEN" });
    }
    if (criteria.since !== undefined) {
      args.push(
        { kind: "atom", value: "SINCE" },
        { kind: "atom", value: formatImapDate(criteria.since) },
      );
    }
    if (criteria.from !== undefined) {
      args.push({ kind: "atom", value: "FROM" }, { kind: "string", value: criteria.from });
    }
    if (criteria.subject !== undefined) {
      args.push({ kind: "atom", value: "SUBJECT" }, { kind: "string", value: criteria.subject });
    }
    if (criteria.text !== undefined) {
      args.push({ kind: "atom", value: "TEXT" }, { kind: "string", value: criteria.text });
    }
    if (args.length === 0) {
      // SEARCH requires at least one search key — an empty criteria object
      // means "everything", never a bodyless (syntactically invalid) command.
      args.push({ kind: "atom", value: "ALL" });
    }
    const response = await this.command("UID SEARCH", args);
    if (response.tagged.status !== "OK") {
      throw VaultError.imapOperationFailed(this.origin, "search");
    }
    const uids: number[] = [];
    for (const line of response.untagged) {
      // `* SEARCH <uid> <uid> ...` — UID SEARCH reports UIDs, not sequence numbers.
      if (line.atoms[0] === "*" && line.atoms[1]?.toUpperCase() === "SEARCH") {
        for (const token of line.atoms.slice(2)) {
          const n = Number(token);
          if (Number.isFinite(n)) {
            uids.push(n);
          }
        }
      }
    }
    return uids;
  }

  async fetch(uids: number[], parts: ImapFetchParts): Promise<ImapMessage[]> {
    const uidSet = formatUidSet(uids);
    const response = await this.command("UID FETCH", [
      { kind: "atom", value: uidSet },
      fetchItemsArg(parts),
    ]);
    if (response.tagged.status !== "OK") {
      throw VaultError.imapOperationFailed(this.origin, "fetch");
    }
    return parseFetchMessages(response.untagged);
  }

  /** The returned count is the requested UID count, not a server-confirmed count. */
  async store(uids: number[], addFlags: string[], removeFlags: string[]): Promise<number> {
    const uidSet = formatUidSet(uids);
    if (addFlags.length > 0) {
      await this.runStore(uidSet, "+FLAGS", addFlags);
    }
    if (removeFlags.length > 0) {
      await this.runStore(uidSet, "-FLAGS", removeFlags);
    }
    return uids.length;
  }

  /**
   * Moves messages to `targetMailbox`. Uses RFC 6851 `UID MOVE` when
   * advertised; otherwise COPY + STORE(\Deleted) + RFC 4315 `UID EXPUNGE
   * <set>`, scoped to exactly the just-copied UIDs. Both decisions read the
   * authenticated capability set `connect` re-reads after login, never the
   * greeting's. A server advertising neither capability there is refused
   * before any command (E83, 2026-09-04): IMAP
   * has no way to scope a plain `EXPUNGE`, and a blanket one would destroy
   * every `\Deleted` message in the mailbox — the caller's own or a concurrent
   * session's — as collateral damage. The refusal points at `copy`, which the
   * caller can follow with an explicit `store` and `expunge` if that cost is
   * acceptable.
   *
   * The returned count is the requested UID count in every branch, not a
   * server-confirmed count.
   */
  async move(uids: number[], targetMailbox: string): Promise<number> {
    if (!this.caps.has("MOVE") && !this.caps.has("UIDPLUS")) {
      throw VaultError.imapMoveUnsupported(this.origin);
    }
    const uidSet = formatUidSet(uids);
    if (this.caps.has("MOVE")) {
      const response = await this.command("UID MOVE", [
        { kind: "atom", value: uidSet },
        { kind: "string", value: targetMailbox },
      ]);
      if (response.tagged.status !== "OK") {
        throw VaultError.imapOperationFailed(this.origin, "move");
      }
      return uids.length;
    }
    // RFC 6851 MOVE is unavailable: COPY, mark \Deleted, then UID EXPUNGE —
    // issued sequentially (command() has a single response waiter; these must
    // never race each other or anything else on this connection).
    const copyResponse = await this.command("UID COPY", [
      { kind: "atom", value: uidSet },
      { kind: "string", value: targetMailbox },
    ]);
    if (copyResponse.tagged.status !== "OK") {
      throw VaultError.imapOperationFailed(this.origin, "move");
    }
    await this.runStore(uidSet, "+FLAGS", ["\\Deleted"]);
    await this.uidExpunge(uidSet);
    return uids.length;
  }

  /** The returned count is the requested UID count, not a server-confirmed count. */
  async copy(uids: number[], targetMailbox: string): Promise<number> {
    const uidSet = formatUidSet(uids);
    const response = await this.command("UID COPY", [
      { kind: "atom", value: uidSet },
      { kind: "string", value: targetMailbox },
    ]);
    if (response.tagged.status !== "OK") {
      throw VaultError.imapOperationFailed(this.origin, "copy");
    }
    return uids.length;
  }

  async expunge(): Promise<number> {
    const response = await this.command("EXPUNGE", []);
    if (response.tagged.status !== "OK") {
      throw VaultError.imapOperationFailed(this.origin, "expunge");
    }
    return countExpungeLines(response.untagged);
  }

  /** RFC 4315 `UID EXPUNGE <set>` — scopes the expunge to exactly `uidSet`,
   * unlike plain `EXPUNGE`'s blanket removal of every `\Deleted` message. */
  private async uidExpunge(uidSet: string): Promise<number> {
    const response = await this.command("UID EXPUNGE", [{ kind: "atom", value: uidSet }]);
    if (response.tagged.status !== "OK") {
      throw VaultError.imapOperationFailed(this.origin, "expunge");
    }
    return countExpungeLines(response.untagged);
  }

  private async runStore(
    uidSet: string,
    verb: "+FLAGS" | "-FLAGS",
    flags: string[],
  ): Promise<void> {
    validateFlags(flags);
    const response = await this.command("UID STORE", [
      { kind: "atom", value: uidSet },
      { kind: "atom", value: verb },
      { kind: "list", items: flags.map(flagArg) },
    ]);
    if (response.tagged.status !== "OK") {
      throw VaultError.imapOperationFailed(this.origin, "store");
    }
  }

  async logout(): Promise<void> {
    try {
      await this.command("LOGOUT", []);
    } catch {
      // A logout that cannot complete is still a teardown — swallow and destroy.
    } finally {
      this.channel.destroy();
    }
  }

  async command(name: string, args: ImapArg[]): Promise<ImapResponse> {
    const tag = this.nextTag();
    const segments: Segment[] = [{ kind: "inline", text: `${tag} ${name}` }];
    for (const arg of args) {
      segments.push({ kind: "inline", text: " " });
      segments.push(...encodeArg(arg));
    }
    await this.sendSegments(segments);
    return this.readUntilTagged(tag);
  }

  private nextTag(): string {
    this.tagCounter += 1;
    return `A${this.tagCounter}`;
  }

  /**
   * Serialize the command. A `literal` segment flushes the accumulated line
   * with its `{n}\r\n` announcement, waits for the server's `+` continuation,
   * then writes the counted octets — the injection defense on the wire.
   */
  private async sendSegments(segments: Segment[]): Promise<void> {
    let lineBuf = "";
    for (const segment of segments) {
      if (segment.kind === "inline") {
        lineBuf += segment.text;
        continue;
      }
      this.channel.write(`${lineBuf}{${segment.bytes.length}}\r\n`);
      lineBuf = "";
      await this.awaitContinuation();
      this.channel.writeBytes(segment.bytes);
    }
    this.channel.write(`${lineBuf}\r\n`);
  }

  private async awaitContinuation(): Promise<void> {
    const line = await this.channel.nextLine();
    if (!line.text.startsWith("+")) {
      throw VaultError.imapOperationFailed(this.origin, "literal");
    }
  }

  private async readUntilTagged(tag: string): Promise<ImapResponse> {
    const untagged: UntaggedLine[] = [];
    for (;;) {
      const line = await this.channel.nextLine();
      if (line.text.startsWith("* ") || line.text === "*") {
        untagged.push(toUntagged(line));
        continue;
      }
      if (line.text.startsWith("+")) {
        // A stray continuation with no literal outstanding is a protocol fault.
        throw VaultError.imapOperationFailed(this.origin, "read");
      }
      const tagged = parseTagged(line.text);
      if (!tagged) {
        throw VaultError.imapOperationFailed(this.origin, "read");
      }
      const receivedTag = line.text.split(/\s+/)[0] ?? "";
      if (receivedTag !== tag) {
        throw VaultError.imapOperationFailed(this.origin, "read");
      }
      return { tagged, untagged };
    }
  }

  private async readGreeting(): Promise<void> {
    const line = await this.channel.nextLine();
    const atoms = line.text.split(/\s+/).filter((a) => a.length > 0);
    const status = atoms[1]?.toUpperCase();
    if (atoms[0] !== "*" || (status !== "OK" && status !== "PREAUTH")) {
      throw VaultError.imapOperationFailed(this.origin, "connect");
    }
    for (const cap of parseCapabilities(atoms)) {
      this.caps.add(cap);
    }
  }

  private async loadCapabilities(): Promise<void> {
    const response = await this.command("CAPABILITY", []);
    if (response.tagged.status !== "OK") {
      throw VaultError.imapOperationFailed(this.origin, "capability");
    }
    for (const line of response.untagged) {
      for (const cap of parseCapabilities(line.atoms)) {
        this.caps.add(cap);
      }
    }
  }

  private async authenticate(auth: ImapAuth): Promise<void> {
    if (auth.kind === "xoauth2") {
      await this.authenticateXoauth2(auth.username, auth.accessToken);
      return;
    }
    const response = await this.command("LOGIN", [
      { kind: "string", value: auth.username },
      { kind: "string", value: auth.password },
    ]);
    if (response.tagged.status !== "OK") {
      throw VaultError.imapOperationFailed(this.origin, "login");
    }
  }

  private async authenticateXoauth2(username: string, accessToken: string): Promise<void> {
    const tag = this.nextTag();
    this.channel.write(`${tag} AUTHENTICATE XOAUTH2\r\n`);
    await this.awaitContinuation();
    const blob = Buffer.from(
      `user=${username}\x01auth=Bearer ${accessToken}\x01\x01`,
      "utf8",
    ).toString("base64");
    this.channel.write(`${blob}\r\n`);
    for (;;) {
      const line = await this.channel.nextLine();
      if (line.text.startsWith("* ") || line.text === "*") {
        continue;
      }
      if (line.text.startsWith("+")) {
        // Server returned a base64 error challenge; an empty response elicits
        // the final tagged status (a NO), which folds to failed below.
        this.channel.write("\r\n");
        continue;
      }
      const tagged = parseTagged(line.text);
      if (!tagged || tagged.status !== "OK") {
        throw VaultError.imapOperationFailed(this.origin, "authenticate");
      }
      return;
    }
  }
}

function toUntagged(line: LogicalLine): UntaggedLine {
  return {
    atoms: line.text.split(/\s+/).filter((a) => a.length > 0),
    literals: line.literals,
    raw: line.text,
  };
}
