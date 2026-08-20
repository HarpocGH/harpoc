import type { ImapAction, ImapResult, InjectionPolicy } from "@harpoc/shared";
import { ActionType, DEFAULT_HTTP_TIMEOUT_MS, DEFAULT_IMAP_PORT, VaultError } from "@harpoc/shared";
import { matchesHostPortAllowlist } from "./allowlist.js";
import type {
  ImapAuth,
  ImapConnectOptions,
  ImapFetchParts,
  ImapMessage,
  ImapSearchCriteria,
} from "./mail/imap-client.js";
import { ImapClient } from "./mail/imap-client.js";
import { mapStringLeaves, redactErrorMessage, redactSecretEncodings } from "./output-sanitizer.js";
import type { MailTlsConfig } from "./smtp-injector.js";
import { validateHostPort } from "./url-validator.js";

/**
 * Per-secret mail TLS connection config, reused verbatim from the SMTP
 * injector (same `mail` connection-config group). IMAP is implicit-TLS only
 * (design §4.2 / imap-client.ts), so only the `{ ca }` override is meaningful.
 * A `tls: false` opt-out is **refused by the engine before this injector is
 * reached** (Task 12): a config the vault cannot honor refuses rather than
 * being silently reinterpreted. The defensive drop below stands for a direct
 * `executeImapAction` caller that bypasses the engine — it can only ever
 * strengthen TLS, never weaken it.
 */
export type ImapTlsConfig = MailTlsConfig;

/** OAuth material for the XOAUTH2 auth arm — resolved by the engine, never here. */
export interface ImapOAuth {
  accessToken: string;
  username: string;
}

/**
 * The operation-shaped half of an {@link ImapResult}: `search` fills `uids`,
 * `fetch` fills `messages`, the mutating kinds fill `affected` — exactly one
 * per operation. The injector wraps it with the `type`/`operation`
 * discriminants to form the wire result.
 */
type ImapOperationFields = Omit<ImapResult, "type" | "operation">;

/**
 * Metadata-only audit projection of an IMAP operation. Names the origin, the
 * selected mailbox, the operation kind and the number of UIDs/messages the
 * result touched — never message content or a credential.
 */
export interface ImapAuditDetails {
  host: string;
  mailbox: string;
  operation: string;
  uid_count: number;
  /** XOAUTH2 identity from the action's `account` — present on the OAuth arm only. */
  auth_account?: string;
}

/** Result of a full run: the wire result plus the audit projection the engine writes. */
export interface ImapExecution {
  result: ImapResult;
  auditDetails: ImapAuditDetails;
}

/**
 * The subset of `ImapClient`'s public surface the injector drives. `ImapClient`
 * itself satisfies this structurally (duck typing) — its private constructor
 * means a test double can only ever be a plain object shaped like this, never
 * a real instance, which is exactly the DI seam this interface exists for.
 */
export interface ImapClientLike {
  select(mailbox: string, readOnly: boolean): Promise<{ exists: number }>;
  searchUids(criteria: ImapSearchCriteria): Promise<number[]>;
  fetch(uids: number[], parts: ImapFetchParts): Promise<ImapMessage[]>;
  store(uids: number[], addFlags: string[], removeFlags: string[]): Promise<number>;
  move(uids: number[], targetMailbox: string): Promise<number>;
  copy(uids: number[], targetMailbox: string): Promise<number>;
  expunge(): Promise<number>;
  logout(): Promise<void>;
}

/**
 * Injectable dependencies: a fake `connectImap` for the connect seam, so a
 * refusal-ordering test can prove no socket ever opens (mirrors
 * `SmtpInjectorDeps`'s `sendSmtp`).
 */
export interface ImapInjectorDeps {
  connectImap?: (opts: ImapConnectOptions) => Promise<ImapClientLike>;
}

/** The four operation kinds that mutate mailbox state — refused outright
 * under `imap_read_only` (design §5.3 / policy field). */
const MUTATION_KINDS = new Set<ImapAction["operation"]["kind"]>([
  "store",
  "move",
  "copy",
  "expunge",
]);

/** The number of UIDs/messages a result actually touched — used for both the
 * audit projection and (indirectly) test assertions on operation shape. */
function resultUidCount(result: ImapOperationFields): number {
  if (result.uids !== undefined) return result.uids.length;
  if (result.messages !== undefined) return result.messages.length;
  return result.affected ?? 0;
}

/**
 * Builds the metadata-only audit projection for an IMAP operation. Pure — the
 * engine (Task 12) or the injector itself calls it once the result is known.
 * Takes only the operation-shaped half, so the engine's zeroed refusal
 * projections (`{ affected: 0 }`) need no discriminants to describe an attempt
 * that produced no result at all.
 */
export function buildImapAuditDetails(
  action: ImapAction,
  result: ImapOperationFields,
): ImapAuditDetails {
  return {
    host: action.host,
    mailbox: action.mailbox,
    operation: action.operation.kind,
    uid_count: resultUidCount(result),
    ...(action.account !== undefined ? { auth_account: action.account } : {}),
  };
}

/**
 * IMAP injector (request-mediated, design §5.3). Turns a schema-validated
 * `ImapAction` into a sequence of IMAP commands over a fresh connection,
 * enforcing — in this exact, load-bearing order — the `imap_read_only` policy
 * gate (BEFORE any socket opens, since a refused mutation must never touch the
 * network), the target host allowlist, then SSRF pre-flight with address
 * pinning. The mailbox is always SELECTed/EXAMINEd according to the operation:
 * `search`/`fetch` always use EXAMINE (`readOnly: true`) regardless of the
 * policy value — a read must never risk setting `\Seen` as a side effect —
 * while a mutation (only reachable when `imap_read_only` is false) uses
 * SELECT. Every throw leaves the injector with the credential stripped
 * (`redactErrorMessage`), and every fetched message's header/text content is
 * redacted the same way before it is returned, so a credential planted in a
 * message body never reaches the model.
 *
 * The credential is injected at the auth arm only: an OAuth access token
 * drives XOAUTH2, otherwise the secret value (`username:password`) drives the
 * password arm. `ImapClient.command()` holds a single response waiter, so
 * every IMAP command this injector issues is awaited in turn — never fired
 * concurrently on the same connection.
 */
export class ImapInjector {
  private readonly connectImap: NonNullable<ImapInjectorDeps["connectImap"]>;

  constructor(deps: ImapInjectorDeps = {}) {
    this.connectImap = deps.connectImap ?? ((opts) => ImapClient.connect(opts));
  }

  async run(
    action: ImapAction,
    secretValue: string,
    policy: InjectionPolicy,
    connection: ImapTlsConfig | undefined,
    oauth: ImapOAuth | undefined,
  ): Promise<ImapExecution> {
    // Redaction material captured up front so it is available on every throw
    // path (mirrors the SMTP injector: origin-only, credential stripped).
    const material = redactionMaterial(secretValue, oauth);
    try {
      return await this.execute(action, secretValue, policy, connection, oauth, material);
    } catch (err) {
      throw redactThrown(err, material);
    }
  }

  private async execute(
    action: ImapAction,
    secretValue: string,
    policy: InjectionPolicy,
    connection: ImapTlsConfig | undefined,
    oauth: ImapOAuth | undefined,
    material: string[],
  ): Promise<ImapExecution> {
    const { host, port } = resolveHostPort(action);
    const kind = action.operation.kind;
    const isMutation = MUTATION_KINDS.has(kind);

    // 1. imap_read_only gate — BEFORE any socket. A refused mutation never
    //    reaches connectImap.
    if (policy.imap_read_only && isMutation) {
      throw VaultError.imapMutationNotAllowed(kind);
    }

    // 2. Host allowlist (optional layer atop the mandatory SSRF floor).
    if (!matchesHostPortAllowlist(host, port, policy.host_allowlist)) {
      throw VaultError.hostNotAllowed(`${host}:${port}`);
    }

    // 3. SSRF pre-flight: reject private/internal targets and pin the dialed
    //    address so the socket cannot be re-resolved (TLS identity stays
    //    bound to the logical host — mirrors the database/SMTP injectors).
    const validated = await validateHostPort(host, port);
    const pinnedAddress = validated.resolvedAddress;

    // 4. Auth arm (credential injected here only).
    const auth = buildAuth(secretValue, oauth);

    // 5. Connect + authenticate.
    const timeoutMs = action.timeout_ms ?? DEFAULT_HTTP_TIMEOUT_MS;
    const tls = imapTls(connection);
    const client = await this.connectImap({
      host,
      port,
      address: pinnedAddress,
      auth,
      timeoutMs,
      ...(tls !== undefined ? { tls } : {}),
    });

    try {
      // 6. SELECT/EXAMINE: reads always EXAMINE (readOnly), regardless of
      //    policy — a mutation only ever reaches here when imap_read_only is
      //    false, so its SELECT is always read-write.
      const isReadOp = !isMutation;
      const readOnly = policy.imap_read_only || isReadOp;
      await client.select(action.mailbox, readOnly);

      // 7. Dispatch the single operation (sequential — one command in flight
      //    per connection), then wrap its operation-shaped fields in the wire
      //    discriminants.
      const fields = await this.runOperation(client, action.operation, material);

      return {
        result: { type: ActionType.IMAP, operation: kind, ...fields },
        auditDetails: buildImapAuditDetails(action, fields),
      };
    } finally {
      try {
        await client.logout();
      } catch {
        // best-effort teardown; do not mask the operation's own outcome
      }
    }
  }

  private async runOperation(
    client: ImapClientLike,
    operation: ImapAction["operation"],
    material: string[],
  ): Promise<ImapOperationFields> {
    switch (operation.kind) {
      case "search": {
        const criteria: ImapSearchCriteria = {
          unseen: operation.unseen,
          since: operation.since,
          from: operation.from,
          subject: operation.subject,
          text: operation.text,
        };
        const uids = await client.searchUids(criteria);
        return { uids };
      }
      case "fetch": {
        const messages = await client.fetch(operation.uids, operation.parts);
        return { messages: redactMessages(messages, material) };
      }
      case "store": {
        const affected = await client.store(
          operation.uids,
          operation.add_flags ?? [],
          operation.remove_flags ?? [],
        );
        return { affected };
      }
      case "move": {
        const affected = await client.move(operation.uids, operation.target_mailbox);
        return { affected };
      }
      case "copy": {
        const affected = await client.copy(operation.uids, operation.target_mailbox);
        return { affected };
      }
      case "expunge": {
        const affected = await client.expunge();
        return { affected };
      }
      default: {
        const exhaustive: never = operation;
        throw VaultError.invalidInput(
          `unsupported IMAP operation: ${String((exhaustive as { kind: string }).kind)}`,
        );
      }
    }
  }
}

/**
 * Executes a schema-validated IMAP action with an injected credential. The
 * engine (Task 12) resolves the OAuth token (when the secret is OAuth-typed)
 * and the mail TLS connection config, then calls this. Returns the wire
 * result; the audit projection is available via {@link buildImapAuditDetails}
 * or the richer {@link ImapInjector.run}.
 */
export async function executeImapAction(
  action: ImapAction,
  secretValue: string,
  policy: InjectionPolicy,
  connection: ImapTlsConfig | undefined,
  oauth: ImapOAuth | undefined,
): Promise<ImapResult> {
  const { result } = await new ImapInjector().run(action, secretValue, policy, connection, oauth);
  return result;
}

/** Split `host` (which may embed `:port`) and an optional explicit port. */
function resolveHostPort(action: ImapAction): { host: string; port: number } {
  const match = /^(.*):(\d+)$/.exec(action.host);
  if (match && match[1] !== undefined && match[2] !== undefined) {
    const embedded = Number.parseInt(match[2], 10);
    if (embedded < 1 || embedded > 65_535) {
      throw VaultError.invalidInput("embedded port out of range (1-65535)");
    }
    return { host: match[1], port: action.port ?? embedded };
  }
  return { host: action.host, port: action.port ?? DEFAULT_IMAP_PORT };
}

/** XOAUTH2 when an OAuth token is present, else the `username:password` arm. */
function buildAuth(secretValue: string, oauth: ImapOAuth | undefined): ImapAuth {
  if (oauth) {
    return { kind: "xoauth2", username: oauth.username, accessToken: oauth.accessToken };
  }
  const i = secretValue.indexOf(":");
  if (i < 0) {
    throw VaultError.invalidInput("IMAP secret must be in 'username:password' form");
  }
  return {
    kind: "password",
    username: secretValue.slice(0, i),
    password: secretValue.slice(i + 1),
  };
}

/** `false` is not honored for IMAP (implicit-TLS only; the engine refuses it
 * outright before reaching here) — only the `{ ca }` override is meaningful;
 * anything else maps to "use default system CAs". */
function imapTls(connection: ImapTlsConfig | undefined): { ca?: string } | undefined {
  const tls = connection?.tls;
  return tls ? tls : undefined;
}

/**
 * The sensitive strings to strip from any thrown error message or fetched
 * message content. XOAUTH2 → the access token; password arm → the password,
 * plus the username when it is long enough that redacting it will not shred
 * unrelated text (parity with the database/SMTP injectors' 3-char floor).
 */
function redactionMaterial(secretValue: string, oauth: ImapOAuth | undefined): string[] {
  if (oauth) return [oauth.accessToken];
  const i = secretValue.indexOf(":");
  if (i < 0) return [secretValue];
  const password = secretValue.slice(i + 1);
  const user = secretValue.slice(0, i);
  return user.length >= 3 ? [password, user] : [password];
}

/** Strip every credential fragment from a thrown error, in turn. */
function redactThrown(err: unknown, material: string[]): unknown {
  let out = err;
  for (const secret of material) {
    if (secret.length > 0) out = redactErrorMessage(out, secret);
  }
  return out;
}

/**
 * Redact every string leaf (headers, text, envelope fields) of every fetched
 * message. A credential planted in a message body — the mail-context analog
 * of a database row or an HTTP response body carrying it back — is redacted
 * the same way those channels are.
 */
function redactMessages(messages: ImapMessage[], material: string[]): ImapMessage[] {
  const redactOne = (s: string): string =>
    material.reduce(
      (acc, secret) => (secret.length > 0 ? redactSecretEncodings(acc, secret) : acc),
      s,
    );
  return mapStringLeaves(messages, redactOne) as ImapMessage[];
}
