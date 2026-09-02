import { readFile as nodeReadFile, stat as nodeStat } from "node:fs/promises";
import { basename } from "node:path";
import type { InjectionPolicy, SmtpAction, SmtpResult } from "@harpoc/shared";
import {
  ActionType,
  DEFAULT_HTTP_TIMEOUT_MS,
  DEFAULT_SMTP_STARTTLS_PORT,
  DEFAULT_SMTP_TLS_PORT,
  MAX_ATTACHMENT_BYTES,
  MAX_ATTACHMENT_TOTAL_BYTES,
  MAX_SMTP_ATTACHMENTS,
  MIN_REDACTABLE_FRAGMENT,
  VaultError,
  matchesRecipientPattern,
} from "@harpoc/shared";
import { matchesHostPortAllowlist } from "./allowlist.js";
import type { MimeAttachment } from "./mail/mime.js";
import { assembleMessage } from "./mail/mime.js";
import type { SmtpAuth, SmtpSendOptions } from "./mail/smtp-client.js";
import { sendSmtp as realSendSmtp } from "./mail/smtp-client.js";
import { redactErrorMessage } from "./output-sanitizer.js";
import { validateHostPort } from "./url-validator.js";

/**
 * Per-secret mail TLS connection config, threaded from the engine's
 * connection-config `mail` group (Task 12). `tls: false` is the audited
 * plaintext opt-out (implicit-TLS mode only — the SMTP client ignores it for
 * STARTTLS); `{ ca }` pins a custom CA bundle; absent means default system CAs.
 * It maps 1:1 onto {@link SmtpSendOptions.tls}.
 */
export interface MailTlsConfig {
  tls?: false | { ca?: string };
}

/** OAuth material for the XOAUTH2 auth arm — resolved by the engine, never here. */
export interface SmtpOAuth {
  accessToken: string;
  username: string;
}

/**
 * Metadata-only audit projection of an SMTP send. Names the origin, the
 * envelope sender, every recipient (to ∪ cc ∪ bcc) and every attachment path
 * plus the total attachment bytes — never a body, header value or credential.
 */
export interface SmtpAuditDetails {
  host: string;
  from: string;
  recipients: string[];
  attachment_paths: string[];
  attachment_total_bytes: number;
}

/** One attachment after policy checks: its path and the bytes actually read. */
export interface SmtpResolvedAttachment {
  path: string;
  bytes: number;
}

/** Result of a full run: the wire result plus the audit projection the engine writes. */
export interface SmtpExecution {
  result: SmtpResult;
  auditDetails: SmtpAuditDetails;
}

/**
 * Injectable dependencies (mirrors `DatabaseInjector`'s constructor-DI style):
 * a fake `sendSmtp` for the send seam, and `stat`/`readFile` so the
 * refusal-ordering tests can prove no attachment file is touched before the
 * recipient/attachment-policy checks have passed.
 */
export interface SmtpInjectorDeps {
  sendSmtp?: (opts: SmtpSendOptions) => Promise<{ accepted: number; messageId: null }>;
  stat?: (path: string) => Promise<{ size: number }>;
  readFile?: (path: string) => Promise<Buffer>;
}

/**
 * Builds the metadata-only audit projection for an SMTP send. Pure — the engine
 * (Task 12) calls it with the attachments the injector resolved. Recipients are
 * the deduplicated to ∪ cc ∪ bcc union (envelope order); attachment bytes come
 * from the caller's resolved list, never re-read here.
 */
export function buildSmtpAuditDetails(
  action: SmtpAction,
  attachments: readonly SmtpResolvedAttachment[],
): SmtpAuditDetails {
  return {
    host: action.host,
    from: action.from,
    recipients: collectRecipients(action),
    attachment_paths: attachments.map((a) => a.path),
    attachment_total_bytes: attachments.reduce((sum, a) => sum + a.bytes, 0),
  };
}

/**
 * SMTP injector (request-mediated, design §5.2). Turns a schema-validated
 * `SmtpAction` into an assembled MIME message and a single `sendSmtp` call,
 * enforcing — in this exact, load-bearing order — the target host allowlist,
 * the recipient-allowlist coupling (attachments demand a configured allowlist;
 * a configured allowlist constrains every recipient), the attachment count/size
 * caps (checked via `stat` BEFORE any byte is read — an over-policy send never
 * touches a local file), then SSRF pre-flight with address pinning. Every throw
 * leaves the injector with the credential stripped (`redactErrorMessage`), and
 * `assembleMessage`'s plain-`Error` reserved-header guard is translated to a
 * `VaultError` so no raw error escapes.
 *
 * The credential is injected at the auth arm only: an OAuth access token drives
 * XOAUTH2, otherwise the secret value (`username:password`) drives the password
 * arm — the token and the password never appear on the same path.
 */
export class SmtpInjector {
  private readonly sendSmtp: NonNullable<SmtpInjectorDeps["sendSmtp"]>;
  private readonly stat: NonNullable<SmtpInjectorDeps["stat"]>;
  private readonly readFile: NonNullable<SmtpInjectorDeps["readFile"]>;

  constructor(deps: SmtpInjectorDeps = {}) {
    this.sendSmtp = deps.sendSmtp ?? realSendSmtp;
    this.stat = deps.stat ?? ((p) => nodeStat(p));
    this.readFile = deps.readFile ?? ((p) => nodeReadFile(p));
  }

  async run(
    action: SmtpAction,
    secretValue: string,
    policy: InjectionPolicy,
    connection: MailTlsConfig | undefined,
    oauth: SmtpOAuth | undefined,
  ): Promise<SmtpExecution> {
    // Redaction material captured up front so it is available on every throw
    // path (SMTP joins the HTTP rule: origin-only, credential stripped).
    const material = redactionMaterial(secretValue, oauth);
    try {
      return await this.execute(action, secretValue, policy, connection, oauth);
    } catch (err) {
      throw redactThrown(err, material);
    }
  }

  private async execute(
    action: SmtpAction,
    secretValue: string,
    policy: InjectionPolicy,
    connection: MailTlsConfig | undefined,
    oauth: SmtpOAuth | undefined,
  ): Promise<SmtpExecution> {
    const { host, port } = resolveHostPort(action);

    // 1. Host allowlist (deny-by-default, atop the mandatory SSRF floor).
    if (!matchesHostPortAllowlist(host, port, policy.host_allowlist)) {
      throw VaultError.hostNotAllowed(`${host}:${port}`);
    }

    // 2. Recipient rules (the exfiltration coupling — design §5.2).
    const recipients = collectRecipients(action);
    const allowlist = policy.smtp_recipient_allowlist;
    const hasAttachments = (action.attachments?.length ?? 0) > 0;
    // Attachments can carry local files outward: they require an explicit
    // recipient allowlist. Refused BEFORE any attachment file is read.
    if (hasAttachments && allowlist.length === 0) {
      throw VaultError.attachmentPolicyRequired();
    }
    // A configured allowlist constrains every recipient (with or without
    // attachments); an empty allowlist leaves a body-only send unrestricted.
    if (allowlist.length > 0) {
      for (const recipient of recipients) {
        if (!matchesRecipientPattern(recipient, allowlist)) {
          throw VaultError.recipientNotAllowed(recipient);
        }
      }
    }

    // 3. Attachment caps — count first (no stat), then per-file and running
    //    total via `stat`, all BEFORE any byte is read. Every rejection reason
    //    is a vault-authored policy string; it never carries a path or content.
    const specs = action.attachments ?? [];
    if (specs.length > MAX_SMTP_ATTACHMENTS) {
      throw VaultError.attachmentRejected(`too many attachments (max ${MAX_SMTP_ATTACHMENTS})`);
    }
    let total = 0;
    for (const spec of specs) {
      const { size } = await this.stat(spec.path);
      if (size > MAX_ATTACHMENT_BYTES) {
        throw VaultError.attachmentRejected(
          `an attachment exceeds the ${MAX_ATTACHMENT_BYTES}-byte per-file limit`,
        );
      }
      total += size;
      if (total > MAX_ATTACHMENT_TOTAL_BYTES) {
        throw VaultError.attachmentRejected(
          `attachments exceed the ${MAX_ATTACHMENT_TOTAL_BYTES}-byte per-message limit`,
        );
      }
    }

    // 4. Read attachment bytes (only now that the policy has passed).
    const mimeAttachments: MimeAttachment[] = [];
    const resolved: SmtpResolvedAttachment[] = [];
    for (const spec of specs) {
      const data = await this.readFile(spec.path);
      mimeAttachments.push({
        filename: spec.filename ?? basename(spec.path),
        contentType: spec.content_type ?? "application/octet-stream",
        data,
      });
      resolved.push({ path: spec.path, bytes: data.length });
    }

    // 5. Assemble the message. mime.ts throws a plain Error on a reserved
    //    header (defensive — the schema denylists them upstream); translate it
    //    so no raw Error leaves the injector.
    let assembled: { message: string; messageId: string };
    try {
      assembled = assembleMessage({
        from: action.from,
        to: action.to,
        cc: action.cc,
        subject: action.subject,
        text: action.text,
        html: action.html,
        attachments: mimeAttachments.length > 0 ? mimeAttachments : undefined,
        extraHeaders: action.headers,
      });
    } catch (err) {
      if (err instanceof VaultError) throw err;
      throw VaultError.invalidInput(
        "message assembly failed: a reserved header field was supplied",
      );
    }

    // 6. SSRF pre-flight: reject private/internal targets and pin the dialed
    //    address so the socket cannot be re-resolved (TLS identity stays bound
    //    to the logical host — mirrors the database injector).
    const validated = await validateHostPort(host, port);
    const pinnedAddress = validated.resolvedAddress;

    // 7. Auth arm (credential injected here only).
    const auth = buildAuth(secretValue, oauth);

    // 8. TLS config maps 1:1 from the connection's mail group.
    const tls = connection?.tls;

    // 9. Send. bcc is in the envelope recipients but was never written into the
    //    message headers (mime.ts has no bcc channel).
    const timeoutMs = action.timeout_ms ?? DEFAULT_HTTP_TIMEOUT_MS;
    const { accepted } = await this.sendSmtp({
      host,
      port,
      address: pinnedAddress,
      security: action.security,
      auth,
      envelope: { from: action.from, recipients },
      message: assembled.message,
      timeoutMs,
      tls,
    });

    return {
      result: { type: ActionType.SMTP, accepted, message_id: assembled.messageId },
      auditDetails: buildSmtpAuditDetails(action, resolved),
    };
  }
}

/**
 * Executes a schema-validated SMTP action with an injected credential. The
 * engine (Task 12) resolves the OAuth token (when the secret is OAuth-typed)
 * and the mail TLS connection config, then calls this. Returns the wire result;
 * the audit projection is available via {@link buildSmtpAuditDetails} or the
 * richer {@link SmtpInjector.run}.
 */
export async function executeSmtpAction(
  action: SmtpAction,
  secretValue: string,
  policy: InjectionPolicy,
  connection: MailTlsConfig | undefined,
  oauth: SmtpOAuth | undefined,
): Promise<SmtpResult> {
  const { result } = await new SmtpInjector().run(action, secretValue, policy, connection, oauth);
  return result;
}

/** The deduplicated to ∪ cc ∪ bcc recipient union, in envelope order. */
function collectRecipients(action: SmtpAction): string[] {
  return [...new Set([...action.to, ...(action.cc ?? []), ...(action.bcc ?? [])])];
}

/**
 * Resolve host and port. Port defaults by `security` (465 implicit-TLS, 587
 * STARTTLS); a `host:port` embedded in the host field is honored unless an
 * explicit `port` overrides it (mirrors the database injector).
 */
function resolveHostPort(action: SmtpAction): { host: string; port: number } {
  const fallback = action.security === "tls" ? DEFAULT_SMTP_TLS_PORT : DEFAULT_SMTP_STARTTLS_PORT;
  const match = /^(.*):(\d+)$/.exec(action.host);
  if (match && match[1] !== undefined && match[2] !== undefined) {
    const embedded = Number.parseInt(match[2], 10);
    if (embedded < 1 || embedded > 65_535) {
      throw VaultError.invalidInput("embedded port out of range (1-65535)");
    }
    return { host: match[1], port: action.port ?? embedded };
  }
  return { host: action.host, port: action.port ?? fallback };
}

/** XOAUTH2 when an OAuth token is present, else the `username:password` arm. */
function buildAuth(secretValue: string, oauth: SmtpOAuth | undefined): SmtpAuth {
  if (oauth) {
    return { kind: "xoauth2", username: oauth.username, accessToken: oauth.accessToken };
  }
  const i = secretValue.indexOf(":");
  if (i < 0) {
    throw VaultError.invalidInput("SMTP secret must be in 'username:password' form");
  }
  return {
    kind: "password",
    username: secretValue.slice(0, i),
    password: secretValue.slice(i + 1),
  };
}

/**
 * The sensitive strings to strip from any thrown error message. XOAUTH2 → the
 * access token; password arm → the password, plus the username when it reaches
 * the shared floor (MIN_REDACTABLE_FRAGMENT), below which redacting it would
 * shred unrelated text.
 */
function redactionMaterial(secretValue: string, oauth: SmtpOAuth | undefined): string[] {
  if (oauth) return [oauth.accessToken];
  const i = secretValue.indexOf(":");
  if (i < 0) return [secretValue];
  const password = secretValue.slice(i + 1);
  const user = secretValue.slice(0, i);
  return user.length >= MIN_REDACTABLE_FRAGMENT ? [password, user] : [password];
}

/** Strip every credential fragment from a thrown error, in turn. */
function redactThrown(err: unknown, material: string[]): unknown {
  let out = err;
  for (const secret of material) {
    if (secret.length > 0) out = redactErrorMessage(out, secret);
  }
  return out;
}
