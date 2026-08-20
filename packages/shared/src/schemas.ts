import { z } from "zod";

import {
  DEFAULT_IMAP_PORT,
  DEFAULT_WS_COLLECT_WINDOW_MS,
  MAX_DOCKER_TIMEOUT_MS,
  MAX_IMAP_FETCH_UIDS,
  MAX_NAME_LENGTH,
  MAX_PROCESS_ARGS,
  MAX_SMTP_ATTACHMENTS,
  MAX_SMTP_RECIPIENTS,
  MAX_WS_COLLECT_MESSAGES,
  MAX_WS_COLLECT_WINDOW_MS,
} from "./constants.js";
import { isValidHandle } from "./handle.js";
import { isValidRecipientPattern } from "./recipient-pattern.js";
import {
  ActionType,
  AuditEventType,
  DatabaseEngine,
  FollowRedirects,
  GitOperation,
  InjectionType,
  McpTransport,
  OAuthGrantType,
  OAuthProviderPreset,
  Permission,
  PrincipalType,
  ResponseMode,
  SecretStatus,
  SecretType,
  TokenPrincipalType,
  VaultState,
} from "./types.js";

// ---------------------------------------------------------------------------
// Single source of truth: every externally-supplied shape (REST bodies, MCP
// tool inputs, CLI args, files read from disk) is validated against a schema
// below, and its TypeScript type is derived from that schema via z.infer —
// the validator and the type cannot drift apart. Enum value sets come from
// the const objects in types.ts, which the z.enum schemas are built from.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Enum schemas (derived from const objects in types.ts)
// ---------------------------------------------------------------------------

const secretTypeValues = Object.values(SecretType) as [SecretType, ...SecretType[]];
export const secretTypeSchema = z.enum(secretTypeValues);

const secretStatusValues = Object.values(SecretStatus) as [SecretStatus, ...SecretStatus[]];
export const secretStatusSchema = z.enum(secretStatusValues);

const permissionValues = Object.values(Permission) as [Permission, ...Permission[]];
export const permissionSchema = z.enum(permissionValues);

const auditEventTypeValues = Object.values(AuditEventType) as [AuditEventType, ...AuditEventType[]];
export const auditEventTypeSchema = z.enum(auditEventTypeValues);

const principalTypeValues = Object.values(PrincipalType) as [PrincipalType, ...PrincipalType[]];
export const principalTypeSchema = z.enum(principalTypeValues);

const tokenPrincipalTypeValues = Object.values(TokenPrincipalType) as [
  TokenPrincipalType,
  ...TokenPrincipalType[],
];
export const tokenPrincipalTypeSchema = z.enum(tokenPrincipalTypeValues);

const injectionTypeValues = Object.values(InjectionType) as [InjectionType, ...InjectionType[]];
export const injectionTypeSchema = z.enum(injectionTypeValues);

const followRedirectsValues = Object.values(FollowRedirects) as [
  FollowRedirects,
  ...FollowRedirects[],
];
export const followRedirectsSchema = z.enum(followRedirectsValues);

const responseModeValues = Object.values(ResponseMode) as [ResponseMode, ...ResponseMode[]];
export const responseModeSchema = z.enum(responseModeValues);

const vaultStateValues = Object.values(VaultState) as [VaultState, ...VaultState[]];
export const vaultStateSchema = z.enum(vaultStateValues);

// ---------------------------------------------------------------------------
// Handle schema
// ---------------------------------------------------------------------------

export const handleSchema = z.string().refine(isValidHandle, { message: "Invalid secret handle" });

/**
 * SMTP recipient allowlist pattern (thesis-aligned v1.3 §5.2): an exact
 * address or a `*@domain` wildcard. See `recipient-pattern.ts` for match
 * semantics.
 */
export const recipientPatternSchema = z
  .string()
  .max(320)
  .refine(isValidRecipientPattern, { message: "Invalid recipient pattern" });

// ---------------------------------------------------------------------------
// Injection config schema
// ---------------------------------------------------------------------------

export const injectionConfigSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal(InjectionType.BEARER) }),
  z.object({ type: z.literal(InjectionType.BASIC_AUTH) }),
  z.object({
    type: z.literal(InjectionType.HEADER),
    header_name: z
      .string()
      .min(1)
      .regex(/^[a-zA-Z0-9\-_]+$/, "Invalid header name characters"),
  }),
  z.object({
    type: z.literal(InjectionType.QUERY),
    query_param: z.string().min(1),
  }),
]);

/** How a secret value is injected into an HTTP request. */
export type InjectionConfig = z.infer<typeof injectionConfigSchema>;

// ---------------------------------------------------------------------------
// Input validation schemas (API boundaries: REST bodies, MCP inputs, CLI args)
// ---------------------------------------------------------------------------

const namePattern = z
  .string()
  .regex(/^[a-zA-Z0-9_-]+$/, "Invalid name format")
  .max(MAX_NAME_LENGTH);

export const createSecretInputSchema = z.object({
  name: namePattern,
  type: secretTypeSchema,
  project: namePattern.optional(),
  value: z.string().base64().optional(),
  expires_at: z.number().int().positive().optional(),
});

/**
 * Create-secret request body (wire shape): the binary secret value travels
 * base64-encoded; `expires_at` is epoch milliseconds.
 */
export type CreateSecretRequest = z.infer<typeof createSecretInputSchema>;

/**
 * Rotate-secret request body. The value is validated exactly like the create
 * route's: `Buffer.from(value, "base64")` silently discards invalid characters,
 * so a truthiness check alone let a malformed value irreversibly rotate the
 * credential to garbage while the API answered 200 (L7).
 */
export const rotateSecretInputSchema = z.object({
  value: z.string().base64(),
});

export type RotateSecretRequest = z.infer<typeof rotateSecretInputSchema>;

export const httpMethodSchema = z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]);

export type HttpMethod = z.infer<typeof httpMethodSchema>;

// ---------------------------------------------------------------------------
// use_secret action schemas (thesis §4.5: two-mechanism injection taxonomy)
// ---------------------------------------------------------------------------

/**
 * URL whose scheme must be http(s). Not https-only at the schema layer:
 * core's validateUrl legitimately allows loopback HTTP and the schema must
 * never be stricter than the enforcement layer it fronts — but javascript:,
 * file:, ftp: et al. are rejected at the boundary instead of one layer down.
 */
const httpishUrlSchema = z
  .string()
  .url()
  .refine((value) => /^https?:\/\//i.test(value), {
    message: "URL scheme must be http or https",
  });

const MAX_HTTP_HEADER_COUNT = 64;
const MAX_HTTP_HEADER_VALUE_LENGTH = 8192;

/**
 * Caller-supplied HTTP headers: names share the injection header_name charset,
 * values are capped and must not smuggle CR/LF/NUL (header-injection defense
 * at the boundary, even though undici also refuses them).
 */
const httpHeadersSchema = z
  .record(
    z
      .string()
      .min(1)
      .max(256)
      .regex(/^[a-zA-Z0-9\-_]+$/, "Invalid header name characters"),
    z
      .string()
      .max(MAX_HTTP_HEADER_VALUE_LENGTH)
      .refine((value) => !/[\r\n\0]/.test(value), {
        message: "Header value must not contain CR, LF or NUL",
      }),
  )
  .refine((headers) => Object.keys(headers).length <= MAX_HTTP_HEADER_COUNT, {
    message: `At most ${MAX_HTTP_HEADER_COUNT} headers are allowed`,
  });

/**
 * HTTP action — request-mediated injection. The vault assembles an outbound
 * HTTP request with the credential placed in a structured field.
 */
export const httpActionSchema = z.object({
  type: z.literal(ActionType.HTTP),
  method: httpMethodSchema,
  url: httpishUrlSchema,
  headers: httpHeadersSchema.optional(),
  body: z.string().optional(),
  injection: injectionConfigSchema,
  follow_redirects: followRedirectsSchema.optional(),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
  response_mode: responseModeSchema.optional(),
});

export type HttpAction = z.infer<typeof httpActionSchema>;

/**
 * Process action — process-mediated injection. The vault spawns a subprocess
 * with the credential placed in its environment under `env_var`. The command
 * and args are passed as data; no shell interpretation is performed.
 */
export const processActionSchema = z.object({
  type: z.literal(ActionType.PROCESS),
  command: z.string().min(1).max(4096),
  args: z.array(z.string().max(4096)).max(MAX_PROCESS_ARGS).optional(),
  working_directory: z.string().min(1).max(4096).optional(),
  env_var: z
    .string()
    .min(1)
    .regex(/^[A-Za-z_][A-Za-z0-9_]*$/, "Invalid environment variable name"),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
});

export type ProcessAction = z.infer<typeof processActionSchema>;

/**
 * MCP action — the vault acts as a transparent MCP proxy, forwarding a single
 * tool call to the downstream MCP server named by `server`. The transport and
 * launch/endpoint configuration come from the secret's McpServerConfig (trusted
 * admin path), never from the action.
 */
export const mcpActionSchema = z.object({
  type: z.literal(ActionType.MCP),
  server: z
    .string()
    .regex(/^[a-zA-Z0-9_-]+$/, "Invalid server name format")
    .max(MAX_NAME_LENGTH),
  tool: z.string().min(1).max(MAX_NAME_LENGTH),
  arguments: z.record(z.unknown()).optional(),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
});

export type McpAction = z.infer<typeof mcpActionSchema>;

const databaseEngineValues = Object.values(DatabaseEngine) as [DatabaseEngine, ...DatabaseEngine[]];
export const databaseEngineSchema = z.enum(databaseEngineValues);

const gitOperationValues = Object.values(GitOperation) as [GitOperation, ...GitOperation[]];
export const gitOperationSchema = z.enum(gitOperationValues);

/** Host or host:port (no scheme). IPv6 literals are out of scope — use a hostname. */
const hostPattern = z
  .string()
  .min(1)
  .max(2048)
  .regex(/^[a-zA-Z0-9._-]+(:\d{1,5})?$/, "Invalid host format")
  .refine(
    (value) => {
      const colon = value.lastIndexOf(":");
      if (colon < 0) return true;
      const port = parseInt(value.slice(colon + 1), 10);
      return port >= 1 && port <= 65_535;
    },
    { message: "Port must be between 1 and 65535" },
  );

const SQL_DATABASE_ENGINES: readonly DatabaseEngine[] = [
  DatabaseEngine.POSTGRESQL,
  DatabaseEngine.MYSQL,
];

/**
 * Database action shape — request-mediated injection. The vault assembles the
 * connection string in-process (the credential is the secret, `user:password`),
 * connects with TLS by default, executes the query/command and returns the
 * result set. `host` may embed a port (`host:port`); an explicit `port`
 * overrides it.
 *
 * Bare (no cross-field refinement) so it can sit as a `z.discriminatedUnion`
 * member in `useSecretActionSchema` — a `superRefine`-wrapped `ZodEffects`
 * has no `.shape` and `discriminatedUnion` throws at construction time. The
 * engine/query/command cross-field matrix lives in `refineDatabaseAction`
 * below, applied both to the standalone export (`databaseActionSchema`) and,
 * via the same function reference, to the outer union's `superRefine`.
 */
const bareDatabaseActionSchema = z.object({
  type: z.literal(ActionType.DATABASE),
  engine: databaseEngineSchema,
  host: hostPattern,
  port: z.number().int().positive().max(65_535).optional(),
  database: z
    .string()
    .min(1)
    .max(255)
    .regex(/^[a-zA-Z0-9_.$-]+$/, "Invalid database name"),
  query: z.string().min(1).max(1_000_000).optional(),
  params: z.array(z.unknown()).max(1_000).optional(),
  command: z
    .union([z.array(z.string().max(65_536)).min(1).max(1_000), z.record(z.unknown())])
    .optional(),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
});

type BareDatabaseAction = z.infer<typeof bareDatabaseActionSchema>;

/**
 * `engine` selects one of two disjoint dispatch shapes (schema-level, like
 * the cert `--bits`/`--curve` pairing rule): `postgresql`/`mysql` require
 * `query` (+ optional `params`) and refuse `command`; `redis` requires
 * `command` as a string array (the command name plus its arguments — never
 * inline protocol text) and refuses `query`/`params`; `mongodb` requires
 * `command` as a document (runCommand-style) and refuses `query`/`params`.
 * `query` is schema-optional so the object shape stays a single type across
 * all four engines, but every existing `{engine: "postgresql"|"mysql",
 * query, params}` caller remains valid — the refinement requires exactly
 * what was always required for those two engines.
 */
function refineDatabaseAction(data: BareDatabaseAction, ctx: z.RefinementCtx): void {
  if (SQL_DATABASE_ENGINES.includes(data.engine)) {
    if (!data.query) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "query is required for this engine",
        path: ["query"],
      });
    }
    if (data.command !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "command is not allowed for this engine",
        path: ["command"],
      });
    }
    return;
  }

  if (data.engine === DatabaseEngine.REDIS) {
    if (!Array.isArray(data.command)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "command must be a string array for redis",
        path: ["command"],
      });
    }
  } else if (data.engine === DatabaseEngine.MONGODB) {
    if (data.command === undefined || Array.isArray(data.command)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "command must be a document for mongodb",
        path: ["command"],
      });
    }
  }

  if (data.query !== undefined) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "query is not allowed for this engine",
      path: ["query"],
    });
  }
  if (data.params !== undefined) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "params is not allowed for this engine",
      path: ["params"],
    });
  }
}

export const databaseActionSchema = bareDatabaseActionSchema.superRefine(refineDatabaseAction);

export type DatabaseAction = z.infer<typeof databaseActionSchema>;

/**
 * Git action — request-mediated over HTTPS (credential helper) or process-mediated
 * over SSH (ephemeral ssh-agent), selected by the `repository` transport. The
 * credential never appears in the command output or the agent's context.
 */
export const gitActionSchema = z.object({
  type: z.literal(ActionType.GIT),
  operation: gitOperationSchema,
  repository: z.string().min(1).max(2048),
  args: z.array(z.string().max(4096)).max(MAX_PROCESS_ARGS).optional(),
  working_directory: z.string().min(1).max(4096).optional(),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
});

export type GitAction = z.infer<typeof gitActionSchema>;

/** Host charset shared by the SSH and SFTP process-mediated contexts. */
const sshHostSchema = z
  .string()
  .min(1)
  .max(255)
  .regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/, "Invalid host format");

/** User charset shared by the SSH and SFTP process-mediated contexts. */
const sshUserSchema = z
  .string()
  .min(1)
  .max(255)
  .regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/, "Invalid user format");

/**
 * SSH action — process-mediated injection. The vault spawns `ssh` with the
 * private key served through an ephemeral ssh-agent (signatures only, key never
 * on disk) and strict host-key verification against the pinned known_hosts.
 */
export const sshActionSchema = z.object({
  type: z.literal(ActionType.SSH),
  host: sshHostSchema,
  user: sshUserSchema,
  command: z.string().min(1).max(65_536),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
});

export type SshAction = z.infer<typeof sshActionSchema>;

// ---------------------------------------------------------------------------
// v1.3 extended-context action schemas (thesis-aligned; design-v1.3-contexts §4)
// ---------------------------------------------------------------------------

const emailAddressSchema = z.string().email().max(320);

const SMTP_ENVELOPE_HEADER_NAMES = new Set([
  "from",
  "to",
  "cc",
  "bcc",
  "subject",
  "content-type",
  "mime-version",
  "date",
  "message-id",
]);

/**
 * Caller-supplied SMTP headers: deny-listed against the envelope and
 * structural headers the vault assembles itself, so the audited envelope
 * (from/to/subject) and the wire headers can never diverge. Matched
 * case-insensitively — header names are case-insensitive per RFC 5322.
 */
const smtpHeadersSchema = z
  .record(z.string().min(1).max(256), z.string().max(8192))
  .refine(
    (headers) =>
      Object.keys(headers).every((k) => !SMTP_ENVELOPE_HEADER_NAMES.has(k.toLowerCase())),
    { message: "Header shadows an envelope or structural field" },
  );

/**
 * True if `value` contains any C0 control character (including CR/LF/NUL) —
 * a path-traversal / batch-injection defense at the schema boundary. Written
 * as a char-code scan rather than a `[\x00-\x1f]` regex class, which ESLint's
 * `no-control-regex` flags.
 */
function hasControlCharacters(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) <= 0x1f) return true;
  }
  return false;
}

/** Absolute path (POSIX or Windows drive-letter), no control characters or newlines. */
const attachmentPathSchema = z
  .string()
  .min(1)
  .max(4096)
  .refine((p) => !hasControlCharacters(p), {
    message: "Path must not contain control characters",
  })
  .refine((p) => /^(\/|[a-zA-Z]:[\\/])/.test(p), {
    message: "Attachment path must be absolute",
  });

/** One SMTP attachment: an absolute file path plus optional wire metadata. */
export const smtpAttachmentSchema = z.object({
  path: attachmentPathSchema,
  filename: z.string().min(1).max(255).optional(),
  content_type: z.string().min(1).max(255).optional(),
});

/**
 * SMTP action shape — request-mediated injection. The vault dials the mail
 * server, authenticates (secret value `username:password`; an OAuth-type
 * handle switches to XOAUTH2) and assembles + sends the message; the client
 * never authors MIME. `port` defaults per `security` (465 for `tls`, 587 for
 * `starttls`) at the connection layer, not in this schema. Attachment byte
 * caps (`MAX_ATTACHMENT_BYTES`/`MAX_ATTACHMENT_TOTAL_BYTES`) are enforced in
 * core — the schema cannot see file sizes before reading them.
 *
 * Bare (no cross-field refinement) for the same `discriminatedUnion`-member
 * reason `bareDatabaseActionSchema` documents above; the at-least-one-of
 * text/html and total-recipient-count rules live in `refineSmtpAction`.
 */
const bareSmtpActionSchema = z.object({
  type: z.literal(ActionType.SMTP),
  host: hostPattern,
  port: z.number().int().positive().max(65_535).optional(),
  security: z.enum(["tls", "starttls"]).optional().default("tls"),
  from: emailAddressSchema,
  to: z.array(emailAddressSchema).min(1).max(MAX_SMTP_RECIPIENTS),
  cc: z.array(emailAddressSchema).max(MAX_SMTP_RECIPIENTS).optional(),
  bcc: z.array(emailAddressSchema).max(MAX_SMTP_RECIPIENTS).optional(),
  subject: z.string().min(1).max(998),
  text: z.string().optional(),
  html: z.string().optional(),
  headers: smtpHeadersSchema.optional(),
  attachments: z.array(smtpAttachmentSchema).max(MAX_SMTP_ATTACHMENTS).optional(),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
});

type BareSmtpAction = z.infer<typeof bareSmtpActionSchema>;

/** At least one of `text`/`html` is required; `to`+`cc`+`bcc` together stay within the recipient cap. */
function refineSmtpAction(data: BareSmtpAction, ctx: z.RefinementCtx): void {
  if (!data.text && !data.html) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "at least one of text or html is required",
      path: ["text"],
    });
  }
  const recipientCount = data.to.length + (data.cc?.length ?? 0) + (data.bcc?.length ?? 0);
  if (recipientCount > MAX_SMTP_RECIPIENTS) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: `At most ${MAX_SMTP_RECIPIENTS} recipients (to + cc + bcc) are allowed`,
      path: ["to"],
    });
  }
}

export const smtpActionSchema = bareSmtpActionSchema.superRefine(refineSmtpAction);

export type SmtpAction = z.infer<typeof smtpActionSchema>;

/** Closed IMAP flag vocabulary — matches the client-authored subset only. */
export const imapFlagSchema = z.enum(["\\Seen", "\\Flagged", "\\Answered", "\\Deleted"]);

const imapUidsSchema = z.array(z.number().int().positive()).min(1).max(MAX_IMAP_FETCH_UIDS);

const imapMailboxSchema = z.string().min(1).max(255);

/**
 * Inner IMAP operation union — the client authors structured criteria only;
 * a raw IMAP query string is never accepted (command/args-are-data
 * convention, mirrors the process/git/ssh contexts).
 */
const imapOperationSchema = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("search"),
    unseen: z.boolean().optional(),
    since: z.string().date().optional(),
    from: z.string().min(1).max(320).optional(),
    subject: z.string().min(1).max(998).optional(),
    text: z.string().min(1).max(1024).optional(),
  }),
  z.object({
    kind: z.literal("fetch"),
    uids: imapUidsSchema,
    parts: z.enum(["envelope", "headers", "text", "full"]),
  }),
  z.object({
    kind: z.literal("store"),
    uids: imapUidsSchema,
    add_flags: z.array(imapFlagSchema).optional(),
    remove_flags: z.array(imapFlagSchema).optional(),
  }),
  z.object({
    kind: z.literal("move"),
    uids: imapUidsSchema,
    target_mailbox: imapMailboxSchema,
  }),
  z.object({
    kind: z.literal("copy"),
    uids: imapUidsSchema,
    target_mailbox: imapMailboxSchema,
  }),
  z.object({
    kind: z.literal("expunge"),
  }),
]);

/**
 * IMAP action — request-mediated injection, implicit TLS only. Same
 * auth ladder as SMTP (PLAIN/LOGIN; XOAUTH2 for OAuth-type handles).
 * `imap_read_only` (policy field) refuses the mutating operation kinds
 * before this schema is even consulted by the injector.
 */
export const imapActionSchema = z.object({
  type: z.literal(ActionType.IMAP),
  host: hostPattern,
  port: z.number().int().positive().max(65_535).optional().default(DEFAULT_IMAP_PORT),
  mailbox: imapMailboxSchema.optional().default("INBOX"),
  // XOAUTH2 identity: the mailbox account the access token is bound to.
  // Required by the engine for an OAuth-type secret (SMTP reads the same
  // identity off `from`; IMAP has no envelope, so it is its own field) and
  // refused for the username:password arm, whose username lives in the value.
  account: emailAddressSchema.optional(),
  operation: imapOperationSchema,
  timeout_ms: z.number().int().positive().max(300_000).optional(),
});

export type ImapAction = z.infer<typeof imapActionSchema>;

const websocketCollectSchema = z.object({
  max_messages: z.number().int().positive().max(MAX_WS_COLLECT_MESSAGES).optional().default(1),
  window_ms: z
    .number()
    .int()
    .positive()
    .max(MAX_WS_COLLECT_WINDOW_MS)
    .optional()
    .default(DEFAULT_WS_COLLECT_WINDOW_MS),
});

/** Mirrors the loopback set the OAuth endpoint schema and core's `validateUrl` use. */
const WS_LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * WebSocket URL: `wss://` anywhere, or `ws://` for loopback only — mirrors
 * core's `validateUrl` SSRF policy (same shape as `oauthEndpointUrlSchema`).
 */
const websocketUrlSchema = z
  .string()
  .url()
  .refine((value) => {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      return false;
    }
    return (
      url.protocol === "wss:" || (url.protocol === "ws:" && WS_LOOPBACK_HOSTS.has(url.hostname))
    );
  }, "WebSocket URL must use wss: (plain ws: is allowed for loopback only)");

/**
 * WebSocket action — request-mediated injection. The credential is applied
 * at the upgrade handshake via the same `injectionConfigSchema` HTTP reuses
 * (bearer/header/query/basic_auth). `message` absent = connect-and-listen
 * only; `collect` bounds how many frames are gathered before the vault
 * closes the connection and returns them.
 */
export const websocketActionSchema = z.object({
  type: z.literal(ActionType.WEBSOCKET),
  url: websocketUrlSchema,
  injection: injectionConfigSchema,
  message: z.string().max(1_048_576).optional(),
  subprotocols: z.array(z.string().min(1).max(255)).max(16).optional(),
  collect: websocketCollectSchema.optional(),
  response_mode: responseModeSchema.optional(),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
});

export type WebsocketAction = z.infer<typeof websocketActionSchema>;

/** Remote/local path: control characters and newlines refused at the boundary. */
const sftpPathSchema = z
  .string()
  .min(1)
  .max(4096)
  .refine((p) => !hasControlCharacters(p), {
    message: "Path must not contain control characters",
  });

/**
 * SFTP action shape — process-mediated injection over the same ephemeral
 * ssh-agent as the SSH context (`sshHostSchema`/`sshUserSchema`, declared
 * above with `sshActionSchema`). Bare (no cross-field refinement) for the
 * same `discriminatedUnion`-member reason `bareDatabaseActionSchema`
 * documents above; the `local_path` requirement lives in `refineSftpAction`.
 */
const bareSftpActionSchema = z.object({
  type: z.literal(ActionType.SFTP),
  host: sshHostSchema,
  user: sshUserSchema,
  operation: z.enum(["upload", "download", "list"]),
  remote_path: sftpPathSchema,
  local_path: sftpPathSchema.optional(),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
});

type BareSftpAction = z.infer<typeof bareSftpActionSchema>;

/**
 * `local_path` is required for `upload`/`download` (the vault-local file
 * side of the transfer) and refused for `list` (nothing local to name).
 */
function refineSftpAction(data: BareSftpAction, ctx: z.RefinementCtx): void {
  if ((data.operation === "upload" || data.operation === "download") && !data.local_path) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "local_path is required for upload/download",
      path: ["local_path"],
    });
  }
  if (data.operation === "list" && data.local_path !== undefined) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "local_path is not allowed for list",
      path: ["local_path"],
    });
  }
}

export const sftpActionSchema = bareSftpActionSchema.superRefine(refineSftpAction);

export type SftpAction = z.infer<typeof sftpActionSchema>;

/**
 * Docker image reference: `[registry-host[:port]/]repo[:tag][@digest]`. The
 * registry component (when present) is the allowlist subject.
 */
const DOCKER_IMAGE_REGEX =
  /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?(?::\d{1,5})?\/)?[a-zA-Z0-9._-]+(?:\/[a-zA-Z0-9._-]+)*(?::[a-zA-Z0-9._-]+)?(?:@sha256:[a-f0-9]{64})?$/;

const dockerImageSchema = z
  .string()
  .min(1)
  .max(512)
  .regex(DOCKER_IMAGE_REGEX, "Invalid image reference");

/**
 * Docker registry action — process-mediated injection: the vault spawns the
 * `docker` CLI. `timeout_ms`'s cap is raised for this context only (image
 * transfers routinely exceed the 5-minute norm). `network_isolation`/
 * `fs_isolation` on the secret refuse this context outright (before any
 * spawn) — the daemon, not the spawned CLI, performs the actual registry
 * I/O, so wrapping the CLI would isolate the messenger, not the actor.
 */
export const dockerRegistryActionSchema = z.object({
  type: z.literal(ActionType.DOCKER_REGISTRY),
  operation: z.enum(["pull", "push"]),
  image: dockerImageSchema,
  timeout_ms: z.number().int().positive().max(MAX_DOCKER_TIMEOUT_MS).optional().default(300_000),
});

export type DockerRegistryAction = z.infer<typeof dockerRegistryActionSchema>;

/**
 * Discriminated union over the execution context. Members are the BARE
 * `z.object(...)` schemas (`discriminatedUnion` requires `.shape` on every
 * member — a `superRefine`-wrapped `ZodEffects` member throws at
 * schema-construction time); the three members with a cross-field rule
 * (database/smtp/sftp) get it applied here, in one outer `.superRefine`
 * dispatching by `type`, calling the exact same refine function their
 * standalone exports use — defined once, enforced both ways.
 *
 * `discriminatedUnion` (not a plain `z.union`) matters beyond dispatch speed:
 * it keeps field-level errors (a missing/invalid required field on any
 * variant) at the top level of `error.issues`. REST
 * (`routes/secrets.ts`) and CLI (`commands/secret/use.ts`) both read
 * `error.issues` directly, never `error.unionErrors` — under a plain
 * `z.union` those field errors get buried per-branch and both surfaces fall
 * back to a bare "Invalid input" instead of naming the field.
 */
export const useSecretActionSchema = z
  .discriminatedUnion("type", [
    httpActionSchema,
    processActionSchema,
    mcpActionSchema,
    bareDatabaseActionSchema,
    gitActionSchema,
    sshActionSchema,
    bareSmtpActionSchema,
    imapActionSchema,
    websocketActionSchema,
    bareSftpActionSchema,
    dockerRegistryActionSchema,
  ])
  .superRefine((data, ctx) => {
    switch (data.type) {
      case "smtp":
        return refineSmtpAction(data, ctx);
      case "database":
        return refineDatabaseAction(data, ctx);
      case "sftp":
        return refineSftpAction(data, ctx);
    }
  });

/** Discriminated union of context-specific use_secret action specifications. */
export type UseSecretAction = z.infer<typeof useSecretActionSchema>;

export const useSecretRequestSchema = z.object({
  handle: handleSchema,
  action: useSecretActionSchema,
});

/** Request to use a secret via a context-specific action. */
export type UseSecretRequest = z.infer<typeof useSecretRequestSchema>;

/** Per-secret injection policy input (URL + host + command + env allowlists + HTTP response mode). */
export const injectionPolicyInputSchema = z.object({
  url_allowlist: z.array(z.string().min(1).max(2048)).max(100).optional().default([]),
  command_allowlist: z.array(z.string().min(1).max(4096)).max(100).optional().default([]),
  env_allowlist: z
    .array(z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/, "Invalid environment variable name"))
    .max(100)
    .optional()
    .default([]),
  host_allowlist: z.array(z.string().min(1).max(2048)).max(100).optional().default([]),
  response_mode: responseModeSchema.optional().default(ResponseMode.FILTERED),
  response_header_allowlist: z
    .array(
      z
        .string()
        .min(1)
        .max(256)
        .regex(/^[a-zA-Z0-9\-_]+$/, "Invalid header name characters"),
    )
    .max(100)
    .optional()
    .default([]),
  network_isolation: z.boolean().optional().default(false),
  fs_isolation: z.boolean().optional().default(false),
  smtp_recipient_allowlist: z.array(recipientPatternSchema).max(100).optional().default([]),
  imap_read_only: z.boolean().optional().default(false),
});

/**
 * Per-secret injection policy: allowlists constraining where a credential may
 * be used (thesis §4.7 target allowlisting). `url_allowlist` bounds URL targets
 * (HTTP, Git-over-HTTPS, MCP-over-HTTP); `host_allowlist` bounds host and
 * host:port targets (SSH, Git-over-SSH, database); `command_allowlist` bounds
 * process-mediated binaries; `env_allowlist` names additional environment
 * variables passed through to a spawned subprocess. `response_mode` is the
 * HTTP response shaping floor (default `filtered`; per-invocation overrides
 * may only tighten it, thesis §4.5.2); `response_header_allowlist` names the
 * headers still returned under `status_only`. `network_isolation` (thesis
 * §4.5.3 layer 4, default `false`) demands that every child process spawned
 * with this secret runs without network access — fail-closed: platforms that
 * cannot deliver it refuse the use. `fs_isolation` (default `false`) demands
 * write-deny filesystem isolation for every process-mediated child: Linux via
 * setpriv with Landlock support, macOS via sandbox-exec, Windows refused
 * fail-closed (unsupported by design); writes to `/dev/null` are exempt.
 * `smtp_recipient_allowlist` (v1.3, default `[]`) bounds SMTP recipients
 * (exact addresses or `*@domain` patterns, design §5.2): absent, any
 * recipient is allowed for a body-only send; configured, every recipient
 * (to/cc/bcc) must match, and an attachment-bearing send additionally
 * refuses outright unless the list is configured — that coupling rule is
 * enforced by the SMTP injector, not this schema. `imap_read_only` (v1.3,
 * default `false`) is a tighten-only knob (same shape as `response_mode`):
 * set, it refuses the mutating IMAP operation kinds (`store`/`move`/`copy`/
 * `expunge`) before any socket opens. The schema's output type: all defaults
 * applied, every field present — the shape the vault loads and returns.
 */
export type InjectionPolicy = z.output<typeof injectionPolicyInputSchema>;

/**
 * The policy as callers may supply it: every field optional; the vault (or
 * the schema's defaults) fills in empty allowlists and `filtered` mode.
 */
export type InjectionPolicyInput = z.input<typeof injectionPolicyInputSchema>;

/**
 * PUT injection-policy request body: the policy plus the per-operation
 * interpreter acknowledgement flag (thesis §4.5.3). The flag is a request
 * field, never stored on the policy.
 */
export const setInjectionPolicyRequestSchema = injectionPolicyInputSchema.extend({
  acknowledge_interpreters: z.boolean().optional().default(false),
});

/**
 * Database endpoint-authentication config. TLS is required by default; `disable`
 * is the audited per-secret opt-out for trusted local sockets (thesis §4.5.5).
 */
export const databaseConnectionConfigSchema = z.object({
  tls_mode: z.enum(["require", "disable"]).optional(),
  ca_pem: z.string().min(1).max(65_536).optional(),
  servername: z
    .string()
    .min(1)
    .max(255)
    .regex(/^[a-zA-Z0-9._-]+$/, "Invalid servername")
    .optional(),
});

export type DatabaseConnectionConfig = z.infer<typeof databaseConnectionConfigSchema>;

/** SSH endpoint-authentication config: host keys pinned at secret creation. */
export const sshConnectionConfigSchema = z.object({
  known_hosts: z.array(z.string().min(1).max(4096)).min(1).max(50),
});

export type SshConnectionConfig = z.infer<typeof sshConnectionConfigSchema>;

/**
 * Mail (SMTP/IMAP) endpoint-authentication config — the database group's TLS
 * policy in the mail contexts' idiom (design §5.5), shaped 1:1 onto core's
 * `MailTlsConfig`. `tls` absent means TLS against the default system CAs;
 * `{ ca }` pins a private CA bundle; `false` is the audited plaintext opt-out
 * — honored by **SMTP only** (`tls_opt_out: true` lands in the `secret.use`
 * row). IMAP is implicit-TLS-only (design §4.2), so an `imap` action on a
 * secret carrying `tls: false` refuses at use time rather than silently
 * ignoring an opt-out the admin believes is in force.
 */
export const mailConnectionConfigSchema = z.object({
  tls: z
    .union([z.literal(false), z.object({ ca: z.string().min(1).max(65_536).optional() })])
    .optional(),
});

export type MailConnectionConfig = z.infer<typeof mailConnectionConfigSchema>;

/**
 * Per-secret endpoint-authentication pins (KEK-encrypted at rest), the §4.7
 * "authenticated target connections" counterpart to the target allowlist. Set
 * only via the trusted admin path (CLI/REST) — never via an MCP tool. `ssh` is
 * shared by the SSH and Git-over-SSH contexts, `mail` by the SMTP and IMAP
 * contexts (v1.3). At least one of `database` / `ssh` / `mail` must be present.
 */
export const connectionConfigSchema = z
  .object({
    database: databaseConnectionConfigSchema.optional(),
    ssh: sshConnectionConfigSchema.optional(),
    mail: mailConnectionConfigSchema.optional(),
  })
  .superRefine((data, ctx) => {
    if (!data.database && !data.ssh && !data.mail) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "connection config must set at least one of database, ssh or mail",
        path: [],
      });
    }
  });

export type ConnectionConfig = z.infer<typeof connectionConfigSchema>;

const mcpTransportValues = Object.values(McpTransport) as [McpTransport, ...McpTransport[]];
export const mcpTransportSchema = z.enum(mcpTransportValues);

/**
 * Per-secret downstream MCP server configuration (trusted admin path only).
 * stdio requires `command` + `env_var`; http requires `url`.
 */
export const mcpServerConfigSchema = z
  .object({
    server_name: z
      .string()
      .regex(/^[a-zA-Z0-9_-]+$/, "Invalid server name format")
      .max(MAX_NAME_LENGTH),
    transport: mcpTransportSchema,
    command: z.string().min(1).max(4096).optional(),
    args: z.array(z.string().max(4096)).max(MAX_PROCESS_ARGS).optional(),
    env_var: z
      .string()
      .regex(/^[A-Za-z_][A-Za-z0-9_]*$/, "Invalid environment variable name")
      .optional(),
    working_directory: z.string().min(1).max(4096).optional(),
    url: httpishUrlSchema.optional(),
  })
  .superRefine((data, ctx) => {
    if (data.transport === McpTransport.STDIO) {
      if (!data.command) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "command is required for stdio transport",
          path: ["command"],
        });
      }
      if (!data.env_var) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "env_var is required for stdio transport",
          path: ["env_var"],
        });
      }
    }
    if (data.transport === McpTransport.HTTP && !data.url) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "url is required for http transport",
        path: ["url"],
      });
    }
  });

/**
 * Per-secret downstream MCP server configuration (KEK-encrypted at rest).
 * Set only via the trusted admin path (CLI/REST) — never via an MCP tool.
 * stdio: `command` + `env_var` required; the launch command is validated
 * against the secret's command allowlist (fail-safe deny) at every use.
 * http: `url` required; validated against the URL allowlist and SSRF checks.
 */
export type McpServerConfig = z.infer<typeof mcpServerConfigSchema>;

export const accessPolicyInputSchema = z.object({
  principal_type: principalTypeSchema,
  principal_id: z.string().min(1),
  permissions: z.array(permissionSchema).min(1),
  expires_at: z.number().int().positive().optional(),
});

/** Access-policy grant request body (principal + permissions). */
export type AccessPolicyInput = z.infer<typeof accessPolicyInputSchema>;

export const auditQuerySchema = z.object({
  secret_id: z.string().uuid().optional(),
  event_type: auditEventTypeSchema.optional(),
  since: z.number().int().nonnegative().optional(),
  until: z.number().int().nonnegative().optional(),
  success: z.boolean().optional(),
  limit: z.number().int().positive().max(1000).optional(),
});

export const healthResponseSchema = z.object({
  state: vaultStateSchema,
  version: z.string().min(1),
});

/** GET /health response (also the SDK VaultClient.getHealth result). */
export type HealthResponse = z.infer<typeof healthResponseSchema>;

// ---------------------------------------------------------------------------
// Session file schema (for deserializing session.json)
// ---------------------------------------------------------------------------

const base64Pattern = z.string().min(1).base64();

/** How the session file's `session_key` is protected at rest (thesis §4.6 off-host hardening). */
export const sessionKeyProtectionSchemeSchema = z.enum([
  "none",
  "dpapi",
  "keychain",
  "secret-service",
  "keyring",
]);

export type SessionKeyProtectionScheme = z.infer<typeof sessionKeyProtectionSchemeSchema>;

export const sessionFileSchema = z.object({
  version: z.literal(1),
  session_id: z.string().min(1),
  vault_id: z.string().min(1),
  created_at: z.number().int().positive(),
  expires_at: z.number().int().positive(),
  max_expires_at: z.number().int().positive(),
  /** Scheme wrapping `session_key`; absent means "none" (files written before this field existed). */
  key_protection: sessionKeyProtectionSchemeSchema.optional(),
  session_key: base64Pattern,
  wrapped_kek: base64Pattern,
  wrapped_kek_iv: base64Pattern,
  wrapped_kek_tag: base64Pattern,
  wrapped_jwt_key: base64Pattern,
  wrapped_jwt_key_iv: base64Pattern,
  wrapped_jwt_key_tag: base64Pattern,
  wrapped_audit_key: base64Pattern,
  wrapped_audit_key_iv: base64Pattern,
  wrapped_audit_key_tag: base64Pattern,
});

/** Session file persisted at ~/.harpoc/session.json (all binary values base64-encoded). */
export type SessionFile = z.infer<typeof sessionFileSchema>;

// ---------------------------------------------------------------------------
// Audit-chain anchor
// ---------------------------------------------------------------------------

export const AUDIT_CHAIN_ANCHOR_FORMAT = "harpoc-audit-anchor/1";

/**
 * Exportable audit-chain tail link. Comparing a stored anchor against the
 * live chain detects tail truncation and database rollback — attacks the
 * chain HMACs alone cannot see, since a shorter chain is still valid.
 * The anchor holds no sensitive material (`row_hmac` is stored in plaintext
 * in the database); its value comes entirely from being stored OFF-HOST.
 */
export const auditChainAnchorSchema = z
  .object({
    format: z.literal(AUDIT_CHAIN_ANCHOR_FORMAT),
    vault_id: z.string().min(1),
    last_id: z.number().int().positive(),
    /** Informational — the row's chain HMAC already covers its timestamp; verification compares only `row_hmac`. */
    timestamp: z.number().int().positive(),
    row_hmac: z.string().regex(/^[0-9a-f]{64}$/, "must be 64 lowercase hex characters"),
  })
  .strict();

export type AuditChainAnchor = z.infer<typeof auditChainAnchorSchema>;

// ---------------------------------------------------------------------------
// OAuth schemas (v1.1)
// ---------------------------------------------------------------------------

const oauthGrantTypeValues = Object.values(OAuthGrantType) as [OAuthGrantType, ...OAuthGrantType[]];
export const oauthGrantTypeSchema = z.enum(oauthGrantTypeValues);

const oauthProviderPresetValues = Object.values(OAuthProviderPreset) as [
  OAuthProviderPreset,
  ...OAuthProviderPreset[],
];
export const oauthProviderPresetSchema = z.enum(oauthProviderPresetValues);

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

// Mirrors core's validateUrl SSRF policy: HTTPS anywhere, plain HTTP for loopback only.
const oauthEndpointUrlSchema = z
  .string()
  .url()
  .refine((value) => {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      return false;
    }
    return (
      url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname))
    );
  }, "URL must use HTTPS (plain HTTP is allowed for loopback only)");

export const oauthProviderConfigSchema = z
  .object({
    provider: oauthProviderPresetSchema,
    grant_type: oauthGrantTypeSchema,
    token_endpoint: oauthEndpointUrlSchema,
    auth_endpoint: oauthEndpointUrlSchema.optional(),
    device_authorization_endpoint: oauthEndpointUrlSchema.optional(),
    client_id: z.string().min(1),
    client_secret: z.string().min(1).optional(),
    token_endpoint_auth_method: z.enum(["client_secret_post", "client_secret_basic"]).optional(),
    scopes: z.array(z.string().min(1)).optional(),
    redirect_uri: z.string().url().optional(),
    pkce_method: z.literal("S256").optional(),
  })
  .superRefine((data, ctx) => {
    if (data.grant_type === OAuthGrantType.AUTHORIZATION_CODE && !data.auth_endpoint) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "auth_endpoint is required for authorization_code grant type",
        path: ["auth_endpoint"],
      });
    }
    if (data.grant_type === OAuthGrantType.DEVICE_CODE && !data.device_authorization_endpoint) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "device_authorization_endpoint is required for device_code grant type",
        path: ["device_authorization_endpoint"],
      });
    }
  });

/** OAuth provider configuration (stored alongside secret). */
export type OAuthProviderConfig = z.infer<typeof oauthProviderConfigSchema>;

export const startOAuthFlowInputSchema = z.object({
  name: namePattern,
  provider: oauthProviderPresetSchema,
  grant_type: oauthGrantTypeSchema,
  client_id: z.string().min(1),
  client_secret: z.string().min(1).optional(),
  token_endpoint_auth_method: z.enum(["client_secret_post", "client_secret_basic"]).optional(),
  scopes: z.array(z.string().min(1)).optional(),
  project: namePattern.optional(),
  auth_endpoint: oauthEndpointUrlSchema.optional(),
  token_endpoint: oauthEndpointUrlSchema.optional(),
  device_authorization_endpoint: oauthEndpointUrlSchema.optional(),
});

export type StartOAuthFlowInput = z.infer<typeof startOAuthFlowInputSchema>;

// ---------------------------------------------------------------------------
// Certificate schemas (v1.1)
// ---------------------------------------------------------------------------

const pemPattern = z
  .string()
  .min(1)
  .refine((s) => s.startsWith("-----BEGIN "), "Value must be PEM-encoded");

export const certificateImportSchema = z.object({
  name: namePattern,
  private_key_pem: pemPattern,
  certificate_pem: pemPattern,
  chain_pem: pemPattern.optional(),
  project: namePattern.optional(),
  auto_renew: z.boolean().optional().default(false),
  renew_before_days: z.number().int().positive().max(365).optional().default(30),
});

export type CertificateImportRequest = z.infer<typeof certificateImportSchema>;

/**
 * The *pre-parse* shape: `auto_renew` and `renew_before_days` carry schema
 * defaults, so the parsed type has them required while a caller may legitimately
 * omit them. Client-facing input types take this one; anything reading a parsed
 * request takes `CertificateImportRequest`.
 */
export type CertificateImportRequestInput = z.input<typeof certificateImportSchema>;

export const generateCsrRequestSchema = z
  .object({
    name: namePattern,
    subject: z.string().min(1),
    sans: z.array(z.string().min(1)).optional(),
    algorithm: z.enum(["rsa", "ec"]).optional(),
    bits: z.union([z.literal(2048), z.literal(4096)]).optional(),
    curve: z.enum(["P-256", "P-384"]).optional(),
    project: namePattern.optional(),
  })
  .superRefine((data, ctx) => {
    const algorithm = data.algorithm ?? "ec"; // the CLI's default: EC P-256
    if (data.bits !== undefined && algorithm !== "rsa") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'bits applies only to algorithm "rsa"',
        path: ["bits"],
      });
    }
    if (data.curve !== undefined && algorithm !== "ec") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'curve applies only to algorithm "ec"',
        path: ["curve"],
      });
    }
  });
export type GenerateCsrRequest = z.infer<typeof generateCsrRequestSchema>;

export const renewCertificateRequestSchema = z.object({
  http_port: z.number().int().min(1).max(65535).optional(),
});
export type RenewCertificateRequest = z.infer<typeof renewCertificateRequestSchema>;
