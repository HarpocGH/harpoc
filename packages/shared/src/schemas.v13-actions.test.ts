import { describe, expect, it } from "vitest";
import { z } from "zod";

import {
  databaseActionSchema,
  dockerRegistryActionSchema,
  gitActionSchema,
  imapActionSchema,
  injectionPolicyInputSchema,
  injectionPolicySchema,
  setInjectionPolicyRequestSchema,
  sftpActionSchema,
  smtpActionSchema,
  useSecretActionSchema,
  websocketActionSchema,
} from "./schemas.js";

// ---------------------------------------------------------------------------
// v1.3 extended-context action schemas
// ---------------------------------------------------------------------------

interface SchemaIssue {
  path: PropertyKey[];
  message: string;
}

/** The issues `schema` reports for `input` as `{ path, message }` pairs; empty when it parses. */
function issuesOf(schema: z.ZodType, input: unknown): SchemaIssue[] {
  const result = schema.safeParse(input);
  return result.success
    ? []
    : result.error.issues.map((issue) => ({ path: issue.path, message: issue.message }));
}

describe("v1.3 action schemas", () => {
  it("accepts a minimal smtp action and applies defaults", () => {
    const a = smtpActionSchema.parse({
      type: "smtp",
      host: "smtp.example.com",
      from: "bot@example.com",
      to: ["ops@example.com"],
      subject: "hi",
      text: "body",
    });
    expect(a.security).toBe("tls");
  });
  it.each([
    ["smtpActionSchema", smtpActionSchema],
    ["useSecretActionSchema", useSecretActionSchema],
  ] as const)("%s refuses an smtp action with neither text nor html", (_name, schema) => {
    const base = { type: "smtp", host: "h", from: "a@b.com", to: ["d@e.com"], subject: "s" };
    expect(issuesOf(schema, { ...base, text: "x" })).toEqual([]);
    expect(issuesOf(schema, { ...base, html: "<p>x</p>" })).toEqual([]);
    expect(issuesOf(schema, base)).toEqual([
      { path: ["text"], message: "at least one of text or html is required" },
    ]);
  });
  it("refuses envelope-shadowing extra headers", () => {
    const base = { type: "smtp", host: "h", from: "a@b.com", to: ["d@e.com"], subject: "s" };
    expect(issuesOf(smtpActionSchema, { ...base, text: "x", headers: { "X-Foo": "v" } })).toEqual(
      [],
    );
    for (const k of [
      "From",
      "to",
      "Subject",
      "content-type",
      "MIME-Version",
      "Date",
      "Message-ID",
      "Cc",
      "bcc",
    ]) {
      expect(issuesOf(smtpActionSchema, { ...base, text: "x", headers: { [k]: "v" } })).toEqual([
        { path: ["headers"], message: "Header shadows an envelope or structural field" },
      ]);
    }
  });
  it("refuses a header name that is not RFC 5322 ftext — whitespace, a colon or a control character", () => {
    for (const k of ["To ", " Bcc", "X\tFoo", "X-Foo:", "X-Foo\r\nBcc", "X Foo"]) {
      expect(() =>
        smtpActionSchema.parse({
          type: "smtp",
          host: "h",
          from: "a@b.com",
          to: ["d@e.com"],
          subject: "s",
          text: "x",
          headers: { [k]: "v" },
        }),
      ).toThrow();
    }
    expect(() =>
      smtpActionSchema.parse({
        type: "smtp",
        host: "h",
        from: "a@b.com",
        to: ["d@e.com"],
        subject: "s",
        text: "x",
        headers: { "X-Foo": "v" },
      }),
    ).not.toThrow();
  });
  it("refuses relative and control-char attachment paths", () => {
    const base = {
      type: "smtp",
      host: "h",
      from: "a@b.com",
      to: ["d@e.com"],
      subject: "s",
      text: "x",
    };
    expect(
      issuesOf(smtpActionSchema, {
        ...base,
        attachments: [{ path: "/srv/file.txt" }, { path: "C:\\srv\\file.txt" }],
      }),
    ).toEqual([]);
    expect(
      issuesOf(smtpActionSchema, { ...base, attachments: [{ path: "rel/file.txt" }] }),
    ).toEqual([{ path: ["attachments", 0, "path"], message: "Attachment path must be absolute" }]);
    expect(issuesOf(smtpActionSchema, { ...base, attachments: [{ path: "C:/x\n.txt" }] })).toEqual([
      { path: ["attachments", 0, "path"], message: "Path must not contain control characters" },
    ]);
  });
  const smtpBase = {
    type: "smtp",
    host: "h",
    from: "a@b.com",
    to: ["d@e.com"],
    subject: "s",
    text: "x",
  };
  const addresses = (n: number, tag: string): string[] =>
    Array.from({ length: n }, (_, i) => `${tag}${i}@e.com`);
  it.each<[string, Record<string, unknown>, PropertyKey[][]]>([
    [
      "accepts 100 recipients across to + cc + bcc",
      { to: addresses(40, "t"), cc: addresses(30, "c"), bcc: addresses(30, "b") },
      [],
    ],
    [
      "refuses 101 recipients across to + cc + bcc",
      { to: addresses(41, "t"), cc: addresses(30, "c"), bcc: addresses(30, "b") },
      [["to"]],
    ],
    ["refuses an empty to", { to: [] }, [["to"]]],
    [
      "accepts 16 attachments",
      { attachments: Array.from({ length: 16 }, () => ({ path: "/srv/f" })) },
      [],
    ],
    [
      "refuses 17 attachments",
      { attachments: Array.from({ length: 17 }, () => ({ path: "/srv/f" })) },
      [["attachments"]],
    ],
    ["accepts a 998-character subject", { subject: "s".repeat(998) }, []],
    ["refuses a 999-character subject", { subject: "s".repeat(999) }, [["subject"]]],
    ["refuses an empty subject", { subject: "" }, [["subject"]]],
    ["accepts security starttls", { security: "starttls" }, []],
    ["refuses security ssl", { security: "ssl" }, [["security"]]],
    ["refuses port 0", { port: 0 }, [["port"]]],
    ["refuses port 65536", { port: 65_536 }, [["port"]]],
    ["accepts an 8192-character header value", { headers: { "X-Foo": "v".repeat(8192) } }, []],
    [
      "refuses an 8193-character header value",
      { headers: { "X-Foo": "v".repeat(8193) } },
      [["headers", "X-Foo"]],
    ],
    [
      "refuses an empty attachment filename",
      { attachments: [{ path: "/srv/f", filename: "" }] },
      [["attachments", 0, "filename"]],
    ],
    [
      "refuses a 256-character attachment filename",
      { attachments: [{ path: "/srv/f", filename: "f".repeat(256) }] },
      [["attachments", 0, "filename"]],
    ],
    [
      "refuses a 256-character attachment content_type",
      { attachments: [{ path: "/srv/f", content_type: "t".repeat(256) }] },
      [["attachments", 0, "content_type"]],
    ],
  ])("smtp caps: %s", (_title, patch, paths) => {
    expect(issuesOf(smtpActionSchema, { ...smtpBase, ...patch }).map((i) => i.path)).toEqual(paths);
  });
  it("smtp caps: the recipient-total refusal names the cap", () => {
    expect(
      issuesOf(smtpActionSchema, {
        ...smtpBase,
        to: addresses(41, "t"),
        cc: addresses(30, "c"),
        bcc: addresses(30, "b"),
      }),
    ).toEqual([{ path: ["to"], message: "At most 100 recipients (to + cc + bcc) are allowed" }]);
  });
  it("imap: mailbox defaults to INBOX", () => {
    expect(
      imapActionSchema.parse({
        type: "imap",
        host: "mail.example.com",
        operation: { kind: "search", unseen: true, since: "2026-08-01" },
      }).mailbox,
    ).toBe("INBOX");
  });
  it("imap: refuses a flag outside the closed enum", () => {
    expect(
      issuesOf(imapActionSchema, {
        type: "imap",
        host: "h",
        operation: { kind: "store", uids: [1], add_flags: ["\\Recent"] },
      }).map((i) => i.path),
    ).toEqual([["operation", "add_flags", 0]]);
  });
  it("imap: refuses more than 100 uids", () => {
    expect(
      issuesOf(imapActionSchema, {
        type: "imap",
        host: "h",
        operation: {
          kind: "fetch",
          uids: Array.from({ length: 101 }, (_, i) => i + 1),
          parts: "headers",
        },
      }).map((i) => i.path),
    ).toEqual([["operation", "uids"]]);
  });
  it("imap: optional account (the XOAUTH2 identity) must be an email address", () => {
    expect(
      imapActionSchema.parse({
        type: "imap",
        host: "mail.example.com",
        operation: { kind: "search", unseen: true },
        account: "agent@example.com",
      }).account,
    ).toBe("agent@example.com");
    expect(
      imapActionSchema.parse({
        type: "imap",
        host: "mail.example.com",
        operation: { kind: "search", unseen: true },
      }),
    ).not.toHaveProperty("account");
    expect(() =>
      imapActionSchema.parse({
        type: "imap",
        host: "mail.example.com",
        operation: { kind: "search", unseen: true },
        account: "not-an-email",
      }),
    ).toThrow();
  });
  it("imap: port defaults to 993", () => {
    expect(
      imapActionSchema.parse({
        type: "imap",
        host: "h",
        operation: { kind: "search", unseen: true },
      }).port,
    ).toBe(993);
  });
  const ws = { type: "websocket", injection: { type: "bearer" } };
  it.each<[string, SchemaIssue[]]>([
    ["ws://127.0.0.1:9/x", []],
    ["ws://localhost:9/x", []],
    ["ws://[::1]:9/x", []],
    [
      "ws://example.com/x",
      [
        {
          path: ["url"],
          message: "WebSocket URL must use wss: (plain ws: is allowed for loopback only)",
        },
      ],
    ],
    [
      "ws://127.0.0.2:9/x",
      [
        {
          path: ["url"],
          message: "WebSocket URL must use wss: (plain ws: is allowed for loopback only)",
        },
      ],
    ],
  ])("websocket: url %s", (url, issues) => {
    expect(issuesOf(websocketActionSchema, { ...ws, url })).toEqual(issues);
  });
  it("websocket: collect.max_messages above 100 is refused", () => {
    expect(
      issuesOf(websocketActionSchema, {
        ...ws,
        url: "wss://a.example/x",
        collect: { max_messages: 101 },
      }).map((i) => i.path),
    ).toEqual([["collect", "max_messages"]]);
  });
  it("websocket: collect defaults to one message over 30 s", () => {
    expect(
      websocketActionSchema.parse({ ...ws, url: "wss://a.example/x", collect: {} }).collect,
    ).toEqual({ max_messages: 1, window_ms: 30_000 });
  });
  it("accepts a non-loopback wss:// URL at the schema boundary", () => {
    expect(
      websocketActionSchema.parse({
        type: "websocket",
        url: "wss://example.com/",
        injection: { type: "bearer" },
      }).url,
    ).toBe("wss://example.com/");
  });
  const sftp = { type: "sftp", host: "h", user: "u", remote_path: "/r" };
  it.each<[string, Record<string, unknown>, SchemaIssue[]]>([
    [
      "sftp: refuses upload without local_path",
      { ...sftp, operation: "upload" },
      [{ path: ["local_path"], message: "local_path is required for upload/download" }],
    ],
    [
      "sftp: refuses download without local_path",
      { ...sftp, operation: "download" },
      [{ path: ["local_path"], message: "local_path is required for upload/download" }],
    ],
    [
      "sftp: refuses list with a local_path",
      { ...sftp, operation: "list", local_path: "/l" },
      [{ path: ["local_path"], message: "local_path is not allowed for list" }],
    ],
    [
      "sftp: refuses a control character in remote_path",
      { ...sftp, operation: "list", remote_path: "/r\nrm x" },
      [{ path: ["remote_path"], message: "Path must not contain control characters" }],
    ],
  ])("%s", (_title, action, issues) => {
    expect(issuesOf(sftpActionSchema, action)).toEqual(issues);
  });
  it("sftp: accepts an optional port in range and refuses 0, 65536 and a string", () => {
    const validSftp = {
      type: "sftp" as const,
      host: "sftp.example.com",
      user: "deploy",
      operation: "list" as const,
      remote_path: "/srv/reports",
    };
    expect(sftpActionSchema.parse({ ...validSftp, port: 2222 }).port).toBe(2222);
    expect(sftpActionSchema.parse(validSftp).port).toBeUndefined();
    for (const port of [0, 65_536, "22", 22.5]) {
      expect(() => sftpActionSchema.parse({ ...validSftp, port })).toThrow();
    }
  });
  it("docker_registry: image reference validated, timeout cap 30 min", () => {
    dockerRegistryActionSchema.parse({
      type: "docker_registry",
      operation: "pull",
      image: "registry.example.com:5000/team/app:1.2",
    });
    expect(() =>
      dockerRegistryActionSchema.parse({
        type: "docker_registry",
        operation: "pull",
        image: "reg/app:1.2",
        timeout_ms: 1_800_001,
      }),
    ).toThrow();
  });
  it("accepts timeout_ms up to 1_800_000 for a docker_registry action", () => {
    const parsed = dockerRegistryActionSchema.safeParse({
      type: "docker_registry",
      operation: "pull",
      image: "registry.example.com/app:1.0",
      timeout_ms: 1_800_000,
    });
    expect(parsed.success).toBe(true);
  });
  it("docker_registry: timeout_ms defaults to 300 000", () => {
    expect(
      dockerRegistryActionSchema.parse({
        type: "docker_registry",
        operation: "pull",
        image: "reg/app:1.2",
      }).timeout_ms,
    ).toBe(300_000);
  });
  const sql = { type: "database", engine: "postgresql", host: "db", database: "d" };
  const redis = { type: "database", engine: "redis", host: "r", database: "0" };
  const mongodb = { type: "database", engine: "mongodb", host: "m", database: "app" };
  const databaseMatrix: Array<[string, Record<string, unknown>, SchemaIssue[]]> = [
    ["accepts postgresql with a query", { ...sql, query: "select 1" }, []],
    [
      "refuses postgresql without a query",
      sql,
      [{ path: ["query"], message: "query is required for this engine" }],
    ],
    [
      "refuses postgresql with a command",
      { ...sql, query: "select 1", command: ["PING"] },
      [{ path: ["command"], message: "command is not allowed for this engine" }],
    ],
    ["accepts redis with a string-array command", { ...redis, command: ["GET", "k"] }, []],
    [
      "refuses redis without a command",
      redis,
      [{ path: ["command"], message: "command must be a string array for redis" }],
    ],
    [
      "refuses redis with a document command",
      { ...redis, command: { get: "k" } },
      [{ path: ["command"], message: "command must be a string array for redis" }],
    ],
    [
      "refuses redis with a query",
      { ...redis, command: ["GET", "k"], query: "GET k" },
      [{ path: ["query"], message: "query is not allowed for this engine" }],
    ],
    [
      "refuses redis with params",
      { ...redis, command: ["GET", "k"], params: ["v"] },
      [{ path: ["params"], message: "params is not allowed for this engine" }],
    ],
    [
      "accepts mongodb with a document command",
      { ...mongodb, command: { find: "users", limit: 1 } },
      [],
    ],
    [
      "refuses mongodb without a command",
      mongodb,
      [{ path: ["command"], message: "command must be a document for mongodb" }],
    ],
    [
      "refuses mongodb with an array command",
      { ...mongodb, command: ["find", "users"] },
      [{ path: ["command"], message: "command must be a document for mongodb" }],
    ],
    [
      "refuses mongodb with params",
      { ...mongodb, command: { find: "users" }, params: [1] },
      [{ path: ["params"], message: "params is not allowed for this engine" }],
    ],
  ];
  describe.each([
    ["databaseActionSchema", databaseActionSchema],
    ["useSecretActionSchema", useSecretActionSchema],
  ] as const)("database per-engine refinement matrix through %s", (_name, schema) => {
    it.each(databaseMatrix)("%s", (_title, action, issues) => {
      expect(issuesOf(schema, action)).toEqual(issues);
    });
  });
  it("redis requires a non-negative integer database index", () => {
    for (const database of ["app", "-1"]) {
      expect(() =>
        databaseActionSchema.parse({
          type: "database",
          engine: "redis",
          host: "r",
          database,
          command: ["PING"],
        }),
      ).toThrow("non-negative integer index");
    }
    databaseActionSchema.parse({
      type: "database",
      engine: "redis",
      host: "r",
      database: "12",
      command: ["PING"],
    });
    databaseActionSchema.parse({
      type: "database",
      engine: "mongodb",
      host: "m",
      database: "admin",
      command: { ping: 1 },
    });
  });
  it("policy input refuses a wildcard-domain recipient and accepts exact and *@domain patterns", () => {
    expect(() => injectionPolicyInputSchema.parse({ smtp_recipient_allowlist: ["*@*"] })).toThrow(); // wildcard domain refused
    injectionPolicyInputSchema.parse({
      smtp_recipient_allowlist: ["ops@example.com", "*@example.com"],
    });
  });
  it("policy input round-trips strict_tree_exit true, refuses a non-boolean, and the wire shape requires it (2026-09-10)", () => {
    expect(injectionPolicyInputSchema.parse({ strict_tree_exit: true }).strict_tree_exit).toBe(
      true,
    );
    expect(injectionPolicyInputSchema.safeParse({ strict_tree_exit: "yes" }).success).toBe(false);
    // The wire shape inherits the field as required: an omitting PUT is told which field it dropped.
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { strict_tree_exit: _omitted, ...tenFields } = injectionPolicySchema.parse({
      ...injectionPolicyInputSchema.parse({}),
    });
    const wire = setInjectionPolicyRequestSchema.safeParse(tenFields);
    expect(wire.success).toBe(false);
    if (!wire.success)
      expect(wire.error.issues.map((i) => i.path.join("."))).toEqual(["strict_tree_exit"]);
  });
});

describe("gitActionSchema", () => {
  const git = { type: "git", operation: "clone", repository: "https://github.com/o/r.git" };
  it.each<[string, Record<string, unknown>, PropertyKey[][]]>([
    ["accepts a minimal clone", {}, []],
    ["refuses operation fetch", { operation: "fetch" }, [["operation"]]],
    ["refuses an empty repository", { repository: "" }, [["repository"]]],
    ["refuses a 2049-character repository", { repository: "r".repeat(2049) }, [["repository"]]],
    ["accepts 256 args", { args: Array.from({ length: 256 }, () => "-v") }, []],
    ["refuses 257 args", { args: Array.from({ length: 257 }, () => "-v") }, [["args"]]],
  ])("%s", (_title, patch, paths) => {
    expect(issuesOf(gitActionSchema, { ...git, ...patch }).map((i) => i.path)).toEqual(paths);
  });
});
