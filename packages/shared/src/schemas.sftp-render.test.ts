import { describe, expect, it } from "vitest";
import type { z } from "zod";

import {
  injectionPolicyInputSchema,
  renderEntryInputSchema,
  renderEntrySchema,
  sftpActionSchema,
  useSecretActionSchema,
} from "./schemas.js";
import type { RenderEntry, SftpAction, SftpRenderAction, UseSecretAction } from "./schemas.js";
import { renderSchemaIssues } from "./schema-issues.js";

// The public key line of core's injection/__fixtures__/ssh-public-keys.ts (ssh-keygen 10.0p2).
const HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICn+7qKS67vacwftKjgcrwUlmC2TZ6j0dyFpyO5UDiVx";

/** An entry and its digest, the one core's `render-entry-digest.test.ts` pins. */
const E1: RenderEntry = {
  name: "env",
  host: "h1.example",
  port: 22,
  user: "deploy",
  path: "/srv/app/.env",
  host_keys: [HOST_KEY],
  template: "TOKEN={{secret://bot-token}}\n",
};
const E1_DIGEST = "7c6a834469ef5a6c2a4b422775e89bf38a601de3f618e3615c684734ca914b66";

const PATH_TEXT =
  "Invalid path: an absolute remote path of at most 4096 bytes without a control or format character, a line or paragraph separator, an empty, '.' or '..' segment or a trailing '/', its last segment at most 200 bytes and not of the render's temporary name form";

const RENDER = { type: "sftp", operation: "render", entry: "env" } as const;
const LIST = { type: "sftp", operation: "list", host: "h", user: "u", remote_path: "/r" } as const;

const ACTION_SCHEMAS: Array<[string, z.ZodType]> = [
  ["useSecretActionSchema", useSecretActionSchema],
  ["sftpActionSchema", sftpActionSchema],
];

/** The rendered refusal of `input`; empty when it parses. */
function refusal(schema: z.ZodType, input: unknown): string {
  const result = schema.safeParse(input);
  return result.success ? "" : renderSchemaIssues(result.error);
}

const RENDER_REFUSALS: Array<[Record<string, unknown>, string]> = [
  [{ ...RENDER, host: "h" }, '<root>: Unrecognized key: "host"'],
  [
    { ...RENDER, host: "h", user: "u", port: 22, remote_path: "/r", local_path: "/l" },
    '<root>: Unrecognized keys: "host", "user", "port", "remote_path", "local_path"',
  ],
  [
    { type: "sftp", operation: "render" },
    "entry: Invalid input: expected string, received undefined",
  ],
  [{ ...RENDER, entry: "a b" }, "entry: Invalid name format"],
];

const TRANSFER_REFUSALS: Array<[Record<string, unknown>, string]> = [
  [{ ...LIST, operation: "upload" }, "local_path: local_path is required for upload/download"],
  [{ ...LIST, operation: "download" }, "local_path: local_path is required for upload/download"],
  [{ ...LIST, local_path: "/l" }, "local_path: local_path is not allowed for list"],
  [{ ...LIST, remote_path: "/r\nrm x" }, "remote_path: Path must not contain control characters"],
  [
    { type: "sftp", operation: "list", user: "u", remote_path: "/r" },
    "host: Invalid input: expected string, received undefined",
  ],
  [{ ...LIST, entry: "env" }, '<root>: Unrecognized key: "entry"'],
  [{ ...LIST, operation: "copy" }, "operation: must be one of upload, download, list, render"],
];

describe("the sftp action's render shape", () => {
  it.each(ACTION_SCHEMAS)("the render action parses alone (%s)", (_name, schema) => {
    expect(schema.parse(RENDER)).toEqual(RENDER);
    expect(schema.parse({ ...RENDER, timeout_ms: 300_000 })).toEqual({
      ...RENDER,
      timeout_ms: 300_000,
    });
    expect(RENDER_REFUSALS.map(([input]) => refusal(schema, input))).toEqual(
      RENDER_REFUSALS.map(([, text]) => text),
    );
  });

  it.each(ACTION_SCHEMAS)("the three transfers parse as before (%s)", (_name, schema) => {
    expect(schema.parse(LIST)).toEqual(LIST);
    expect(TRANSFER_REFUSALS.map(([input]) => refusal(schema, input))).toEqual(
      TRANSFER_REFUSALS.map(([, text]) => text),
    );
  });

  it.each(ACTION_SCHEMAS)("the narrowing adds no issue (%s)", (_name, schema) => {
    for (const [input] of [...RENDER_REFUSALS, ...TRANSFER_REFUSALS]) {
      const text = refusal(schema, input);
      expect(text).not.toBe("");
      expect(text.includes("<root>: Invalid input"), text).toBe(false);
    }
  });

  it("compile-time pin: a render takes its entry alone, a transfer its host, user and path", () => {
    const renderWithHost = { ...RENDER, host: "h" } as const;
    const listWithEntry = { ...LIST, entry: "env" } as const;
    const listWithoutHost = {
      type: "sftp",
      operation: "list",
      user: "u",
      remote_path: "/r",
    } as const;
    // @ts-expect-error — a render names no host
    const refusedRender: UseSecretAction = renderWithHost;
    // @ts-expect-error — a transfer names no entry
    const refusedEntry: UseSecretAction = listWithEntry;
    // @ts-expect-error — a transfer names its host
    const refusedTransfer: UseSecretAction = listWithoutHost;
    expect([refusedRender, refusedEntry, refusedTransfer]).toHaveLength(3);

    const a = useSecretActionSchema.parse(RENDER);
    const r: SftpRenderAction | undefined =
      a.type === "sftp" && a.operation === "render" ? a : undefined;
    const t: SftpAction | undefined = a.type === "sftp" && a.operation !== "render" ? a : undefined;
    expect(r?.entry).toBe("env");
    expect(t).toBeUndefined();
  });
});

describe("the policy's render field", () => {
  it("the field defaults to no entries and no approvals, a fresh object per parse", () => {
    const first = injectionPolicyInputSchema.parse({});
    expect(first.render).toEqual({ entries: [], approvals: [] });
    first.render.entries.push(E1);
    expect(injectionPolicyInputSchema.parse({}).render.entries).toEqual([]);
  });

  it("an entry: the port defaults to 22, the keys in their order", () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { port: _dropped, ...withoutPort } = E1;
    const parsed = renderEntryInputSchema.parse(withoutPort);
    expect(parsed.port).toBe(22);
    expect(Object.keys(parsed)).toEqual([
      "name",
      "host",
      "port",
      "user",
      "path",
      "host_keys",
      "template",
    ]);
    expect(refusal(renderEntrySchema, withoutPort)).toBe(
      "port: Invalid input: expected number, received undefined",
    );
  });

  it.each(["localhost", "127.0.0.1", "db.localhost", "0.0.0.0"])(
    "an entry's host is a plain name or address, no loopback: %j",
    (host) => {
      expect(refusal(renderEntrySchema, { ...E1, host })).toBe(
        "host: Invalid host: the vault host's own loopback (localhost, 127.0.0.0/8, 0.0.0.0) is no render target",
      );
    },
  );

  it("an entry's host is a plain name or address: an IPv4 address in its dotted form alone", () => {
    expect(refusal(renderEntrySchema, { ...E1, host: "127.1" })).toBe(
      "host: Invalid host: an IPv4 address only as four decimal numbers 0-255 without leading zeros",
    );
    expect(refusal(renderEntrySchema, { ...E1, host: "h1.example" })).toBe("");
    expect(refusal(renderEntrySchema, { ...E1, host: "10.0.0.5" })).toBe("");
  });

  it.each([
    ["U+202E", "‮"],
    ["U+2028", " "],
    ["U+2029", " "],
    ["U+061C", "؜"],
    ["U+2060", "⁠"],
    ["U+00AD", "­"],
    ["a tag character", "\u{e0041}"],
  ])(
    "an entry's path holds no format character and no line or paragraph separator: %s",
    (_label, char) => {
      for (const schema of [renderEntrySchema, renderEntryInputSchema]) {
        expect(refusal(schema, { ...E1, path: `/srv/app/${char}env` })).toBe(`path: ${PATH_TEXT}`);
      }
    },
  );

  it("an entry's template keeps its format characters: the refusal is the path's alone", () => {
    const template = "﻿A=‮{{secret://a}} ­\n";
    expect(renderEntrySchema.parse({ ...E1, template }).template).toBe(template);
  });

  it("an entry's path, host keys and template are bounded", () => {
    expect(refusal(renderEntrySchema, { ...E1, path: "srv" })).toBe(`path: ${PATH_TEXT}`);
    expect(refusal(renderEntrySchema, { ...E1, host_keys: [] })).toBe(
      "host_keys: Too small: expected array to have >=1 items",
    );
    expect(refusal(renderEntrySchema, { ...E1, host_keys: Array<string>(9).fill(HOST_KEY) })).toBe(
      "host_keys: Too big: expected array to have <=8 items",
    );
    expect(refusal(renderEntrySchema, { ...E1, host_keys: [`h1.example ${HOST_KEY}`] })).toBe(
      "host_keys.0: Invalid host key: one of ssh-ed25519, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, ssh-rsa, one space and its base64 key, nothing else",
    );
    expect(refusal(renderEntrySchema, { ...E1, template: "é".repeat(8192) })).toBe("");
    expect(refusal(renderEntrySchema, { ...E1, template: "é".repeat(8193) })).toBe(
      "template: Invalid template: longer than 16384 bytes",
    );
    expect(refusal(renderEntrySchema, { ...E1, template: "a\u0000" })).toBe(
      "template: Invalid template: a NUL character",
    );
    expect(refusal(renderEntrySchema, { ...E1, template: "\ud800" })).toBe(
      "template: Invalid template: not UTF-8 text",
    );
    expect(refusal(renderEntrySchema, { ...E1, template: "{{secret://a" })).toBe(
      "template: Invalid template: every {{ must open a slot {{secret://name}} or {{secret://project/name}}, at most 16 slots",
    );
  });

  it("the policy: caps, unique names and pairs, the digest's form, strict", () => {
    const approval = { key: "sid-1", entry: "env", digest: E1_DIGEST };
    const policy = (render: unknown): string => refusal(injectionPolicyInputSchema, { render });
    const entries = Array.from({ length: 17 }, (_, i) => ({ ...E1, name: `env${String(i)}` }));
    const approvals = Array.from({ length: 33 }, (_, i) => ({
      ...approval,
      key: `sid-${String(i)}`,
    }));
    expect(policy({ entries: entries.slice(0, 16), approvals: [] })).toBe("");
    expect(policy({ entries, approvals: [] })).toBe(
      "render.entries: Too big: expected array to have <=16 items",
    );
    expect(policy({ entries: [], approvals: approvals.slice(0, 32) })).toBe("");
    expect(policy({ entries: [], approvals })).toBe(
      "render.approvals: Too big: expected array to have <=32 items",
    );
    expect(policy({ entries: [E1, E1], approvals: [] })).toBe(
      "render.entries.1.name: Duplicate entry name",
    );
    expect(policy({ entries: [], approvals: [approval, approval] })).toBe(
      "render.approvals.1: Duplicate approval: one per key and entry",
    );
    expect(policy({ entries: [], approvals: [approval, { ...approval, entry: "env2" }] })).toBe("");
    expect(policy({ entries: [], approvals: [{ ...approval, digest: "ABC" }] })).toBe(
      "render.approvals.0.digest: Invalid digest: 64 lowercase hex characters",
    );
    expect(policy({ entries: [{ ...E1, extra: 1 }], approvals: [] })).toBe(
      'render.entries.0: Unrecognized key: "extra"',
    );
  });
});
