import { describe, expect, it } from "vitest";
import type { z } from "zod";

import {
  injectionPolicyInputSchema,
  injectionPolicySchema,
  sshActionSchema,
  useSecretActionSchema,
} from "./schemas.js";
import type { SshAction, UseSecretAction } from "./schemas.js";
import { renderSchemaIssues } from "./schema-issues.js";

const HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICn+7qKS67vacwftKjgcrwUlmC2TZ6j0dyFpyO5UDiVx";
const KEY_A =
  "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCz9X9B5Ls3wqgwaWax6lXZilG0yR+qBdY+tYQpr1fpizTydsdzfyl0ESyVBtR6XYCQum8+x0NktMqPL7ISyqGU=";
const SK_KEY =
  "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIEINLyuDfy3/jy8/r3dZMETntyjcGo9rV7Bi3GNUlp60AAAABHNzaDo=";

const COMMAND = { type: "ssh", host: "h", user: "u", command: "id" };
const BOOT = {
  type: "ssh",
  operation: "bootstrap",
  host: "h1.example",
  user: "ubuntu",
  public_key: KEY_A,
};

const HOST_KEY_TEXT =
  "Invalid host key: one of ssh-ed25519, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, ssh-rsa, one space and its base64 key, nothing else";
const PUBLIC_KEY_TEXT =
  "Invalid public key: one of ssh-ed25519, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, ssh-rsa, sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com, one space and its base64 key, nothing else";
const HOST_TEXT =
  "Invalid host: an IPv4 address only as four decimal numbers 0-255 without leading zeros";

const ACTION_SCHEMAS: Array<[string, z.ZodType]> = [
  ["useSecretActionSchema", useSecretActionSchema],
  ["sshActionSchema", sshActionSchema],
];

function refusal(schema: z.ZodType, input: unknown): string {
  const parsed = schema.safeParse(input);
  return parsed.success ? "" : renderSchemaIssues(parsed.error);
}

const REFUSED_COMMAND_ACTIONS: Array<[string, Record<string, unknown>, string]> = [
  [
    "without command",
    { type: "ssh", host: "h", user: "u" },
    "command: Invalid input: expected string, received undefined",
  ],
  ["with public_key", { ...COMMAND, public_key: KEY_A }, '<root>: Unrecognized key: "public_key"'],
  ["with operation copy", { ...COMMAND, operation: "copy" }, "operation: must be one of bootstrap"],
];

const REFUSED_BOOTSTRAPS: Array<[string, Record<string, unknown>, string]> = [
  ["with command", { ...BOOT, command: "id" }, '<root>: Unrecognized key: "command"'],
  ["with timeout_ms", { ...BOOT, timeout_ms: 5 }, '<root>: Unrecognized key: "timeout_ms"'],
  [
    "without public_key",
    { ...BOOT, public_key: undefined },
    "public_key: Invalid input: expected string, received undefined",
  ],
  [
    "with a commented public_key",
    { ...BOOT, public_key: `${KEY_A} me@laptop` },
    `public_key: ${PUBLIC_KEY_TEXT}`,
  ],
];

describe.each(ACTION_SCHEMAS)("the ssh action through %s", (_name, schema) => {
  it("the command action parses as today", () => {
    const parsed = schema.safeParse(COMMAND);
    expect(parsed.success).toBe(true);
    expect(parsed.data).toEqual(COMMAND);
    for (const [, input, text] of REFUSED_COMMAND_ACTIONS) {
      expect(refusal(schema, input)).toBe(text);
    }
  });

  it("the bootstrap action parses, alone", () => {
    expect(schema.safeParse(BOOT).data).toEqual(BOOT);
    const full = { ...BOOT, port: 2222, public_key: SK_KEY, sudoers: true };
    expect(schema.safeParse(full).data).toEqual(full);
    for (const [, input, text] of REFUSED_BOOTSTRAPS) {
      expect(refusal(schema, input)).toBe(text);
    }
  });

  it.each([...REFUSED_COMMAND_ACTIONS, ...REFUSED_BOOTSTRAPS])(
    "the narrowing adds no issue: %s",
    (_case, input, text) => {
      expect(refusal(schema, input)).toBe(text);
      expect(refusal(schema, input).includes("<root>: Invalid input")).toBe(false);
    },
  );
});

describe("the ssh action's types", () => {
  it("sshActionSchema.shape.timeout_ms is the field the timeout table reads", () => {
    expect(sshActionSchema.shape.timeout_ms.safeParse(300_001).success).toBe(false);
    expect(sshActionSchema.shape.timeout_ms.safeParse(undefined).success).toBe(true);
  });

  it("compile-time pin: a command action needs its command; a bootstrap takes neither command nor timeout_ms", () => {
    const boot = { type: "ssh", operation: "bootstrap", host: "h", user: "u" } as const;
    const commandless = { type: "ssh", host: "h", user: "u" } as const;
    const bootWithCommand = { ...boot, public_key: KEY_A, command: "id" };
    const bootWithTimeout = { ...boot, public_key: KEY_A, timeout_ms: 5 };
    // @ts-expect-error — a command action needs its command
    const noCommand: UseSecretAction = commandless;
    // @ts-expect-error — a bootstrap takes no command
    const withCommand: UseSecretAction = bootWithCommand;
    // @ts-expect-error — a bootstrap takes no timeout_ms
    const withTimeout: UseSecretAction = bootWithTimeout;
    // @ts-expect-error — a bootstrap needs its public_key
    const noKey: UseSecretAction = boot;
    const a = useSecretActionSchema.parse(COMMAND);
    const narrowed: SshAction | undefined =
      a.type === "ssh" && a.operation === undefined ? a : undefined;
    expect(narrowed?.command).toBe("id");
    expect([noCommand, withCommand, withTimeout, noKey]).toHaveLength(4);
  });
});

describe("the ssh_bootstrap block", () => {
  const block = { host: "10.0.0.5", user: "ubuntu", host_keys: [HOST_KEY], install_keys: [KEY_A] };
  const inputRefusal = (ssh_bootstrap: unknown): string =>
    refusal(injectionPolicyInputSchema, { ssh_bootstrap });

  it("the block: defaults, bounds, key types, the host rule", () => {
    expect(injectionPolicyInputSchema.parse({}).ssh_bootstrap).toBeNull();
    const parsed = injectionPolicyInputSchema.parse({ ssh_bootstrap: block }).ssh_bootstrap;
    expect(parsed).toEqual({ ...block, port: 22, sudoers: false });
    expect(Object.keys(parsed ?? {})).toEqual([
      "host",
      "port",
      "user",
      "host_keys",
      "install_keys",
      "sudoers",
    ]);
    expect(inputRefusal({ ...block, host_keys: [] })).toBe(
      "ssh_bootstrap.host_keys: Too small: expected array to have >=1 items",
    );
    expect(inputRefusal({ ...block, install_keys: Array.from({ length: 17 }, () => KEY_A) })).toBe(
      "ssh_bootstrap.install_keys: Too big: expected array to have <=16 items",
    );
    expect(inputRefusal({ ...block, host_keys: [SK_KEY] })).toBe(
      `ssh_bootstrap.host_keys.0: ${HOST_KEY_TEXT}`,
    );
    expect(inputRefusal({ ...block, install_keys: [SK_KEY] })).toBe("");
    expect(inputRefusal({ ...block, extra: 1 })).toBe('ssh_bootstrap: Unrecognized key: "extra"');
  });

  it.each(["127.1", "2130706433", "017700000001", "0x7f000001", "127.0.0.1.", "127.000.0.1"])(
    "the host rule refuses %j",
    (host) => {
      expect(inputRefusal({ ...block, host })).toBe(`ssh_bootstrap.host: ${HOST_TEXT}`);
    },
  );

  it.each(["127.0.0.1", "10.0.0.5", "Host-1.example", "vm1"])("the host rule admits %j", (host) => {
    expect(inputRefusal({ ...block, host })).toBe("");
  });

  it("the stored block requires its port", () => {
    const stored = {
      ...injectionPolicyInputSchema.parse({}),
      ssh_bootstrap: { ...block, sudoers: false },
    };
    expect(refusal(injectionPolicySchema, stored)).toBe(
      "ssh_bootstrap.port: Invalid input: expected number, received undefined",
    );
  });
});
