import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import type { InjectionPolicy, RenderApproval, RenderEntry } from "@harpoc/shared";
import { VaultError } from "@harpoc/shared";
import { expectAbsent } from "@harpoc/test-utils";
import { renderEntryDigest } from "@harpoc/core";

const { mockEngine, mockPromptConfirm } = vi.hoisted(() => ({
  mockEngine: {
    getInjectionPolicy: vi.fn<(handle: string, caller?: unknown) => Promise<InjectionPolicy>>(),
    setInjectionPolicy: vi.fn().mockResolvedValue(undefined),
    verifyToken: vi.fn(),
    auditScopeRefusal: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
  mockPromptConfirm: vi.fn<(message: string) => Promise<boolean>>(),
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
  resolveSecretId: vi.fn(),
}));
vi.mock("../../utils/prompt.js", () => ({ promptConfirm: mockPromptConfirm }));

import { registerSecretRenderCommand } from "./render.js";
import { loadUnlockedEngine, resolveSecretId } from "../../utils/vault-loader.js";
import { buildCli, spyCli, tokenFixture, type CliSpies } from "../../__fixtures__/cli-harness.js";

const run = buildCli(
  (program) => registerSecretRenderCommand(program.command("secret")),
  ["secret", "render"],
);

// The public key line of core's injection/__fixtures__/ssh-public-keys.ts (ssh-keygen 10.0p2).
const HOST_KEY_BASE64 = "AAAAC3NzaC1lZDI1NTE5AAAAICn+7qKS67vacwftKjgcrwUlmC2TZ6j0dyFpyO5UDiVx";
const HOST_KEY = `ssh-ed25519 ${HOST_KEY_BASE64}`;
const FP_HOST = "SHA256:dngXInM6F9ixKWjZmnsLT+7TH7k+7qKeHsHP6BtaKS8";
const E1_TEMPLATE = "TOKEN={{secret://bot-token}}\n";
const E1: RenderEntry = {
  name: "env",
  host: "h1.example",
  port: 22,
  user: "deploy",
  path: "/srv/app/.env",
  host_keys: [HOST_KEY],
  template: E1_TEMPLATE,
};
/** E1's digest, as core's `render-entry-digest.test.ts` pins it. */
const D1 = "7c6a834469ef5a6c2a4b422775e89bf38a601de3f618e3615c684734ca914b66";
/** The digest of E1 with `port: 2222`, as that suite pins it. */
const D1_PORT_2222 = "82ccb88c2fd441c47e21863af0a40ad41f51795126561d5af3dad3d3ea3f2aaf";
const B: RenderEntry = {
  name: "other",
  host: "h1.example",
  port: 22,
  user: "deploy",
  path: "/srv/app/other.conf",
  host_keys: [HOST_KEY],
  template: "X=1\n",
};
const KEY_ID = "0193b1c2-0000-7000-8000-000000000001";
const OTHER_KEY_ID = "0193b1c2-0000-7000-8000-000000000002";
const SLOT_ID = "0193b1c2-0000-7000-8000-000000000003";
const APPROVAL: RenderApproval = { key: KEY_ID, entry: "env", digest: D1 };
const OTHER_APPROVAL: RenderApproval = { key: OTHER_KEY_ID, entry: "env", digest: D1 };

const STORED: InjectionPolicy = {
  url_allowlist: [],
  command_allowlist: [],
  env_allowlist: [],
  host_allowlist: ["h1.example"],
  response_mode: "filtered",
  response_header_allowlist: [],
  network_isolation: false,
  fs_isolation: false,
  smtp_recipient_allowlist: [],
  imap_read_only: false,
  strict_tree_exit: false,
  proxy: false,
  ssh_agent_socket: false,
  local_dirs: [],
  ssh_bootstrap: null,
  render: { entries: [], approvals: [] },
};
const SLOT: InjectionPolicy = { ...STORED, host_allowlist: [], command_allowlist: ["deploy"] };

const withEntries = (...entries: RenderEntry[]): InjectionPolicy => ({
  ...STORED,
  render: { entries, approvals: [] },
});
const withApprovals = (...approvals: RenderApproval[]): InjectionPolicy => ({
  ...SLOT,
  render: { entries: [], approvals },
});

const LOOPBACK_TEXT =
  "Invalid host: the vault host's own loopback (localhost, 127.0.0.0/8, 0.0.0.0) is no render target";
const PATH_TEXT =
  "Invalid path: an absolute remote path of at most 4096 bytes without a control or format character, a line or paragraph separator, an empty, '.' or '..' segment or a trailing '/', its last segment at most 200 bytes and not of the render's temporary name form";
const HOST_KEY_TEXT =
  "Invalid host key: one of ssh-ed25519, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, ssh-rsa, one space and its base64 key, nothing else";
const TEMPLATE_TEXT =
  "Invalid template: every {{ must open a slot {{secret://name}} or {{secret://project/name}}, at most 16 slots";
const CHANGED_LINE = "the entry's digest changed; approvals of the old digest no longer hold";

let spies: CliSpies;
let dir: string;

beforeEach(() => {
  vi.clearAllMocks();
  spies = spyCli();
  dir = mkdtempSync(join(tmpdir(), "harpoc-render-"));
  vi.mocked(resolveSecretId).mockResolvedValue(KEY_ID);
  mockPromptConfirm.mockResolvedValue(false);
});

afterEach(() => {
  spies.restore();
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

/** The engine's stored policy per handle; a handle without one is no fixture of the row. */
function storePolicies(policies: Record<string, InjectionPolicy>): void {
  mockEngine.getInjectionPolicy.mockImplementation(async (handle: string) => {
    const policy = policies[handle];
    if (policy === undefined) throw new Error(`no policy fixture for ${handle}`);
    return structuredClone(policy);
  });
}

/** As `storePolicies`, but the read of `secret://key` refuses as the engine refuses a caller that holds nothing on it. */
function storePoliciesKeyUnread(policies: Record<string, InjectionPolicy>): void {
  mockEngine.getInjectionPolicy.mockImplementation(async (handle: string) => {
    if (handle === "secret://key") throw VaultError.secretNotFound(handle);
    const policy = policies[handle];
    if (policy === undefined) throw new Error(`no policy fixture for ${handle}`);
    return structuredClone(policy);
  });
}

const KEY_UNREAD_LINE = "Error: Secret not found: secret://key";
const TOKEN_CALLER: unknown = expect.objectContaining({
  principal_id: "agent-1",
  interface: "cli",
});

function templateFile(content: string | Uint8Array, name = "env.tmpl"): string {
  const path = join(dir, name);
  writeFileSync(path, content);
  return path;
}

interface EntryFlags {
  host?: string;
  user?: string;
  path?: string;
  port?: string;
  hostKeys?: string[];
}

const ENTRY_FLAGS: EntryFlags = {
  host: "h1.example",
  user: "deploy",
  path: "/srv/app/.env",
  hostKeys: [HOST_KEY],
};

function setArgs(file: string, flags: EntryFlags = ENTRY_FLAGS): string[] {
  return [
    "set",
    "secret://k",
    "--entry",
    "env",
    ...(flags.host === undefined ? [] : ["--host", flags.host]),
    ...(flags.user === undefined ? [] : ["--user", flags.user]),
    ...(flags.path === undefined ? [] : ["--path", flags.path]),
    ...(flags.port === undefined ? [] : ["--port", flags.port]),
    ...(flags.hostKeys ?? []).flatMap((line) => ["--host-key", line]),
    "--template-file",
    file,
  ];
}

const writtenPolicies = (): InjectionPolicy[] =>
  mockEngine.setInjectionPolicy.mock.calls.map((call) => call[1] as InjectionPolicy);

describe("secret render set", () => {
  it("set adds an entry to a key without one and prints its digest", async () => {
    storePolicies({ "secret://k": STORED });
    await run(setArgs(templateFile(E1_TEMPLATE)));
    expect(mockEngine.setInjectionPolicy.mock.calls).toEqual([
      [
        "secret://k",
        { ...STORED, render: { entries: [E1], approvals: [] } },
        { acknowledge_interpreters: false },
        undefined,
      ],
    ]);
    expect(spies.stdout()).toBe(D1);
    expect(spies.errorSpy).toHaveBeenLastCalledWith("OK: Render entry set (secret://k)");
  });

  it("set writes the key's id to standard error and the digest alone to standard output (P-3)", async () => {
    storePolicies({ "secret://k": STORED });
    await run(setArgs(templateFile(E1_TEMPLATE)));
    expect(vi.mocked(resolveSecretId).mock.calls).toEqual([
      [mockEngine, "secret://k", undefined, "policy.grant"],
    ]);
    expect(spies.logSpy.mock.calls).toEqual([[D1]]);
    expect(spies.errorSpy.mock.calls).toEqual([
      [`key: ${KEY_ID}`],
      ["OK: Render entry set (secret://k)"],
    ]);
  });

  it("set replaces the entry of its name in place and leaves the others", async () => {
    storePolicies({ "secret://k": withEntries(E1, B) });
    await run(setArgs(templateFile(E1_TEMPLATE), { ...ENTRY_FLAGS, port: "2222" }));
    expect(writtenPolicies()).toEqual([
      { ...STORED, render: { entries: [{ ...E1, port: 2222 }, B], approvals: [] } },
    ]);
  });

  it("a replaced entry says that its approvals are void", async () => {
    storePolicies({ "secret://k": withEntries(E1) });
    await run(setArgs(templateFile(E1_TEMPLATE), { ...ENTRY_FLAGS, port: "2222" }));
    expect(spies.logSpy.mock.calls).toEqual([[D1_PORT_2222]]);
    expect(spies.errorSpy.mock.calls).toEqual([
      [`key: ${KEY_ID}`],
      [CHANGED_LINE],
      ["OK: Render entry set (secret://k)"],
    ]);
  });

  it("a set that changes nothing does not say that approvals are void", async () => {
    storePolicies({ "secret://k": withEntries(E1) });
    await run(setArgs(templateFile(E1_TEMPLATE)));
    expect(writtenPolicies()).toEqual([withEntries(E1)]);
    expect(spies.logSpy.mock.calls).toEqual([[D1]]);
    expect(spies.errorSpy.mock.calls).toEqual([
      [`key: ${KEY_ID}`],
      ["OK: Render entry set (secret://k)"],
    ]);
  });

  it.each<[string, EntryFlags, string | undefined, string]>([
    [
      "--host missing",
      { ...ENTRY_FLAGS, host: undefined },
      undefined,
      "Error: [SCHEMA_VALIDATION_ERROR] host: Invalid input: expected string, received undefined",
    ],
    [
      "--host 127.0.0.1",
      { ...ENTRY_FLAGS, host: "127.0.0.1" },
      undefined,
      `Error: [SCHEMA_VALIDATION_ERROR] host: ${LOOPBACK_TEXT}`,
    ],
    [
      "--path srv",
      { ...ENTRY_FLAGS, path: "srv" },
      undefined,
      `Error: [SCHEMA_VALIDATION_ERROR] path: ${PATH_TEXT}`,
    ],
    [
      "an ssh-keyscan line as --host-key",
      { ...ENTRY_FLAGS, hostKeys: [`h1.example ${HOST_KEY}`] },
      undefined,
      `Error: [SCHEMA_VALIDATION_ERROR] host_keys.0: ${HOST_KEY_TEXT}`,
    ],
    [
      "nine --host-key",
      { ...ENTRY_FLAGS, hostKeys: Array.from({ length: 9 }, () => HOST_KEY) },
      undefined,
      "Error: [SCHEMA_VALIDATION_ERROR] host_keys: Too big: expected array to have <=8 items",
    ],
    [
      "--port 0x16",
      { ...ENTRY_FLAGS, port: "0x16" },
      undefined,
      'Error: [INVALID_INPUT] Invalid port "0x16". Must be 1-65535.',
    ],
    [
      "a template that opens a slot it does not close",
      ENTRY_FLAGS,
      "A={{secret://a\n",
      `Error: [SCHEMA_VALIDATION_ERROR] template: ${TEMPLATE_TEXT}`,
    ],
  ])("refused before the vault opens, naming the field: %s", async (_case, flags, text, line) => {
    await expect(run(setArgs(templateFile(text ?? E1_TEMPLATE), flags))).rejects.toThrow(
      "process.exit",
    );
    expect(spies.errorSpy.mock.calls).toEqual([[line]]);
    expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it.each<[string, () => string, (path: string) => string]>([
    ["an empty path", () => "", () => "--template-file: empty path"],
    [
      "a flag",
      () => "-t",
      () => "--template-file: a flag, not a path (give a path that starts with a dash as ./-name)",
    ],
    [
      "a missing file",
      () => join(dir, "missing.tmpl"),
      (path) => `Cannot read template file: ${path}`,
    ],
    [
      "a directory",
      () => {
        const path = join(dir, "a-directory");
        mkdirSync(path);
        return path;
      },
      (path) => `Cannot read template file: ${path}`,
    ],
    [
      "16 385 bytes",
      () => templateFile("a".repeat(16_385)),
      (path) => `The template file exceeds the 16384-byte limit: ${path}`,
    ],
    [
      "the bytes ff fe",
      () => templateFile(Uint8Array.of(0xff, 0xfe)),
      (path) => `The template file is not UTF-8 text: ${path}`,
    ],
  ])("--template-file is read under the CLI's file checks: %s", async (_case, make, message) => {
    const path = make();
    await expect(run(setArgs(path))).rejects.toThrow("process.exit");
    expect(spies.errorSpy.mock.calls).toEqual([[`Error: [INVALID_INPUT] ${message(path)}`]]);
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("the template's bytes reach the entry unchanged", async () => {
    storePolicies({ "secret://k": STORED });
    const bytes = Uint8Array.of(
      0xef,
      0xbb,
      0xbf,
      ...new TextEncoder().encode("K={{secret://a}}\r\nB=x"),
    );
    await run(setArgs(templateFile(bytes)));
    expect(writtenPolicies().map((policy) => policy.render.entries[0]?.template)).toEqual([
      "﻿K={{secret://a}}\r\nB=x",
    ]);
  });

  it("a refusal does not echo a pasted key line", async () => {
    await expect(
      run(
        setArgs(templateFile(E1_TEMPLATE), {
          ...ENTRY_FLAGS,
          hostKeys: [`h1.example ${HOST_KEY}`],
        }),
      ),
    ).rejects.toThrow("process.exit");
    const stderr = spies.stderr();
    expectAbsent(stderr, HOST_KEY_BASE64, "the refusal");
    expect(stderr).toBe(`Error: [SCHEMA_VALIDATION_ERROR] host_keys.0: ${HOST_KEY_TEXT}`);
  });
});

describe("secret render remove", () => {
  it("remove drops the named entry and nothing else", async () => {
    storePolicies({ "secret://k": withEntries(E1, B) });
    await run(["remove", "secret://k", "--entry", "env"]);
    expect(mockEngine.setInjectionPolicy.mock.calls).toEqual([
      ["secret://k", withEntries(B), { acknowledge_interpreters: false }, undefined],
    ]);
    expect(spies.errorSpy.mock.calls).toEqual([["OK: Render entry removed (secret://k)"]]);
  });

  it("remove of an entry the key does not hold writes nothing", async () => {
    storePolicies({ "secret://k": withEntries(B) });
    await expect(run(["remove", "secret://k", "--entry", "env"])).rejects.toThrow("process.exit");
    expect(spies.errorSpy.mock.calls).toEqual([
      ["Error: [INVALID_INPUT] --entry: the secret's policy holds no render entry of that name"],
    ]);
    expect(mockEngine.setInjectionPolicy).not.toHaveBeenCalled();
  });

  it("--entry is judged before the vault opens, as approve and revoke judge it", async () => {
    await expect(run(["remove", "secret://k", "--entry", "a b"])).rejects.toThrow("process.exit");
    expect(spies.errorSpy.mock.calls).toEqual([
      ["Error: [SCHEMA_VALIDATION_ERROR] entry: Invalid name format"],
    ]);
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });
});

describe("secret render approve", () => {
  const APPROVE = ["approve", "secret://slot", "--key", "secret://key", "--entry", "env"];

  it("approve shows the key's entry, asks, and stores the approval", async () => {
    storePolicies({ "secret://key": withEntries(E1), "secret://slot": SLOT });
    mockPromptConfirm.mockResolvedValue(true);
    await run(APPROVE);
    expect(vi.mocked(resolveSecretId).mock.calls).toEqual([
      [mockEngine, "secret://key", undefined, "policy.grant"],
    ]);
    expect(mockEngine.getInjectionPolicy.mock.calls).toEqual([
      ["secret://key", undefined],
      ["secret://slot", undefined],
    ]);
    expect(mockPromptConfirm.mock.calls).toEqual([
      ["Approve this render entry for secret://slot?"],
    ]);
    expect(mockEngine.setInjectionPolicy.mock.calls).toEqual([
      [
        "secret://slot",
        { ...SLOT, render: { entries: [], approvals: [APPROVAL] } },
        { acknowledge_interpreters: false },
        undefined,
      ],
    ]);
    expect(spies.errorSpy.mock.calls).toEqual([
      [`key: ${KEY_ID}`],
      ["entry: env"],
      ["host: h1.example"],
      ["port: 22"],
      ["user: deploy"],
      ["path: /srv/app/.env"],
      [`host_key_fingerprints: ${FP_HOST}`],
      ["slots: secret://bot-token"],
      [`digest: ${D1}`],
      ["template:"],
      [E1_TEMPLATE],
      ["OK: Render approval stored (secret://slot)"],
    ]);
  });

  describe("the display a key's administrator cannot bend", () => {
    const shownTemplate = (): unknown =>
      spies.errorSpy.mock.calls[
        spies.errorSpy.mock.calls.findIndex(([line]) => line === "template:") + 1
      ]?.[0];

    it("shows the template's control and format characters escaped, none raw", async () => {
      const bent: RenderEntry = {
        ...E1,
        path: "/srv/app/\u202Eenv",
        template: "\uFEFFTOKEN={{secret://bot-token}}\r\n\u001b[2KX=\u202Eabc\n",
      };
      storePolicies({ "secret://key": withEntries(bent), "secret://slot": SLOT });
      mockPromptConfirm.mockResolvedValue(true);
      await run(APPROVE);
      expect(shownTemplate()).toBe(
        "\\ufeffTOKEN={{secret://bot-token}}\\r\n\\x1b[2KX=\\u202eabc\n",
      );
      expect(spies.errorSpy).toHaveBeenCalledWith("path: /srv/app/\\u202eenv");
      const stderr = spies.stderr();
      for (const raw of ["\u001b", "\r", "\u202E", "\uFEFF"]) {
        expect(stderr.includes(raw), JSON.stringify(raw)).toBe(false);
      }
      expect(writtenPolicies()).toEqual([
        withApprovals({ key: KEY_ID, entry: "env", digest: renderEntryDigest(bent) }),
      ]);
    });

    it("shows a backslash doubled", async () => {
      storePolicies({
        "secret://key": withEntries({ ...E1, template: "DIR=C:\\data\\x1b\n" }),
        "secret://slot": SLOT,
      });
      await run(APPROVE);
      expect(shownTemplate()).toBe("DIR=C:\\\\data\\\\x1b\n");
    });

    it("shows a plain template byte for byte", async () => {
      const plain = "# é ü 😀 {} \"quoted\" 'single'\nTOKEN={{secret://bot-token}}\n";
      storePolicies({
        "secret://key": withEntries({ ...E1, template: plain }),
        "secret://slot": SLOT,
      });
      await run(APPROVE);
      expect(shownTemplate()).toBe(plain);
    });
  });

  it("a declined prompt writes nothing", async () => {
    storePolicies({ "secret://key": withEntries(E1), "secret://slot": SLOT });
    mockPromptConfirm.mockResolvedValue(false);
    await run(APPROVE);
    expect(spies.errorSpy).toHaveBeenLastCalledWith("Aborted.");
    expect(mockEngine.getInjectionPolicy.mock.calls).toEqual([["secret://key", undefined]]);
    expect(mockEngine.setInjectionPolicy).not.toHaveBeenCalled();
  });

  it("--digest approves without showing the key's entry, the key read under the caller's grant first", async () => {
    storePolicies({ "secret://key": withEntries(B), "secret://slot": SLOT });
    await run([...APPROVE, "--digest", D1, "--confirm"]);
    expect(mockEngine.getInjectionPolicy.mock.calls).toEqual([
      ["secret://key", undefined],
      ["secret://slot", undefined],
    ]);
    expect(mockPromptConfirm).not.toHaveBeenCalled();
    expect(writtenPolicies()).toEqual([withApprovals(APPROVAL)]);
    expect(spies.errorSpy.mock.calls).toEqual([
      [`key: ${KEY_ID}`],
      ["entry: env"],
      [`digest: ${D1}`],
      ["OK: Render approval stored (secret://slot)"],
    ]);
  });

  it("--key-id with --digest names the key by its id", async () => {
    storePolicies({ "secret://slot": SLOT });
    await run([
      "approve",
      "secret://slot",
      "--key-id",
      KEY_ID,
      "--entry",
      "env",
      "--digest",
      D1,
      "--confirm",
    ]);
    expect(resolveSecretId).not.toHaveBeenCalled();
    expect(mockEngine.getInjectionPolicy.mock.calls).toEqual([["secret://slot", undefined]]);
    expect(writtenPolicies()).toEqual([withApprovals(APPROVAL)]);
  });

  it("an approval of the same key and entry is replaced", async () => {
    storePolicies({
      "secret://key": withEntries(E1),
      "secret://slot": withApprovals(OTHER_APPROVAL, { ...APPROVAL, digest: "0".repeat(64) }),
    });
    await run([...APPROVE, "--digest", D1, "--confirm"]);
    expect(writtenPolicies()).toEqual([withApprovals(OTHER_APPROVAL, APPROVAL)]);
  });

  it.each<[string, string[], string]>([
    [
      "neither --key nor --key-id",
      ["approve", "secret://slot", "--entry", "env"],
      "Error: [INVALID_INPUT] secret render approve needs --key <handle> or --key-id <id>",
    ],
    [
      "neither --key nor --key-id (revoke)",
      ["revoke", "secret://slot", "--entry", "env"],
      "Error: [INVALID_INPUT] secret render revoke needs --key <handle> or --key-id <id>",
    ],
    [
      "both",
      [...APPROVE, "--key-id", KEY_ID, "--digest", D1],
      "Error: [INVALID_INPUT] --key and --key-id exclude each other",
    ],
    [
      "--key-id without --digest",
      ["approve", "secret://slot", "--key-id", KEY_ID, "--entry", "env"],
      "Error: [INVALID_INPUT] --key-id needs --digest: the key's policy is read through --key alone",
    ],
    [
      "--digest ABC",
      [...APPROVE, "--digest", "ABC"],
      "Error: [SCHEMA_VALIDATION_ERROR] digest: Invalid digest: 64 lowercase hex characters",
    ],
    [
      "--key nope",
      ["approve", "secret://slot", "--key", "nope", "--entry", "env"],
      "Error: [INVALID_HANDLE] Invalid handle: nope",
    ],
    [
      '--entry "a b"',
      ["approve", "secret://slot", "--key", "secret://key", "--entry", "a b"],
      "Error: [SCHEMA_VALIDATION_ERROR] entry: Invalid name format",
    ],
  ])("the approval's options are judged before the vault opens: %s", async (_case, args, line) => {
    await expect(run(args)).rejects.toThrow("process.exit");
    expect(spies.errorSpy.mock.calls).toEqual([[line]]);
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("an entry the key's policy does not hold is refused, nothing written", async () => {
    storePolicies({ "secret://key": withEntries(B), "secret://slot": SLOT });
    await expect(run(APPROVE)).rejects.toThrow("process.exit");
    expect(spies.errorSpy.mock.calls).toEqual([
      ["Error: [INVALID_INPUT] --entry: the key's policy holds no render entry of that name"],
    ]);
    expect(mockPromptConfirm).not.toHaveBeenCalled();
    expect(mockEngine.setInjectionPolicy).not.toHaveBeenCalled();
  });

  describe.each<[string, string[]]>([
    ["its entry shown", APPROVE],
    ["its entry named by --digest", [...APPROVE, "--digest", D1]],
  ])("--key, %s", (_case, args) => {
    it("resolves the key's id only after the key's read under the caller's grant", async () => {
      mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["admin", "read"] }));
      storePolicies({ "secret://key": withEntries(E1), "secret://slot": SLOT });
      await run([...args, "--confirm", "--token", "jwt-value"]);
      expect(mockEngine.getInjectionPolicy.mock.calls[0]).toEqual(["secret://key", TOKEN_CALLER]);
      expect(vi.mocked(resolveSecretId).mock.calls).toEqual([
        [mockEngine, "secret://key", TOKEN_CALLER, "policy.grant"],
      ]);
      expect(vi.mocked(resolveSecretId).mock.invocationCallOrder[0] as number).toBeGreaterThan(
        mockEngine.getInjectionPolicy.mock.invocationCallOrder[0] as number,
      );
      expect(writtenPolicies()).toEqual([withApprovals(APPROVAL)]);
    });

    it("a key the caller may not read is refused as its read refuses it: no id resolved or shown, nothing written", async () => {
      mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["admin", "read"] }));
      storePoliciesKeyUnread({ "secret://slot": SLOT });
      await expect(run([...args, "--confirm", "--token", "jwt-value"])).rejects.toThrow(
        "process.exit",
      );
      expect(spies.errorSpy.mock.calls).toEqual([[KEY_UNREAD_LINE]]);
      expect(mockEngine.getInjectionPolicy.mock.calls).toEqual([["secret://key", TOKEN_CALLER]]);
      expect(resolveSecretId).not.toHaveBeenCalled();
      expect(mockEngine.setInjectionPolicy).not.toHaveBeenCalled();
    });
  });

  it("with a token, the key's handle is judged by the token's scope", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["admin"], project: "a" }));
    storePolicies({ "secret://b/key": withEntries(E1), "secret://a/slot": SLOT });
    await expect(
      run([
        "approve",
        "secret://a/slot",
        "--key",
        "secret://b/key",
        "--entry",
        "env",
        "--token",
        "jwt-value",
      ]),
    ).rejects.toThrow("process.exit");
    expect(spies.errorSpy.mock.calls).toEqual([
      ["Error: [ACCESS_DENIED] Access denied: Token is scoped to project: a"],
    ]);
    expect(mockEngine.auditScopeRefusal.mock.calls).toEqual([
      [
        expect.objectContaining({ principal_id: "agent-1", interface: "cli" }),
        "secret render approve",
        "project",
      ],
    ]);
    expect(mockEngine.getInjectionPolicy).not.toHaveBeenCalled();
    expect(mockEngine.setInjectionPolicy).not.toHaveBeenCalled();
  });
});

describe("secret render revoke", () => {
  const REVOKE = ["revoke", "secret://slot", "--key", "secret://key", "--entry", "env"];

  it("revoke removes that approval and nothing else", async () => {
    storePolicies({
      "secret://key": withEntries(E1),
      "secret://slot": withApprovals(OTHER_APPROVAL, APPROVAL),
    });
    await run(REVOKE);
    expect(vi.mocked(resolveSecretId).mock.calls).toEqual([
      [mockEngine, "secret://key", undefined, "policy.grant"],
    ]);
    expect(mockEngine.setInjectionPolicy.mock.calls).toEqual([
      [
        "secret://slot",
        withApprovals(OTHER_APPROVAL),
        { acknowledge_interpreters: false },
        undefined,
      ],
    ]);
    expect(spies.errorSpy.mock.calls).toEqual([["OK: Render approval removed (secret://slot)"]]);
  });

  it("revoke of an approval not held writes nothing", async () => {
    storePolicies({
      "secret://key": withEntries(E1),
      "secret://slot": withApprovals(OTHER_APPROVAL),
    });
    await expect(run(REVOKE)).rejects.toThrow("process.exit");
    expect(spies.errorSpy.mock.calls).toEqual([
      ["Error: [INVALID_INPUT] the secret's policy holds no approval of that key's entry"],
    ]);
    expect(mockEngine.setInjectionPolicy).not.toHaveBeenCalled();
  });

  it("--key resolves the key's id only after the key's read under the caller's grant", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["admin", "read"] }));
    storePolicies({ "secret://key": withEntries(E1), "secret://slot": withApprovals(APPROVAL) });
    await run([...REVOKE, "--token", "jwt-value"]);
    expect(mockEngine.getInjectionPolicy.mock.calls[0]).toEqual(["secret://key", TOKEN_CALLER]);
    expect(vi.mocked(resolveSecretId).mock.calls).toEqual([
      [mockEngine, "secret://key", TOKEN_CALLER, "policy.grant"],
    ]);
    expect(vi.mocked(resolveSecretId).mock.invocationCallOrder[0] as number).toBeGreaterThan(
      mockEngine.getInjectionPolicy.mock.invocationCallOrder[0] as number,
    );
    expect(writtenPolicies()).toEqual([withApprovals()]);
  });

  it("--key: a key the caller may not read is refused as its read refuses it, no id resolved, nothing written", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["admin", "read"] }));
    storePoliciesKeyUnread({ "secret://slot": withApprovals(APPROVAL) });
    await expect(run([...REVOKE, "--token", "jwt-value"])).rejects.toThrow("process.exit");
    expect(spies.errorSpy.mock.calls).toEqual([[KEY_UNREAD_LINE]]);
    expect(mockEngine.getInjectionPolicy.mock.calls).toEqual([["secret://key", TOKEN_CALLER]]);
    expect(resolveSecretId).not.toHaveBeenCalled();
    expect(mockEngine.setInjectionPolicy).not.toHaveBeenCalled();
  });

  it("--key-id removes the approval without a read of the key", async () => {
    storePolicies({ "secret://slot": withApprovals(OTHER_APPROVAL, APPROVAL) });
    await run(["revoke", "secret://slot", "--key-id", KEY_ID, "--entry", "env"]);
    expect(resolveSecretId).not.toHaveBeenCalled();
    expect(mockEngine.getInjectionPolicy.mock.calls).toEqual([["secret://slot", undefined]]);
    expect(writtenPolicies()).toEqual([withApprovals(OTHER_APPROVAL)]);
  });

  it("with a token, revoke judges the key's handle by the token's scope", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["admin"], project: "a" }));
    storePolicies({ "secret://a/slot": withApprovals(APPROVAL) });
    await expect(
      run([
        "revoke",
        "secret://a/slot",
        "--key",
        "secret://b/key",
        "--entry",
        "env",
        "--token",
        "jwt-value",
      ]),
    ).rejects.toThrow("process.exit");
    expect(spies.errorSpy.mock.calls).toEqual([
      ["Error: [ACCESS_DENIED] Access denied: Token is scoped to project: a"],
    ]);
    expect(mockEngine.auditScopeRefusal.mock.calls).toEqual([
      [
        expect.objectContaining({ principal_id: "agent-1", interface: "cli" }),
        "secret render revoke",
        "project",
      ],
    ]);
    expect(resolveSecretId).not.toHaveBeenCalled();
    expect(mockEngine.setInjectionPolicy).not.toHaveBeenCalled();
  });
});

describe("secret render list", () => {
  const E1_VIEW = {
    name: "env",
    host: "h1.example",
    port: 22,
    user: "deploy",
    path: "/srv/app/.env",
    host_key_fingerprints: [FP_HOST],
    slots: ["secret://bot-token"],
    digest: D1,
  };
  let stdoutWrite: MockInstance;

  beforeEach(() => {
    stdoutWrite = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  });

  afterEach(() => {
    stdoutWrite.mockRestore();
  });

  it("list prints the entries' view and the approvals", async () => {
    storePolicies({ "secret://k": withEntries(E1) });
    await run(["list", "secret://k"]);
    expect(spies.stdout()).toBe(
      JSON.stringify({ key_id: KEY_ID, entries: [E1_VIEW], approvals: [] }, null, 2),
    );
  });

  it("list names the listed secret's id as key_id, resolved after the read (P-3)", async () => {
    storePolicies({ "secret://k": withEntries(E1) });
    await run(["list", "secret://k"]);
    expect(vi.mocked(resolveSecretId).mock.calls).toEqual([[mockEngine, "secret://k", undefined]]);
    expect(vi.mocked(resolveSecretId).mock.invocationCallOrder[0] as number).toBeGreaterThan(
      mockEngine.getInjectionPolicy.mock.invocationCallOrder[0] as number,
    );
    expect((JSON.parse(spies.stdout()) as { key_id: string }).key_id).toBe(KEY_ID);
  });

  it("list --template prints the template's bytes alone", async () => {
    storePolicies({ "secret://k": withEntries(B, E1) });
    await run(["list", "secret://k", "--template", "env"]);
    expect(stdoutWrite.mock.calls).toEqual([[E1_TEMPLATE]]);
    expect(spies.logSpy).not.toHaveBeenCalled();
    expect(resolveSecretId).not.toHaveBeenCalled();

    await expect(run(["list", "secret://k", "--template", "api"])).rejects.toThrow("process.exit");
    expect(spies.errorSpy.mock.calls).toEqual([
      ["Error: [INVALID_INPUT] --template: the secret's policy holds no render entry of that name"],
    ]);
  });

  it("--template is judged before the vault opens", async () => {
    await expect(run(["list", "secret://k", "--template", "a b"])).rejects.toThrow("process.exit");
    expect(spies.errorSpy.mock.calls).toEqual([
      ["Error: [INVALID_INPUT] --template: Invalid name format"],
    ]);
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  describe("the stale mark", () => {
    const API: RenderEntry = { ...E1, name: "api", port: 2222 };
    const CURRENT: RenderApproval = APPROVAL;
    const CHANGED: RenderApproval = { key: KEY_ID, entry: "api", digest: D1 };
    const GONE: RenderApproval = { key: KEY_ID, entry: "gone", digest: D1 };
    const OTHER_KEY: RenderApproval = { key: OTHER_KEY_ID, entry: "api", digest: "0".repeat(64) };

    beforeEach(() => {
      storePolicies({
        "secret://slot": withApprovals(CURRENT, CHANGED, GONE, OTHER_KEY),
        "secret://key": withEntries(E1, API),
      });
      vi.mocked(resolveSecretId).mockImplementation(async (_engine, handle) =>
        handle === "secret://key" ? KEY_ID : SLOT_ID,
      );
    });

    it("an approval whose entry changed is listed stale", async () => {
      await run(["list", "secret://slot", "--key", "secret://key"]);
      expect(mockEngine.getInjectionPolicy.mock.calls).toEqual([
        ["secret://slot", undefined],
        ["secret://key", undefined],
      ]);
      const stdout = spies.stdout();
      expect(stdout).toBe(
        JSON.stringify(
          {
            key_id: SLOT_ID,
            entries: [],
            approvals: [CURRENT, { ...CHANGED, stale: true }, { ...GONE, stale: true }, OTHER_KEY],
          },
          null,
          2,
        ),
      );
      expect(stdout.includes("h1.example")).toBe(false);
      expect(stdout.includes(D1_PORT_2222)).toBe(false);
    });

    it("without --key nothing is marked and no read of the key happens", async () => {
      await run(["list", "secret://slot"]);
      expect(mockEngine.getInjectionPolicy.mock.calls).toEqual([["secret://slot", undefined]]);
      expect(vi.mocked(resolveSecretId).mock.calls).toEqual([
        [mockEngine, "secret://slot", undefined],
      ]);
      expect(spies.stdout()).toBe(
        JSON.stringify(
          { key_id: SLOT_ID, entries: [], approvals: [CURRENT, CHANGED, GONE, OTHER_KEY] },
          null,
          2,
        ),
      );
    });

    it("with a token, --key is judged by the token's scope", async () => {
      mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["read"], project: "a" }));
      await expect(
        run(["list", "secret://a/slot", "--key", "secret://b/key", "--token", "jwt-value"]),
      ).rejects.toThrow("process.exit");
      expect(spies.errorSpy.mock.calls).toEqual([
        ["Error: [ACCESS_DENIED] Access denied: Token is scoped to project: a"],
      ]);
      expect(mockEngine.auditScopeRefusal.mock.calls).toEqual([
        [
          expect.objectContaining({ principal_id: "agent-1", interface: "cli" }),
          "secret render list",
          "project",
        ],
      ]);
      expect(mockEngine.getInjectionPolicy).not.toHaveBeenCalled();
    });

    it.each<[string, string[], string]>([
      [
        "--key nope",
        ["list", "secret://slot", "--key", "nope"],
        "Error: [INVALID_HANDLE] Invalid handle: nope",
      ],
      [
        "--key beside --template",
        ["list", "secret://slot", "--key", "secret://key", "--template", "env"],
        "Error: [INVALID_INPUT] --key and --template exclude each other",
      ],
    ])("--key is judged before the vault opens: %s", async (_case, args, line) => {
      await expect(run(args)).rejects.toThrow("process.exit");
      expect(spies.errorSpy.mock.calls).toEqual([[line]]);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
    });
  });
});
