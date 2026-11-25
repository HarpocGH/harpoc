import { describe, expect, it } from "vitest";
import type { UseSecretAction } from "@harpoc/shared";
import { actionShapeRefusal, imapOperationRefusal } from "./action-shape.js";
import { BOOT } from "./__fixtures__/ssh-public-keys.js";

const CONTEXTS = [
  "http",
  "process",
  "mcp",
  "database",
  "git",
  "ssh",
  "smtp",
  "imap",
  "websocket",
  "sftp",
  "docker_registry",
] as const;

describe("actionShapeRefusal", () => {
  it("passes an action of each context", () => {
    for (const type of CONTEXTS) expect(actionShapeRefusal({ type })).toBeUndefined();
  });

  it("passes an action with keys it does not know, and one on a null-prototype object", () => {
    expect(actionShapeRefusal({ type: "http", url: 5, unknown: true })).toBeUndefined();
    const bare = Object.assign(Object.create(null) as object, { type: "imap" });
    expect(actionShapeRefusal(bare)).toBeUndefined();
  });

  it("refuses an action that is no object", () => {
    const actions = [null, undefined, 5, "http", true, [], [{ type: "http" }], () => "http"];
    for (const action of actions) {
      expect(actionShapeRefusal(action)).toBe("action must be an object");
    }
  });

  it("refuses a type that names no context, with its text", () => {
    for (const type of ["ftp", "constructor", "__proto__", "toString", "HTTP", ""]) {
      expect(actionShapeRefusal({ type })).toBe(`Unsupported action type: ${type}`);
    }
  });

  it("refuses a type that is no string, with its JavaScript type", () => {
    const cases: [unknown, string][] = [
      [7, "number"],
      [null, "object"],
      [["http"], "object"],
      [true, "boolean"],
      [Symbol("http"), "symbol"],
    ];
    for (const [type, rendered] of cases) {
      expect(actionShapeRefusal({ type })).toBe(`Unsupported action type: ${rendered}`);
    }
    expect(actionShapeRefusal({})).toBe("Unsupported action type: undefined");
  });
});

describe("actionShapeRefusal — the ssh bootstrap's shape", () => {
  const OPERATION = 'ssh operation must be "bootstrap"';
  const ALONE =
    "an ssh bootstrap takes type, operation, host, user, port, public_key and sudoers alone";
  const NAMES =
    "an ssh bootstrap's host and user must be names of letters, digits, '.', '_' and '-'";
  const PORT = "an ssh bootstrap's port must be an integer from 1 to 65535";
  const KEY = "an ssh bootstrap's public_key must be a string of at most 4096 characters";
  const SUDOERS = "an ssh bootstrap's sudoers must be a boolean";

  it("passes an ssh action without operation, whatever else it carries", () => {
    const actions = [
      { type: "ssh" },
      { type: "ssh", host: "h1.example", user: "ubuntu", command: "id", timeout_ms: 5 },
      { type: "ssh", operation: undefined, host: "-h", user: 7, command: "id", public_key: 5 },
      { type: "ssh", port: "22", sudoers: "yes", public_key: "k".repeat(4097), extra: true },
    ];
    for (const action of actions) expect(actionShapeRefusal(action)).toBeUndefined();
  });

  it.each<[string, unknown, string]>([
    [
      "an operation other than bootstrap",
      { type: "ssh", operation: "copy", host: "h", user: "u", command: "id" },
      OPERATION,
    ],
    ["an operation of null", { ...BOOT, operation: null }, OPERATION],
    ["an operation that is an object", { ...BOOT, operation: { kind: "bootstrap" } }, OPERATION],
    ["an operation that is an array", { ...BOOT, operation: ["bootstrap"] }, OPERATION],
    [
      "an operation that is a String object",
      { ...BOOT, operation: Object("bootstrap") as unknown },
      OPERATION,
    ],
    ["a command beside the operation", { ...BOOT, command: "id" }, ALONE],
    ["a timeout_ms beside the operation", { ...BOOT, timeout_ms: 5 }, ALONE],
    ["a dash-led host", { ...BOOT, host: "-h" }, NAMES],
    ["a host of 256 characters", { ...BOOT, host: "h".repeat(256) }, NAMES],
    ["a user that is a number", { ...BOOT, user: 7 }, NAMES],
    ["port 0", { ...BOOT, port: 0 }, PORT],
    ["port 65536", { ...BOOT, port: 65_536 }, PORT],
    ["port 22.5", { ...BOOT, port: 22.5 }, PORT],
    ['port "22"', { ...BOOT, port: "22" }, PORT],
    ["a public_key that is a number", { ...BOOT, public_key: 5 }, KEY],
    ["a public_key of 4097 characters", { ...BOOT, public_key: "k".repeat(4097) }, KEY],
    ['sudoers "yes"', { ...BOOT, sudoers: "yes" }, SUDOERS],
  ])("refuses a malformed bootstrap, each with its fixed text — %s", (_label, action, text) => {
    expect(actionShapeRefusal(action)).toBe(text);
  });

  it.each<[string, Record<string, unknown>]>([
    ["port 1", { port: 1 }],
    ["port 65535", { port: 65_535 }],
    ["a public_key of 4096 characters", { public_key: "k".repeat(4096) }],
  ])("passes a bootstrap at the edge of each bound — %s", (_label, fields) => {
    expect(actionShapeRefusal({ ...BOOT, ...fields })).toBeUndefined();
  });

  it("passes a well-formed bootstrap", () => {
    expect(actionShapeRefusal(BOOT)).toBeUndefined();
    expect(
      actionShapeRefusal({ ...BOOT, port: 2222, sudoers: false, command: undefined }),
    ).toBeUndefined();
    const bare = Object.assign(Object.create(null) as object, BOOT);
    expect(actionShapeRefusal(bare)).toBeUndefined();
  });
});

describe("actionShapeRefusal — the sftp render's shape", () => {
  const FORBIDDEN = "an sftp render takes no host, user, port, remote_path or local_path";
  const ENTRY_NAME =
    "an sftp render's entry must be a name of letters, digits, '_' and '-' of at most 255 characters";
  const RENDER = { type: "sftp", operation: "render", entry: "env" };

  it("passes the three file operations and any other operation, whatever else they carry", () => {
    const transfer = { type: "sftp", host: "h1.example", user: "deploy", remote_path: "/srv/a" };
    const actions = [
      { ...transfer, operation: "upload", local_path: "/tmp/a", entry: "a b" },
      { ...transfer, operation: "download", local_path: "/tmp/a", entry: 5 },
      { ...transfer, operation: "list", entry: "env" },
      { ...transfer, operation: "bootstrap", entry: "" },
      { type: "sftp", entry: "a/b" },
    ];
    for (const action of actions) expect(actionShapeRefusal(action)).toBeUndefined();
  });

  it("passes a well-formed render, with and without timeout_ms, and with a forbidden key set to undefined", () => {
    expect(actionShapeRefusal(RENDER)).toBeUndefined();
    expect(actionShapeRefusal({ ...RENDER, timeout_ms: 5000 })).toBeUndefined();
    expect(
      actionShapeRefusal({
        ...RENDER,
        host: undefined,
        user: undefined,
        port: undefined,
        remote_path: undefined,
        local_path: undefined,
      }),
    ).toBeUndefined();
    expect(actionShapeRefusal({ ...RENDER, entry: "e".repeat(255) })).toBeUndefined();
  });

  it.each<[string, unknown]>([
    ["host", "h1.example"],
    ["user", "deploy"],
    ["port", 22],
    ["remote_path", "/srv/app/.env"],
    ["local_path", "/tmp/a"],
    ["host", null],
    ["port", 0],
  ])("refuses a render that carries %s (%s)", (key, value) => {
    expect(actionShapeRefusal({ ...RENDER, [key]: value })).toBe(FORBIDDEN);
  });

  it.each<[string, Record<string, unknown>]>([
    ["absent", { type: "sftp", operation: "render" }],
    ["a number", { ...RENDER, entry: 5 }],
    ["empty", { ...RENDER, entry: "" }],
    ["with a blank", { ...RENDER, entry: "a b" }],
    ["with a slash", { ...RENDER, entry: "a/b" }],
    ["of 256 characters", { ...RENDER, entry: "e".repeat(256) }],
  ])("refuses a render whose entry is no name — %s", (_label, action) => {
    expect(actionShapeRefusal(action)).toBe(ENTRY_NAME);
  });

  it("judges the forbidden keys before the entry", () => {
    expect(actionShapeRefusal({ type: "sftp", operation: "render", host: "h" })).toBe(FORBIDDEN);
  });

  it("leaves timeout_ms to the timeout guard", () => {
    expect(actionShapeRefusal({ ...RENDER, timeout_ms: -1 })).toBeUndefined();
    expect(actionShapeRefusal({ ...RENDER, timeout_ms: "5" })).toBeUndefined();
  });
});

describe("imapOperationRefusal", () => {
  const REFUSAL = "imap operation must be an object with a supported kind";

  function imap(operation?: unknown): UseSecretAction {
    return {
      type: "imap",
      ...(operation === undefined ? {} : { operation }),
    } as unknown as UseSecretAction;
  }

  it("does not judge an action of another context", () => {
    for (const type of CONTEXTS.filter((context) => context !== "imap")) {
      expect(imapOperationRefusal({ type } as unknown as UseSecretAction)).toBeUndefined();
    }
  });

  it("passes each of the six kinds", () => {
    for (const kind of ["search", "fetch", "store", "move", "copy", "expunge"]) {
      expect(imapOperationRefusal(imap({ kind }))).toBeUndefined();
    }
  });

  it("refuses an operation that is no object with one of the six kinds", () => {
    const operations = [
      undefined,
      null,
      "search",
      5,
      [],
      ["search"],
      {},
      { kind: 5 },
      { kind: "delete" },
      { kind: "__proto__" },
      { kind: "constructor" },
      { kind: "SEARCH" },
    ];
    for (const operation of operations) {
      expect(imapOperationRefusal(imap(operation))).toBe(REFUSAL);
    }
  });
});
