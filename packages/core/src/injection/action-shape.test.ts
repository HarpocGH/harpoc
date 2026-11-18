import { describe, expect, it } from "vitest";
import type { UseSecretAction } from "@harpoc/shared";
import { actionShapeRefusal, imapOperationRefusal } from "./action-shape.js";

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
