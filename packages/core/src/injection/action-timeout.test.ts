import { describe, expect, it } from "vitest";
import type { SftpRenderAction, UseSecretAction } from "@harpoc/shared";
import { MAX_DOCKER_TIMEOUT_MS } from "@harpoc/shared";
import { actionTimeoutRefusal } from "./action-timeout.js";
import { BOOT } from "./__fixtures__/ssh-public-keys.js";

const CONTEXTS = [
  "http",
  "process",
  "mcp",
  "git",
  "ssh",
  "sftp",
  "docker_registry",
  "smtp",
  "imap",
  "websocket",
] as const;
const OUTSIDE: unknown[] = [0, -1, 1.5, "30000", Number.NaN, Number.POSITIVE_INFINITY, null];

function action(type: unknown, timeout?: unknown): UseSecretAction {
  return {
    type,
    ...(timeout === undefined ? {} : { timeout_ms: timeout }),
  } as UseSecretAction;
}

function cap(type: string): number {
  return type === "docker_registry" ? MAX_DOCKER_TIMEOUT_MS : 300_000;
}

describe("actionTimeoutRefusal", () => {
  it.each(CONTEXTS)(
    "%s: a timeout_ms outside the schema is refused with the context's cap",
    (type) => {
      for (const value of [...OUTSIDE, cap(type) + 1]) {
        expect(actionTimeoutRefusal(action(type, value))).toBe(
          `timeout_ms must be a positive integer up to ${String(cap(type))}`,
        );
      }
    },
  );

  it.each(CONTEXTS)("%s: an absent timeout_ms, 1 and the cap pass", (type) => {
    for (const value of [undefined, 1, cap(type)]) {
      expect(actionTimeoutRefusal(action(type, value))).toBeUndefined();
    }
  });

  it("a bootstrap action passes the table: it carries no timeout_ms", () => {
    expect(actionTimeoutRefusal(BOOT)).toBeUndefined();
    expect(actionTimeoutRefusal({ ...BOOT, port: 2222, sudoers: true })).toBeUndefined();
  });

  it("a render passes the table as the sftp context, and is refused above 300000", () => {
    const render: SftpRenderAction = { type: "sftp", operation: "render", entry: "env" };
    expect(actionTimeoutRefusal(render)).toBeUndefined();
    for (const value of [1, 300_000]) {
      expect(actionTimeoutRefusal({ ...render, timeout_ms: value })).toBeUndefined();
    }
    expect(actionTimeoutRefusal({ ...render, timeout_ms: 300_001 })).toBe(
      "timeout_ms must be a positive integer up to 300000",
    );
  });

  it("the database context is not judged here", () => {
    expect(actionTimeoutRefusal(action("database", 0))).toBeUndefined();
  });

  it("an action type that is no context is not judged here", () => {
    for (const type of ["ftp", "constructor", "__proto__", "toString", 7, null, undefined]) {
      expect(actionTimeoutRefusal(action(type, 0))).toBeUndefined();
    }
  });
});
