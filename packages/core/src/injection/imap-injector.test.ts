import { describe, expect, it } from "vitest";
import type { ImapAction, ImapResult, InjectionPolicy, InjectionPolicyInput } from "@harpoc/shared";
import { ActionType, ErrorCode, VaultError, injectionPolicyInputSchema } from "@harpoc/shared";
import type { ImapConnectOptions, ImapMessage } from "./mail/imap-client.js";
import type {
  ImapClientLike,
  ImapInjectorDeps,
  ImapOAuth,
  ImapOperationFields,
} from "./imap-injector.js";
import { ImapInjector, buildImapAuditDetails, executeImapAction } from "./imap-injector.js";

const SECRET = "imapuser:imappass";

/** Build a full ImapAction from a partial (bypasses the schema — the injector
 * receives an already-validated action; tests exercise its own guards). */
function baseAction(partial: Record<string, unknown> = {}): ImapAction {
  return {
    type: ActionType.IMAP,
    host: "127.0.0.1",
    port: 993,
    mailbox: "INBOX",
    operation: { kind: "search", unseen: true },
    ...partial,
  } as unknown as ImapAction;
}

function basePolicy(partial: Partial<InjectionPolicyInput> = {}): InjectionPolicy {
  return injectionPolicyInputSchema.parse(partial);
}

interface FakeClient extends ImapClientLike {
  selectCalls: Array<{ mailbox: string; readOnly: boolean }>;
}

/** A fake ImapClientLike recording every call; each method resolves to a
 * caller-supplied canned value where relevant. */
function makeFakeClient(overrides: Partial<ImapClientLike> = {}): FakeClient {
  const selectCalls: Array<{ mailbox: string; readOnly: boolean }> = [];
  return {
    selectCalls,
    select: (mailbox: string, readOnly: boolean) => {
      selectCalls.push({ mailbox, readOnly });
      return Promise.resolve({ exists: 0 });
    },
    searchUids: () => Promise.resolve([1, 2, 3]),
    fetch: () => Promise.resolve([]),
    store: (uids: number[]) => Promise.resolve(uids.length),
    move: (uids: number[]) => Promise.resolve(uids.length),
    copy: (uids: number[]) => Promise.resolve(uids.length),
    expunge: () => Promise.resolve(0),
    logout: () => Promise.resolve(),
    ...overrides,
  };
}

/** connectImap fake that fails the test if it is ever invoked — proves a
 * refused mutation never opens a socket. */
function connectMustNotBeCalled(): {
  fn: NonNullable<ImapInjectorDeps["connectImap"]>;
  calls: number[];
} {
  const calls: number[] = [];
  const fn: NonNullable<ImapInjectorDeps["connectImap"]> = () => {
    calls.push(1);
    throw new Error("connectImap must not be called");
  };
  return { fn, calls };
}

function connectReturning(client: ImapClientLike): {
  fn: NonNullable<ImapInjectorDeps["connectImap"]>;
  opts: ImapConnectOptions[];
} {
  const opts: ImapConnectOptions[] = [];
  const fn: NonNullable<ImapInjectorDeps["connectImap"]> = (o) => {
    opts.push(o);
    return Promise.resolve(client);
  };
  return { fn, opts };
}

describe("ImapInjector — imap_read_only mutation gate (fires before any socket)", () => {
  const mutationKinds: Array<{ kind: string; operation: Record<string, unknown> }> = [
    { kind: "store", operation: { kind: "store", uids: [1], add_flags: ["\\Seen"] } },
    { kind: "move", operation: { kind: "move", uids: [1], target_mailbox: "Archive" } },
    { kind: "copy", operation: { kind: "copy", uids: [1], target_mailbox: "Archive" } },
    { kind: "expunge", operation: { kind: "expunge" } },
  ];

  for (const { kind, operation } of mutationKinds) {
    it(`refuses '${kind}' under imap_read_only with IMAP_MUTATION_NOT_ALLOWED, zero connections`, async () => {
      const { fn, calls } = connectMustNotBeCalled();
      const injector = new ImapInjector({ connectImap: fn });

      await expect(
        injector.run(
          baseAction({ operation }),
          SECRET,
          basePolicy({ imap_read_only: true }),
          undefined,
          undefined,
        ),
      ).rejects.toMatchObject({ code: ErrorCode.IMAP_MUTATION_NOT_ALLOWED });

      expect(calls).toEqual([]);
    });
  }

  it("allows a mutation when imap_read_only is false", async () => {
    const client = makeFakeClient();
    const { fn } = connectReturning(client);
    const injector = new ImapInjector({ connectImap: fn });

    const { result } = await injector.run(
      baseAction({ operation: { kind: "expunge" } }),
      SECRET,
      basePolicy({ imap_read_only: false }),
      undefined,
      undefined,
    );
    expect(result).toEqual({ type: "imap", operation: "expunge", affected: 0 });
  });
});

describe("ImapInjector — read-only SELECT (EXAMINE) semantics", () => {
  it("search/fetch always select with readOnly:true, even when imap_read_only is false", async () => {
    const client = makeFakeClient();
    const { fn } = connectReturning(client);
    const injector = new ImapInjector({ connectImap: fn });

    await injector.run(
      baseAction({ operation: { kind: "search", unseen: true } }),
      SECRET,
      basePolicy({ imap_read_only: false }),
      undefined,
      undefined,
    );
    expect(client.selectCalls).toEqual([{ mailbox: "INBOX", readOnly: true }]);
  });

  it("fetch also selects with readOnly:true", async () => {
    const client = makeFakeClient();
    const { fn } = connectReturning(client);
    const injector = new ImapInjector({ connectImap: fn });

    await injector.run(
      baseAction({ operation: { kind: "fetch", uids: [1], parts: "envelope" } }),
      SECRET,
      basePolicy({}),
      undefined,
      undefined,
    );
    expect(client.selectCalls).toEqual([{ mailbox: "INBOX", readOnly: true }]);
  });

  it("a mutation (allowed, imap_read_only false) selects with readOnly:false (SELECT)", async () => {
    const client = makeFakeClient();
    const { fn } = connectReturning(client);
    const injector = new ImapInjector({ connectImap: fn });

    await injector.run(
      baseAction({ operation: { kind: "store", uids: [1], add_flags: ["\\Seen"] } }),
      SECRET,
      basePolicy({ imap_read_only: false }),
      undefined,
      undefined,
    );
    expect(client.selectCalls).toEqual([{ mailbox: "INBOX", readOnly: false }]);
  });
});

describe("ImapInjector — host allowlist", () => {
  it("refuses a host outside the allowlist before connecting", async () => {
    const { fn, calls } = connectMustNotBeCalled();
    const injector = new ImapInjector({ connectImap: fn });

    await expect(
      injector.run(
        baseAction({ host: "unlisted.example.net" }),
        SECRET,
        basePolicy({ host_allowlist: ["imap.example.com"] }),
        undefined,
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.HOST_NOT_ALLOWED });
    expect(calls).toEqual([]);
  });

  it("an empty allowlist permits any host (optional-atop-floor)", async () => {
    const client = makeFakeClient();
    const { fn } = connectReturning(client);
    const injector = new ImapInjector({ connectImap: fn });

    await injector.run(
      baseAction(),
      SECRET,
      basePolicy({ host_allowlist: [] }),
      undefined,
      undefined,
    );
    expect(client.selectCalls.length).toBe(1);
  });

  it("a matching host is permitted", async () => {
    const client = makeFakeClient();
    const { fn } = connectReturning(client);
    const injector = new ImapInjector({ connectImap: fn });

    await injector.run(
      baseAction({ host: "127.0.0.1" }),
      SECRET,
      basePolicy({ host_allowlist: ["127.0.0.1"] }),
      undefined,
      undefined,
    );
    expect(client.selectCalls.length).toBe(1);
  });
});

describe("ImapInjector — fetched content sanitization", () => {
  it("redacts a credential planted in a fetched message body", async () => {
    const secretValue = "imapuser:s3cr3tpass";
    const messages: ImapMessage[] = [
      {
        uid: 1,
        flags: [],
        headers: "Subject: leak\r\n",
        text: "please use password: s3cr3tpass to log in",
      },
    ];
    const client = makeFakeClient({ fetch: () => Promise.resolve(messages) });
    const { fn } = connectReturning(client);
    const injector = new ImapInjector({ connectImap: fn });

    const { result } = await injector.run(
      baseAction({ operation: { kind: "fetch", uids: [1], parts: "full" } }),
      secretValue,
      basePolicy({}),
      undefined,
      undefined,
    );

    expect("messages" in result).toBe(true);
    const out = (result as { messages: ImapMessage[] }).messages;
    expect(out[0]?.text).toContain("[REDACTED]");
    expect(out[0]?.text).not.toContain("s3cr3tpass");
    expect(JSON.stringify(out)).not.toContain("s3cr3tpass");
  });

  it("does not touch message content when no credential is present", async () => {
    const messages: ImapMessage[] = [{ uid: 1, flags: ["\\Seen"], text: "hello world" }];
    const client = makeFakeClient({ fetch: () => Promise.resolve(messages) });
    const { fn } = connectReturning(client);
    const injector = new ImapInjector({ connectImap: fn });

    const { result } = await injector.run(
      baseAction({ operation: { kind: "fetch", uids: [1], parts: "text" } }),
      SECRET,
      basePolicy({}),
      undefined,
      undefined,
    );
    const out = (result as { messages: ImapMessage[] }).messages;
    expect(out[0]?.text).toBe("hello world");
  });
});

describe("ImapInjector — audit details shape", () => {
  it("buildImapAuditDetails names host, mailbox, operation kind and uid_count from the result", () => {
    const action = baseAction({
      host: "imap.example.com",
      mailbox: "Work",
      operation: { kind: "search" },
    });
    expect(buildImapAuditDetails(action, { uids: [1, 2] })).toEqual({
      host: "imap.example.com",
      mailbox: "Work",
      operation: "search",
      uid_count: 2,
    });
    expect(buildImapAuditDetails(action, { affected: 5 })).toEqual({
      host: "imap.example.com",
      mailbox: "Work",
      operation: "search",
      uid_count: 5,
    });
  });

  it("buildImapAuditDetails carries auth_account when the action names an XOAUTH2 identity", () => {
    const action = baseAction({
      host: "imap.example.com",
      mailbox: "Work",
      account: "agent@example.com",
      operation: { kind: "search" },
    });
    expect(buildImapAuditDetails(action, { uids: [1] })).toEqual({
      host: "imap.example.com",
      mailbox: "Work",
      operation: "search",
      uid_count: 1,
      auth_account: "agent@example.com",
    });
  });

  it("reports uid_count 0 for a zero-affected mutating result", () => {
    const action = baseAction({ operation: { kind: "expunge" } });
    expect(buildImapAuditDetails(action, { affected: 0 })).toMatchObject({ uid_count: 0 });
  });

  it("run() returns audit details reflecting the operation kind and mailbox", async () => {
    const client = makeFakeClient({ searchUids: () => Promise.resolve([7, 8, 9]) });
    const { fn } = connectReturning(client);
    const injector = new ImapInjector({ connectImap: fn });

    const { auditDetails } = await injector.run(
      baseAction({ host: "127.0.0.1", mailbox: "INBOX", operation: { kind: "search" } }),
      SECRET,
      basePolicy({}),
      undefined,
      undefined,
    );
    expect(auditDetails).toEqual({
      host: "127.0.0.1",
      mailbox: "INBOX",
      operation: "search",
      uid_count: 3,
    });
  });
});

describe("ImapInjector — auth arms", () => {
  it("uses XOAUTH2 when an oauth token is provided; the secret password never appears", async () => {
    const client = makeFakeClient();
    const { fn, opts } = connectReturning(client);
    const injector = new ImapInjector({ connectImap: fn });

    const oauth: ImapOAuth = { accessToken: "tok-abc123", username: "oauth-user@example.com" };
    await injector.run(baseAction(), "ignored-user:ignored-pass", basePolicy({}), undefined, oauth);

    expect(opts[0]?.auth).toEqual({
      kind: "xoauth2",
      username: "oauth-user@example.com",
      accessToken: "tok-abc123",
    });
    expect(JSON.stringify(opts[0]?.auth)).not.toContain("ignored-pass");
  });

  it("uses the password arm from the secret value when no oauth token is provided", async () => {
    const client = makeFakeClient();
    const { fn, opts } = connectReturning(client);
    const injector = new ImapInjector({ connectImap: fn });

    await injector.run(baseAction(), "imapuser:s3cr3t", basePolicy({}), undefined, undefined);

    expect(opts[0]?.auth).toEqual({ kind: "password", username: "imapuser", password: "s3cr3t" });
    expect(JSON.stringify(opts[0]?.auth)).not.toContain("accessToken");
  });

  it("never leaks the oauth token in a thrown error", async () => {
    const fn: NonNullable<ImapInjectorDeps["connectImap"]> = () =>
      Promise.reject(
        new VaultError(
          ErrorCode.IMAP_OPERATION_FAILED,
          "IMAP operation 'connect' failed: tok-abc123 rejected",
        ),
      );
    const injector = new ImapInjector({ connectImap: fn });
    const oauth: ImapOAuth = { accessToken: "tok-abc123", username: "oauth-user@example.com" };

    let caught: unknown;
    try {
      await injector.run(baseAction(), "ignored:ignored", basePolicy({}), undefined, oauth);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(VaultError);
    expect((caught as VaultError).message).not.toContain("tok-abc123");
  });

  it("refuses a secret value without a colon separator", async () => {
    const { fn, calls } = connectMustNotBeCalled();
    const injector = new ImapInjector({ connectImap: fn });
    await expect(
      injector.run(baseAction(), "no-colon-here", basePolicy({}), undefined, undefined),
    ).rejects.toBeInstanceOf(VaultError);
    expect(calls).toEqual([]);
  });
});

describe("ImapInjector — operation dispatch shapes", () => {
  it("search returns { uids }", async () => {
    const client = makeFakeClient({ searchUids: () => Promise.resolve([4, 5]) });
    const { fn } = connectReturning(client);
    const injector = new ImapInjector({ connectImap: fn });
    const { result } = await injector.run(
      baseAction({ operation: { kind: "search" } }),
      SECRET,
      basePolicy({}),
      undefined,
      undefined,
    );
    expect(result).toEqual({ type: "imap", operation: "search", uids: [4, 5] });
  });

  it("fetch returns { messages }", async () => {
    const messages: ImapMessage[] = [{ uid: 1, flags: [] }];
    const client = makeFakeClient({ fetch: () => Promise.resolve(messages) });
    const { fn } = connectReturning(client);
    const injector = new ImapInjector({ connectImap: fn });
    const { result } = await injector.run(
      baseAction({ operation: { kind: "fetch", uids: [1], parts: "headers" } }),
      SECRET,
      basePolicy({}),
      undefined,
      undefined,
    );
    expect(result).toEqual({ type: "imap", operation: "fetch", messages });
  });

  it("store/move/copy/expunge return { affected }", async () => {
    const client = makeFakeClient();
    const { fn } = connectReturning(client);
    const injector = new ImapInjector({ connectImap: fn });

    const store = await injector.run(
      baseAction({ operation: { kind: "store", uids: [1, 2], add_flags: ["\\Seen"] } }),
      SECRET,
      basePolicy({}),
      undefined,
      undefined,
    );
    expect(store.result).toEqual({ type: "imap", operation: "store", affected: 2 });

    const move = await injector.run(
      baseAction({ operation: { kind: "move", uids: [1], target_mailbox: "Archive" } }),
      SECRET,
      basePolicy({}),
      undefined,
      undefined,
    );
    expect(move.result).toEqual({ type: "imap", operation: "move", affected: 1 });

    const copy = await injector.run(
      baseAction({ operation: { kind: "copy", uids: [1, 2, 3], target_mailbox: "Archive" } }),
      SECRET,
      basePolicy({}),
      undefined,
      undefined,
    );
    expect(copy.result).toEqual({ type: "imap", operation: "copy", affected: 3 });

    const expunge = await injector.run(
      baseAction({ operation: { kind: "expunge" } }),
      SECRET,
      basePolicy({}),
      undefined,
      undefined,
    );
    expect(expunge.result).toEqual({ type: "imap", operation: "expunge", affected: 0 });
  });
});

describe("ImapInjector — logout", () => {
  it("logs out even when the operation throws", async () => {
    let loggedOut = false;
    const client = makeFakeClient({
      searchUids: () => Promise.reject(new VaultError(ErrorCode.IMAP_OPERATION_FAILED, "boom")),
      logout: () => {
        loggedOut = true;
        return Promise.resolve();
      },
    });
    const { fn } = connectReturning(client);
    const injector = new ImapInjector({ connectImap: fn });

    await expect(
      injector.run(baseAction(), SECRET, basePolicy({}), undefined, undefined),
    ).rejects.toBeInstanceOf(VaultError);
    expect(loggedOut).toBe(true);
  });

  it("logs out on a successful run", async () => {
    let loggedOut = false;
    const client = makeFakeClient({
      logout: () => {
        loggedOut = true;
        return Promise.resolve();
      },
    });
    const { fn } = connectReturning(client);
    const injector = new ImapInjector({ connectImap: fn });
    await injector.run(baseAction(), SECRET, basePolicy({}), undefined, undefined);
    expect(loggedOut).toBe(true);
  });
});

describe("ImapResult / ImapOperationFields (compile-time pins)", () => {
  it("pins the shared ImapResult wire shape (compile-time)", () => {
    // Compile-time pin against the shared import: the injector's exported
    // result type is shared's, never a local shadow.
    const result = {
      type: "imap",
      operation: "search",
      uids: [1, 2],
    } satisfies ImapResult;
    expect(result.operation).toBe("search");
  });

  it("rejects a two-field operation result (compile-time)", () => {
    // Compile-time pin: exactly one operation field per result.
    // @ts-expect-error uids and affected cannot coexist
    const bad: ImapOperationFields = { uids: [1], affected: 1 };
    expect(bad).toBeDefined();
  });
});

describe("executeImapAction (free function, default deps)", () => {
  it("enforces the read-only gate without reaching the network", async () => {
    await expect(
      executeImapAction(
        baseAction({ operation: { kind: "expunge" } }),
        SECRET,
        basePolicy({ imap_read_only: true }),
        undefined,
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.IMAP_MUTATION_NOT_ALLOWED });
  });
});
