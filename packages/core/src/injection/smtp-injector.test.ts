import { describe, expect, it } from "vitest";
import type { InjectionPolicy, InjectionPolicyInput, SmtpAction, SmtpResult } from "@harpoc/shared";
import {
  ActionType,
  ErrorCode,
  MAX_ATTACHMENT_BYTES,
  MAX_ATTACHMENT_TOTAL_BYTES,
  MAX_SMTP_ATTACHMENTS,
  VaultError,
  injectionPolicyInputSchema,
} from "@harpoc/shared";
import type { SmtpSendOptions } from "./mail/smtp-client.js";
import type { MailTlsConfig, SmtpInjectorDeps, SmtpOAuth } from "./smtp-injector.js";
import { SmtpInjector, buildSmtpAuditDetails, executeSmtpAction } from "./smtp-injector.js";

const SECRET = "smtpuser:smtppass";

/** Build a full SmtpAction from a partial (bypasses the schema — the injector
 * receives an already-validated action; tests exercise its own guards). */
function baseAction(partial: Record<string, unknown> = {}): SmtpAction {
  return {
    type: ActionType.SMTP,
    host: "127.0.0.1",
    security: "tls",
    from: "sender@example.com",
    to: ["to@example.com"],
    subject: "hi",
    text: "body",
    ...partial,
  } as unknown as SmtpAction;
}

function basePolicy(partial: Partial<InjectionPolicyInput> = {}): InjectionPolicy {
  return injectionPolicyInputSchema.parse(partial);
}

/** Fake sendSmtp that records every call and reports all recipients accepted. */
function makeFakeSend(): {
  fn: NonNullable<SmtpInjectorDeps["sendSmtp"]>;
  calls: SmtpSendOptions[];
} {
  const calls: SmtpSendOptions[] = [];
  const fn: NonNullable<SmtpInjectorDeps["sendSmtp"]> = (opts) => {
    calls.push(opts);
    return Promise.resolve({ accepted: opts.envelope.recipients.length, messageId: null });
  };
  return { fn, calls };
}

/** A stat/readFile pair that throws if ever touched — proves no file was read. */
function throwingFsProbe(probed: string[]): Required<Pick<SmtpInjectorDeps, "stat" | "readFile">> {
  return {
    stat: (p: string) => {
      probed.push(p);
      return Promise.reject(new Error("stat must not be reached"));
    },
    readFile: (p: string) => {
      probed.push(p);
      return Promise.reject(new Error("readFile must not be reached"));
    },
  };
}

function firstCall(calls: SmtpSendOptions[]): SmtpSendOptions {
  expect(calls.length).toBeGreaterThan(0);
  return calls[0] as SmtpSendOptions;
}

describe("SmtpInjector — refusal ordering (security guardrails)", () => {
  it("attachments without a recipient allowlist refuse BEFORE any file read", async () => {
    const probed: string[] = [];
    const { fn, calls } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn, ...throwingFsProbe(probed) });

    await expect(
      injector.run(
        baseAction({ attachments: [{ path: "/secrets/id_rsa" }] }),
        SECRET,
        basePolicy({ smtp_recipient_allowlist: [] }),
        undefined,
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.ATTACHMENT_POLICY_REQUIRED });

    expect(probed).toEqual([]);
    expect(calls).toEqual([]);
  });

  it("the host allowlist is checked before the recipient rules", async () => {
    const probed: string[] = [];
    const { fn, calls } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn, ...throwingFsProbe(probed) });

    // Empty recipient allowlist + attachments would otherwise be
    // ATTACHMENT_POLICY_REQUIRED — HOST_NOT_ALLOWED proves the host check fires first.
    await expect(
      injector.run(
        baseAction({ host: "unlisted.example.net", attachments: [{ path: "/x" }] }),
        SECRET,
        basePolicy({ host_allowlist: ["smtp.example.com"], smtp_recipient_allowlist: [] }),
        undefined,
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.HOST_NOT_ALLOWED });

    expect(probed).toEqual([]);
    expect(calls).toEqual([]);
  });

  it("a configured allowlist constrains body-only sends too", async () => {
    const { fn, calls } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn });

    await expect(
      injector.run(
        baseAction({ to: ["evil@other.com"], text: "x" }),
        SECRET,
        basePolicy({ smtp_recipient_allowlist: ["*@example.com"] }),
        undefined,
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.RECIPIENT_NOT_ALLOWED });

    expect(calls).toEqual([]);
  });

  it("the recipient check runs before the attachment caps (mismatch → RECIPIENT_NOT_ALLOWED)", async () => {
    const probed: string[] = [];
    const { fn } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn, ...throwingFsProbe(probed) });

    await expect(
      injector.run(
        baseAction({ to: ["evil@other.com"], attachments: [{ path: "/x" }] }),
        SECRET,
        basePolicy({ smtp_recipient_allowlist: ["*@example.com"] }),
        undefined,
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.RECIPIENT_NOT_ALLOWED });

    expect(probed).toEqual([]);
  });
});

describe("SmtpInjector — attachment caps (vault-authored reasons only)", () => {
  it("refuses more than the attachment count cap", async () => {
    const probed: string[] = [];
    const { fn } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn, ...throwingFsProbe(probed) });
    const attachments = Array.from({ length: MAX_SMTP_ATTACHMENTS + 1 }, (_v, i) => ({
      path: `/f${i}`,
    }));

    let caught: unknown;
    try {
      await injector.run(
        baseAction({ attachments }),
        SECRET,
        basePolicy({ smtp_recipient_allowlist: ["*@example.com"] }),
        undefined,
        undefined,
      );
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(VaultError);
    expect((caught as VaultError).code).toBe(ErrorCode.ATTACHMENT_REJECTED);
    // Count guard fires before any stat, and the reason names no path.
    expect(probed).toEqual([]);
    expect((caught as VaultError).message).not.toContain("/f0");
  });

  it("refuses a single file over the per-file byte cap (reason is a policy string)", async () => {
    const { fn } = makeFakeSend();
    const injector = new SmtpInjector({
      sendSmtp: fn,
      stat: () => Promise.resolve({ size: MAX_ATTACHMENT_BYTES + 1 }),
      readFile: () => Promise.reject(new Error("must not read an over-cap file")),
    });

    let caught: unknown;
    try {
      await injector.run(
        baseAction({ attachments: [{ path: "/big.bin" }] }),
        SECRET,
        basePolicy({ smtp_recipient_allowlist: ["*@example.com"] }),
        undefined,
        undefined,
      );
    } catch (e) {
      caught = e;
    }
    expect((caught as VaultError).code).toBe(ErrorCode.ATTACHMENT_REJECTED);
    expect((caught as VaultError).message).not.toContain("/big.bin");
  });

  it("refuses when the total across files exceeds the message cap", async () => {
    const { fn } = makeFakeSend();
    const per = 9 * 1024 * 1024; // 9 MiB each, three files → 27 MiB > 25 MiB
    const injector = new SmtpInjector({
      sendSmtp: fn,
      stat: () => Promise.resolve({ size: per }),
      readFile: () => Promise.reject(new Error("must not read once total exceeded")),
    });

    let caught: unknown;
    try {
      await injector.run(
        baseAction({ attachments: [{ path: "/a" }, { path: "/b" }, { path: "/c" }] }),
        SECRET,
        basePolicy({ smtp_recipient_allowlist: ["*@example.com"] }),
        undefined,
        undefined,
      );
    } catch (e) {
      caught = e;
    }
    expect((caught as VaultError).code).toBe(ErrorCode.ATTACHMENT_REJECTED);
    expect(per * 3).toBeGreaterThan(MAX_ATTACHMENT_TOTAL_BYTES);
  });
});

describe("SmtpInjector — envelope and bcc", () => {
  it("bcc joins the envelope but never the message headers", async () => {
    const { fn, calls } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn });

    const { result } = await injector.run(
      baseAction({
        to: ["a@example.com"],
        cc: ["c@example.com"],
        bcc: ["hidden@secret.example"],
        text: "hi",
      }),
      SECRET,
      basePolicy({}),
      undefined,
      undefined,
    );

    const opts = firstCall(calls);
    expect(opts.envelope.recipients).toEqual(
      expect.arrayContaining(["a@example.com", "c@example.com", "hidden@secret.example"]),
    );
    // The assembled message never carries the bcc address or a Bcc header.
    expect(opts.message).not.toContain("hidden@secret.example");
    expect(opts.message.toLowerCase()).not.toContain("bcc:");
    // To/Cc DO appear in the headers.
    expect(opts.message).toContain("a@example.com");
    expect(opts.message).toContain("c@example.com");
    expect(result.accepted).toBe(3);
  });

  it("returns the assembled Message-ID as message_id", async () => {
    const { fn } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn });
    const { result } = await injector.run(
      baseAction(),
      SECRET,
      basePolicy({}),
      undefined,
      undefined,
    );
    expect(result.message_id).toMatch(/^<.+@harpoc\.local>$/);
  });
});

describe("SmtpInjector — auth arms", () => {
  it("uses XOAUTH2 when an oauth token is provided; the secret password never appears", async () => {
    const { fn, calls } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn });

    await injector.run(baseAction(), "ignored-user:ignored-pass", basePolicy({}), undefined, {
      accessToken: "tok-abc123",
      username: "oauth-user@example.com",
    });

    const auth = firstCall(calls).auth;
    expect(auth).toEqual({
      kind: "xoauth2",
      username: "oauth-user@example.com",
      accessToken: "tok-abc123",
    });
    expect(JSON.stringify(auth)).not.toContain("ignored-pass");
  });

  it("uses the password arm from the secret value when no oauth token; the token slot stays empty", async () => {
    const { fn, calls } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn });

    await injector.run(baseAction(), "smtpuser:s3cr3t", basePolicy({}), undefined, undefined);

    const auth = firstCall(calls).auth;
    expect(auth).toEqual({ kind: "password", username: "smtpuser", password: "s3cr3t" });
    expect(JSON.stringify(auth)).not.toContain("accessToken");
  });

  it("refuses a secret value without a colon separator", async () => {
    const { fn } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn });
    await expect(
      injector.run(baseAction(), "no-colon-here", basePolicy({}), undefined, undefined),
    ).rejects.toBeInstanceOf(VaultError);
  });
});

describe("SmtpInjector — TLS and port derivation", () => {
  it("maps connection.tls === false to the plaintext opt-out", async () => {
    const { fn, calls } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn });
    const connection: MailTlsConfig = { tls: false };
    await injector.run(baseAction(), SECRET, basePolicy({}), connection, undefined);
    expect(firstCall(calls).tls).toBe(false);
  });

  it("passes a custom CA through from the connection config", async () => {
    const { fn, calls } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn });
    const connection: MailTlsConfig = { tls: { ca: "-----BEGIN CERT-----" } };
    await injector.run(baseAction(), SECRET, basePolicy({}), connection, undefined);
    expect(firstCall(calls).tls).toEqual({ ca: "-----BEGIN CERT-----" });
  });

  it("leaves tls unset for an undefined connection (system CAs)", async () => {
    const { fn, calls } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn });
    await injector.run(baseAction(), SECRET, basePolicy({}), undefined, undefined);
    expect(firstCall(calls).tls).toBeUndefined();
  });

  it("defaults the port to 465 (tls) and 587 (starttls)", async () => {
    const { fn, calls } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn });
    await injector.run(
      baseAction({ security: "tls" }),
      SECRET,
      basePolicy({}),
      undefined,
      undefined,
    );
    await injector.run(
      baseAction({ security: "starttls" }),
      SECRET,
      basePolicy({}),
      undefined,
      undefined,
    );
    expect(calls[0]?.port).toBe(465);
    expect(calls[1]?.port).toBe(587);
  });

  it("honors an explicit port over the security default", async () => {
    const { fn, calls } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn });
    await injector.run(baseAction({ port: 2525 }), SECRET, basePolicy({}), undefined, undefined);
    expect(firstCall(calls).port).toBe(2525);
  });
});

describe("SmtpInjector — error redaction and translation", () => {
  it("redacts the credential from a thrown delivery error", async () => {
    const injector = new SmtpInjector({
      sendSmtp: () =>
        Promise.reject(
          new VaultError(
            ErrorCode.SMTP_DELIVERY_FAILED,
            "SMTP delivery failed: relay said s3cr3tpass",
          ),
        ),
    });

    let caught: unknown;
    try {
      await injector.run(baseAction(), "smtpuser:s3cr3tpass", basePolicy({}), undefined, undefined);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(VaultError);
    expect((caught as VaultError).code).toBe(ErrorCode.SMTP_DELIVERY_FAILED);
    expect((caught as VaultError).message).not.toContain("s3cr3tpass");
  });

  it("translates a reserved-header plain Error from assembleMessage into a VaultError", async () => {
    const { fn } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn });
    // headers set a reserved field — mime.ts throws a plain Error; the injector
    // must not let a raw Error escape.
    await expect(
      injector.run(
        baseAction({ headers: { Bcc: "smuggled@evil.example" } }),
        SECRET,
        basePolicy({}),
        undefined,
        undefined,
      ),
    ).rejects.toBeInstanceOf(VaultError);
  });
});

describe("buildSmtpAuditDetails", () => {
  it("names every attachment path and the total bytes", () => {
    const action = baseAction({
      to: ["a@example.com"],
      cc: ["c@example.com"],
      bcc: ["b@example.com"],
      attachments: [{ path: "/a.txt" }, { path: "/b.txt" }],
    });
    const details = buildSmtpAuditDetails(action, [
      { path: "/a.txt", bytes: 100 },
      { path: "/b.txt", bytes: 250 },
    ]);
    expect(details.attachment_paths).toEqual(["/a.txt", "/b.txt"]);
    expect(details.attachment_total_bytes).toBe(350);
    expect(details.recipients).toEqual(["a@example.com", "c@example.com", "b@example.com"]);
    expect(details.from).toBe("sender@example.com");
    expect(details.host).toBe("127.0.0.1");
  });

  it("run() returns audit details reflecting the resolved attachment bytes", async () => {
    const { fn } = makeFakeSend();
    const injector = new SmtpInjector({
      sendSmtp: fn,
      stat: (p: string) => Promise.resolve({ size: p === "/a.txt" ? 100 : 250 }),
      readFile: (p: string) => Promise.resolve(Buffer.alloc(p === "/a.txt" ? 100 : 250)),
    });
    const { auditDetails } = await injector.run(
      baseAction({ attachments: [{ path: "/a.txt" }, { path: "/b.txt" }] }),
      SECRET,
      basePolicy({ smtp_recipient_allowlist: ["*@example.com"] }),
      undefined,
      undefined,
    );
    expect(auditDetails.attachment_paths).toEqual(["/a.txt", "/b.txt"]);
    expect(auditDetails.attachment_total_bytes).toBe(350);
  });
});

describe("executeSmtpAction (free function, default deps)", () => {
  it("enforces the refusal ordering without reaching the network", async () => {
    // ATTACHMENT_POLICY_REQUIRED fires before any stat/read/socket, so the real
    // default deps are never exercised.
    await expect(
      executeSmtpAction(
        baseAction({ attachments: [{ path: "/x" }] }),
        SECRET,
        basePolicy({ smtp_recipient_allowlist: [] }),
        undefined,
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.ATTACHMENT_POLICY_REQUIRED });
  });

  it("pins the shared SmtpResult wire shape (compile-time)", () => {
    const oauth: SmtpOAuth | undefined = undefined;
    expect(oauth).toBeUndefined();
    // Compile-time pin against the shared import: the injector's exported
    // result type is shared's, never a local shadow.
    const result = { type: "smtp", accepted: 1, message_id: "x" } satisfies SmtpResult;
    expect(result.accepted).toBe(1);
    expect(typeof executeSmtpAction).toBe("function");
  });
});
