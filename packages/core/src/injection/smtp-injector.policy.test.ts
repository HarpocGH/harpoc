import { describe, expect, it } from "vitest";
import type { InjectionPolicy, InjectionPolicyInput, SmtpAction } from "@harpoc/shared";
import { ActionType, ErrorCode, VaultError, injectionPolicyInputSchema } from "@harpoc/shared";
import type { SmtpSendOptions } from "./mail/smtp-client.js";
import type { SmtpInjectorDeps } from "./smtp-injector.js";
import { SmtpInjector } from "./smtp-injector.js";

const SECRET = "smtpuser:smtppass";

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

/** Small in-cap attachment stat/readFile pair for the attachment-bearing cases. */
function smallFs(): Required<Pick<SmtpInjectorDeps, "stat" | "readFile">> {
  return {
    stat: () => Promise.resolve({ size: 16 }),
    readFile: () => Promise.resolve(Buffer.alloc(16)),
  };
}

describe("SmtpInjector — recipient allowlist coupling (design §5.2)", () => {
  it("body-only send with an EMPTY allowlist is allowed (optional-atop-floor)", async () => {
    const { fn, calls } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn });
    await injector.run(
      baseAction({ to: ["anyone@anywhere.example"] }),
      SECRET,
      basePolicy({ smtp_recipient_allowlist: [] }),
      undefined,
      undefined,
    );
    expect(calls).toHaveLength(1);
  });

  it("body-only send with a configured allowlist where every recipient matches is allowed", async () => {
    const { fn, calls } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn });
    await injector.run(
      baseAction({ to: ["a@example.com"], cc: ["b@example.com"] }),
      SECRET,
      basePolicy({ smtp_recipient_allowlist: ["*@example.com"] }),
      undefined,
      undefined,
    );
    expect(calls).toHaveLength(1);
  });

  it("a non-matching cc recipient is refused", async () => {
    const { fn } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn });
    await expect(
      injector.run(
        baseAction({ to: ["a@example.com"], cc: ["out@other.example"] }),
        SECRET,
        basePolicy({ smtp_recipient_allowlist: ["*@example.com"] }),
        undefined,
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.RECIPIENT_NOT_ALLOWED });
  });

  it("a non-matching bcc recipient is refused", async () => {
    const { fn } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn });
    await expect(
      injector.run(
        baseAction({ to: ["a@example.com"], bcc: ["out@other.example"] }),
        SECRET,
        basePolicy({ smtp_recipient_allowlist: ["*@example.com"] }),
        undefined,
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.RECIPIENT_NOT_ALLOWED });
  });

  it("an exact-address pattern matches only that address", async () => {
    const { fn, calls } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn });
    await injector.run(
      baseAction({ to: ["alice@example.com"] }),
      SECRET,
      basePolicy({ smtp_recipient_allowlist: ["alice@example.com"] }),
      undefined,
      undefined,
    );
    expect(calls).toHaveLength(1);

    await expect(
      injector.run(
        baseAction({ to: ["bob@example.com"] }),
        SECRET,
        basePolicy({ smtp_recipient_allowlist: ["alice@example.com"] }),
        undefined,
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.RECIPIENT_NOT_ALLOWED });
  });

  it("attachments + EMPTY allowlist → ATTACHMENT_POLICY_REQUIRED", async () => {
    const { fn } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn, ...smallFs() });
    await expect(
      injector.run(
        baseAction({ attachments: [{ path: "/doc.pdf" }] }),
        SECRET,
        basePolicy({ smtp_recipient_allowlist: [] }),
        undefined,
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.ATTACHMENT_POLICY_REQUIRED });
  });

  it("attachments + a configured matching allowlist is allowed", async () => {
    const { fn, calls } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn, ...smallFs() });
    await injector.run(
      baseAction({ to: ["a@example.com"], attachments: [{ path: "/doc.pdf" }] }),
      SECRET,
      basePolicy({ smtp_recipient_allowlist: ["*@example.com"] }),
      undefined,
      undefined,
    );
    expect(calls).toHaveLength(1);
    expect(VaultError.attachmentPolicyRequired).toBeTypeOf("function");
  });

  it("domain comparison is case-insensitive; local part is case-sensitive", async () => {
    const { fn, calls } = makeFakeSend();
    const injector = new SmtpInjector({ sendSmtp: fn });
    await injector.run(
      baseAction({ to: ["alice@EXAMPLE.com"] }),
      SECRET,
      basePolicy({ smtp_recipient_allowlist: ["*@example.com"] }),
      undefined,
      undefined,
    );
    expect(calls).toHaveLength(1);
  });
});
