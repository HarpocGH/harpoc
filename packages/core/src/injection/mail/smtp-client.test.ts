import { afterEach, describe, expect, it } from "vitest";
import { VaultError } from "@harpoc/shared";
import { sendSmtp } from "./smtp-client.js";
import type { SmtpSendOptions } from "./smtp-client.js";
import { getFixtureCaPem, FIXTURE_HOST, startFakeSmtp } from "./__fixtures__/fake-smtp-server.js";
import type { FakeSmtp, SmtpScript } from "./__fixtures__/fake-smtp-server.js";

const MESSAGE =
  [
    "From: sender@harpoc.local",
    "To: rcpt@example.com",
    "Subject: hello",
    "",
    "a normal line",
    ".leading-dot must be stuffed",
    "trailing",
  ].join("\r\n") + "\r\n";

const servers: FakeSmtp[] = [];

async function fake(script: SmtpScript): Promise<FakeSmtp> {
  const srv = await startFakeSmtp(script);
  servers.push(srv);
  return srv;
}

function optsFor(srv: FakeSmtp, overrides: Partial<SmtpSendOptions> = {}): SmtpSendOptions {
  return {
    host: FIXTURE_HOST,
    port: srv.port,
    address: "127.0.0.1",
    security: "starttls",
    auth: { kind: "password", username: "u", password: "hunter2secret" },
    envelope: { from: "sender@harpoc.local", recipients: ["rcpt@example.com"] },
    message: MESSAGE,
    timeoutMs: 5_000,
    tls: { ca: getFixtureCaPem() },
    ...overrides,
  };
}

const PLAIN_CRED = Buffer.from("\0u\0hunter2secret").toString("base64");

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.close()));
});

describe("sendSmtp — credential never crosses the plaintext leg", () => {
  it("STARTTLS: no AUTH bytes ever appear on the plaintext leg", async () => {
    const srv = await fake({ starttls: true, authMechanisms: ["PLAIN"] });
    await sendSmtp(
      optsFor(srv, {
        security: "starttls",
        auth: { kind: "password", username: "u", password: "hunter2secret" },
      }),
    );
    const plain = srv.wire().plaintext.toString("latin1");
    expect(plain).not.toMatch(/AUTH/i);
    expect(plain).not.toContain(PLAIN_CRED);
    expect(srv.wire().postTls.toString("latin1")).toContain("AUTH PLAIN");
    expect(srv.wire().postTls.toString("latin1")).toContain(`AUTH PLAIN ${PLAIN_CRED}`);
  });

  it("server without STARTTLS → SMTP_STARTTLS_UNAVAILABLE, zero credential bytes sent", async () => {
    const srv = await fake({ starttls: false, authMechanisms: ["PLAIN"] });
    await expect(sendSmtp(optsFor(srv, { security: "starttls" }))).rejects.toMatchObject({
      code: "SMTP_STARTTLS_UNAVAILABLE",
    });
    const plain = srv.wire().plaintext.toString("latin1");
    expect(plain).not.toMatch(/AUTH|hunter2/i);
    expect(srv.wire().postTls.length).toBe(0);
  });
});

describe("sendSmtp — delivery over TLS", () => {
  it("implicit TLS happy path: EHLO → AUTH PLAIN → MAIL → RCPT → DATA (dot-stuffed) → QUIT", async () => {
    const srv = await fake({ starttls: false, authMechanisms: ["PLAIN"], implicitTls: true });
    const result = await sendSmtp(optsFor(srv, { security: "tls" }));
    expect(result).toEqual({ accepted: 1, messageId: null });

    const post = srv.wire().postTls.toString("latin1");
    expect(srv.wire().plaintext.length).toBe(0);
    expect(post).toContain(`AUTH PLAIN ${PLAIN_CRED}`);
    expect(post).toContain("MAIL FROM:<sender@harpoc.local>");
    expect(post).toContain("RCPT TO:<rcpt@example.com>");
    expect(post).toMatch(/\r\nDATA\r\n/);
    expect(post).toContain("..leading-dot must be stuffed");
    expect(post).toContain("QUIT");
  });

  it("STARTTLS upgrade then AUTH PLAIN over the secure leg", async () => {
    const srv = await fake({ starttls: true, authMechanisms: ["PLAIN"] });
    const result = await sendSmtp(optsFor(srv, { security: "starttls" }));
    expect(result).toEqual({ accepted: 1, messageId: null });

    const plain = srv.wire().plaintext.toString("latin1");
    expect(plain).toContain("STARTTLS");
    expect(plain).not.toMatch(/AUTH/i);
    expect(srv.wire().postTls.toString("latin1")).toContain(`AUTH PLAIN ${PLAIN_CRED}`);
  });

  it("multiple recipients: each gets its own RCPT TO and all are counted", async () => {
    const srv = await fake({ starttls: false, authMechanisms: ["PLAIN"], implicitTls: true });
    const result = await sendSmtp(
      optsFor(srv, {
        security: "tls",
        envelope: { from: "s@harpoc.local", recipients: ["a@x.test", "b@x.test", "c@x.test"] },
      }),
    );
    expect(result.accepted).toBe(3);
    const post = srv.wire().postTls.toString("latin1");
    expect(post).toContain("RCPT TO:<a@x.test>");
    expect(post).toContain("RCPT TO:<b@x.test>");
    expect(post).toContain("RCPT TO:<c@x.test>");
  });

  it("falls back to AUTH LOGIN when PLAIN is not advertised", async () => {
    const srv = await fake({ starttls: false, authMechanisms: ["LOGIN"], implicitTls: true });
    await sendSmtp(optsFor(srv, { security: "tls" }));
    const post = srv.wire().postTls.toString("latin1");
    expect(post).toContain("AUTH LOGIN");
    expect(post).toContain(Buffer.from("u").toString("base64"));
    expect(post).toContain(Buffer.from("hunter2secret").toString("base64"));
    expect(post).not.toContain("hunter2secret");
  });

  it("XOAUTH2 sends the SASL bearer blob and no other credential form", async () => {
    const srv = await fake({ starttls: false, authMechanisms: ["XOAUTH2"], implicitTls: true });
    await sendSmtp(
      optsFor(srv, {
        security: "tls",
        auth: { kind: "xoauth2", username: "user@x.test", accessToken: "tok-abc-123" },
      }),
    );
    const blob = Buffer.from("user=user@x.test\x01auth=Bearer tok-abc-123\x01\x01").toString(
      "base64",
    );
    const post = srv.wire().postTls.toString("latin1");
    expect(post).toContain(`AUTH XOAUTH2 ${blob}`);
    expect(post).not.toContain("tok-abc-123");
  });
});

describe("sendSmtp — failures fold to SMTP_DELIVERY_FAILED", () => {
  it("5xx on RCPT → SMTP_DELIVERY_FAILED naming the host origin only", async () => {
    const srv = await fake({
      starttls: false,
      authMechanisms: ["PLAIN"],
      implicitTls: true,
      rcpt: "fail",
    });
    let caught: unknown;
    try {
      await sendSmtp(optsFor(srv, { security: "tls" }));
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(VaultError);
    const err = caught as VaultError;
    expect(err.code).toBe("SMTP_DELIVERY_FAILED");
    expect(err.message).toContain(FIXTURE_HOST);
    expect(err.message).not.toContain("hunter2secret");
  });

  it("5xx on AUTH also folds to SMTP_DELIVERY_FAILED", async () => {
    const srv = await fake({
      starttls: false,
      authMechanisms: ["PLAIN"],
      implicitTls: true,
      auth: "fail",
    });
    await expect(sendSmtp(optsFor(srv, { security: "tls" }))).rejects.toMatchObject({
      code: "SMTP_DELIVERY_FAILED",
    });
  });

  it("a ballooning banner line is refused at the read cap", async () => {
    const srv = await fake({ starttls: false, authMechanisms: ["PLAIN"], banner: "flood" });
    await expect(sendSmtp(optsFor(srv, { security: "starttls" }))).rejects.toBeInstanceOf(
      VaultError,
    );
  });

  it("honors timeoutMs when the server never greets", async () => {
    const srv = await fake({ starttls: false, authMechanisms: ["PLAIN"], banner: "silent" });
    await expect(
      sendSmtp(optsFor(srv, { security: "starttls", timeoutMs: 300 })),
    ).rejects.toBeInstanceOf(VaultError);
  });
});
