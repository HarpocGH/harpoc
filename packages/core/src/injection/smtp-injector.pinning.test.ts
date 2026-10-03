import { afterEach, describe, expect, it, vi } from "vitest";
import { connect as tlsConnect } from "node:tls";
import type { SmtpAction } from "@harpoc/shared";
import { injectionPolicyInputSchema } from "@harpoc/shared";

const PIN = vi.hoisted(() => ({ host: "fixture.example.com", address: "127.0.0.1" }));

vi.mock("./url-validator.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./url-validator.js")>();
  return {
    ...actual,
    validateHostPort: vi.fn(async (host: string, port: number) => {
      if (host === PIN.host) {
        return { host, port, resolvedAddress: PIN.address };
      }
      throw new Error(`unexpected host ${host}`);
    }),
  };
});

vi.mock("node:tls", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:tls")>();
  return { ...actual, connect: vi.fn(actual.connect) };
});

import type { FakeSmtp } from "./mail/__fixtures__/fake-smtp-server.js";
import { getFixtureCaPem, startFakeSmtp } from "./mail/__fixtures__/fake-smtp-server.js";
import { SmtpInjector } from "./smtp-injector.js";
import { validateHostPort } from "./url-validator.js";

let server: FakeSmtp | undefined;

afterEach(async () => {
  vi.mocked(tlsConnect).mockClear();
  if (server) {
    await server.close();
    server = undefined;
  }
});

describe("SMTP DNS-rebinding pinning", () => {
  it("dials the address resolved at validation time while TLS stays bound to the logical host", async () => {
    server = await startFakeSmtp({ starttls: false, implicitTls: true, authMechanisms: ["PLAIN"] });
    const action: SmtpAction = {
      type: "smtp",
      host: PIN.host,
      port: server.port,
      security: "tls",
      from: "sender@example.com",
      to: ["to@example.com"],
      subject: "pinned",
      text: "body",
      timeout_ms: 5_000,
    };

    const { result } = await new SmtpInjector().run(
      action,
      "smtpuser:smtppass",
      injectionPolicyInputSchema.parse({ host_allowlist: [PIN.host] }),
      { tls: { ca: getFixtureCaPem() } },
      undefined,
    );

    expect(validateHostPort).toHaveBeenCalledWith(PIN.host, server.port);
    expect(tlsConnect).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ host: PIN.address, port: server.port, servername: PIN.host }),
    );
    expect(result.accepted).toBe(1);
    expect(server.wire().postTls.toString("latin1")).toContain("MAIL FROM:<sender@example.com>");
  });
});
