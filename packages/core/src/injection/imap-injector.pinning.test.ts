import { afterEach, describe, expect, it, vi } from "vitest";
import { connect as tlsConnect } from "node:tls";
import type { ConnectionOptions } from "node:tls";
import type { ImapAction } from "@harpoc/shared";
import { ErrorCode, injectionPolicyInputSchema } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";

const PIN = vi.hoisted(() => ({ host: "fixture.example.com", address: "127.0.0.1" }));

vi.mock("./url-validator.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./url-validator.js")>();
  return {
    ...actual,
    validateHostPort: vi.fn(async (host: string, port: number) => {
      if (host === PIN.host || host === PIN.address) {
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

import type { FakeImap } from "./mail/__fixtures__/fake-imap-server.js";
import { getFixtureCaPem, startFakeImap } from "./mail/__fixtures__/fake-imap-server.js";
import { ImapInjector } from "./imap-injector.js";
import { validateHostPort } from "./url-validator.js";

let server: FakeImap | undefined;

afterEach(async () => {
  vi.mocked(tlsConnect).mockClear();
  if (server) {
    await server.close();
    server = undefined;
  }
});

describe("IMAP DNS-rebinding pinning", () => {
  it("dials the address resolved at validation time while TLS stays bound to the logical host", async () => {
    server = await startFakeImap({ searchResults: [4, 9] });
    const action: ImapAction = {
      type: "imap",
      host: PIN.host,
      port: server.port,
      mailbox: "INBOX",
      operation: { kind: "search", unseen: true },
      timeout_ms: 5_000,
    };

    const { result } = await new ImapInjector().run(
      action,
      "imapuser:imappass",
      injectionPolicyInputSchema.parse({ host_allowlist: [PIN.host] }),
      { tls: { ca: getFixtureCaPem() } },
      undefined,
    );

    expect(validateHostPort).toHaveBeenCalledWith(PIN.host, server.port);
    expect(tlsConnect).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ host: PIN.address, port: server.port, servername: PIN.host }),
    );
    expect(result).toEqual({ type: "imap", operation: "search", uids: [4, 9] });
    expect(server.commands().map((command) => command.name)).toContain("UID SEARCH");
  });

  it("sets no TLS ServerName for an IP-literal host (RFC 6066, DEP0123); a certificate that does not name the address is refused before any credential byte", async () => {
    server = await startFakeImap({ searchResults: [4, 9] });
    const action: ImapAction = {
      type: "imap",
      host: PIN.address,
      port: server.port,
      mailbox: "INBOX",
      operation: { kind: "search", unseen: true },
      timeout_ms: 5_000,
    };

    // The fixture certificate names fixture.example.com and alt.example.com only, so the
    // identity check refuses it for the literal — the dial itself is what this case pins.
    await expectVaultError(
      () =>
        new ImapInjector().run(
          action,
          "imapuser:imappass",
          injectionPolicyInputSchema.parse({ host_allowlist: [PIN.address] }),
          { tls: { ca: getFixtureCaPem() } },
          undefined,
        ),
      ErrorCode.IMAP_OPERATION_FAILED,
    );

    expect(tlsConnect).toHaveBeenCalledOnce();
    const options = vi.mocked(tlsConnect).mock.calls[0]?.[0] as unknown as ConnectionOptions;
    expect(options).toMatchObject({ host: PIN.address, port: server.port });
    expect(options).not.toHaveProperty("servername");
    expect(server.commands()).toEqual([]);
  });
});
