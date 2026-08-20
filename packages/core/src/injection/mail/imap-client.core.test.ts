import { afterEach, describe, expect, it } from "vitest";
import { VaultError } from "@harpoc/shared";
import { ImapClient } from "./imap-client.js";
import type { ImapConnectOptions } from "./imap-client.js";
import { getFixtureCaPem, FIXTURE_HOST, startFakeImap } from "./__fixtures__/fake-imap-server.js";
import type { FakeImap, ImapScript } from "./__fixtures__/fake-imap-server.js";

const servers: FakeImap[] = [];
const clients: ImapClient[] = [];

async function fake(script: ImapScript): Promise<FakeImap> {
  const srv = await startFakeImap(script);
  servers.push(srv);
  return srv;
}

function optsFor(srv: FakeImap, overrides: Partial<ImapConnectOptions> = {}): ImapConnectOptions {
  return {
    host: FIXTURE_HOST,
    port: srv.port,
    address: "127.0.0.1",
    auth: { kind: "password", username: "u", password: "hunter2secret" },
    timeoutMs: 5_000,
    tls: { ca: getFixtureCaPem() },
    ...overrides,
  };
}

async function connect(
  srv: FakeImap,
  overrides: Partial<ImapConnectOptions> = {},
): Promise<ImapClient> {
  const client = await ImapClient.connect(optsFor(srv, overrides));
  clients.push(client);
  return client;
}

afterEach(async () => {
  await Promise.all(clients.splice(0).map((c) => c.logout().catch(() => undefined)));
  await Promise.all(servers.splice(0).map((s) => s.close()));
});

describe("ImapClient — command injection is impossible by construction", () => {
  it("a CRLF-bearing mailbox arrives as ONE command inside a literal, never a second command", async () => {
    const srv = await fake({ capabilities: ["IMAP4rev1"] });
    const client = await connect(srv);

    const payload = 'INBOX"\r\nA2 DELETE INBOX';
    await client.select(payload, false);

    const names = srv.commands().map((c) => c.name);
    // Exactly the three commands connect+select issue — no injected fourth.
    expect(names).toEqual(["CAPABILITY", "LOGIN", "SELECT"]);
    expect(names).not.toContain("DELETE");

    const select = srv.commands().find((c) => c.name === "SELECT");
    expect(select).toBeDefined();
    // The whole CRLF-bearing payload was delivered as a single literal argument
    // — the server consumed it as counted octets, not as a second command line.
    expect(select?.literals).toHaveLength(1);
    expect(select?.literals[0]?.toString("utf8")).toBe(payload);
  });

  it("a short, safe mailbox is sent as a quoted string, not a literal", async () => {
    const srv = await fake({});
    const client = await connect(srv);
    await client.select("INBOX", true);

    const examine = srv.commands().find((c) => c.name === "EXAMINE");
    expect(examine?.literals).toHaveLength(0);
    expect(examine?.text).toContain('"INBOX"');
  });
});

describe("ImapClient — connect: TLS, greeting, CAPABILITY, auth", () => {
  it("happy path: greeting → CAPABILITY → LOGIN, capabilities exposed", async () => {
    const srv = await fake({ capabilities: ["IMAP4rev1", "IDLE", "MOVE"] });
    const client = await connect(srv);

    expect(client.capabilities().has("IMAP4rev1")).toBe(true);
    expect(client.capabilities().has("MOVE")).toBe(true);

    const names = srv.commands().map((c) => c.name);
    expect(names).toEqual(["CAPABILITY", "LOGIN"]);
    const raw = srv.raw().toString("latin1");
    // The password rides as an IMAP string argument, never as an atom on the verb line.
    expect(raw).toContain("LOGIN");
    expect(raw).toContain("hunter2secret");
  });

  it("AUTHENTICATE XOAUTH2 sends the SASL bearer blob and no bare token", async () => {
    const srv = await fake({ capabilities: ["IMAP4rev1", "AUTH=XOAUTH2"] });
    await connect(srv, {
      auth: { kind: "xoauth2", username: "user@x.test", accessToken: "tok-abc-123" },
    });

    const blob = Buffer.from("user=user@x.test\x01auth=Bearer tok-abc-123\x01\x01").toString(
      "base64",
    );
    const raw = srv.raw().toString("latin1");
    expect(raw).toContain("AUTHENTICATE XOAUTH2");
    expect(raw).toContain(blob);
    expect(raw).not.toContain("tok-abc-123");
    expect(srv.commands().map((c) => c.name)).toContain("AUTHENTICATE");
  });

  it("a hostile greeting (* BYE) fails the connect, credential never sent", async () => {
    const srv = await fake({ greeting: "bye" });
    await expect(ImapClient.connect(optsFor(srv))).rejects.toMatchObject({
      code: "IMAP_OPERATION_FAILED",
    });
    const raw = srv.raw().toString("latin1");
    expect(raw).not.toContain("hunter2secret");
  });
});

describe("ImapClient — SELECT vs EXAMINE and the response parser", () => {
  it("readOnly picks EXAMINE and !readOnly picks SELECT; EXISTS is parsed", async () => {
    const srvRw = await fake({ existsOnSelect: 7 });
    const rw = await connect(srvRw);
    const rwResult = await rw.select("INBOX", false);
    expect(rwResult.exists).toBe(7);
    expect(srvRw.commands().map((c) => c.name)).toContain("SELECT");
    expect(srvRw.commands().map((c) => c.name)).not.toContain("EXAMINE");

    const srvRo = await fake({ existsOnSelect: 2 });
    const ro = await connect(srvRo);
    const roResult = await ro.select("INBOX", true);
    expect(roResult.exists).toBe(2);
    expect(srvRo.commands().map((c) => c.name)).toContain("EXAMINE");
    expect(srvRo.commands().map((c) => c.name)).not.toContain("SELECT");
  });

  it("reassembles a server literal ({5}\\r\\nhello) into the untagged line", async () => {
    const srv = await fake({ fetchLiteral: "hello" });
    const client = await connect(srv);
    const res = await client.command("FETCH", [
      { kind: "atom", value: "1" },
      { kind: "atom", value: "BODY[TEXT]" },
    ]);
    expect(res.tagged.status).toBe("OK");
    const literals = res.untagged.flatMap((u) => u.literals);
    expect(literals.map((b) => b.toString("utf8"))).toContain("hello");
  });
});

describe("ImapClient — capped-output discipline and failures", () => {
  it("refuses an oversized announced literal before buffering it", async () => {
    const srv = await fake({ fetchOversizedLiteral: 104_857_600 });
    const client = await connect(srv);
    let caught: unknown;
    try {
      await client.command("FETCH", [{ kind: "atom", value: "1" }]);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(VaultError);
    const err = caught as VaultError;
    expect(err.code).toBe("IMAP_OPERATION_FAILED");
    expect(err.message).toContain(FIXTURE_HOST);
    expect(err.message).not.toContain("hunter2secret");
  });

  it("refuses a response stream that blows past the session cap", async () => {
    const srv = await fake({ flood: true });
    const client = await connect(srv);
    await expect(client.command("FETCH", [{ kind: "atom", value: "1" }])).rejects.toBeInstanceOf(
      VaultError,
    );
  });

  it("a tagged NO folds to imapOperationFailed naming the origin only", async () => {
    const srv = await fake({ selectStatus: "no" });
    const client = await connect(srv);
    let caught: unknown;
    try {
      await client.select("INBOX", false);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(VaultError);
    const err = caught as VaultError;
    expect(err.code).toBe("IMAP_OPERATION_FAILED");
    expect(err.message).toContain(FIXTURE_HOST);
    expect(err.message).not.toContain("hunter2secret");
  });

  it("a failed LOGIN (tagged NO) folds to imapOperationFailed", async () => {
    const srv = await fake({ auth: "fail" });
    await expect(ImapClient.connect(optsFor(srv))).rejects.toMatchObject({
      code: "IMAP_OPERATION_FAILED",
    });
  });

  it("honors timeoutMs when the server never greets", async () => {
    const srv = await fake({ greeting: "silent" });
    await expect(ImapClient.connect(optsFor(srv, { timeoutMs: 300 }))).rejects.toBeInstanceOf(
      VaultError,
    );
  });
});
