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

describe("ImapClient — searchUids (UID SEARCH)", () => {
  it("renders UNSEEN, SINCE (IMAP date) and FROM as a quoted string, and parses the UID list", async () => {
    const srv = await fake({ searchResults: [2, 3, 5] });
    const client = await connect(srv);

    const uids = await client.searchUids({ unseen: true, since: "2026-08-01", from: "a@b" });
    expect(uids).toEqual([2, 3, 5]);

    const cmd = srv.commands().find((c) => c.name === "UID SEARCH");
    expect(cmd).toBeDefined();
    expect(cmd?.text).toMatch(/UID SEARCH UNSEEN SINCE 1-Aug-2026 FROM "a@b"$/);
    expect(cmd?.literals).toHaveLength(0);
  });

  it("falls back to SEARCH ALL when criteria is empty (never a bodyless SEARCH)", async () => {
    const srv = await fake({ searchResults: [] });
    const client = await connect(srv);

    const uids = await client.searchUids({});
    expect(uids).toEqual([]);

    const cmd = srv.commands().find((c) => c.name === "UID SEARCH");
    expect(cmd?.text).toContain("UID SEARCH ALL");
  });

  it("guard-flip: a CRLF-bearing 'from' value arrives as ONE literal, never a second command", async () => {
    const srv = await fake({ searchResults: [] });
    const client = await connect(srv);

    const payload = 'a@b.com"\r\nA9 LOGOUT';
    await client.searchUids({ from: payload });

    const names = srv.commands().map((c) => c.name);
    expect(names).toEqual(["CAPABILITY", "LOGIN", "UID SEARCH"]);
    expect(names).not.toContain("LOGOUT");

    const search = srv.commands().find((c) => c.name === "UID SEARCH");
    expect(search?.literals).toHaveLength(1);
    expect(search?.literals[0]?.toString("utf8")).toBe(payload);
  });

  it("renders SUBJECT and TEXT as quoted strings", async () => {
    const srv = await fake({ searchResults: [11] });
    const client = await connect(srv);

    const uids = await client.searchUids({ subject: "hi", text: "world" });
    expect(uids).toEqual([11]);

    const cmd = srv.commands().find((c) => c.name === "UID SEARCH");
    expect(cmd?.text).toContain('UID SEARCH SUBJECT "hi" TEXT "world"');
  });
});

describe("ImapClient — fetch (UID FETCH, always .PEEK)", () => {
  it("'envelope' requests (UID FLAGS ENVELOPE) and parses ENVELOPE incl. NIL fields", async () => {
    const srv = await fake({
      uidFetch: [
        {
          uid: 42,
          flags: ["\\Seen"],
          envelope:
            '("1-Aug-2026 10:00:00 +0000" "Hello World" ((NIL NIL "alice" "x.test")) NIL NIL NIL NIL NIL NIL NIL)',
        },
      ],
    });
    const client = await connect(srv);

    const messages = await client.fetch([42], "envelope");

    const cmd = srv.commands().find((c) => c.name === "UID FETCH");
    expect(cmd?.text).toContain("UID FETCH 42 (UID FLAGS ENVELOPE)");
    expect(cmd?.text).not.toContain("BODY");

    expect(messages).toHaveLength(1);
    expect(messages[0]).toMatchObject({ uid: 42, flags: ["\\Seen"] });
    expect(messages[0]?.envelope).toEqual({
      date: "1-Aug-2026 10:00:00 +0000",
      subject: "Hello World",
      from: ["alice@x.test"],
      to: [],
    });
  });

  it("ENVELOPE with a display name renders 'name <mailbox@host>'", async () => {
    const srv = await fake({
      uidFetch: [
        {
          uid: 1,
          envelope:
            '("d" "s" ((NIL NIL "alice" "x.test")) NIL NIL (("Bob B" NIL "bob" "y.test")) NIL NIL NIL NIL)',
        },
      ],
    });
    const client = await connect(srv);
    const messages = await client.fetch([1], "envelope");
    expect(messages[0]?.envelope?.to).toEqual(["Bob B <bob@y.test>"]);
  });

  it("'headers' requests bare BODY.PEEK[HEADER] (asserted on the wire) and returns the literal", async () => {
    const srv = await fake({ uidFetch: [{ uid: 7, header: "Subject: hi\r\nFrom: a@b\r\n" }] });
    const client = await connect(srv);

    const messages = await client.fetch([7], "headers");

    const cmd = srv.commands().find((c) => c.name === "UID FETCH");
    expect(cmd?.text).toContain("UID FETCH 7 BODY.PEEK[HEADER]");
    expect(cmd?.text).not.toContain("ENVELOPE");
    expect(cmd?.text).not.toContain("BODY.PEEK[TEXT]");

    expect(messages[0]?.uid).toBe(7);
    expect(messages[0]?.headers).toBe("Subject: hi\r\nFrom: a@b\r\n");
  });

  it("'text' requests bare BODY.PEEK[TEXT] (asserted on the wire) and returns the literal", async () => {
    const srv = await fake({ uidFetch: [{ uid: 8, text: "the body" }] });
    const client = await connect(srv);

    const messages = await client.fetch([8], "text");

    const cmd = srv.commands().find((c) => c.name === "UID FETCH");
    expect(cmd?.text).toContain("UID FETCH 8 BODY.PEEK[TEXT]");
    expect(cmd?.text).not.toContain("BODY.PEEK[HEADER]");

    expect(messages[0]?.text).toBe("the body");
  });

  it("'full' requests (UID FLAGS ENVELOPE BODY.PEEK[HEADER] BODY.PEEK[TEXT]) and parses all fields together", async () => {
    const srv = await fake({
      uidFetch: [
        {
          uid: 9,
          flags: ["\\Flagged"],
          envelope: '("d" "s" NIL NIL NIL NIL NIL NIL NIL NIL)',
          header: "Subject: s\r\n",
          text: "body text",
        },
      ],
    });
    const client = await connect(srv);

    const messages = await client.fetch([9], "full");

    const cmd = srv.commands().find((c) => c.name === "UID FETCH");
    expect(cmd?.text).toContain("(UID FLAGS ENVELOPE BODY.PEEK[HEADER] BODY.PEEK[TEXT])");

    expect(messages[0]).toMatchObject({
      uid: 9,
      flags: ["\\Flagged"],
      headers: "Subject: s\r\n",
      text: "body text",
    });
    expect(messages[0]?.envelope?.date).toBe("d");
    expect(messages[0]?.envelope?.subject).toBe("s");
  });

  it("rejects an empty UID list before sending anything", async () => {
    const srv = await fake({});
    const client = await connect(srv);
    await expect(client.fetch([], "envelope")).rejects.toBeInstanceOf(VaultError);
    expect(srv.commands().map((c) => c.name)).not.toContain("UID FETCH");
  });
});

describe("ImapClient — store (UID STORE)", () => {
  it("renders +FLAGS and -FLAGS as separate, sequential UID STORE commands", async () => {
    const srv = await fake({});
    const client = await connect(srv);

    const changed = await client.store([3, 5], ["\\Flagged"], ["\\Seen"]);
    expect(changed).toBe(2);

    const stores = srv.commands().filter((c) => c.name === "UID STORE");
    expect(stores).toHaveLength(2);
    expect(stores[0]?.text).toContain("UID STORE 3,5 +FLAGS (\\Flagged)");
    expect(stores[1]?.text).toContain("UID STORE 3,5 -FLAGS (\\Seen)");
  });

  it("issues nothing when both flag lists are empty", async () => {
    const srv = await fake({});
    const client = await connect(srv);
    const changed = await client.store([1], [], []);
    expect(changed).toBe(1);
    expect(srv.commands().map((c) => c.name)).not.toContain("UID STORE");
  });

  it("rejects a malformed flag (embedded space) as a VaultError before sending anything", async () => {
    const srv = await fake({});
    const client = await connect(srv);
    await expect(client.store([1], ["not a flag"], [])).rejects.toBeInstanceOf(VaultError);
    expect(srv.commands().map((c) => c.name)).not.toContain("UID STORE");
  });

  it("rejects a malformed flag (embedded backslash / empty) as a VaultError before sending anything", async () => {
    const srv = await fake({});
    const client = await connect(srv);
    await expect(client.store([1], [], ["\\Se\\en"])).rejects.toBeInstanceOf(VaultError);
    await expect(client.store([1], [], [""])).rejects.toBeInstanceOf(VaultError);
    expect(srv.commands().map((c) => c.name)).not.toContain("UID STORE");
  });
});

describe("ImapClient — move (UID MOVE, or COPY+STORE+[UID ]EXPUNGE fallback)", () => {
  it("(a) uses UID MOVE when the MOVE capability is present", async () => {
    const srv = await fake({ capabilities: ["IMAP4rev1", "MOVE"] });
    const client = await connect(srv);

    const moved = await client.move([1, 2], "Archive");
    expect(moved).toBe(2);

    const names = srv.commands().map((c) => c.name);
    expect(names).toEqual(["CAPABILITY", "LOGIN", "UID MOVE"]);
    const cmd = srv.commands().find((c) => c.name === "UID MOVE");
    expect(cmd?.text).toContain('UID MOVE 1,2 "Archive"');
  });

  it("(b) without MOVE but with UIDPLUS: COPY+STORE+UID EXPUNGE <set>, scoped — never blanket EXPUNGE", async () => {
    const srv = await fake({
      capabilities: ["IMAP4rev1", "UIDPLUS"],
      // A nonzero, deliberately-uncorrelated count proves the returned value
      // is the requested UID count, not whatever EXPUNGE happened to report.
      expungeCount: 5,
    });
    const client = await connect(srv);

    const moved = await client.move([1, 2], "Archive");
    expect(moved).toBe(2);

    const names = srv.commands().map((c) => c.name);
    expect(names).toEqual(["CAPABILITY", "LOGIN", "UID COPY", "UID STORE", "UID EXPUNGE"]);
    expect(names).not.toContain("EXPUNGE");
    expect(srv.commands()[2]?.text).toContain('UID COPY 1,2 "Archive"');
    expect(srv.commands()[3]?.text).toContain("UID STORE 1,2 +FLAGS (\\Deleted)");
    expect(srv.commands()[4]?.text).toContain("UID EXPUNGE 1,2");
  });

  it("(c) without MOVE and without UIDPLUS: COPY+STORE+blanket EXPUNGE (no scoping is possible)", async () => {
    const srv = await fake({
      capabilities: ["IMAP4rev1"],
      // Same uncorrelated-count proof as (b), on the blanket-EXPUNGE path.
      expungeCount: 5,
    });
    const client = await connect(srv);

    const moved = await client.move([1, 2], "Archive");
    expect(moved).toBe(2);

    const names = srv.commands().map((c) => c.name);
    expect(names).toEqual(["CAPABILITY", "LOGIN", "UID COPY", "UID STORE", "EXPUNGE"]);
    expect(names).not.toContain("UID EXPUNGE");
    expect(srv.commands()[2]?.text).toContain('UID COPY 1,2 "Archive"');
    expect(srv.commands()[3]?.text).toContain("UID STORE 1,2 +FLAGS (\\Deleted)");
  });

  it("guard-flip: a CRLF-bearing target mailbox arrives as a literal, not a second command", async () => {
    const srv = await fake({ capabilities: ["IMAP4rev1", "MOVE"] });
    const client = await connect(srv);

    const payload = 'Archive"\r\nA9 LOGOUT';
    await client.move([1], payload);

    const names = srv.commands().map((c) => c.name);
    expect(names).toEqual(["CAPABILITY", "LOGIN", "UID MOVE"]);
    const cmd = srv.commands().find((c) => c.name === "UID MOVE");
    expect(cmd?.literals).toHaveLength(1);
    expect(cmd?.literals[0]?.toString("utf8")).toBe(payload);
  });
});

describe("ImapClient — copy (UID COPY)", () => {
  it("issues UID COPY with the target mailbox as a string", async () => {
    const srv = await fake({});
    const client = await connect(srv);

    const copied = await client.copy([4], "Archive");
    expect(copied).toBe(1);

    const cmd = srv.commands().find((c) => c.name === "UID COPY");
    expect(cmd?.text).toContain('UID COPY 4 "Archive"');
  });
});

describe("ImapClient — expunge", () => {
  it("counts untagged '* n EXPUNGE' lines", async () => {
    const srv = await fake({ expungeCount: 3 });
    const client = await connect(srv);

    const count = await client.expunge();
    expect(count).toBe(3);

    expect(srv.commands().map((c) => c.name)).toEqual(["CAPABILITY", "LOGIN", "EXPUNGE"]);
  });

  it("reports zero when nothing was expunged", async () => {
    const srv = await fake({});
    const client = await connect(srv);
    const count = await client.expunge();
    expect(count).toBe(0);
  });
});

describe("ImapClient — UID validation (fail closed before sending)", () => {
  it("rejects an invalid UID (non-integer / non-positive) before sending anything", async () => {
    const srv = await fake({});
    const client = await connect(srv);
    await expect(client.copy([0], "Archive")).rejects.toBeInstanceOf(VaultError);
    await expect(client.store([-1], ["\\Seen"], [])).rejects.toBeInstanceOf(VaultError);
    expect(srv.commands().map((c) => c.name)).not.toContain("UID COPY");
    expect(srv.commands().map((c) => c.name)).not.toContain("UID STORE");
  });
});
