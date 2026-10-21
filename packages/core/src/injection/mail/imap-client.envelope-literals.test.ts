import { afterEach, describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { ImapClient } from "./imap-client.js";
import type { ImapConnectOptions, ImapEnvelope } from "./imap-client.js";
import { getFixtureCaPem, FIXTURE_HOST, startFakeImap } from "./__fixtures__/fake-imap-server.js";
import type { FakeImap, ImapScript } from "./__fixtures__/fake-imap-server.js";
import { expectVaultError } from "@harpoc/test-utils";

const servers: FakeImap[] = [];
const clients: ImapClient[] = [];

async function fake(script: ImapScript): Promise<FakeImap> {
  const srv = await startFakeImap(script);
  servers.push(srv);
  return srv;
}

function optsFor(srv: FakeImap): ImapConnectOptions {
  return {
    host: FIXTURE_HOST,
    port: srv.port,
    address: "127.0.0.1",
    auth: { kind: "password", username: "u", password: "S3CRET-TOKEN-xyz" },
    timeoutMs: 5_000,
    tls: { ca: getFixtureCaPem() },
  };
}

async function connect(srv: FakeImap): Promise<ImapClient> {
  const client = await ImapClient.connect(optsFor(srv));
  clients.push(client);
  return client;
}

afterEach(async () => {
  await Promise.all(clients.splice(0).map((c) => c.logout().catch(() => undefined)));
  await Promise.all(servers.splice(0).map((s) => s.close()));
});

function literal(text: string): { literal: Buffer } {
  return { literal: Buffer.from(text, "utf8") };
}

const DATE = '"Mon, 19 Oct 2026 10:00:00 +0000"';
const FROM = '(("Alice A" NIL "alice" "x.test"))';
const SENDER = '(("Sender S" NIL "sender" "x.test"))';
const REPLY_TO = '(("Reply R" NIL "reply" "x.test"))';
const TO = '(("Bob B" NIL "bob" "y.test"))';
const CC = '(("Carol C" NIL "carol" "y.test"))';
const HEADER = "Subject: =?UTF-8?Q?Caf=C3=A9!?=\r\nFrom: Alice A <alice@x.test>\r\n";
const BODY = "the body\r\n";

const ENVELOPE: ImapEnvelope = {
  date: "Mon, 19 Oct 2026 10:00:00 +0000",
  subject: "Café!",
  from: ["Alice A <alice@x.test>"],
  to: ["Bob B <bob@y.test>"],
};

const SUBJECT_AS_LITERAL = [
  `(${DATE} `,
  literal("Café!"),
  ` ${FROM} ${SENDER} ${REPLY_TO} ${TO} ${CC} NIL NIL "<m1@x.test>")`,
];

describe("ImapClient — FETCH reads an envelope field sent as a literal in place", () => {
  it("'envelope': the subject sent as {6}\\r\\nCafé! is the subject, decoded as UTF-8, and every other field is its own", async () => {
    const srv = await fake({
      uidFetch: [{ uid: 11, flags: ["\\Seen"], envelopeSegments: SUBJECT_AS_LITERAL }],
    });
    const client = await connect(srv);

    const messages = await client.fetch([11], "envelope");

    expect(messages).toEqual([{ uid: 11, flags: ["\\Seen"], envelope: ENVELOPE }]);
  });

  it("'full': the envelope's literal stays the subject, BODY[HEADER] is the header literal and BODY[TEXT] the body literal", async () => {
    const srv = await fake({
      uidFetch: [{ uid: 12, envelopeSegments: SUBJECT_AS_LITERAL, header: HEADER, text: BODY }],
    });
    const client = await connect(srv);

    const messages = await client.fetch([12], "full");

    expect(messages).toEqual([
      { uid: 12, flags: [], envelope: ENVELOPE, headers: HEADER, text: BODY },
    ]);
  });

  it("'envelope': a literal in a later field (the To display name) is that name and the fields before it are untouched", async () => {
    const srv = await fake({
      uidFetch: [
        {
          uid: 13,
          envelopeSegments: [
            `(${DATE} "Café!" ${FROM} ${SENDER} ${REPLY_TO} ((`,
            literal("Böb B"),
            ` NIL "bob" "y.test")) ${CC} NIL NIL "<m1@x.test>")`,
          ],
        },
      ],
    });
    const client = await connect(srv);

    const messages = await client.fetch([13], "envelope");

    expect(messages).toEqual([
      { uid: 13, flags: [], envelope: { ...ENVELOPE, to: ["Böb B <bob@y.test>"] } },
    ]);
  });

  it("'full': two envelope literals (the subject and the Message-ID) are both claimed by the envelope, never by the BODY sections", async () => {
    const srv = await fake({
      uidFetch: [
        {
          uid: 14,
          envelopeSegments: [
            `(${DATE} `,
            literal("Café!"),
            ` ${FROM} ${SENDER} ${REPLY_TO} ${TO} ${CC} NIL NIL `,
            literal("<mü1@x.test>"),
            ")",
          ],
          header: HEADER,
          text: BODY,
        },
      ],
    });
    const client = await connect(srv);

    const messages = await client.fetch([14], "full");

    expect(messages).toEqual([
      { uid: 14, flags: [], envelope: ENVELOPE, headers: HEADER, text: BODY },
    ]);
  });

  it("'full': BODY[HEADER] NIL beside a BODY[TEXT] literal leaves headers absent and the body literal to BODY[TEXT]", async () => {
    const srv = await fake({
      uidFetch: [
        {
          uid: 15,
          envelope: `(${DATE} "Café!" ${FROM} ${SENDER} ${REPLY_TO} ${TO} ${CC} NIL NIL "<m1@x.test>")`,
          headerInline: "NIL",
          text: BODY,
        },
      ],
    });
    const client = await connect(srv);

    const messages = await client.fetch([15], "full");

    expect(messages).toEqual([{ uid: 15, flags: [], envelope: ENVELOPE, text: BODY }]);
    expect(messages[0]).not.toHaveProperty("headers");
  });

  it("'full': a quoted BODY[HEADER] beside a BODY[TEXT] literal is the header, and the body literal stays BODY[TEXT]", async () => {
    const srv = await fake({
      uidFetch: [
        {
          uid: 16,
          envelope: `(${DATE} "Café!" ${FROM} ${SENDER} ${REPLY_TO} ${TO} ${CC} NIL NIL "<m1@x.test>")`,
          headerInline: '"Subject: q"',
          text: BODY,
        },
      ],
    });
    const client = await connect(srv);

    const messages = await client.fetch([16], "full");

    expect(messages).toEqual([
      { uid: 16, flags: [], envelope: ENVELOPE, headers: "Subject: q", text: BODY },
    ]);
  });

  it("'full': a quoted envelope subject that spells BODY[TEXT] stays the subject, and BODY[HEADER] and BODY[TEXT] are each their own literal", async () => {
    const srv = await fake({
      uidFetch: [
        {
          uid: 19,
          envelope: `(${DATE} "see BODY[TEXT] here" ${FROM} ${SENDER} ${REPLY_TO} ${TO} ${CC} NIL NIL "<m1@x.test>")`,
          header: HEADER,
          text: BODY,
        },
      ],
    });
    const client = await connect(srv);

    const messages = await client.fetch([19], "full");

    expect(messages).toEqual([
      {
        uid: 19,
        flags: [],
        envelope: { ...ENVELOPE, subject: "see BODY[TEXT] here" },
        headers: HEADER,
        text: BODY,
      },
    ]);
  });

  it("'full': a BODY[TEXT] literal announced with no SP before its {n} is still the body, and BODY[HEADER] its own literal", async () => {
    const srv = await fake({
      uidFetch: [
        {
          uid: 20,
          envelope: `(${DATE} "Café!" ${FROM} ${SENDER} ${REPLY_TO} ${TO} ${CC} NIL NIL "<m1@x.test>")`,
          header: HEADER,
          text: BODY,
          textGlued: true,
        },
      ],
    });
    const client = await connect(srv);

    const messages = await client.fetch([20], "full");

    expect(messages).toEqual([
      { uid: 20, flags: [], envelope: ENVELOPE, headers: HEADER, text: BODY },
    ]);
  });

  it("control: an all-quoted envelope beside both BODY literals parses every field exactly", async () => {
    const srv = await fake({
      uidFetch: [
        {
          uid: 17,
          envelope: `(${DATE} "Café!" ${FROM} ${SENDER} ${REPLY_TO} ${TO} ${CC} NIL NIL "<m1@x.test>")`,
          header: HEADER,
          text: BODY,
        },
      ],
    });
    const client = await connect(srv);

    const messages = await client.fetch([17], "full");

    expect(messages).toEqual([
      { uid: 17, flags: [], envelope: ENVELOPE, headers: HEADER, text: BODY },
    ]);
  });
});

describe("ImapClient — a NUL byte in a server text line is a protocol fault", () => {
  it("a FETCH line whose text carries a NUL (a spelled placeholder) is refused IMAP_OPERATION_FAILED and never resolves to the body literal", async () => {
    const srv = await fake({
      uidFetch: [
        {
          uid: 18,
          envelope: '("d" \u00000\u0000 NIL NIL NIL NIL NIL NIL NIL NIL)',
          text: "S3CRET-TOKEN-xyz body",
        },
      ],
    });
    const client = await connect(srv);

    const err = await expectVaultError(
      () => client.fetch([18], "full"),
      ErrorCode.IMAP_OPERATION_FAILED,
    );
    expect(err.message).toContain(FIXTURE_HOST);
    expect(err.message).not.toContain("S3CRET-TOKEN-xyz");
  });
});
