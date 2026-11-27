import { describe, expect, it, vi } from "vitest";
import { MAX_HTTP_RESPONSE_BYTES } from "@harpoc/shared";
import { expectAbsent } from "@harpoc/test-utils";
import { redactValues, redactValuesTracked } from "./output-sanitizer.js";
import { referenceRedact } from "./__fixtures__/redact-reference.js";
import { DOC, PW, TABLE, permutations, tableRow } from "./__fixtures__/redact-cases.js";

const R = "[REDACTED]";
const ONE_LETTER_TEXT = "the cat sat on a bed";
const FIRST_OF_LIST = "zzz";
const MARKER_PIECE_TEXT = `${FIRST_OF_LIST} RED ACT R E DA ${R} ${FIRST_OF_LIST}`;
const LEFT_VALUE = "abcd";
const RIGHT_VALUE = "cdef";
const SELF_OVERLAPPING = "aa";
const TOUCHING = "ab";
const MARKER_INFIX = "RED";
const BRACKET_TAIL = "s[";
const DENSE_VALUE = "n\\";
const VALUE_MIXED = "sk?mixed/Válue+1";
const QUOTE_SECRET = 'tok"en-x';
const BACKSLASH_SECRET = "dom\\user-pw";
const NON_ASCII_SECRET = "passwörd-1";
const BOUNDARY_SECRET = 'tok"en-y';
const KEY_SECRET = 'tok"en-k';
const PROTO_SECRET = 'tok"en-p';
const ABSENT_SECRET = 'tok"en-z';
const GUARD_SECRET = 'tok"en-big';
const CAP_SECRET = 'tok"en-cap';
const NUMBER_VALUE = "1000";

const withoutMarkers = (text: string): string => text.split(R).join("");
const spelled = (value: string, layers: number): string =>
  layers === 0 ? value : spelled(JSON.stringify(value).slice(1, -1), layers - 1);
const wrap = (inner: string): string => JSON.stringify({ data: inner });
const t1 = (secret: string): string => JSON.stringify({ echo: secret });
const base64 = (value: string): string => Buffer.from(value, "utf8").toString("base64");

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32(value: string): string {
  let out = "";
  let acc = 0;
  let bits = 0;
  for (const byte of Buffer.from(value, "utf8")) {
    acc = ((acc << 8) | byte) & 0x1fff;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(acc >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(acc << (5 - bits)) & 31];
  return out;
}

function capBody(length: number): string {
  const inner = t1(CAP_SECRET);
  const skeleton = JSON.stringify({ pad: "", data: inner });
  return JSON.stringify({ pad: "x".repeat(length - skeleton.length), data: inner });
}

describe("redactValues — spans", () => {
  it.each(["a", "c", "d", "e", "t"])(
    "a one-letter value leaves every marker whole: %s",
    (value) => {
      const out = redactValues(ONE_LETTER_TEXT, [value]);

      expectAbsent(out, value);
      expect(withoutMarkers(out).includes("[")).toBe(false);
      expect(withoutMarkers(out).includes("]")).toBe(false);
      expect(redactValues(out, [value])).toBe(out);
    },
  );

  it.each(["RED", "ACT", "R", "E", "DA"])(
    "a value that is a piece of the marker cuts none: %s",
    (value) => {
      for (const list of [[value], [FIRST_OF_LIST, value]]) {
        const out = redactValues(MARKER_PIECE_TEXT, list);

        expectAbsent(withoutMarkers(out), value, "the value outside the markers");
        if (list.length > 1) expectAbsent(out, FIRST_OF_LIST, "the first value of the list");
        expect(withoutMarkers(out).includes("[")).toBe(false);
        expect(withoutMarkers(out).includes("]")).toBe(false);
        expect(redactValues(out, list)).toBe(out);
      }
    },
  );

  it("two values whose ends overlap leave no fragment", () => {
    const text = `${LEFT_VALUE.slice(0, 2)}${RIGHT_VALUE}`;

    expect(redactValues(text, [LEFT_VALUE, RIGHT_VALUE])).toBe(R);
    expect(redactValues(text, [RIGHT_VALUE, LEFT_VALUE])).toBe(R);
  });

  it("one value that overlaps itself leaves no fragment", () => {
    expect(redactValues(`x${SELF_OVERLAPPING}ax`, [SELF_OVERLAPPING])).toBe(`x${R}x`);
  });

  it("two occurrences that only touch stay two markers", () => {
    expect(redactValues(`${TOUCHING}${TOUCHING}`, [TOUCHING])).toBe(`${R}${R}`);
  });

  it("a marker already in the text is kept or covered whole", () => {
    expect(redactValues(`x ${R} y`, [MARKER_INFIX])).toBe(`x ${R} y`);
    expect(redactValues(`x${BRACKET_TAIL}REDACTED]`, [BRACKET_TAIL])).toBe(`x${R}`);
  });

  it("a nested hit keeps a foreign document's bytes", () => {
    const row = tableRow(25);

    const out = redactValues(row.text, row.values);

    expect(out).toBe(row.expect);
    expect(out.split(" ").length).toBe(row.text.split(" ").length);
  });

  const stringified: [string, string, string][] = [
    ["a quote-bearing credential behind an envelope", wrap(t1(QUOTE_SECRET)), QUOTE_SECRET],
    [
      "a backslash-bearing credential behind an envelope",
      wrap(t1(BACKSLASH_SECRET)),
      BACKSLASH_SECRET,
    ],
    [
      "an ensure_ascii body behind an envelope",
      wrap(`{"echo":"passw\\u00f6rd-1"}`),
      NON_ASCII_SECRET,
    ],
    ["five documents", wrap(wrap(wrap(wrap(t1(BOUNDARY_SECRET))))), BOUNDARY_SECRET],
    ["six documents", wrap(wrap(wrap(wrap(wrap(t1(BOUNDARY_SECRET)))))), BOUNDARY_SECRET],
    ["a key at depth", wrap(JSON.stringify({ [KEY_SECRET]: 1 })), KEY_SECRET],
    [
      "a __proto__ key beside a nested credential",
      JSON.stringify({ ["__proto__"]: "keep-me", nested: t1(PROTO_SECRET) }),
      PROTO_SECRET,
    ],
    ["a nested body that holds nothing", wrap(JSON.stringify({ echo: "harmless" })), ABSENT_SECRET],
    [
      "a body over the size guard",
      JSON.stringify({ pad: "x".repeat(5 * 1024 * 1024), data: t1(GUARD_SECRET) }),
      GUARD_SECRET,
    ],
    ["a body of exactly the HTTP cap", capBody(MAX_HTTP_RESPONSE_BYTES), CAP_SECRET],
    ["a body one character past the HTTP cap", capBody(MAX_HTTP_RESPONSE_BYTES + 1), CAP_SECRET],
  ];

  it.each(stringified)(
    "a document `JSON.stringify` wrote reads as it did: %s",
    (_label, text, value) => {
      expect(redactValues(text, [value]) === referenceRedact(text, value)).toBe(true);
    },
  );

  const orderCases: [number, [string, number][]][] = [
    [
      9,
      [
        [PW, 4],
        [NUMBER_VALUE, 0],
      ],
    ],
    [
      10,
      [
        [DOC, 0],
        [base64(DOC), 0],
      ],
    ],
    [
      11,
      [
        [DOC, 0],
        [PW, 2],
      ],
    ],
  ];

  it.each(orderCases)("the two cases the order broke: row %i", (row, needles) => {
    const { text, values } = tableRow(row);
    for (const [value, layers] of needles) {
      expect(text.includes(spelled(value, layers))).toBe(true);
    }

    permutations(values).forEach((order, index) => {
      const out = redactValues(text, order);
      for (const [value, layers] of needles) {
        expectAbsent(out, spelled(value, layers), `a value in order ${index}`);
      }
    });
  });

  it("a value with a bracket gets the second application", () => {
    const { text, values } = tableRow(22);

    const out = redactValues(text, values);

    expect(redactValues(out, values)).toBe(out);
  });

  it("changed says whether the text differs", () => {
    for (const { text, values } of TABLE) {
      const tracked = redactValuesTracked(text, values);
      expect(tracked.changed).toBe(tracked.text !== text);
    }
  });

  it("a 4 MiB body dense with backslashes, and one with a one-letter value throughout", () => {
    const dense = "\\n".repeat(2 * 1024 * 1024);
    const denseOut = redactValues(dense, [DENSE_VALUE]);
    expect(denseOut === `\\${R.repeat(2 * 1024 * 1024 - 1)}n`).toBe(true);

    const letters = "e".repeat(4 * 1024 * 1024);
    const lettersOut = redactValues(letters, ["e"]);
    expect(lettersOut === R.repeat(4 * 1024 * 1024)).toBe(true);
  });

  it("the forms are today's", () => {
    const bytes = Buffer.from(VALUE_MIXED, "utf8");
    const forms = [
      bytes.toString("base64"),
      bytes.toString("base64url"),
      bytes.toString("hex"),
      bytes.toString("hex").toUpperCase(),
      encodeURIComponent(VALUE_MIXED),
    ];
    expect(new Set(forms).size).toBe(forms.length);

    for (const form of forms) {
      const out = redactValues(`form: ${form} end`, [VALUE_MIXED]);
      expectAbsent(out, form);
      expect(out).toBe(`form: ${R} end`);
    }
    const unknown = base32(VALUE_MIXED);
    expect(redactValues(`form: ${unknown} end`, [VALUE_MIXED]).includes(unknown)).toBe(true);
  });

  it("needlesFor leaves no value in its buffer", () => {
    const spy = vi.spyOn(Buffer, "from");
    try {
      redactValues("x", [VALUE_MIXED]);

      const calls = spy.mock.calls as unknown[][];
      const results = spy.mock.results as { type: string; value: unknown }[];
      const buffers = calls.flatMap((call, i) =>
        call[1] === "utf8" ? [results[i]?.value as Buffer] : [],
      );
      expect(buffers.length).toBeGreaterThan(0);
      for (const buffer of buffers) expect(buffer.every((byte) => byte === 0)).toBe(true);
    } finally {
      spy.mockRestore();
    }
  });
});
