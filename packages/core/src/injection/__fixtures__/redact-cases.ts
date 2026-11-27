import { Buffer } from "node:buffer";

export interface RedactCase {
  name: string;
  text: string;
  values: string[];
  expect: string;
}

const R = "[REDACTED]";
const b64 = (s: string): string => Buffer.from(s, "utf8").toString("base64");
const b64url = (s: string): string => Buffer.from(s, "utf8").toString("base64url");
const hex = (s: string): string => Buffer.from(s, "utf8").toString("hex");
const wrap = (inner: string): string => JSON.stringify({ data: inner });
const t1 = (secret: string): string => JSON.stringify({ echo: secret });
const nest = (s: unknown): string => JSON.stringify(JSON.stringify(s));

export const PW = 'p"w';
export const DOC = '{"k": "v"}';
const BQ = 'dom\\us"er';
const HEXY = "deadbeef01";
const WIN = "DOM\\user";
const MONO = "DOMAIN\\name";
const B64SLASH = "sk?credential-with-slash-in-b64-xyz";
const LONG = "sk-topsecretvalue-123456>>";

/** The case table, in its numbered order: row n is `TABLE[n - 1]`. */
export const TABLE: readonly RedactCase[] = [
  {
    name: "one-letter values a c d e t",
    text: "a cat ate the red date",
    values: ["a", "c", "d", "e", "t"],
    expect: `${R} ${R}${R}${R} ${R}${R}${R} ${R}h${R} r${R}${R} ${R}${R}${R}${R}`,
  },
  {
    name: "RED, ACT, R",
    text: "x RED y ACT z R",
    values: ["RED", "ACT", "R"],
    expect: `x ${R} y ${R} z ${R}`,
  },
  {
    name: "marker fragments as later values of a list",
    text: "key SECRETVALUE end",
    values: ["SECRETVALUE", "RED", "E", "R"],
    expect: `key ${R} end`,
  },
  { name: "abcd + cdef in abcdef", text: "abcdef", values: ["abcd", "cdef"], expect: R },
  { name: "aa in xaaax", text: "xaaax", values: ["aa"], expect: `x${R}x` },
  { name: "aa in xaaaax", text: "xaaaax", values: ["aa"], expect: `x${R}x` },
  {
    name: "touching occurrences stay two markers",
    text: "SECRETSECRET aaa",
    values: ["SECRET", "a"],
    expect: `${R}${R} ${R}${R}${R}`,
  },
  {
    name: "a value that holds another",
    text: "fatal: x-INNER-y",
    values: ["INNER", "x-INNER-y"],
    expect: `fatal: ${R}`,
  },
  {
    name: "(A) bare number beside a password three documents deep",
    text: JSON.stringify({ uid: 1000, msg: wrap(wrap(t1(PW))) }),
    values: [PW, "1000"],
    expect: JSON.stringify({ uid: 1000, msg: wrap(wrap(t1(R))) }).replace("1000", R),
  },
  {
    name: "(B) a value that is a JSON document, raw beside its base64",
    text: `{"a": ${DOC}, "b": "${b64(DOC)}", "c": "x\\ny"}`,
    values: [DOC],
    expect: `{"a": ${R}, "b": "${R}", "c": "x\\ny"}`,
  },
  {
    name: "(A)+(B) raw document value beside another value nested",
    text: `{"a": ${DOC}, "d": ${nest({ e: PW })}}`,
    values: [DOC, PW],
    expect: `{"a": ${R}, "d": ${nest({ e: R })}}`,
  },
  {
    name: "backslash and quote, raw in plain text",
    text: `login ${BQ} failed`,
    values: [BQ],
    expect: `login ${R} failed`,
  },
  {
    name: "backslash and quote, V8-escaped in a document",
    text: JSON.stringify({ user: BQ, note: "x" }),
    values: [BQ],
    expect: JSON.stringify({ user: R, note: "x" }),
  },
  {
    name: "backslash and quote, \\uXXXX-escaped",
    text: '{"u":"dom\\u005cus\\u0022er"}',
    values: [BQ],
    expect: `{"u":"${R}"}`,
  },
  {
    name: "hex-shaped value, lower and upper case, and its hex forms",
    text: `lower ${HEXY} upper ${HEXY.toUpperCase()} hex ${hex(HEXY)} HEX ${hex(HEXY).toUpperCase()}`,
    values: [HEXY],
    expect: `lower ${R} upper ${R} hex ${R} HEX ${R}`,
  },
  { name: "doubly serialized", text: wrap(t1(PW)), values: [PW], expect: wrap(t1(R)) },
  { name: "triply serialized", text: wrap(wrap(t1(PW))), values: [PW], expect: wrap(wrap(t1(R))) },
  {
    name: "five documents (the cap)",
    text: wrap(wrap(wrap(wrap(t1(PW))))),
    values: [PW],
    expect: wrap(wrap(wrap(wrap(t1(R))))),
  },
  {
    name: "six documents (blind, as today)",
    text: wrap(wrap(wrap(wrap(wrap(t1(PW)))))),
    values: [PW],
    expect: wrap(wrap(wrap(wrap(wrap(t1(PW)))))),
  },
  {
    name: "a marker already in the text",
    text: `old ${R} and SECRETVALUE`,
    values: ["SECRETVALUE", "E", "RED"],
    expect: `old ${R} and ${R}`,
  },
  {
    name: "a match that overlaps a marker of the text",
    text: `x${R} y`,
    values: ["x[RE"],
    expect: `${R} y`,
  },
  {
    name: "a match completed by a marker this call wrote",
    text: "passUVW",
    values: ["ss[", "UVW"],
    expect: `pa${R}`,
  },
  {
    name: "a document only the redaction makes parseable",
    text: `{"user":"${WIN}","data":${nest({ e: WIN })}}`,
    values: [WIN],
    expect: JSON.stringify({ user: R, data: JSON.stringify({ e: R }) }),
  },
  {
    name: "a sibling that only re-serialization turns into the value",
    text: `{"data":${nest({ echo: MONO })},"sibling":"DOMAIN\\u000Aame"}`,
    values: [MONO],
    expect: `{"data":${nest({ echo: R })},"sibling":"DOMAIN\\u000Aame"}`,
  },
  {
    name: "a nested hit in a document that is not JSON.stringify output",
    text: `{"id": 7, "data": ${nest({ echo: PW })}}`,
    values: [PW],
    expect: `{"id": 7, "data": ${nest({ echo: R })}}`,
  },
  {
    name: "key position at depth",
    text: wrap(JSON.stringify({ [PW]: 1 })),
    values: [PW],
    expect: wrap(JSON.stringify({ [R]: 1 })),
  },
  {
    name: "two keys redacted onto one name",
    text: `{"p\\\\\\"w":1,"${b64(PW)}":2}`,
    values: [PW],
    expect: `{"${R}":1,"${R}":2}`,
  },
  {
    name: "base64 with an escaped solidus",
    text: `{"echo":"${b64(B64SLASH).replace(/\//g, "\\/")}"}`,
    values: [B64SLASH],
    expect: `{"echo":"${R}"}`,
  },
  {
    name: "ensure_ascii escaping",
    text: '{"echo":"sk-t\\u00fcr-1"}',
    values: ["sk-tür-1"],
    expect: `{"echo":"${R}"}`,
  },
  {
    name: "a match that starts inside an escape",
    text: '{"a":"x\\ty \\u0062"}',
    values: ["t", "u0062"],
    expect: `{"a":"x\\${R}y \\${R}"}`,
  },
  { name: "percent form", text: "q=a%20b%2Fc%3Fd&r=1", values: ["a b/c?d"], expect: `q=${R}&r=1` },
  {
    name: "base64 and base64url forms",
    text: `${b64(LONG)} ${b64url(LONG)}`,
    values: [LONG],
    expect: `${R} ${R}`,
  },
  {
    name: "nothing to redact",
    text: '{"marker":"keep-me","n":"a\\nb"}',
    values: ["abc123"],
    expect: '{"marker":"keep-me","n":"a\\nb"}',
  },
  { name: "empty text", text: "", values: ["x"], expect: "" },
  { name: "empty list", text: "text", values: [], expect: "text" },
];

export function tableRow(n: number): RedactCase {
  return TABLE[n - 1] as RedactCase;
}

const esc = (s: string): string => JSON.stringify(s).slice(1, -1);
const JOIN = '","x":"';
const LEFT = '{"k":"';
const RIGHT = `","d":${JSON.stringify(t1(PW))}}`;

/** Inputs on which the positional redaction keeps what the old fold removes in one order. */
export const RESIDUALS: readonly RedactCase[] = [
  {
    name: "a document that only two of three values together make parseable",
    text: `{"a":"A\\uz","b":"B\\uy","n":1000,"d":${nest({ e: "B\\uy" })}}`,
    values: ["A\\uz", "B\\uy", "1000"],
    expect: `{"a":"${R}","b":"${R}","n":${R},"d":${nest({ e: "B\\uy" })}}`,
  },
  {
    name: "a value whose span joins two strings into one nested document",
    text: `{"a":"${esc(LEFT)}${JOIN}${esc(RIGHT)}"}`,
    values: [JOIN, PW],
    expect: `{"a":"${esc(LEFT)}${R}${esc(RIGHT)}"}`,
  },
];

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const SPECIAL = [
  "a",
  "c",
  "d",
  "e",
  "t",
  "R",
  "RED",
  "ACT",
  "aa",
  "abcd",
  "cdef",
  "1000",
  "10",
  'p"w',
  '{"k": "v"}',
  "dom\\user",
  "a/b",
  "tür",
  "ab12ef",
  "x[",
  "D]y",
  "ss[",
  "]q",
  "\\n",
  "u0041",
  "n",
  '"',
  "\\",
  " ",
  ":",
  '","',
  "true",
  "tok-en-1",
  "sk/live+1",
  'q"u\\o',
  "ab",
  "ba",
  "aba",
  "[1, 2]",
  "e1",
];
const SMALL = "acdetRED10";
const MIXED = 'ab"\\/x1[]{}: ,n';
const LIMITS = [400, 400, 160, 60, 30];

function makeGenerator(seed: number): () => { text: string; values: string[] } {
  const rnd = mulberry32(seed);
  const int = (n: number): number => Math.floor(rnd() * n);
  const pick = <T>(list: readonly T[]): T => list[int(list.length)] as T;
  const word = (alphabet: string, min: number, max: number): string => {
    let out = "";
    for (let n = min + int(max - min + 1); n > 0; n--) out += alphabet[int(alphabet.length)];
    return out;
  };

  const value = (): string => {
    const r = rnd();
    if (r < 0.5) return pick(SPECIAL);
    if (r < 0.75) return word(SMALL, 1, 3);
    return word(MIXED, 2, 6);
  };
  const values = (): string[] => {
    const r = rnd();
    const size = r < 0.25 ? 1 : r < 0.7 ? 2 : r < 0.95 ? 3 : 4;
    const out = new Set<string>();
    for (let tries = 0; out.size < size && tries < 20; tries++) out.add(value());
    return [...out];
  };

  const unicodeEscape = (s: string, every: boolean): string =>
    Array.from({ length: s.length }, (_, i) =>
      every || rnd() < 0.4
        ? `\\u${s.charCodeAt(i).toString(16).padStart(4, "0")}`
        : JSON.stringify(s[i]).slice(1, -1),
    ).join("");
  const form = (v: string): string => {
    const bytes = Buffer.from(v, "utf8");
    switch (int(12)) {
      case 0:
        return bytes.toString("base64");
      case 1:
        return bytes.toString("base64url");
      case 2:
        return bytes.toString("hex");
      case 3:
        return bytes.toString("hex").toUpperCase();
      case 4:
        return encodeURIComponent(v);
      case 5:
        return JSON.stringify(v).slice(1, -1);
      case 6:
        return JSON.stringify(v).slice(1, -1).replace(/\//g, "\\/");
      case 7:
        return unicodeEscape(v, true);
      case 8:
        return unicodeEscape(v, false);
      case 9:
        return v.toUpperCase();
      default:
        return v;
    }
  };
  const atom = (vals: readonly string[]): string => {
    const r = rnd();
    if (r < 0.5) return form(pick(vals));
    if (r < 0.6) {
      const a = pick(vals);
      const b = pick(vals);
      return a + b.slice(int(b.length + 1));
    }
    if (r < 0.66) return R;
    if (r < 0.8) return word(SMALL, 1, 4);
    if (r < 0.9) return word(MIXED, 1, 5);
    return pick(["\\n", "\\t", "\\u000a", "\\/", "1000", "1e3", "\\\\", "\n", "x"]);
  };
  const plain = (vals: readonly string[]): string => {
    let out = "";
    for (let n = 1 + int(4); n > 0; n--)
      out += atom(vals) + pick(["", "", " ", ",", "=", "\\", '"']);
    return out;
  };

  const token = (s: string): string => {
    const v8 = JSON.stringify(s);
    const r = rnd();
    if (r < 0.7) return v8;
    if (r < 0.85) return v8.replace(/\//g, "\\/");
    return `"${unicodeEscape(s, false)}"`;
  };
  const doc = (vals: readonly string[], depth: number): string => {
    const spaced = rnd() < 0.3;
    const sep = spaced ? ", " : ",";
    const colon = spaced ? ": " : ":";
    const member = (): string => {
      const r = rnd();
      if (depth > 0 && r < 0.4) return token(doc(vals, depth - 1));
      if (r < 0.75) return token(plain(vals));
      if (r < 0.82) return pick(["1000", "10", "1e3", "true", "null", "12"]);
      if (r < 0.88) return pick(vals);
      if (r < 0.93) return `"${pick(vals)}"`;
      return depth > 0 ? doc(vals, depth - 1) : "[1,2]";
    };
    const key = (): string =>
      rnd() < 0.8 ? JSON.stringify(word("kmnuv", 1, 3)) : token(atom(vals));
    const parts: string[] = [];
    const asArray = rnd() < 0.2;
    for (let n = 1 + int(3); n > 0; n--)
      parts.push(asArray ? member() : `${key()}${colon}${member()}`);
    return asArray ? `[${parts.join(sep)}]` : `{${parts.join(sep)}}`;
  };

  const text = (vals: readonly string[]): string => {
    const r = rnd();
    if (r < 0.3) return plain(vals);
    let out = doc(vals, int(5));
    if (r > 0.9) out = out.slice(0, out.length - 1 - int(4));
    else if (r > 0.86) out = ` ${out}\n`;
    return out;
  };

  return () => {
    const vals = values();
    const growing = vals.filter((v) => R.includes(v) || R.includes(v.toUpperCase())).length;
    return { text: text(vals).slice(0, LIMITS[growing]), values: vals };
  };
}

/** Seeded texts and lists: short, over a small alphabet, so that overlaps and collisions are frequent. */
export function randomCases(seed: number, count: number): { text: string; values: string[] }[] {
  const next = makeGenerator(seed);
  return Array.from({ length: count }, () => next());
}

export function permutations<T>(list: readonly T[]): T[][] {
  if (list.length <= 1) return [[...list]];
  const out: T[][] = [];
  list.forEach((head, i) => {
    for (const tail of permutations([...list.slice(0, i), ...list.slice(i + 1)])) {
      out.push([head, ...tail]);
    }
  });
  return out;
}
