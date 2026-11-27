import { Buffer } from "node:buffer";

const REDACTION = "[REDACTED]";
const MAX_JSON_PARSES = 4;
const MAX_STRUCTURAL_CHARS = 4 * 1024 * 1024;

const SIMPLE_ESCAPES: Record<string, string> = {
  '"': '"',
  "\\": "\\",
  "/": "/",
  b: "\b",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "\t",
};

function isHex(ch: string | undefined): boolean {
  return ch !== undefined && /^[0-9a-fA-F]$/.test(ch);
}

function consume(text: string, at: number, wanted: string): number {
  if (at >= text.length) return 0;

  if (text[at] === "\\") {
    const next = text[at + 1];
    if (next !== undefined) {
      const simple = SIMPLE_ESCAPES[next];
      if (simple !== undefined) return simple === wanted ? 2 : 0;
      if (
        next === "u" &&
        isHex(text[at + 2]) &&
        isHex(text[at + 3]) &&
        isHex(text[at + 4]) &&
        isHex(text[at + 5])
      ) {
        const code = Number.parseInt(text.slice(at + 2, at + 6), 16);
        return String.fromCharCode(code) === wanted ? 6 : 0;
      }
    }
  }

  return text[at] === wanted ? 1 : 0;
}

export function referenceMatchAt(text: string, start: number, needle: string): number {
  let at = start;
  for (let i = 0; i < needle.length; i++) {
    const step = consume(text, at, needle[i] as string);
    if (step === 0) return -1;
    at += step;
  }
  return at;
}

function redactEscapeTolerant(text: string, needle: string, replacement: string): string {
  if (text.length === 0 || needle.length === 0) return text;

  const first = needle[0] as string;
  let out = "";
  let cursor = 0;
  let i = 0;

  while (i < text.length) {
    if (text[i] === first || text[i] === "\\") {
      const end = referenceMatchAt(text, i, needle);
      if (end !== -1) {
        out += text.slice(cursor, i) + replacement;
        cursor = end;
        i = end;
        continue;
      }
    }
    i++;
  }

  return cursor === 0 ? text : out + text.slice(cursor);
}

function setOwnProperty(target: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(target, key, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

function mapStringLeavesTracked(
  value: unknown,
  fn: (s: string) => string,
  budget: number,
): { value: unknown; changed: boolean } {
  if (typeof value === "string") {
    const mapped = fn(value);
    if (budget > 0) {
      const trimmed = mapped.trim();
      if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        try {
          const parsed: unknown = JSON.parse(trimmed);
          if (typeof parsed === "object" && parsed !== null) {
            const inner = mapStringLeavesTracked(parsed, fn, budget - 1);
            if (inner.changed) return { value: JSON.stringify(inner.value), changed: true };
          }
        } catch {
          // the mapped form stands
        }
      }
    }
    return { value: mapped, changed: mapped !== value };
  }

  if (Array.isArray(value)) {
    let changed = false;
    const mapped = value.map((item) => {
      const r = mapStringLeavesTracked(item, fn, budget);
      if (r.changed) changed = true;
      return r.value;
    });
    return { value: mapped, changed };
  }

  if (value !== null && typeof value === "object") {
    const result: Record<string, unknown> = {};
    let changed = false;
    for (const [key, val] of Object.entries(value)) {
      let mappedKey = fn(key);
      if (mappedKey !== key) changed = true;
      if (Object.prototype.hasOwnProperty.call(result, mappedKey)) {
        let suffix = 2;
        while (Object.prototype.hasOwnProperty.call(result, `${mappedKey}_${suffix}`)) suffix++;
        mappedKey = `${mappedKey}_${suffix}`;
        changed = true;
      }
      const r = mapStringLeavesTracked(val, fn, budget);
      if (r.changed) changed = true;
      setOwnProperty(result, mappedKey, r.value);
    }
    return { value: result, changed };
  }

  return { value, changed: false };
}

function needlesFor(secret: string): string[] {
  const secretBytes = Buffer.from(secret, "utf8");
  return [
    ...new Set<string>([
      secret,
      secretBytes.toString("base64"),
      secretBytes.toString("base64url"),
      secretBytes.toString("hex"),
      encodeURIComponent(secret),
    ]),
  ].filter((n) => n.length > 0);
}

function isHexNeedle(needle: string): boolean {
  return needle.toUpperCase() !== needle && /^[0-9a-fA-F]+$/.test(needle);
}

/** Every string `redactFlat` searches for one value: its needles and their upper-case hex forms. */
export function referenceNeedles(secret: string): string[] {
  const out = new Set<string>();
  for (const needle of needlesFor(secret)) {
    out.add(needle);
    if (isHexNeedle(needle)) out.add(needle.toUpperCase());
  }
  return [...out];
}

function redactFlat(text: string, needles: string[]): string {
  if (text.length === 0) return text;
  const hasBackslash = text.includes("\\");
  let result = text;
  for (const needle of needles) {
    if (result.includes(needle)) {
      result = result.split(needle).join(REDACTION);
    }
    const upper = needle.toUpperCase();
    const isHexNeedle = upper !== needle && /^[0-9a-fA-F]+$/.test(needle);
    if (isHexNeedle && result.includes(upper)) {
      result = result.split(upper).join(REDACTION);
    }
    if (hasBackslash && isHexNeedle) {
      result = redactEscapeTolerant(result, upper, REDACTION);
    }
    if (hasBackslash) {
      result = redactEscapeTolerant(result, needle, REDACTION);
    }
  }
  return result;
}

/** `redactSecretEncodings` as it stood before the positional redaction. */
export function referenceRedact(text: string, secret: string): string {
  if (text.length === 0 || secret.length === 0) return text;

  const needles = needlesFor(secret);
  const flat = redactFlat(text, needles);

  if (!text.includes("\\") || flat.length > MAX_STRUCTURAL_CHARS) return flat;

  const trimmed = flat.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return flat;

  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (typeof parsed !== "object" || parsed === null) return flat;
    const walked = mapStringLeavesTracked(
      parsed,
      (s) => redactFlat(s, needles),
      MAX_JSON_PARSES - 1,
    );
    if (!walked.changed) return flat;
    return redactFlat(JSON.stringify(walked.value), needles);
  } catch {
    return flat;
  }
}

/** The old function applied once per value, in the order of the list. */
export function referenceFold(text: string, values: readonly string[]): string {
  return values.reduce((out, value) => referenceRedact(out, value), text);
}

interface Char {
  c: string;
  lo: number;
  hi: number;
  m: boolean;
  s: boolean;
  r: boolean;
  src: Char[] | null;
}

type Kind = "marker" | "synthetic" | "respelled";

interface Rec {
  all: Uint8Array;
  genuine: Uint8Array;
  kind: (Kind | undefined)[];
}

type Node =
  | { t: "s"; pt: Char[] }
  | { t: "v"; value: unknown; raw: Char[] }
  | { t: "a"; items: Node[] }
  | { t: "o"; entries: Entry[] };

interface Entry {
  key: Char[];
  value: Node;
}

const ch = (
  c: string,
  lo: number,
  hi: number,
  flags: Partial<Pick<Char, "m" | "s" | "r" | "src">> = {},
): Char => ({ c, lo, hi, m: false, s: false, r: false, src: null, ...flags });

const ptOf = (text: string): Char[] =>
  Array.from({ length: text.length }, (_, i) => ch(text[i] as string, i, i + 1));

const strOf = (pt: readonly Char[]): string => {
  let out = "";
  for (const x of pt) out += x.c;
  return out;
};

const synthetic = (text: string): Char[] => Array.from(text, (c) => ch(c, -1, -1, { s: true }));

const at = (pt: readonly Char[], i: number): Char => pt[i] as Char;

function literalSpans(text: string, needle: string): [number, number][] {
  const spans: [number, number][] = [];
  for (let i = text.indexOf(needle); i !== -1; i = text.indexOf(needle, i + needle.length)) {
    spans.push([i, i + needle.length]);
  }
  return spans;
}

function readAhead(text: string, start: number, needle: string): number {
  let pos = start;
  let seen = start;
  for (let i = 0; i < needle.length; i++) {
    const next = text[pos + 1];
    if (text[pos] === "\\" && next !== undefined) {
      const reach = SIMPLE_ESCAPES[next] !== undefined ? 2 : next === "u" ? 6 : 2;
      seen = Math.max(seen, Math.min(text.length, pos + reach));
    }
    pos += consume(text, pos, needle[i] as string);
  }
  return Math.max(seen, pos);
}

function tolerantSpans(text: string, needle: string): [number, number, number][] {
  const spans: [number, number, number][] = [];
  let i = 0;
  while (i < text.length) {
    if (text[i] === needle[0] || text[i] === "\\") {
      const end = referenceMatchAt(text, i, needle);
      if (end !== -1) {
        spans.push([i, end, readAhead(text, i, needle)]);
        i = end;
        continue;
      }
    }
    i++;
  }
  return spans;
}

function replace(pt: Char[], spans: readonly (readonly number[])[], rec: Rec): Char[] {
  if (spans.length === 0) return pt;
  const out: Char[] = [];
  let cursor = 0;
  for (const span of spans) {
    const s = span[0] as number;
    const e = span[1] as number;
    const read = span[2] ?? e;
    for (let i = cursor; i < s; i++) out.push(at(pt, i));
    const cut = pt.slice(s, e);
    const seen = pt.slice(s, read);
    const kind: Kind | "genuine" = seen.some((x) => x.m)
      ? "marker"
      : seen.some((x) => x.s)
        ? "synthetic"
        : seen.some((x) => x.r)
          ? "respelled"
          : "genuine";
    for (const x of cut) {
      for (let p = x.lo; p < x.hi; p++) {
        rec.all[p] = 1;
        if (kind === "genuine") rec.genuine[p] = 1;
        else if (rec.kind[p] === undefined) rec.kind[p] = kind;
      }
    }
    for (const c of REDACTION) out.push(ch(c, -1, -1, { m: true }));
    cursor = e;
  }
  for (let i = cursor; i < pt.length; i++) out.push(at(pt, i));
  return out;
}

function modelFlat(pt: Char[], needles: string[], rec: Rec): Char[] {
  if (pt.length === 0) return pt;
  const hasBackslash = strOf(pt).includes("\\");
  let result = pt;
  for (const needle of needles) {
    result = replace(result, literalSpans(strOf(result), needle), rec);
    const upper = needle.toUpperCase();
    const hexNeedle = isHexNeedle(needle);
    if (hexNeedle) result = replace(result, literalSpans(strOf(result), upper), rec);
    if (hasBackslash && hexNeedle)
      result = replace(result, tolerantSpans(strOf(result), upper), rec);
    if (hasBackslash) result = replace(result, tolerantSpans(strOf(result), needle), rec);
  }
  return result;
}

function parseTree(pt: Char[]): Node {
  let i = 0;
  const ws = (): void => {
    while (i < pt.length && " \t\n\r".includes(at(pt, i).c)) i++;
  };
  const str = (): Char[] => {
    i++;
    const out: Char[] = [];
    while (at(pt, i).c !== '"') {
      if (at(pt, i).c !== "\\") {
        out.push(at(pt, i++));
        continue;
      }
      const len = at(pt, i + 1).c === "u" ? 6 : 2;
      const raw = pt.slice(i, i + len);
      const c =
        len === 6
          ? String.fromCharCode(Number.parseInt(strOf(raw.slice(2)), 16))
          : (SIMPLE_ESCAPES[at(raw, 1).c] as string);
      const known = raw.filter((x) => x.lo >= 0);
      out.push(
        ch(
          c,
          known.length ? Math.min(...known.map((x) => x.lo)) : -1,
          known.length ? Math.max(...known.map((x) => x.hi)) : -1,
          {
            m: raw.some((x) => x.m),
            s: raw.some((x) => x.s),
            r: raw.some((x) => x.r),
            src: raw,
          },
        ),
      );
      i += len;
    }
    i++;
    return out;
  };
  const val = (): Node => {
    ws();
    const c = at(pt, i).c;
    if (c === '"') return { t: "s", pt: str() };
    if (c === "[") {
      i++;
      const items: Node[] = [];
      ws();
      if (at(pt, i).c === "]") {
        i++;
        return { t: "a", items };
      }
      for (;;) {
        items.push(val());
        ws();
        if (at(pt, i++).c === "]") return { t: "a", items };
      }
    }
    if (c === "{") {
      i++;
      const order: Record<string, number> = {};
      const byKey = new Map<string, Entry>();
      ws();
      if (at(pt, i).c === "}") {
        i++;
        return { t: "o", entries: [] };
      }
      for (;;) {
        ws();
        const key = str();
        ws();
        i++;
        const value = val();
        const name = strOf(key);
        Object.defineProperty(order, name, {
          value: 1,
          enumerable: true,
          configurable: true,
          writable: true,
        });
        byKey.set(name, { key, value });
        ws();
        if (at(pt, i++).c === "}") {
          return { t: "o", entries: Object.keys(order).map((k) => byKey.get(k) as Entry) };
        }
      }
    }
    const start = i;
    while (i < pt.length && !",]} \t\n\r".includes(at(pt, i).c)) i++;
    const raw = pt.slice(start, i);
    return { t: "v", value: JSON.parse(strOf(raw)) as unknown, raw };
  };
  return val();
}

function stringifyString(pt: Char[], out: Char[]): void {
  out.push(...synthetic('"'));
  const emit = (y: Char, text: string): void => {
    if (y.src !== null && strOf(y.src) === text) out.push(...y.src);
    else if (y.src === null && text === y.c) out.push(y);
    else for (const c of text) out.push(ch(c, y.lo, y.hi, { m: y.m, s: y.s, r: true }));
  };
  for (let i = 0; i < pt.length; i++) {
    const x = at(pt, i);
    const code = x.c.charCodeAt(0);
    const following = pt[i + 1];
    const next = following === undefined ? Number.NaN : following.c.charCodeAt(0);
    const paired = code >= 0xd800 && code <= 0xdbff && next >= 0xdc00 && next <= 0xdfff;
    if (paired && following !== undefined) {
      emit(x, x.c);
      emit(following, following.c);
      i++;
    } else {
      emit(x, JSON.stringify(x.c).slice(1, -1));
    }
  }
  out.push(...synthetic('"'));
}

function stringifyTree(node: Node, out: Char[] = []): Char[] {
  if (node.t === "s") stringifyString(node.pt, out);
  else if (node.t === "v") {
    const text = JSON.stringify(node.value);
    if (text === strOf(node.raw)) out.push(...node.raw);
    else out.push(...synthetic(text));
  } else if (node.t === "a") {
    out.push(...synthetic("["));
    node.items.forEach((item, n) => {
      if (n > 0) out.push(...synthetic(","));
      stringifyTree(item, out);
    });
    out.push(...synthetic("]"));
  } else {
    out.push(...synthetic("{"));
    node.entries.forEach((entry, n) => {
      if (n > 0) out.push(...synthetic(","));
      stringifyString(entry.key, out);
      out.push(...synthetic(":"));
      stringifyTree(entry.value, out);
    });
    out.push(...synthetic("}"));
  }
  return out;
}

function walk(
  node: Node,
  fn: (pt: Char[]) => Char[],
  budget: number,
): { node: Node; changed: boolean } {
  if (node.t === "s") {
    const mapped = fn(node.pt);
    const text = strOf(mapped);
    if (budget > 0) {
      const trimmed = text.trim();
      if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        try {
          const parsed: unknown = JSON.parse(trimmed);
          if (typeof parsed === "object" && parsed !== null) {
            const lead = text.length - text.trimStart().length;
            const inner = walk(
              parseTree(mapped.slice(lead, lead + trimmed.length)),
              fn,
              budget - 1,
            );
            if (inner.changed) {
              return { node: { t: "s", pt: stringifyTree(inner.node) }, changed: true };
            }
          }
        } catch {
          // the mapped form stands
        }
      }
    }
    return { node: { t: "s", pt: mapped }, changed: text !== strOf(node.pt) };
  }
  if (node.t === "a") {
    let changed = false;
    const items = node.items.map((item) => {
      const r = walk(item, fn, budget);
      if (r.changed) changed = true;
      return r.node;
    });
    return { node: { t: "a", items }, changed };
  }
  if (node.t === "o") {
    const order: Record<string, number> = {};
    const byKey = new Map<string, Entry>();
    let changed = false;
    for (const { key, value } of node.entries) {
      let mappedKey = fn(key);
      let name = strOf(mappedKey);
      if (name !== strOf(key)) changed = true;
      if (Object.prototype.hasOwnProperty.call(order, name)) {
        let suffix = 2;
        while (Object.prototype.hasOwnProperty.call(order, `${name}_${suffix}`)) suffix++;
        mappedKey = [...mappedKey, ...synthetic(`_${suffix}`)];
        name = `${name}_${suffix}`;
        changed = true;
      }
      const r = walk(value, fn, budget);
      if (r.changed) changed = true;
      Object.defineProperty(order, name, {
        value: 1,
        enumerable: true,
        configurable: true,
        writable: true,
      });
      byKey.set(name, { key: mappedKey, value: r.node });
    }
    return {
      node: { t: "o", entries: Object.keys(order).map((k) => byKey.get(k) as Entry) },
      changed,
    };
  }
  return { node, changed: false };
}

function modelRedact(pt: Char[], secret: string, rec: Rec): Char[] {
  if (pt.length === 0 || secret.length === 0) return pt;
  const needles = needlesFor(secret);
  const flat = modelFlat(pt, needles, rec);
  const flatText = strOf(flat);
  if (!strOf(pt).includes("\\") || flatText.length > MAX_STRUCTURAL_CHARS) return flat;
  const trimmed = flatText.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return flat;
  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (typeof parsed !== "object" || parsed === null) return flat;
    const lead = flatText.length - flatText.trimStart().length;
    const tree = parseTree(flat.slice(lead, lead + trimmed.length));
    const walked = walk(tree, (s) => modelFlat(s, needles, rec), MAX_JSON_PARSES - 1);
    if (!walked.changed) return flat;
    return modelFlat(stringifyTree(walked.node), needles, rec);
  } catch {
    return flat;
  }
}

/**
 * The old fold over `values` in their order, with the positions of `text` it removed.
 * A removal is through a marker or through re-serialization when a character it was
 * matched against, the look-ahead of an escape included, was part of a marker the fold
 * wrote, or was written or respelled by its `JSON.stringify`; a position that some
 * removal of the text itself reached is in neither set.
 */
export function referencePositions(
  text: string,
  values: readonly string[],
): {
  output: string;
  removed: Set<number>;
  throughMarker: Set<number>;
  throughReserialization: Set<number>;
} {
  const rec: Rec = {
    all: new Uint8Array(text.length),
    genuine: new Uint8Array(text.length),
    kind: [],
  };
  let pt = ptOf(text);
  for (const value of values) pt = modelRedact(pt, value, rec);
  const removed = new Set<number>();
  const throughMarker = new Set<number>();
  const throughReserialization = new Set<number>();
  for (let p = 0; p < text.length; p++) {
    if (rec.all[p] !== 1) continue;
    removed.add(p);
    if (rec.genuine[p] === 1) continue;
    if (rec.kind[p] === "marker") throughMarker.add(p);
    else throughReserialization.add(p);
  }
  return { output: strOf(pt), removed, throughMarker, throughReserialization };
}
