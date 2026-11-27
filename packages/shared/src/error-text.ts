export type EchoPath = readonly (string | number)[];

export type TextPart =
  | { readonly kind: "words"; readonly text: string }
  | { readonly kind: "number"; readonly text: string }
  | { readonly kind: "token"; readonly text: string }
  | { readonly kind: "outside"; readonly text: string }
  | {
      readonly kind: "echo";
      readonly source: "handle" | "action";
      readonly path: EchoPath;
      readonly shown: string;
    };

export interface VaultText {
  readonly parts: readonly TextPart[];
}

export interface EchoSource {
  readonly handle?: string;
  readonly action?: unknown;
}

export const ECHO_UNREADABLE = "[unreadable]";
export const TOKEN_UNKNOWN = "unknown";

const MADE_PARTS = new WeakSet<object>();
const MADE_TEXTS = new WeakSet<object>();

function made(part: TextPart): TextPart {
  MADE_PARTS.add(Object.freeze(part));
  return part;
}

export function isTextPart(value: unknown): value is TextPart {
  return typeof value === "object" && value !== null && MADE_PARTS.has(value);
}

export function isVaultText(value: unknown): value is VaultText {
  return typeof value === "object" && value !== null && MADE_TEXTS.has(value);
}

export function vaultText(
  strings: TemplateStringsArray,
  ...parts: readonly (TextPart | VaultText)[]
): VaultText {
  const out: TextPart[] = [];
  strings.forEach((text, i) => {
    out.push(made({ kind: "words", text }));
    if (i >= parts.length) return;
    const part: unknown = parts[i];
    if (isVaultText(part)) out.push(...part.parts);
    else if (isTextPart(part)) out.push(part);
    else out.push(made({ kind: "words", text: TOKEN_UNKNOWN }));
  });
  const text: VaultText = Object.freeze({ parts: Object.freeze(out) });
  MADE_TEXTS.add(text);
  return text;
}

export function num(value: unknown): TextPart {
  return made(
    Number.isFinite(value)
      ? { kind: "number", text: String(value) }
      : { kind: "words", text: TOKEN_UNKNOWN },
  );
}

export function token(
  word: unknown,
  list: ReadonlySet<string> | readonly string[],
  other?: string,
): TextPart {
  const listed = typeof word === "string" && ("has" in list ? list.has(word) : list.includes(word));
  return made(
    listed ? { kind: "token", text: word } : { kind: "words", text: other ?? TOKEN_UNKNOWN },
  );
}

function readField(source: unknown, path: EchoPath): string {
  let at = source;
  for (const key of path) {
    if (typeof at !== "object" || at === null || !Object.hasOwn(at, key)) return ECHO_UNREADABLE;
    at = (at as Record<string | number, unknown>)[key];
  }
  return typeof at === "string" ? at : ECHO_UNREADABLE;
}

export function echoHandle(handle: unknown): TextPart {
  return made({
    kind: "echo",
    source: "handle",
    path: Object.freeze([]),
    shown: readField(handle, []),
  });
}

export function echoField(source: unknown, ...path: (string | number)[]): TextPart {
  return made({
    kind: "echo",
    source: "action",
    path: Object.freeze(path),
    shown: readField(source, path),
  });
}

export function outsidePart(redacted: string): TextPart {
  return made({ kind: "outside", text: redacted });
}

export function renderVaultText(text: VaultText, call?: EchoSource): string {
  return text.parts
    .map((part) => {
      if (part.kind !== "echo") return part.text;
      if (call === undefined) return part.shown;
      return readField(part.source === "handle" ? call.handle : call.action, part.path);
    })
    .join("");
}
