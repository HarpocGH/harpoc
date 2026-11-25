import { describe, expect, it } from "vitest";
import { escapeForTerminal } from "./terminal-escape.js";

const hex = (code: number, width: number): string => code.toString(16).padStart(width, "0");
const codes = (...ranges: [number, number][]): [string, number][] =>
  ranges.flatMap(([from, to]) =>
    Array.from({ length: to - from + 1 }, (_, i): [string, number] => [
      hex(from + i, 4).toUpperCase(),
      from + i,
    ]),
  );

describe("escapeForTerminal", () => {
  it.each(codes([0x00, 0x08], [0x0b, 0x0c], [0x0e, 0x1f]))(
    "shows the C0 control U+%s as \\xHH",
    (_label, code) => {
      expect(escapeForTerminal(`a${String.fromCharCode(code)}b`)).toBe(`a\\x${hex(code, 2)}b`);
    },
  );

  it("shows TAB as \\t, CR as \\r and ESC as \\x1b", () => {
    expect(escapeForTerminal("a\tb\rc\u001b[2Kd")).toBe("a\\tb\\rc\\x1b[2Kd");
  });

  it("keeps LF a line break", () => {
    expect(escapeForTerminal("a\nb\n")).toBe("a\nb\n");
  });

  it.each(codes([0x7f, 0x9f]))("shows DEL and the C1 control U+%s as \\xHH", (_label, code) => {
    expect(escapeForTerminal(`a${String.fromCharCode(code)}b`)).toBe(`a\\x${hex(code, 2)}b`);
  });

  it.each(
    codes(
      [0x00ad, 0x00ad],
      [0x061c, 0x061c],
      [0x180e, 0x180e],
      [0x200b, 0x200f],
      [0x202a, 0x202e],
      [0x2060, 0x2064],
      [0x2066, 0x206f],
      [0x2028, 0x2029],
      [0xfeff, 0xfeff],
    ),
  )("shows the format character or line separator U+%s as \\uXXXX", (_label, code) => {
    expect(escapeForTerminal(`a${String.fromCharCode(code)}b`)).toBe(`a\\u${hex(code, 4)}b`);
  });

  it.each(codes([0x110bd, 0x110bd], [0x1d173, 0x1d17a], [0xe0001, 0xe0001], [0xe0020, 0xe007f]))(
    "shows the format character U+%s, above U+FFFF, as \\u{…}",
    (_label, code) => {
      expect(escapeForTerminal(`a${String.fromCodePoint(code)}b`)).toBe(
        `a\\u{${code.toString(16)}}b`,
      );
    },
  );

  it("escapes by class: no control but LF, no format character and no line or paragraph separator is shown raw", () => {
    const hidden = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
    const raw: string[] = [];
    let judged = 0;
    for (let code = 0; code <= 0x10ffff; code++) {
      if (code >= 0xd800 && code <= 0xdfff) continue;
      const char = String.fromCodePoint(code);
      if (char === "\n" || !hidden.test(char)) continue;
      judged += 1;
      const shown = escapeForTerminal(char);
      if (!/^\\(?:[tr]|x[0-9a-f]{2}|u[0-9a-f]{4}|u\{[0-9a-f]{5,6}\})$/.test(shown)) {
        raw.push(`U+${hex(code, 4).toUpperCase()}`);
      }
    }
    expect(raw).toEqual([]);
    expect(judged).toBeGreaterThan(200);
  });

  it("doubles a backslash, so an escape it prints is never the text's own", () => {
    expect(escapeForTerminal("C:\\data\\x1b")).toBe("C:\\\\data\\\\x1b");
    expect(escapeForTerminal("\\\u001b")).toBe("\\\\\\x1b");
  });

  it("leaves every other character as it is, the escaped ranges' neighbours included", () => {
    const plain =
      " ~\u00a0\u00e9\u00fc\u200a\u2010\u2027\u202f\u2065\ufefe\uff01😀{{secret://bot-token}}\"'`$";
    expect(escapeForTerminal(plain)).toBe(plain);
  });
});
