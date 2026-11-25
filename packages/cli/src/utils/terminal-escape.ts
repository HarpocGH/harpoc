const CONTROL_CHARACTER = /\p{Cc}/u;
const HIDDEN_CHARACTER = /[\p{Cf}\p{Zl}\p{Zp}]/u;

/**
 * Text another party wrote, for a person to read on a terminal, escaped by class: every control
 * character but LF as `\xHH` (TAB `\t`, CR `\r`), every format character and the line and
 * paragraph separators, which reorder or hide text, as `\uXXXX`, above U+FFFF as `\u{…}`; a
 * backslash doubled; LF stays a line break.
 */
export function escapeForTerminal(text: string): string {
  let shown = "";
  for (const char of text) {
    const code = char.codePointAt(0) as number;
    if (char === "\\") shown += "\\\\";
    else if (char === "\n") shown += char;
    else if (char === "\t") shown += "\\t";
    else if (char === "\r") shown += "\\r";
    else if (CONTROL_CHARACTER.test(char)) {
      shown += `\\x${code.toString(16).padStart(2, "0")}`;
    } else if (HIDDEN_CHARACTER.test(char)) {
      shown +=
        code > 0xffff ? `\\u{${code.toString(16)}}` : `\\u${code.toString(16).padStart(4, "0")}`;
    } else shown += char;
  }
  return shown;
}
