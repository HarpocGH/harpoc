import { describe, expect, it } from "vitest";

import {
  echoField,
  echoHandle,
  isTextPart,
  isVaultText,
  num,
  outsidePart,
  renderVaultText,
  token,
  vaultText,
} from "./error-text.js";
import type { TextPart } from "./error-text.js";

type EchoPart = Extract<TextPart, { kind: "echo" }>;

const shown = (part: TextPart): string => (part as EchoPart).shown;
const rendered = (part: TextPart): string => renderVaultText(vaultText`${part}`);

describe("error-text", () => {
  it("a template of words and parts renders in order", () => {
    expect(renderVaultText(vaultText`a ${num(3)} b ${token("ENOENT", ["ENOENT"])} c`)).toBe(
      "a 3 b ENOENT c",
    );
  });

  it("a number that is none is the fixed word", () => {
    expect([num("7"), num(NaN), num(Infinity), num(undefined)].map(rendered)).toEqual([
      "unknown",
      "unknown",
      "unknown",
      "unknown",
    ]);
  });

  it("a token off its list is the fixed word", () => {
    expect(rendered(token("ERR_SSL_X", ["ENOENT"]))).toBe("unknown");
    expect(rendered(token("ERR_SSL_X", ["ENOENT"], "unknown error"))).toBe("unknown error");
    expect(rendered(token(5, ["5"]))).toBe("unknown");
    expect(rendered(token("ENOENT", new Set(["ENOENT"])))).toBe("ENOENT");
  });

  it("an echo reads the field it names", () => {
    expect(shown(echoField({ url: "https://x/a" }, "url"))).toBe("https://x/a");
    expect(shown(echoField({ args: ["a", "b"] }, "args", 1))).toBe("b");
  });

  it("an echo of what is no string is the fixed word", () => {
    const sources: unknown[] = [
      { url: 5 },
      {},
      null,
      { url: { toString: () => "x" } },
      Object.create({ url: "x" }),
    ];
    expect(sources.map((source) => shown(echoField(source, "url")))).toEqual([
      "[unreadable]",
      "[unreadable]",
      "[unreadable]",
      "[unreadable]",
      "[unreadable]",
    ]);
  });

  it("an echo keeps no reference to its source", () => {
    const part = echoField({ url: "https://x/a" }, "url");
    expect(Reflect.ownKeys(part).sort()).toEqual(["kind", "path", "shown", "source"]);
  });

  it("the pass's rendering reads the call, not what the site showed", () => {
    const text = vaultText`URL not in secret allowlist: ${echoField({ url: "derived" }, "url")}`;
    expect(renderVaultText(text, { action: { url: "as sent" } })).toBe(
      "URL not in secret allowlist: as sent",
    );
    expect(renderVaultText(text, { action: {} })).toBe("URL not in secret allowlist: [unreadable]");
    expect(renderVaultText(vaultText`${echoHandle("h")}`, { handle: "other" })).toBe("other");
    expect(renderVaultText(vaultText`${echoHandle("h")}`, {})).toBe("[unreadable]");
  });

  it("a text among the parts is spliced", () => {
    expect(vaultText`a ${vaultText`b ${num(1)}`} c`.parts).toHaveLength(5);
  });

  it("a string is no part", () => {
    // @ts-expect-error a plain string is no part
    const t = vaultText`x ${"y"}`;
    expect(typeof t).toBe("object");
  });

  it("a part made elsewhere is no part", () => {
    const forged = JSON.parse('{"kind":"words","text":"raw text"}') as TextPart;
    expect(isTextPart(forged)).toBe(false);
    expect(isVaultText({ parts: [num(1)] })).toBe(false);
    expect(renderVaultText(vaultText`a ${forged}`)).toBe("a unknown");
    expect(isTextPart(num(1))).toBe(true);
    expect(isVaultText(vaultText`a`)).toBe(true);
  });

  it("a text cannot be changed after assembly", () => {
    const text = vaultText`a ${echoField({ args: ["x"] }, "args", 0)} b`;
    expect(Object.isFrozen(text)).toBe(true);
    expect(Object.isFrozen(text.parts)).toBe(true);
    expect(text.parts.every((part) => Object.isFrozen(part))).toBe(true);
    expect(Object.isFrozen((text.parts[1] as EchoPart).path)).toBe(true);
    const made = [num(1), token("a", ["a"]), outsidePart("o"), echoHandle("h")];
    expect(made.every((part) => Object.isFrozen(part))).toBe(true);
  });

  it("a 10 MiB field is shown whole", () => {
    const part = echoField({ url: "u".repeat(10 * 1024 * 1024) }, "url");
    expect(shown(part).length).toBe(10485760);
  });
});
