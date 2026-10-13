import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// M-P3-8 (test-review-2026-10-09): the light theme and the OS default are
// CSS-only — jsdom applies no stylesheet and evaluates no media query — so the
// contract is pinned on the stylesheet's source and the entry HTML, located the
// way posture.test.ts locates them.
const SRC = dirname(fileURLToPath(import.meta.url));
const CSS = readFileSync(join(SRC, "styles", "app.css"), "utf-8").replace(/\/\*[\s\S]*?\*\//g, "");
const ENTRY_HTML = readFileSync(join(dirname(SRC), "index.html"), "utf-8");

const OS_LIGHT_MEDIA = "@media (prefers-color-scheme: light)";
const GUARD = ':root:not([data-theme="dark"])';
const EXPLICIT_LIGHT = ':root[data-theme="light"]';

interface Rule {
  selector: string;
  body: string;
}

/** The top-level rules of a stylesheet (or of an at-rule's body), braces matched. */
function rulesOf(text: string): Rule[] {
  const rules: Rule[] = [];
  let depth = 0;
  let start = 0;
  let open = 0;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "{" && depth++ === 0) open = i;
    if (text[i] === "}" && --depth === 0) {
      rules.push({ selector: text.slice(start, open).trim(), body: text.slice(open + 1, i) });
      start = i + 1;
    }
  }
  return rules;
}

function only(rules: Rule[], selector: string): Rule {
  const matching = rules.filter((rule) => rule.selector === selector);
  expect(matching, selector).toHaveLength(1);
  return matching[0] as Rule;
}

function tokensOf(rule: Rule): Map<string, string> {
  const declarations = rule.body.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g);
  return new Map([...declarations].map((m): [string, string] => [m[1] ?? "", m[2] ?? ""]));
}

function colorSchemeOf(rule: Rule): string | undefined {
  return /(?:^|[;\s])color-scheme\s*:\s*([^;]+);/.exec(rule.body)?.[1]?.trim();
}

function luminance(hex: string): number {
  const [r = 0, g = 0, b = 0] = [1, 3, 5].map((i) => {
    const c = Number.parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

const top = rulesOf(CSS);

function osLightRules(): Rule[] {
  return rulesOf(only(top, OS_LIGHT_MEDIA).body);
}

describe("the theme's CSS contract (M-P3-8)", () => {
  it("the OS default: one prefers-color-scheme: light block, guarded against an explicit dark choice", () => {
    const osLight = osLightRules();
    expect(osLight.map((rule) => rule.selector)).toEqual([GUARD]);
    expect(colorSchemeOf(osLight[0] as Rule)).toBe("light");
  });

  it("the explicit light theme sets color-scheme: light; bare :root is the dark canonical", () => {
    expect(colorSchemeOf(only(top, EXPLICIT_LIGHT))).toBe("light");
    expect(colorSchemeOf(only(top, ":root"))).toBe("dark");
    const selectors = [...top, ...osLightRules()].map((rule) => rule.selector);
    expect(selectors).not.toContain(':root[data-theme="dark"]');
  });

  it("both light blocks redefine exactly the dark palette's colour tokens, identically", () => {
    const colours = [...tokensOf(only(top, ":root")).keys()].filter(
      (name) => name !== "--mono" && name !== "--sans",
    );
    const explicit = tokensOf(only(top, EXPLICIT_LIGHT));
    expect([...explicit.keys()].sort()).toEqual(colours.sort());
    expect(tokensOf(osLightRules()[0] as Rule)).toEqual(explicit);
  });

  it("the light palette's text tokens meet WCAG AA (4.5:1) on its background and panel", () => {
    const light = tokensOf(only(top, EXPLICIT_LIGHT));
    for (const text of ["--ink", "--muted", "--brass", "--patina", "--amber", "--wax"]) {
      for (const surface of ["--bg", "--panel"]) {
        const ratio = contrast(light.get(text) ?? "", light.get(surface) ?? "");
        expect(ratio, `${text} on ${surface}`).toBeGreaterThanOrEqual(4.5);
      }
    }
  });

  it("index.html declares both colour schemes to the browser", () => {
    expect(/<meta name="color-scheme" content="([^"]*)"/.exec(ENTRY_HTML)?.[1]).toBe("dark light");
  });
});
