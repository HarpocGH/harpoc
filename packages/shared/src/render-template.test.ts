import { describe, expect, it } from "vitest";

import {
  distinctRenderSlots,
  isSingleSlotTemplate,
  parseRenderTemplate,
} from "./render-template.js";
import type { RenderTemplate } from "./render-template.js";

function parsed(text: string): RenderTemplate {
  const template = parseRenderTemplate(text);
  expect(template).not.toBeNull();
  return template as RenderTemplate;
}

describe("parseRenderTemplate", () => {
  it("parses text and slots in order", () => {
    expect(parseRenderTemplate("A={{secret://a}}\nB={{secret://ops/b}}")).toEqual({
      pieces: ["A=", "\nB=", ""],
      slots: ["secret://a", "secret://ops/b"],
    });
  });

  it("a template without a slot is one piece, and }} alone is text", () => {
    expect(parseRenderTemplate("x}}y")).toEqual({ pieces: ["x}}y"], slots: [] });
  });

  it.each([
    "{{",
    "{{}}",
    "a{{b}}",
    "{{secret://a",
    "{{ secret://a}}",
    "{{secret://a }}",
    "{{secret://}}",
    "{{secret://a/b/c}}",
    "{{secret://a.b}}",
    "{{SECRET://a}}",
    "{{{secret://a}}",
    "{{secret://a}}{{",
  ])("every {{ must open a slot: %j", (text) => {
    expect(parseRenderTemplate(text)).toBeNull();
  });

  it("at most 16 occurrences, a repeated handle counted each time", () => {
    expect(parsed("{{secret://a}}".repeat(16)).slots).toHaveLength(16);
    expect(parseRenderTemplate("{{secret://a}}".repeat(17))).toBeNull();
  });

  it("line ends and a BOM are the text's own", () => {
    const template = parsed("\ufeffK={{secret://a}}\r\n");
    expect(template.pieces[0]).toBe("\ufeffK=");
    expect(template.pieces[1]).toBe("\r\n");
  });

  it("CRLF and a byte order mark are the template's own; a brace form that is no slot is refused", () => {
    const text = "\ufeffA={{secret://a}}\r\nB={% raw %}{{secret://ops/b}}\r\nC=x}}y\r\n";
    const template = parsed(text);
    const joined = template.pieces
      .map((piece, i) => {
        const slot = template.slots[i];
        return slot === undefined ? piece : `${piece}{{${slot}}}`;
      })
      .join("");
    expect(joined).toBe(text);
    expect(template.slots).toEqual(["secret://a", "secret://ops/b"]);
    for (const refused of ["{{ name }}", "{{name}}", "{{secret://a b}}"]) {
      expect(parseRenderTemplate(refused)).toBeNull();
    }
  });
});

describe("distinctRenderSlots", () => {
  it("distinctRenderSlots keeps the first occurrence order", () => {
    expect(distinctRenderSlots(parsed("{{secret://b}}{{secret://a}}{{secret://b}}"))).toEqual([
      "secret://b",
      "secret://a",
    ]);
  });
});

describe("isSingleSlotTemplate", () => {
  it("isSingleSlotTemplate is one slot and nothing else", () => {
    expect(isSingleSlotTemplate(parsed("{{secret://a}}"))).toBe(true);
    for (const text of ["{{secret://a}}\n", "{{secret://a}}{{secret://a}}", "x"]) {
      expect(isSingleSlotTemplate(parsed(text))).toBe(false);
    }
  });
});
