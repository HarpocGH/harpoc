import { describe, expect, it } from "vitest";

import {
  isNormalRemotePath,
  isRenderTempName,
  RENDER_MIXED_VALUE_REGEX,
  renderEntryCanonicalBytes,
  renderTempName,
  utf8ByteLength,
} from "./render-entry.js";

// The public key lines of core's injection/__fixtures__/ssh-public-keys.ts (ssh-keygen 10.0p2).
const HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICn+7qKS67vacwftKjgcrwUlmC2TZ6j0dyFpyO5UDiVx";
const KEY_A =
  "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCz9X9B5Ls3wqgwaWax6lXZilG0yR+qBdY+tYQpr1fpizTydsdzfyl0ESyVBtR6XYCQum8+x0NktMqPL7ISyqGU=";

/** A smallest entry: one key line, an empty template; its canonical bytes are `M_HEX`. */
const M = { host: "h", port: 22, user: "u", path: "/f", host_keys: [HOST_KEY], template: "" };
const M_HEX =
  "00000016686172706f632d72656e6465722d656e7472792d76310000000168000000160000000175000000022f6600000001000000507373682d65643235353139204141414143334e7a6143316c5a4449314e5445354141414149436e2b37714b5336377661637766744b6a67637277556c6d4332545a366a3064794670794f35554469567800000000";

const HEX32 = "0123456789abcdef".repeat(2);
const PATH_4096 = "/" + ("a".repeat(199) + "/").repeat(20) + "a".repeat(95);

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("utf8ByteLength", () => {
  it.each([
    ["a", 1],
    ["é", 2],
    ["€", 3],
    ["😀", 4],
    ["é".repeat(8192), 16_384],
    ["\ud800", null],
    ["\udc00a", null],
  ] as const)(
    "utf8ByteLength counts UTF-8 bytes and refuses an unpaired surrogate: %j",
    (text, bytes) => {
      expect(utf8ByteLength(text)).toBe(bytes);
    },
  );
});

describe("isNormalRemotePath", () => {
  it.each(["/srv/app/.env", "/a", "/a b/c", "/ü/ñ.txt", PATH_4096, "/d/" + "é".repeat(100)])(
    "isNormalRemotePath admits a normal path: %j",
    (path) => {
      expect(isNormalRemotePath(path)).toBe(true);
    },
  );

  it.each([
    "",
    "srv/app",
    "/",
    "/srv/",
    "//srv",
    "/srv//app",
    "/srv/./app",
    "/srv/../app",
    "/srv/.",
    "/srv/..",
    "/a\nb",
    "/a\u0000b",
    "/a\u007fb",
    "/a\u0085b",
    PATH_4096 + "a",
    "/" + "a".repeat(201),
    "/d/" + "é".repeat(100) + "x",
    "/a\ud800",
    "/srv/.env.harpoc-" + "0".repeat(32) + ".tmp",
  ])("refuses every other spelling: %j", (path) => {
    expect(isNormalRemotePath(path)).toBe(false);
  });

  it.each([
    ["U+00AD, a soft hyphen", "­"],
    ["U+061C, the Arabic letter mark", "؜"],
    ["U+180E, the Mongolian vowel separator", "᠎"],
    ["U+200B, a zero-width space", "​"],
    ["U+202E, the right-to-left override", "‮"],
    ["U+2060, the word joiner", "⁠"],
    ["U+2066, a directional isolate", "⁦"],
    ["U+206A, a deprecated format character", "⁪"],
    ["U+FEFF, a byte order mark", "﻿"],
    ["U+E0041, a tag character", "\u{e0041}"],
    ["U+2028, the line separator", " "],
    ["U+2029, the paragraph separator", " "],
  ])(
    "refuses a format character and a line or paragraph separator anywhere: %s",
    (_label, char) => {
      expect(isNormalRemotePath(`/srv/app/${char}env`)).toBe(false);
      expect(isNormalRemotePath(`/srv/${char}/env`)).toBe(false);
      expect(isNormalRemotePath(`/srv/app/env${char}`)).toBe(false);
    },
  );
});

describe("renderTempName", () => {
  it("renderTempName is the temporary name, within 255 bytes for a 200-byte segment", () => {
    expect(renderTempName("env", "0".repeat(32))).toBe(
      ".env.harpoc-00000000000000000000000000000000.tmp",
    );
    expect(renderTempName("x".repeat(200), HEX32)).toHaveLength(245);
  });

  it("isRenderTempName recognizes the vault's form alone", () => {
    const name = renderTempName("env", HEX32);
    expect(isRenderTempName(name)).toBe(true);
    expect(isRenderTempName(name, "env")).toBe(true);
    expect(isRenderTempName(name, "other")).toBe(false);
    expect(isRenderTempName(renderTempName("env", HEX32.toUpperCase()))).toBe(false);
    expect(isRenderTempName(renderTempName("env", HEX32.slice(1)))).toBe(false);
    expect(isRenderTempName(name.slice(1))).toBe(false);
    expect(isRenderTempName(`.harpoc-${HEX32}.tmp`)).toBe(false);
    expect(isRenderTempName(`${name}x`)).toBe(false);
  });
});

describe("renderEntryCanonicalBytes", () => {
  it("the canonical bytes of an entry, byte for byte", () => {
    const bytes = renderEntryCanonicalBytes(M);
    expect(hex(bytes)).toBe(M_HEX);
    expect(bytes).toHaveLength(138);
  });

  it("host key order does not change them", () => {
    expect(hex(renderEntryCanonicalBytes({ ...M, host_keys: [HOST_KEY, KEY_A] }))).toBe(
      hex(renderEntryCanonicalBytes({ ...M, host_keys: [KEY_A, HOST_KEY] })),
    );
  });

  it("the length prefixes keep the fields apart", () => {
    expect(hex(renderEntryCanonicalBytes({ ...M, user: "u", path: "/a/b" }))).not.toBe(
      hex(renderEntryCanonicalBytes({ ...M, user: "u/a", path: "/b" })),
    );
  });

  it("a template is UTF-8 encoded", () => {
    expect(
      hex(renderEntryCanonicalBytes({ ...M, template: "é😀" })).endsWith("00000006c3a9f09f9880"),
    ).toBe(true);
  });
});

describe("RENDER_MIXED_VALUE_REGEX", () => {
  it("RENDER_MIXED_VALUE_REGEX admits its class alone", () => {
    expect(RENDER_MIXED_VALUE_REGEX.test("abcXYZ019._~+/=:@%-")).toBe(true);
    for (const value of [
      "",
      "a b",
      "a\nb",
      "${X}",
      "$(x)",
      "'",
      '"',
      " ",
      "é",
      "a\tb",
      "#",
      "\\",
      ";",
      "`",
    ]) {
      expect(RENDER_MIXED_VALUE_REGEX.test(value), JSON.stringify(value)).toBe(false);
    }
  });
});
