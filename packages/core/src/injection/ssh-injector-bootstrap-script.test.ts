import { createHash, randomBytes } from "node:crypto";
import { SSH_INSTALL_KEY_TYPES } from "@harpoc/shared";
import { describe, expect, it } from "vitest";
import { redactCaptured } from "./spawn-captured.js";
import {
  BOOTSTRAP_REMOTE_COMMAND,
  type BootstrapStatus,
  bootstrapStdin,
  readBootstrapStatus,
} from "./ssh-injector-bootstrap-script.js";

const DIGEST = "ad761b0a60ce2e617ddb327c6574ae8db0f34a7db4e536194adf913e8fc2aac9";
const PREFIX = "harpoc-bootstrap-v1";

const PASSWORD_E = "e";
const PASSWORD_INSTALLED = "installed";
const PASSWORD_HARPOC = "harpoc";
const PASSWORD_ONE = "1";

type Pair = [BootstrapStatus["dropIn"], BootstrapStatus["key"]];

const DROP_IN_WORDS: readonly BootstrapStatus["dropIn"][] = [
  "written",
  "present",
  "not_asked",
  "not_attempted",
  "refused",
];
const KEY_WORDS: readonly BootstrapStatus["key"][] = [
  "installed",
  "present",
  "not_attempted",
  "failed",
];
const TWELVE: Pair[] = [
  ["not_asked", "installed"],
  ["not_asked", "present"],
  ["not_asked", "failed"],
  ["not_asked", "not_attempted"],
  ["written", "installed"],
  ["written", "present"],
  ["written", "failed"],
  ["present", "installed"],
  ["present", "present"],
  ["present", "failed"],
  ["not_attempted", "not_attempted"],
  ["refused", "not_attempted"],
];
const EIGHT: Pair[] = DROP_IN_WORDS.flatMap((dropIn) =>
  KEY_WORDS.map((key): Pair => [dropIn, key]),
).filter(([dropIn, key]) => !TWELVE.some(([d, k]) => d === dropIn && k === key));

function drawFrame(redact: (text: string) => string = (t) => t): string {
  for (;;) {
    const frame = randomBytes(18).toString("base64url");
    if (redact(`\n${frame}\n`) === `\n${frame}\n`) return frame;
  }
}

function drawKeyLine(): string {
  return `ssh-ed25519 ${randomBytes(51).toString("base64")}`;
}

function count(text: string, part: string): number {
  return text.split(part).length - 1;
}

describe("BOOTSTRAP_REMOTE_COMMAND", () => {
  it("the remote command is the pinned text", () => {
    const command = BOOTSTRAP_REMOTE_COMMAND;
    expect(createHash("sha256").update(command).digest("hex")).toBe(DIGEST);
    expect(command.length).toBe(2548);
    expect(command.startsWith("/bin/sh -c '")).toBe(true);
    expect(command.endsWith("'")).toBe(true);
    expect(count(command, "'")).toBe(4);
    expect(count(command, "\t")).toBe(2);
    expect(command.includes("\n")).toBe(false);
    expect(command.includes("\r")).toBe(false);
    expect(command.includes("\\\\")).toBe(false);
    expect(/^[\t\x20-\x7e]*$/.test(command)).toBe(true);
  });

  it("the script's key types are the key reader's", () => {
    const head = "case $t in ";
    const tail = ") ;; *) k= ;; esac;";
    expect(count(BOOTSTRAP_REMOTE_COMMAND, head)).toBe(1);
    const from = BOOTSTRAP_REMOTE_COMMAND.indexOf(head) + head.length;
    const names = BOOTSTRAP_REMOTE_COMMAND.slice(
      from,
      BOOTSTRAP_REMOTE_COMMAND.indexOf(tail, from),
    );
    expect(names.split("|").sort()).toEqual([...SSH_INSTALL_KEY_TYPES].sort());
  });
});

describe("bootstrapStdin", () => {
  it("the input without a password", () => {
    const frame = drawFrame();
    const line = drawKeyLine();
    expect(bootstrapStdin(frame, line)).toEqual(Buffer.from(`${PREFIX} ${frame} key\n${line}\n`));
  });

  it("the input with a password", () => {
    const frame = drawFrame();
    const line = drawKeyLine();
    const password = randomBytes(18);
    const kept = Buffer.from(password);
    const expected = Buffer.concat([
      Buffer.from(`${PREFIX} ${frame} sudoers\n${line}\n`),
      kept,
      Buffer.from("\n"),
    ]);
    const input = bootstrapStdin(frame, line, password);
    expect(input).toEqual(expected);
    input.fill(0);
    expect(password.equals(kept)).toBe(true);
    const again = bootstrapStdin(frame, line, password);
    password.fill(0);
    expect(again.equals(expected)).toBe(true);
  });
});

describe("readBootstrapStatus", () => {
  it.each(TWELVE)("each of the twelve pairs is read: %s %s", (dropIn, key) => {
    const frame = drawFrame();
    const stdout = `Welcome to host\n${PREFIX} ${frame} ${dropIn} ${key}\n`;
    expect(readBootstrapStatus(stdout, frame, (t) => t)).toEqual({ dropIn, key });
  });

  it.each(EIGHT)("the eight pairs the script never writes read as none: %s %s", (dropIn, key) => {
    const frame = drawFrame();
    const stdout = `Welcome to host\n${PREFIX} ${frame} ${dropIn} ${key}\n`;
    expect(readBootstrapStatus(stdout, frame, (t) => t)).toBeNull();
  });

  it.each([
    [
      "the frameless line",
      (frame: string) => ({ stdout: `\n${PREFIX} - not_attempted not_attempted\n`, frame }),
    ],
    [
      "another call's frame",
      (frame: string) => ({ stdout: `\n${PREFIX} ${drawFrame()} not_asked installed\n`, frame }),
    ],
    [
      "a frame of 23 characters",
      (frame: string) => ({
        stdout: `\n${PREFIX} ${frame.slice(1)} not_asked installed\n`,
        frame: frame.slice(1),
      }),
    ],
  ])("a status line without the call's part reads as none: %s", (_label, make) => {
    const { stdout, frame } = make(drawFrame());
    expect(readBootstrapStatus(stdout, frame, (t) => t)).toBeNull();
  });

  it.each([
    ["text after the status line", (line: string) => `\n${line}\nbye\n`],
    ["the status line as the whole output", (line: string) => `${line}\n`],
    ["without its final line feed", (line: string) => `\n${line}`],
    ["ending in a carriage return and a line feed", (line: string) => `\n${line}\r\n`],
    ["a word behind it", (line: string) => `\n${line} installed\n`],
    ["the empty output", () => ""],
  ])("only the last line counts, after a line feed of its own: %s", (_label, make) => {
    const frame = drawFrame();
    const stdout = make(`${PREFIX} ${frame} not_asked installed`);
    expect(readBootstrapStatus(stdout, frame, (t) => t)).toBeNull();
  });

  it.each(
    [
      ["a one-letter password", PASSWORD_E],
      ["a status word", PASSWORD_INSTALLED],
      ["a part of the prefix", PASSWORD_HARPOC],
      ["a digit of the prefix", PASSWORD_ONE],
    ].flatMap(([label, password]) =>
      (
        [
          ["written", "installed"],
          ["not_asked", "failed"],
          ["refused", "not_attempted"],
        ] as Pair[]
      ).flatMap(([dropIn, key]) =>
        ["C:\\motd", "motd"].map(
          (first) => [label as string, dropIn, key, first, password as string] as const,
        ),
      ),
    ),
  )(
    "a password that is part of the status line: %s, %s %s, behind %s",
    (_label, dropIn, key, first, password) => {
      const redact = (text: string): string => redactCaptured(text, [password]);
      const frame = drawFrame(redact);
      const stdout = redact(`${first}\n${PREFIX} ${frame} ${dropIn} ${key}\n`);
      expect(readBootstrapStatus(stdout, frame, redact)).toEqual({ dropIn, key });
    },
  );

  it.each([
    ["written", "installed"],
    ["not_asked", "failed"],
    ["refused", "not_attempted"],
  ] as Pair[])(
    "a one-letter password behind its own escape, the output's only backslash, which the redaction removes: %s %s",
    (dropIn, key) => {
      const redact = (text: string): string => redactCaptured(text, [PASSWORD_E]);
      const frame = drawFrame(redact);
      const stdout = redact(`\\u0065\n${PREFIX} ${frame} ${dropIn} ${key}\n`);
      expect(stdout.includes("\\")).toBe(false);
      expect(readBootstrapStatus(stdout, frame, redact)).toEqual({ dropIn, key });
    },
  );

  it("a redaction that makes two of the twelve lines equal reads as none", () => {
    const redact = (text: string): string => text.replace(/written|present/g, "[REDACTED]");
    const frame = drawFrame();
    const stdout = redact(`motd\n${PREFIX} ${frame} written installed\n`);
    expect(readBootstrapStatus(stdout, frame, redact)).toBeNull();
  });
});
