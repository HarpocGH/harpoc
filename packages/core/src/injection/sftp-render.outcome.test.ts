import { randomInt } from "node:crypto";
import { describe, expect, it } from "vitest";
import { expectAbsent } from "@harpoc/test-utils";
import type { SftpWriteOutcome } from "./sftp/sftp-writer.js";
import { readRenderOutcome } from "./sftp-render.js";
import { redactCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";

const BASE_RESULT: SpawnCapturedResult = {
  exit_code: 0,
  stdout: "",
  stderr: "",
  timed_out: false,
  truncated: false,
  signal: null,
  spawn_failed: false,
  redacted: false,
};

const HOST_KEY_LINE = "Host key verification failed.";
const HOST_KEY_FAILED = `${HOST_KEY_LINE}\r\n`;
const CHANGED_KEY = [
  "@".repeat(59),
  "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @",
  "@".repeat(59),
  "IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!",
  "Host key for [host.example]:2222 has changed and you have requested strict checking.",
  HOST_KEY_LINE,
]
  .map((line) => `${line}\r\n`)
  .join("");
const CONNECTION_REFUSED = "ssh: connect to host 10.0.0.5 port 22: Connection refused\r\n";
const MARKER = "HARPOC-T9-STREAM-MARKER";

function listRedaction(list: string[]): (text: string) => string {
  return (text) => redactCaptured(text, list);
}

const NO_REDACTION = listRedaction([]);

type Row = [string, SftpWriteOutcome, Partial<SpawnCapturedResult>, SftpWriteOutcome];

const TABLE: Row[] = [
  [
    "a spawn that failed, a writer that says yes",
    { written: "yes" },
    { spawn_failed: true, exit_code: null },
    { written: "no", reason: "connect" },
  ],
  [
    "a spawn that failed, a writer that says open",
    { written: "no", reason: "open" },
    { spawn_failed: true, exit_code: null },
    { written: "no", reason: "connect" },
  ],
  [
    "a kill that failed beside a timeout",
    { written: "no", reason: "timeout" },
    { spawn_failed: true, timed_out: true, exit_code: null },
    { written: "no", reason: "timeout" },
  ],
  [
    "connect with ssh's host-key line",
    { written: "no", reason: "connect" },
    { exit_code: 255, stderr: HOST_KEY_FAILED },
    { written: "no", reason: "host_key" },
  ],
  [
    "connect with a changed host key",
    { written: "no", reason: "connect" },
    { exit_code: 255, stderr: CHANGED_KEY },
    { written: "no", reason: "host_key" },
  ],
  [
    "connect with a refused connection",
    { written: "no", reason: "connect" },
    { exit_code: 255, stderr: CONNECTION_REFUSED },
    { written: "no", reason: "connect" },
  ],
  [
    "open with the host-key line, which the remote host wrote",
    { written: "no", reason: "open" },
    { exit_code: 255, stderr: HOST_KEY_FAILED },
    { written: "no", reason: "open" },
  ],
  [
    "timeout with the host-key line",
    { written: "no", reason: "timeout" },
    { timed_out: true, exit_code: null, stderr: HOST_KEY_FAILED },
    { written: "no", reason: "timeout" },
  ],
  ["yes with exit 255", { written: "yes" }, { exit_code: 255 }, { written: "yes" }],
  [
    "an unconfirmed rename",
    { written: "unconfirmed", reason: "rename" },
    { exit_code: 0 },
    { written: "unconfirmed", reason: "rename" },
  ],
];

describe("readRenderOutcome", () => {
  it.each(TABLE)("the table: %s", (_name, writer, seen, reading) => {
    expect(readRenderOutcome(writer, { ...BASE_RESULT, ...seen }, NO_REDACTION)).toEqual(reading);
  });

  it("a slot value inside ssh's host-key line", () => {
    const words = HOST_KEY_LINE.slice(0, -1).split(" ");
    const letters = [...new Set(HOST_KEY_LINE.replace(/[^A-Za-z]/g, ""))];
    const list = [
      words[randomInt(words.length)] as string,
      letters[randomInt(letters.length)] as string,
    ];
    const drawn = `the values drawn: ${JSON.stringify(list)}`;
    const redact = listRedaction(list);
    const stderr = redactCaptured(HOST_KEY_FAILED, list);
    expect(stderr === HOST_KEY_FAILED, drawn).toBe(false);
    expect(
      readRenderOutcome(
        { written: "no", reason: "connect" },
        { ...BASE_RESULT, exit_code: 255, stderr, redacted: true },
        redact,
      ),
      drawn,
    ).toEqual({ written: "no", reason: "host_key" });
  });

  it("nothing of the streams is in a reading", () => {
    for (const [, writer, seen] of TABLE) {
      const reading = readRenderOutcome(
        writer,
        { ...BASE_RESULT, ...seen, stderr: `${MARKER}\r\n${seen.stderr ?? ""}${MARKER}\r\n` },
        NO_REDACTION,
      );
      expectAbsent(JSON.stringify(reading), MARKER, "a reading");
    }
  });
});
