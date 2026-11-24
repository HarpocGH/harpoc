import { randomBytes } from "node:crypto";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { expectAbsent } from "@harpoc/test-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { serialized } from "./__fixtures__/serialized.js";
import { redactCaptured, type SpawnCapturedResult } from "./spawn-captured.js";
import {
  type BootstrapExpected,
  type BootstrapReading,
  readBootstrapOutcome,
} from "./ssh-injector-bootstrap.js";
import { type BootstrapStatus, readBootstrapStatus } from "./ssh-injector-bootstrap-script.js";

vi.mock("./ssh-injector-bootstrap-script.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./ssh-injector-bootstrap-script.js")>();
  return { ...actual, readBootstrapStatus: vi.fn() };
});

const PASSWORD_METHOD = "password";
const PASSWORD_USER = "deploy";
const PASSWORD_E = "e";
const PASSWORD_D = "d";
const PASSWORD_A = "a";
const PASSWORD_PERMISSION = "Permission";
const PASSWORD_KEY = "key";
const PASSWORD_HOST = "Host";
const PASSWORD_OPENING = "denied (publickey";
const PASSWORD_CLOSING = "password).";

const PREFIX = "harpoc-bootstrap-v1";
const FRAME = randomBytes(18).toString("base64url");
const USER = "u1";
const HOST = "h2spawn-srv";
const KNOWN_HOSTS_FILE = "/tmp/harpoc-ssh-kh-T11/known_hosts";

const REFUSAL_WITH = "u1@h2spawn-srv: Permission denied (publickey,password).\r\n";
const REFUSAL_WITHOUT = "u1@h2spawn-srv: Permission denied (publickey).\r\n";
function changedKey(file: string): string {
  return [
    "@".repeat(59),
    "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @",
    "@".repeat(59),
    "IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!",
    "Someone could be eavesdropping on you right now (man-in-the-middle attack)!",
    "It is also possible that a host key has just been changed.",
    "The fingerprint for the ED25519 key sent by the remote host is\nSHA256:7fV0n2bS4m1Yp8Qe3kXcR6tLw9uJhZ5dGaN0oPiTqEs.",
    "Please contact your system administrator.",
    `Add correct host key in ${file} to get rid of this message.`,
    `Offending ED25519 key in ${file}:1`,
    "Host key for [h2spawn-srv]:2222 has changed and you have requested strict checking.",
    "Host key verification failed.",
  ]
    .map((line) => `${line}\r\n`)
    .join("");
}

const CHANGED_KEY = changedKey(KNOWN_HOSTS_FILE);
const UNKNOWN_KEY =
  "No ED25519 host key is known for [h2spawn-srv]:2222 and you have requested strict checking.\r\nHost key verification failed.\r\n";
const CONNECTION_REFUSED = "ssh: connect to host h2spawn-srv port 2299: Connection refused\r\n";
const CONNECTION_TIMED_OUT =
  "ssh: connect to host 10.255.255.1 port 2222: Connection timed out\r\n";
const BANNER_TIMED_OUT = "Connection timed out during banner exchange\r\n";
const NOT_RESOLVED =
  "ssh: Could not resolve hostname nohost.invalid: Name or service not known\r\n";
const CLOSED_BY_HOST = "Connection to h2spawn-srv closed by remote host.\r\n";

const SEAM_ERROR = VaultError.networkIsolationUnavailable("no wrapper on this host");

type Pair = readonly [BootstrapStatus["dropIn"], BootstrapStatus["key"]];
type Seen = SpawnCapturedResult | { notSpawned: VaultError };

const DONE_PAIRS = [
  ["not_asked", "installed"],
  ["not_asked", "present"],
  ["written", "installed"],
  ["written", "present"],
  ["present", "installed"],
  ["present", "present"],
] as const;
const FAILED_PAIRS = [
  ["not_asked", "failed"],
  ["written", "failed"],
  ["present", "failed"],
  ["not_asked", "not_attempted"],
  ["not_attempted", "not_attempted"],
  ["refused", "not_attempted"],
] as const;
const NEVER_WRITTEN = [
  ["refused", "installed"],
  ["refused", "present"],
  ["not_attempted", "installed"],
  ["not_attempted", "present"],
] as const;
const TWELVE: readonly Pair[] = [...DONE_PAIRS, ...FAILED_PAIRS];

const STATUS_BY_STDOUT = new Map<string, BootstrapStatus>();

function statusOutput([dropIn, key]: Pair, before = "Welcome to host\n"): string {
  const stdout = `${before}\n${PREFIX} ${FRAME} ${dropIn} ${key}\n`;
  if (TWELVE.some(([d, k]) => d === dropIn && k === key)) {
    STATUS_BY_STDOUT.set(stdout, { dropIn, key });
  }
  return stdout;
}

function drawMark(redact: (text: string) => string = (text) => text): string {
  for (;;) {
    const mark = randomBytes(18).toString("base64url");
    if (redact(`\n${mark}\n`) === `\n${mark}\n`) return mark;
  }
}

function wordLine(word: string): string {
  return `\n${word}\n`;
}

function ran(overrides: Partial<SpawnCapturedResult> = {}): SpawnCapturedResult {
  return {
    exit_code: 0,
    stdout: "",
    stderr: "",
    timed_out: false,
    truncated: false,
    signal: null,
    spawn_failed: false,
    redacted: false,
    ...overrides,
  };
}

function expectedFor(word: string, overrides: Partial<BootstrapExpected> = {}): BootstrapExpected {
  return { word, frame: FRAME, user: USER, host: HOST, redact: (text) => text, ...overrides };
}

function errorOf(reading: BootstrapReading): VaultError | undefined {
  return "error" in reading ? reading.error : undefined;
}

interface Refusal {
  error: () => VaultError;
  code: ErrorCode;
}

const UNCONFIRMED: BootstrapReading = { kind: "unconfirmed" };
const HOST_KEY: Refusal = {
  error: () => VaultError.sshHostKeyMismatch(),
  code: ErrorCode.SSH_HOST_KEY_MISMATCH,
};
const REFUSED: Refusal = {
  error: () => VaultError.sshPasswordRefused(),
  code: ErrorCode.SSH_PASSWORD_REFUSED,
};
const NOT_OFFERED: Refusal = {
  error: () => VaultError.sshPasswordNotOffered(),
  code: ErrorCode.SSH_PASSWORD_NOT_OFFERED,
};
const CONNECT: Refusal = {
  error: () => VaultError.sshConnectFailed(),
  code: ErrorCode.SSH_CONNECT_FAILED,
};

interface TableCase {
  title: string;
  seen: (word: string) => Seen;
  reading: BootstrapReading;
  code?: ErrorCode;
}

function line(
  title: string,
  result: (word: string) => Partial<SpawnCapturedResult>,
  reading: BootstrapReading,
  code?: ErrorCode,
): TableCase {
  return { title, seen: (word) => ran(result(word)), reading, code };
}

function refusedBy(refusal: Refusal): BootstrapReading {
  return { kind: "refused", error: refusal.error() };
}

function refusedLine(
  title: string,
  result: (word: string) => Partial<SpawnCapturedResult>,
  refusal: Refusal,
): TableCase {
  return line(title, result, refusedBy(refusal), refusal.code);
}

const NO_WORD_TEXTS: readonly (readonly [string, string, Refusal])[] = [
  ["another key in the known-hosts file", CHANGED_KEY, HOST_KEY],
  ["no line for the host", UNKNOWN_KEY, HOST_KEY],
  ["a refusal with the password method", REFUSAL_WITH, REFUSED],
  ["a refusal without the password method", REFUSAL_WITHOUT, NOT_OFFERED],
  ["nothing listens", CONNECTION_REFUSED, CONNECT],
  ["an address that answers nothing", CONNECTION_TIMED_OUT, CONNECT],
  ["a listener that stays silent", BANNER_TIMED_OUT, CONNECT],
  ["a name that does not resolve", NOT_RESOLVED, CONNECT],
];

const TABLE: TableCase[] = [
  {
    title: "line 1, test 1: the seam threw",
    seen: () => ({ notSpawned: SEAM_ERROR }),
    reading: { kind: "not_spawned", error: SEAM_ERROR },
    code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE,
  },
  line(
    "line 2, test 1: spawn_failed, not timed out",
    () => ({ exit_code: null, spawn_failed: true }),
    {
      kind: "not_spawned",
      error: VaultError.sshConnectFailed("the ssh client could not be started"),
    },
    ErrorCode.SSH_CONNECT_FAILED,
  ),
  line(
    "line 3, test 2: a cut capture with a done status",
    (word) => ({
      truncated: true,
      stdout: statusOutput(["not_asked", "installed"]),
      stderr: wordLine(word),
    }),
    UNCONFIRMED,
  ),
  line(
    "line 3, test 2: a cut capture with a failed key step",
    (word) => ({
      truncated: true,
      stdout: statusOutput(["not_asked", "failed"]),
      stderr: wordLine(word),
    }),
    UNCONFIRMED,
  ),
  ...DONE_PAIRS.map(([dropIn, key]) =>
    line(
      `line 4, test 3: drop-in ${dropIn}, key ${key}`,
      (word) => ({ stdout: statusOutput([dropIn, key]), stderr: wordLine(word) }),
      { kind: "done", key, sudoers: dropIn },
    ),
  ),
  line(
    "line 4, test 3: a session by its output without a word (an account that asks for no password)",
    () => ({ stdout: statusOutput(["written", "present"]) }),
    { kind: "done", key: "present", sudoers: "written" },
  ),
  ...FAILED_PAIRS.map(([dropIn, key]) =>
    line(
      `line 5, test 4: drop-in ${dropIn}, key ${key}`,
      (word) => ({ stdout: statusOutput([dropIn, key]), stderr: wordLine(word) }),
      {
        kind: "refused",
        error: VaultError.sshBootstrapStepFailed(dropIn, key),
        status: { dropIn, key },
      },
      ErrorCode.SSH_BOOTSTRAP_STEP_FAILED,
    ),
  ),
  line(
    "line 5, test 4: a session by its output without a word",
    () => ({ stdout: statusOutput(["present", "failed"]) }),
    {
      kind: "refused",
      error: VaultError.sshBootstrapStepFailed("present", "failed"),
      status: { dropIn: "present", key: "failed" },
    },
    ErrorCode.SSH_BOOTSTRAP_STEP_FAILED,
  ),
  line(
    "line 6, test 5: output without a status line",
    (word) => ({ stdout: "Welcome to host\n", stderr: wordLine(word) }),
    UNCONFIRMED,
  ),
  ...NEVER_WRITTEN.map(([dropIn, key]) =>
    line(
      `line 6, test 5: drop-in ${dropIn} beside key ${key}, which the status reader answers as none`,
      (word) => ({ stdout: statusOutput([dropIn, key]), stderr: wordLine(word) }),
      UNCONFIRMED,
    ),
  ),
  line(
    "line 6, test 5: output without a status line and without a word",
    () => ({ stdout: "Welcome to host\n" }),
    UNCONFIRMED,
  ),
  line(
    "line 7, test 5: no output, exit 0, one word",
    (word) => ({ stderr: wordLine(word) }),
    UNCONFIRMED,
  ),
  line(
    "line 7, test 5: no output, exit 3, one word",
    (word) => ({ exit_code: 3, stderr: `${wordLine(word)}ERRTEXT\n` }),
    UNCONFIRMED,
  ),
  line(
    "line 7, test 5: no output, exit 0, two words",
    (word) => ({ stderr: wordLine(word).repeat(2) }),
    UNCONFIRMED,
  ),
  line(
    "line 7, test 5: no output, exit 3, two words",
    (word) => ({ exit_code: 3, stderr: `${wordLine(word).repeat(2)}ERRTEXT\n` }),
    UNCONFIRMED,
  ),
  ...[0, 3].flatMap((exit) =>
    NO_WORD_TEXTS.slice(0, 4).map(([label, stderr, refusal], index) =>
      refusedLine(
        `line ${index < 2 ? "8" : "9"}, test 6: exit ${String(exit)}, no word, ${label}`,
        () => ({ exit_code: exit, stderr }),
        refusal,
      ),
    ),
  ),
  refusedLine(
    "line 10, test 6: exit 0, no word, no output and nothing on the error stream (an account that asks for no password)",
    () => ({}),
    CONNECT,
  ),
  refusedLine(
    "line 10, test 6: exit 3, no word, nothing listens",
    () => ({ exit_code: 3, stderr: CONNECTION_REFUSED }),
    CONNECT,
  ),
  ...NO_WORD_TEXTS.map(([label, stderr, refusal]) =>
    refusedLine(
      `line 11, test 6: exit 255, no word, ${label}`,
      () => ({ exit_code: 255, stderr }),
      refusal,
    ),
  ),
  ...[false, true].flatMap((timedOut) =>
    (
      [
        ["another key in the known-hosts file", CHANGED_KEY, HOST_KEY],
        ["a refusal with the password method", REFUSAL_WITH, REFUSED],
        ["a refusal without the password method", REFUSAL_WITHOUT, NOT_OFFERED],
        ["nothing on the error stream", "", CONNECT],
      ] as const
    ).map(([label, stderr, refusal]) =>
      refusedLine(
        `line 12, test 6: no exit, timed_out ${String(timedOut)}, no word, ${label}`,
        () => ({ exit_code: null, signal: "SIGKILL", timed_out: timedOut, stderr }),
        refusal,
      ),
    ),
  ),
  refusedLine(
    "line 13, test 7: exit 255, one word, the refusal with the password method",
    (word) => ({ exit_code: 255, stderr: `${wordLine(word)}${REFUSAL_WITH}` }),
    REFUSED,
  ),
  refusedLine(
    "line 13, test 7: exit 255, one word, the refusal without the password method",
    (word) => ({ exit_code: 255, stderr: `${wordLine(word)}${REFUSAL_WITHOUT}` }),
    REFUSED,
  ),
  line(
    "line 14, test 8: exit 255, one word, nothing after it (the remote command's own 255)",
    (word) => ({ exit_code: 255, stderr: wordLine(word) }),
    UNCONFIRMED,
  ),
  line(
    "line 14, test 8: exit 255, one word, the session closed by the host",
    (word) => ({ exit_code: 255, stderr: `${wordLine(word)}${CLOSED_BY_HOST}` }),
    UNCONFIRMED,
  ),
  line(
    "line 15, test 8: exit 255, two words, the refusal",
    (word) => ({ exit_code: 255, stderr: `${wordLine(word).repeat(2)}${REFUSAL_WITH}` }),
    UNCONFIRMED,
  ),
  ...[false, true].flatMap((timedOut) =>
    [1, 2].map((words) =>
      line(
        `line 16, test 8: no exit, timed_out ${String(timedOut)}, ${String(words)} word(s), the refusal`,
        (word) => ({
          exit_code: null,
          signal: "SIGKILL",
          timed_out: timedOut,
          stderr: `${wordLine(word).repeat(words)}${REFUSAL_WITH}`,
        }),
        UNCONFIRMED,
      ),
    ),
  ),
];

beforeEach(() => {
  vi.mocked(readBootstrapStatus).mockImplementation(
    (stdout) => STATUS_BY_STDOUT.get(stdout) ?? null,
  );
});

describe("readBootstrapOutcome", () => {
  it.each(TABLE.map((row) => [row.title, row] as const))(
    "the table, line by line: %s",
    (_title, { seen, reading, code }) => {
      const word = drawMark();
      const got = readBootstrapOutcome(seen(word), expectedFor(word));
      expect(errorOf(got)?.code).toBe(code);
      expect(got).toEqual(reading);
    },
  );

  it.each([
    [
      ErrorCode.SSH_PASSWORD_NOT_OFFERED,
      "SSH bootstrap refused: the server does not offer password login",
      () => ran({ exit_code: 255, stderr: REFUSAL_WITHOUT }),
    ],
    [
      ErrorCode.SSH_PASSWORD_REFUSED,
      "SSH bootstrap refused: the server refused the stored password; repeating the bootstrap can lock the vault host out of the server",
      (word: string) => ran({ exit_code: 255, stderr: `${wordLine(word)}${REFUSAL_WITH}` }),
    ],
    [
      ErrorCode.SSH_BOOTSTRAP_STEP_FAILED,
      "SSH bootstrap failed: no key was installed (sudoers: written, key: failed)",
      (word: string) =>
        ran({ stdout: statusOutput(["written", "failed"]), stderr: wordLine(word) }),
    ],
    [
      ErrorCode.SSH_HOST_KEY_MISMATCH,
      "SSH host key does not match the pinned key",
      () => ran({ exit_code: 255, stderr: CHANGED_KEY }),
    ],
    [
      ErrorCode.SSH_CONNECT_FAILED,
      "SSH connection failed",
      () => ran({ exit_code: 255, stderr: CONNECTION_REFUSED }),
    ],
    [
      ErrorCode.SSH_CONNECT_FAILED,
      "SSH connection failed: the ssh client could not be started",
      () => ran({ exit_code: null, spawn_failed: true }),
    ],
  ])("the message of %s, letter for letter: %s", (code, message, seen) => {
    const word = drawMark();
    const error = errorOf(readBootstrapOutcome(seen(word), expectedFor(word)));
    expect(error?.code).toBe(code);
    expect(error?.message).toBe(message);
  });

  it.each([
    ["without a redaction", (text: string): string => text, ""],
    ["under the password a", (text: string): string => redactCaptured(text, [PASSWORD_A]), ""],
    [
      "under the password a, behind a backslash",
      (text: string): string => redactCaptured(text, [PASSWORD_A]),
      "C:\\motd\r\n",
    ],
  ] as const)(
    "every combination has one reading, and a word never stays outside two tests: %s",
    (_label, redact, behind) => {
      const word = drawMark(redact);
      const marker = drawMark(redact);
      const expected = expectedFor(word, { host: "h2", redact });
      const refusalWith = `u1@h2: Permission denied (publickey,password,${marker}).\r\n`;
      const refusalWithout = `u1@h2: Permission denied (publickey,${marker}).\r\n`;
      const lastLines = [
        changedKey(`/tmp/${marker}/known_hosts`),
        refusalWith,
        refusalWithout,
        `ssh: connect to host h2spawn-srv port ${marker}: Connection refused\r\n`,
        "",
      ];
      const refusals = new Set([refusalWith, refusalWithout]);
      const outputs: (readonly [string, BootstrapStatus | null])[] = [
        ["", null],
        [`${marker}\n`, null],
        ...TWELVE.map(
          ([dropIn, key]) => [statusOutput([dropIn, key], `${marker}\n`), { dropIn, key }] as const,
        ),
      ];
      const kinds = new Set(["not_spawned", "done", "refused", "unconfirmed"]);
      const wrong: string[] = [];
      let combinations = 0;
      for (const spawned of ["threw", "spawn_failed", "spawned"] as const) {
        for (const truncated of [false, true]) {
          for (const timedOut of [false, true]) {
            for (const exit of [null, 0, 3, 255]) {
              for (const [out, [stdout, status]] of outputs.entries()) {
                for (const words of [0, 1, 2]) {
                  for (const [last, lastLine] of lastLines.entries()) {
                    combinations++;
                    const label = `${spawned} truncated=${String(truncated)} timed_out=${String(timedOut)} exit=${String(exit)} stdout#${String(out)} words=${String(words)} last#${String(last)}`;
                    const seen: Seen =
                      spawned === "threw"
                        ? { notSpawned: SEAM_ERROR }
                        : ran({
                            exit_code: exit,
                            signal: exit === null ? "SIGKILL" : null,
                            stdout,
                            stderr: redact(
                              `${behind}${marker}\r\n${wordLine(word).repeat(words)}${lastLine}`,
                            ),
                            timed_out: timedOut,
                            truncated,
                            spawn_failed: spawned === "spawn_failed",
                          });
                    const reading = readBootstrapOutcome(seen, expected);
                    expectAbsent(serialized(reading), marker, `the reading of ${label}`);
                    if (!kinds.has(reading.kind)) wrong.push(`${label}: kind ${reading.kind}`);
                    const byTest1 =
                      spawned === "threw" || (spawned === "spawn_failed" && !timedOut);
                    if (!byTest1 && truncated && reading.kind !== "unconfirmed") {
                      wrong.push(`${label}: a cut capture read as ${reading.kind}`);
                    }
                    const session = stdout !== "" || (exit !== null && exit !== 255 && words >= 1);
                    const byTest4 =
                      !truncated &&
                      session &&
                      status !== null &&
                      (status.key === "not_attempted" || status.key === "failed");
                    const byTest7 =
                      !truncated &&
                      !session &&
                      words === 1 &&
                      exit === 255 &&
                      refusals.has(lastLine);
                    if (
                      (reading.kind === "refused" || reading.kind === "not_spawned") &&
                      words >= 1 &&
                      !byTest1 &&
                      !byTest4 &&
                      !byTest7
                    ) {
                      wrong.push(`${label}: a word stays as ${reading.kind}`);
                    }
                    if (
                      !byTest1 &&
                      byTest7 &&
                      errorOf(reading)?.code !== ErrorCode.SSH_PASSWORD_REFUSED
                    ) {
                      wrong.push(`${label}: a refused password read as ${reading.kind}`);
                    }
                  }
                }
              }
            }
          }
        }
      }
      expect(combinations).toBe(3 * 2 * 2 * 4 * 14 * 3 * 5);
      expect(wrong).toEqual([]);
    },
  );

  it.each(
    [
      ["the method's name", PASSWORD_METHOD],
      ["the user's name", PASSWORD_USER],
      ["one hex letter", PASSWORD_E],
      ["one hex letter of the method", PASSWORD_D],
      ["a hex letter of the method alone", PASSWORD_A],
      ["a word of the line", PASSWORD_PERMISSION],
    ].flatMap(([label, password]) =>
      [
        ["deploy", "host.example"],
        ["u1", "h2"],
      ].flatMap(([user, host]) =>
        [
          ["a plain stream", ""],
          ["a stream that holds a backslash", "C:\\motd\r\n"],
        ].flatMap(([stream, behind]) =>
          (
            [
              [
                "a word, the list with the method",
                1,
                "publickey,password",
                ErrorCode.SSH_PASSWORD_REFUSED,
              ],
              ["a word, the list without it", 1, "publickey", ErrorCode.SSH_PASSWORD_REFUSED],
              [
                "no word, the list with the method",
                0,
                "publickey,password",
                ErrorCode.SSH_PASSWORD_REFUSED,
              ],
              ["no word, the list without it", 0, "publickey", ErrorCode.SSH_PASSWORD_NOT_OFFERED],
            ] as const
          ).map(
            ([shape, words, list, code]) =>
              [
                label as string,
                `${user as string}@${host as string}`,
                stream as string,
                shape,
                {
                  password: password as string,
                  user: user as string,
                  host: host as string,
                  behind: behind as string,
                  words,
                  list,
                  code,
                },
              ] as const,
          ),
        ),
      ),
    ),
  )(
    "a password that is part of ssh's refusal line: %s, %s, %s, %s",
    (_label, _target, _stream, _shape, { password, user, host, behind, words, list, code }) => {
      const redact = (text: string): string => redactCaptured(text, [password]);
      const word = drawMark(redact);
      const stderr = redact(
        `${behind}${words === 1 ? wordLine(word) : ""}${user}@${host}: Permission denied (${list}).\r\n`,
      );
      const reading = readBootstrapOutcome(
        ran({ exit_code: 255, stderr }),
        expectedFor(word, { user, host, redact }),
      );
      expect(errorOf(reading)?.code).toBe(code);
      expect(reading.kind).toBe("refused");
    },
  );

  it.each(
    [
      ["one hex letter", PASSWORD_E],
      ["a hex letter of the method alone", PASSWORD_A],
      ["a word of the texts", PASSWORD_KEY],
      ["another word of the texts", PASSWORD_HOST],
    ].flatMap(([label, password]) =>
      [
        ["another key in the known-hosts file", CHANGED_KEY],
        ["no line for the host", UNKNOWN_KEY],
      ].flatMap(([text, stderr]) =>
        [
          ["a plain stream", ""],
          ["a stream that holds a backslash", "C:\\motd\r\n"],
        ].map(
          ([stream, behind]) =>
            [
              label as string,
              text as string,
              stream as string,
              password as string,
              `${behind as string}${stderr as string}`,
            ] as const,
        ),
      ),
    ),
  )(
    "a password that is part of ssh's host-key text: %s, %s, %s",
    (_label, _text, _stream, password, raw) => {
      const redact = (text: string): string => redactCaptured(text, [password]);
      const word = drawMark(redact);
      const reading = readBootstrapOutcome(
        ran({ exit_code: 255, stderr: redact(raw) }),
        expectedFor(word, { redact }),
      );
      expect(errorOf(reading)?.code).toBe(ErrorCode.SSH_HOST_KEY_MISMATCH);
      expect(reading).toEqual(refusedBy(HOST_KEY));
    },
  );

  it("ssh's host-key text counts wherever it stands in the error stream", () => {
    const word = drawMark();
    const reading = readBootstrapOutcome(
      ran({ exit_code: 255, stderr: `${CHANGED_KEY}Connection closed by 192.0.2.1 port 22\r\n` }),
      expectedFor(word),
    );
    expect(errorOf(reading)?.code).toBe(ErrorCode.SSH_HOST_KEY_MISMATCH);
    expect(reading).toEqual(refusedBy(HOST_KEY));
  });

  it.each([
    ["across the opening parenthesis", PASSWORD_OPENING],
    ["across the closing parenthesis", PASSWORD_CLOSING],
  ])(
    "a password that reaches across the edge of the line's fixed part ends as unconfirmed: %s",
    (_label, password) => {
      const redact = (text: string): string => redactCaptured(text, [password]);
      const word = drawMark(redact);
      const stderr = redact(
        `${wordLine(word)}deploy@host.example: Permission denied (publickey,password).\r\n`,
      );
      const reading = readBootstrapOutcome(
        ran({ exit_code: 255, stderr }),
        expectedFor(word, { user: "deploy", host: "host.example", redact }),
      );
      expect(reading).toEqual(UNCONFIRMED);
    },
  );

  it.each(
    [
      ["another user", "root@host.example: Permission denied (publickey,password).\r\n"],
      ["another host", "deploy@other.example: Permission denied (publickey,password).\r\n"],
      [
        "the line followed by one more line",
        "deploy@host.example: Permission denied (publickey,password).\r\nConnection closed by 192.0.2.1 port 22\r\n",
      ],
      ["a blank in the list", "deploy@host.example: Permission denied (publickey, password).\r\n"],
    ].flatMap(([label, text]) => [
      [label as string, "with a word", text as string, 1, UNCONFIRMED] as const,
      [label as string, "without a word", text as string, 0, refusedBy(CONNECT)] as const,
    ]),
  )(
    "the refusal for another user or host is no refusal: %s, %s",
    (_label, _shape, text, words, reading) => {
      const word = drawMark();
      const got = readBootstrapOutcome(
        ran({ exit_code: 255, stderr: `${words === 1 ? wordLine(word) : ""}${text}` }),
        expectedFor(word, { user: "deploy", host: "host.example" }),
      );
      expect(got).toEqual(reading);
    },
  );

  it.each([
    ["names the method in one form", "publickey,[REDACTED]", REFUSED, REFUSED],
    ["names it in neither form", "publickey", REFUSED, NOT_OFFERED],
  ] as const)(
    "a form that does not find the method is no evidence against one that does: the list %s",
    (_label, list, withWord, withoutWord) => {
      const redact = (text: string): string =>
        text.includes("\\") ? text.replaceAll("password", "[REDACTED]") : text;
      const word = drawMark();
      const refusal = `u1@h2spawn-srv: Permission denied (${list}).\r\n`;
      const expected = expectedFor(word, { redact });
      expect(
        readBootstrapOutcome(
          ran({ exit_code: 255, stderr: `${wordLine(word)}${refusal}` }),
          expected,
        ),
      ).toEqual(refusedBy(withWord));
      expect(readBootstrapOutcome(ran({ exit_code: 255, stderr: refusal }), expected)).toEqual(
        refusedBy(withoutWord),
      );
    },
  );

  it.each([
    [
      "glued to a banner",
      (word: string) => ran({ stderr: `BANNER-NO-NEWLINE${word}\n` }),
      UNCONFIRMED,
    ],
    [
      "twice on one line",
      (word: string) => ran({ exit_code: 255, stderr: `\n${word}${word}\n${REFUSAL_WITH}` }),
      UNCONFIRMED,
    ],
    [
      "once in stdout only, where the output decides",
      (word: string) => ran({ exit_code: 255, stdout: `${word}\n`, stderr: REFUSAL_WITH }),
      UNCONFIRMED,
    ],
  ])("the word is counted wherever it stands: %s", (_label, seen, reading) => {
    const word = drawMark();
    expect(readBootstrapOutcome(seen(word), expectedFor(word))).toEqual(reading);
  });

  it.each([
    ["a plain stream", ""],
    ["a stream that holds a backslash", "C:\\motd\n"],
  ])("a word the redaction changes is counted as the stream holds it: %s", (_label, behind) => {
    const redact = (text: string): string => redactCaptured(text, [PASSWORD_E]);
    const word = `e${drawMark().slice(1)}`;
    const reading = readBootstrapOutcome(
      ran({ stderr: redact(`${behind}${wordLine(word)}`) }),
      expectedFor(word, { redact }),
    );
    expect(reading).toEqual(UNCONFIRMED);
  });

  it("a spawn_failed beside timed_out is read as a child that ran", () => {
    const word = drawMark();
    const reading = readBootstrapOutcome(
      ran({
        exit_code: null,
        signal: "SIGKILL",
        timed_out: true,
        spawn_failed: true,
        stderr: wordLine(word),
      }),
      expectedFor(word),
    );
    expect(reading).toEqual(UNCONFIRMED);
  });

  it.each([
    ["motd", "motd"],
    ["C:\\motd", "C:\\motd"],
  ])("a one-letter password and a failed key step: behind %s", async (_label, behind) => {
    const actual = await vi.importActual<typeof import("./ssh-injector-bootstrap-script.js")>(
      "./ssh-injector-bootstrap-script.js",
    );
    vi.mocked(readBootstrapStatus).mockImplementation(actual.readBootstrapStatus);
    const redact = (text: string): string => redactCaptured(text, [PASSWORD_E]);
    const word = drawMark(redact);
    const frame = drawMark(redact);
    const reading = readBootstrapOutcome(
      ran({
        stdout: redact(`${behind}\n${PREFIX} ${frame} not_asked failed\n`),
        stderr: redact(wordLine(word)),
      }),
      expectedFor(word, { frame, redact }),
    );
    expect(errorOf(reading)?.code).toBe(ErrorCode.SSH_BOOTSTRAP_STEP_FAILED);
    expect(reading).toEqual({
      kind: "refused",
      error: VaultError.sshBootstrapStepFailed("not_asked", "failed"),
      status: { dropIn: "not_asked", key: "failed" },
    });
  });
});
