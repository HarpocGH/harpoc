import { realpathSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import type { Arm, CallOutcome } from "../arms/arm.js";
import { RECORD_REDACTION, redactForRecord } from "../assert/opacity.js";
import { MAX_PARSE_DEPTH, scan } from "../assert/scan.js";
import { EVIDENCE_TEXT_CAP, callEvidence, recordingArm } from "./calls.js";

// The redaction is spied so the fail-closed elision can be driven: a
// pass-through keeps every other case on the real redaction.
vi.mock("../assert/opacity.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../assert/opacity.js")>();
  return { ...actual, redactForRecord: vi.fn(actual.redactForRecord) };
});
const redactForRecordMock = vi.mocked(redactForRecord);

// The host roots are mocked so every platform's forms can be driven on any
// host: a pass-through keeps every other case on the real roots.
vi.mock("node:os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:os")>();
  return { ...actual, homedir: vi.fn(actual.homedir), tmpdir: vi.fn(actual.tmpdir) };
});
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  const native = vi.fn(actual.realpathSync.native);
  return { ...actual, realpathSync: Object.assign(vi.fn(actual.realpathSync), { native }) };
});

const CREDENTIAL = "p4-calls-marker:not/a-credential";
const B64 = Buffer.from(CREDENTIAL, "utf8").toString("base64");

function completed(text: string, extra: Partial<CallOutcome> = {}): CallOutcome {
  return { ok: true, result: { content: [{ type: "text", text }] }, text, ...extra };
}

/**
 * The capture layer behind `EvidenceRecord.calls` (test-review-2026-10-09 I1):
 * a record carries the surface calls its verdict was judged on, so the verdict
 * can be re-checked from the record alone. The credential is replaced by a
 * marker of its own — never the sanitizer's `[REDACTED]`, which is itself one of
 * the things a reader re-checks.
 */
describe("callEvidence", () => {
  it("carries ok, the texts and the error, with the credential and its encodings marked", () => {
    const ev = callEvidence(
      completed(`{"stdout":"${CREDENTIAL} and ${B64}"}`, {
        errorText: `refused for ${CREDENTIAL}`,
        stderr: `child saw ${CREDENTIAL}`,
      }),
      CREDENTIAL,
    );
    expect(ev).toEqual({
      ok: true,
      error: `refused for ${RECORD_REDACTION}`,
      text: `{"stdout":"${RECORD_REDACTION} and ${RECORD_REDACTION}"}`,
      stderr: `child saw ${RECORD_REDACTION}`,
    });
    expect(JSON.stringify(ev)).not.toContain(CREDENTIAL);
    expect(JSON.stringify(ev)).not.toContain(B64);
  });

  it("uses a marker distinct from the sanitizer's, so the two redactions stay tellable apart", () => {
    const ev = callEvidence(completed(`[REDACTED] then ${CREDENTIAL}`), CREDENTIAL);
    expect(RECORD_REDACTION).not.toBe("[REDACTED]");
    expect(ev.text).toBe(`[REDACTED] then ${RECORD_REDACTION}`);
  });

  it("marks every credential it is given", () => {
    const second = "second-credential-value";
    const ev = callEvidence(completed(`${CREDENTIAL}|${second}`), CREDENTIAL, second);
    expect(ev.text).toBe(`${RECORD_REDACTION}|${RECORD_REDACTION}`);
  });

  it("omits the error and stderr keys when the outcome carries none", () => {
    const ev = callEvidence({ ok: false, text: "nothing" }, CREDENTIAL);
    expect(ev).toEqual({ ok: false, text: "nothing" });
    expect(Object.keys(ev)).toEqual(["ok", "text"]);
  });

  it("caps each text at EVIDENCE_TEXT_CAP after the redaction and says so", () => {
    const long = `${CREDENTIAL}${"x".repeat(EVIDENCE_TEXT_CAP * 2)}`;
    const ev = callEvidence(completed(long, { stderr: "short" }), CREDENTIAL);
    expect(ev.text).toHaveLength(EVIDENCE_TEXT_CAP);
    expect(ev.text.startsWith(RECORD_REDACTION)).toBe(true);
    expect(ev.truncated).toBe(true);
    expect(ev.stderr).toBe("short");

    const within = callEvidence(completed("x".repeat(EVIDENCE_TEXT_CAP)), CREDENTIAL);
    expect(within.text).toHaveLength(EVIDENCE_TEXT_CAP);
    expect("truncated" in within).toBe(false);
  });

  it("leaves room for the metadata probe's joined text", () => {
    // The probe joins ten sub-calls — the pretty-printed listing of every secret
    // in the harness vault and the tools/list schemas among them — and ran past
    // 16 KiB on the 2026-10-15 rehearsal; a cap below it would leave the H2
    // error channel the probe exists to check uncaptured.
    expect(EVIDENCE_TEXT_CAP).toBeGreaterThanOrEqual(65_536);
  });

  it("marks a credential nested three JSON levels deep in place — no elision needed", () => {
    const quoted = 'sk-quoted"credential';
    const deep = JSON.stringify({ a: JSON.stringify({ b: JSON.stringify({ c: quoted }) }) });
    expect(scan(quoted, deep).length).toBeGreaterThan(0);
    const ev = callEvidence(completed(deep), quoted);
    expect(scan(quoted, ev.text)).toEqual([]);
    expect(ev.text).toContain(RECORD_REDACTION);
    expect(ev.text).not.toBe(RECORD_REDACTION);
    expect("elided" in ev).toBe(false);
  });

  it("elides a field whole when the redaction leaves a sighting (fail-closed)", () => {
    // The redaction made to miss once: whatever it cannot reach must never be
    // committed with the credential in it.
    redactForRecordMock.mockImplementationOnce((text) => text);
    const ev = callEvidence(completed(`x ${CREDENTIAL}`, { errorText: "plain" }), CREDENTIAL);
    expect(ev.text).toBe(RECORD_REDACTION);
    expect(ev.elided).toBe(true);
    expect(ev.error).toBe("plain");
    expect(scan(CREDENTIAL, ev)).toEqual([]);
  });

  it("does not elide a credential at the opacity scan's deepest parse — the redaction reaches it", () => {
    const quoted = 'sk-depth"credential';
    const atReach = nest(quoted, MAX_PARSE_DEPTH + 1);
    expect(scan(quoted, atReach).length).toBeGreaterThan(0);
    const ev = callEvidence(completed(atReach), quoted);
    expect("elided" in ev).toBe(false);
    expect(ev.text).toContain(RECORD_REDACTION);
    expect(scan(quoted, ev.text)).toEqual([]);
  });

  it("marks a credential whose own backslash reads as a JSON escape, raw — not committed, not elided (C6-ae)", () => {
    const backslashed = "pw\\tail";
    const ev = callEvidence(completed(`x ${backslashed} y`), backslashed);
    expect(ev).toEqual({ ok: true, text: `x ${RECORD_REDACTION} y` });
  });
});

/** `inner` under `layers` JSON escape layers, each one more JSON.parse away. */
function nest(inner: string, layers: number): string {
  return new Array<null>(layers).fill(null).reduce((out) => JSON.stringify({ next: out }), inner);
}

const BS = "\\";
const WIN_HOME = ["C:", "Users", "runneradmin"].join(BS);
const WIN_TMP = [WIN_HOME, "AppData", "Local", "Temp"].join(BS);
const fwd = (path: string): string => path.split(BS).join("/");

function hostRoots(tmp: string, home: string, realpaths: Record<string, string> = {}): void {
  vi.mocked(tmpdir).mockReturnValue(tmp);
  vi.mocked(homedir).mockReturnValue(home);
  vi.mocked(realpathSync.native).mockImplementation(
    ((path: string) => realpaths[path] ?? path) as unknown as typeof realpathSync.native,
  );
}

/**
 * S10 (review 2026-10-15): a record carries no path of the host it was taken
 * on — the temp and home roots, in every form a call's text carries them, read
 * `<TMP>` and `<HOME>`. The win32 home here starts a segment with `r`, so its
 * raw backslash form holds `\r`: a matcher that decodes JSON escapes in raw
 * text would read a carriage return there and miss it.
 */
describe("callEvidence with the host's temp and home roots", () => {
  afterEach(async () => {
    const os = await vi.importActual<typeof import("node:os")>("node:os");
    const fs = await vi.importActual<typeof import("node:fs")>("node:fs");
    vi.mocked(tmpdir).mockImplementation(os.tmpdir);
    vi.mocked(homedir).mockImplementation(os.homedir);
    vi.mocked(realpathSync.native).mockImplementation(fs.realpathSync.native);
  });

  it("replaces the win32 temp root one JSON level inside a text with <TMP>, the clone path kept", () => {
    hostRoots(WIN_TMP, WIN_HOME);
    const stderr = (root: string): string =>
      JSON.stringify({ stderr: `Cloning into '${root}${BS}harpoc-p4b-clone-x'...\n` });
    const ev = callEvidence(completed(stderr(WIN_TMP)), CREDENTIAL);
    expect(ev.text).toBe(stderr("<TMP>"));
    expect(ev.text).not.toContain("runneradmin");
  });

  it("replaces git's forward-slash rendering of the temp root", () => {
    hostRoots(WIN_TMP, WIN_HOME);
    const stdout = (root: string): string =>
      JSON.stringify({
        stdout: `Initialized empty Git repository in ${root}/harpoc-oc-ctx-x/spawned/.git/\n`,
      });
    expect(callEvidence(completed(stdout(fwd(WIN_TMP))), CREDENTIAL).text).toBe(stdout("<TMP>"));
  });

  it("replaces a path under temp with <TMP> and one under home outside temp with <HOME> — temp first", () => {
    hostRoots(WIN_TMP, WIN_HOME);
    const ev = callEvidence(completed(`${WIN_TMP}${BS}a and ${WIN_HOME}${BS}b`), CREDENTIAL);
    expect(ev.text).toBe(`<TMP>${BS}a and <HOME>${BS}b`);
  });

  it("replaces the POSIX roots: /tmp/x reads <TMP>/x and /home/runner/x reads <HOME>/x", () => {
    hostRoots("/tmp", "/home/runner");
    const text = (tmp: string, home: string): string =>
      JSON.stringify({
        stderr: `Cloning into '${tmp}/harpoc-e2e-clone-x'...`,
        cwd: `${home}/work`,
      });
    expect(callEvidence(completed(text("/tmp", "/home/runner")), CREDENTIAL).text).toBe(
      text("<TMP>", "<HOME>"),
    );
  });

  it("replaces a root's realpath as well as the root the host reports", () => {
    const shortTmp = [["C:", "Users", "RUNNER~1"].join(BS), "AppData", "Local", "Temp"].join(BS);
    hostRoots(shortTmp, WIN_HOME, { [shortTmp]: WIN_TMP });
    const text = JSON.stringify({ a: `${shortTmp}${BS}x`, b: `${WIN_TMP}${BS}y` });
    expect(callEvidence(completed(text), CREDENTIAL).text).toBe(
      JSON.stringify({ a: `<TMP>${BS}x`, b: `<TMP>${BS}y` }),
    );
  });

  it("replaces a root at every JSON level the opacity scan parses down to", () => {
    hostRoots(WIN_TMP, WIN_HOME);
    const levels = [...new Array<null>(MAX_PARSE_DEPTH + 1).keys()];
    for (const level of levels) {
      const ev = callEvidence(completed(nest(`'${WIN_TMP}${BS}x'`, level)), CREDENTIAL);
      expect(ev.text).toBe(nest(`'<TMP>${BS}x'`, level));
    }
  });

  it("replaces the roots in the error and stderr fields too", () => {
    hostRoots(WIN_TMP, WIN_HOME);
    const ev = callEvidence(
      {
        ok: false,
        text: "",
        errorText: `ENOENT: no such file '${WIN_HOME}${BS}.gitconfig'`,
        stderr: `fatal: '${fwd(WIN_TMP)}/x' exists`,
      },
      CREDENTIAL,
    );
    expect(ev).toEqual({
      ok: false,
      text: "",
      error: `ENOENT: no such file '<HOME>${BS}.gitconfig'`,
      stderr: "fatal: '<TMP>/x' exists",
    });
  });

  it("leaves a name that only starts or ends like a root alone: /tmpfoo, /var/tmp, a longer user name", () => {
    hostRoots("/tmp", "/home/runner");
    const text = "/tmpfoo/x /var/tmp/x /home/runner2/x /home/runner";
    expect(callEvidence(completed(text), CREDENTIAL).text).toBe(
      "/tmpfoo/x /var/tmp/x /home/runner2/x <HOME>",
    );
  });

  it("replaces a root at the start of an escaped line: after \\n, \\t or a \\u escape inside a JSON text", () => {
    hostRoots("/tmp", "/home/runner");
    expect(
      callEvidence(completed(JSON.stringify({ stdout: "a\n/tmp/b\n\t/home/runner/c" })), CREDENTIAL)
        .text,
    ).toBe(JSON.stringify({ stdout: "a\n<TMP>/b\n\t<HOME>/c" }));
    expect(
      callEvidence(completed(JSON.stringify({ stdout: "\u0007/tmp/x" })), CREDENTIAL).text,
    ).toBe(JSON.stringify({ stdout: "\u0007<TMP>/x" }));
    hostRoots(WIN_TMP, WIN_HOME);
    const ev = callEvidence(
      completed(JSON.stringify({ stderr: `x\n${WIN_TMP}${BS}a` })),
      CREDENTIAL,
    );
    expect(ev.text).toBe(JSON.stringify({ stderr: `x\n<TMP>${BS}a` }));
    expect(ev.text).not.toContain("runneradmin");
  });

  it("takes no filesystem root as a host root — a home of / leaves every other path alone", () => {
    hostRoots("/tmp", "/");
    expect(callEvidence(completed("/tmp/x and /etc/y and /"), CREDENTIAL).text).toBe(
      "<TMP>/x and /etc/y and /",
    );
  });

  it("leaves a text that carries no host root byte-identical", () => {
    hostRoots(WIN_TMP, WIN_HOME);
    const text = JSON.stringify({ stdout: "C:/elsewhere/x D:\\Users\\other" }, null, 2);
    expect(callEvidence(completed(text), CREDENTIAL).text).toBe(text);
  });

  it("marks a credential that is itself a path under temp as the credential, not as a path", () => {
    hostRoots("/tmp", "/home/runner");
    const ev = callEvidence(completed("read /tmp/vault.key and /tmp/other"), "/tmp/vault.key");
    expect(ev.text).toBe(`read ${RECORD_REDACTION} and <TMP>/other`);
  });

  it("decides the elision on the credential redaction's output, before the roots are replaced", () => {
    hostRoots("/tmp", "/home/runner");
    redactForRecordMock.mockImplementationOnce((text) => text);
    const ev = callEvidence(completed("read /tmp/vault.key"), "/tmp/vault.key");
    expect(ev.text).toBe(RECORD_REDACTION);
    expect(ev.elided).toBe(true);
  });

  it("replaces a root that straddles the cap before the cut — the placeholder kept, no fragment of the root", () => {
    hostRoots(WIN_TMP, WIN_HOME);
    const lead = `${"x".repeat(EVIDENCE_TEXT_CAP - 9)} `;
    const ev = callEvidence(completed(`${lead}${WIN_TMP}${BS}${"y".repeat(100)}`), CREDENTIAL);
    expect(ev.text).toBe(`${lead}<TMP>${BS}yy`);
    expect(ev.truncated).toBe(true);
  });
});

describe("recordingArm", () => {
  function fakeArm(
    invokeOutcome: CallOutcome,
    probeOutcome: CallOutcome,
  ): Arm & {
    invoke: Mock<Arm["invoke"]>;
    probeMetadata: Mock<Arm["probeMetadata"]>;
    close: Mock<Arm["close"]>;
  } {
    return {
      name: "harpoc",
      invoke: vi.fn(() => Promise.resolve(invokeOutcome)),
      probeMetadata: vi.fn(() => Promise.resolve(probeOutcome)),
      close: vi.fn(() => Promise.resolve()),
    };
  }

  it("forwards every call unchanged and captures each outcome in order, redacted", async () => {
    const invoked = completed(`{"stdout":"${CREDENTIAL}"}`);
    const probed: CallOutcome = {
      ok: false,
      text: "",
      errorText: `Secret not found: ${CREDENTIAL}`,
    };
    const inner = fakeArm(invoked, probed);
    const arm = recordingArm(inner, CREDENTIAL);

    expect(arm.name).toBe("harpoc");
    await expect(arm.invoke("secret://x", { type: "process" })).resolves.toBe(invoked);
    await expect(arm.probeMetadata("secret://x")).resolves.toBe(probed);
    await expect(arm.probeMetadata()).resolves.toBe(probed);
    expect(inner.invoke).toHaveBeenCalledWith("secret://x", { type: "process" });
    expect(inner.probeMetadata.mock.calls).toEqual([["secret://x"], [undefined]]);

    expect(arm.calls()).toEqual([
      { ok: true, text: `{"stdout":"${RECORD_REDACTION}"}` },
      { ok: false, text: "", error: `Secret not found: ${RECORD_REDACTION}` },
      { ok: false, text: "", error: `Secret not found: ${RECORD_REDACTION}` },
    ]);
    expect(JSON.stringify(arm.calls())).not.toContain(CREDENTIAL);
  });

  it("captures nothing for a call that threw, and forwards close()", async () => {
    const inner = fakeArm(completed("unused"), completed("unused"));
    inner.invoke.mockImplementation(() => Promise.reject(new Error("transport down")));
    const arm = recordingArm(inner, CREDENTIAL);

    await expect(arm.invoke("secret://x", {})).rejects.toThrow("transport down");
    expect(arm.calls()).toEqual([]);

    await arm.close();
    expect(inner.close).toHaveBeenCalledTimes(1);
  });

  it("returns a fresh copy of the captured calls each time", async () => {
    const arm = recordingArm(fakeArm(completed("a"), completed("b")), CREDENTIAL);
    await arm.invoke("secret://x", {});
    const first = arm.calls();
    first.length = 0;
    expect(arm.calls()).toHaveLength(1);
  });
});
