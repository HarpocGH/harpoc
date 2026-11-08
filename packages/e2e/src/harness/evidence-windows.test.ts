import { afterAll, describe, expect, it, vi } from "vitest";
import type { EvidenceRecord } from "../evidence/record.js";

const paths = await vi.hoisted(async () => {
  const { tmpdir } = await import("node:os");
  const { dirname, join } = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const dir = join(tmpdir(), `harpoc-record-windows-${String(process.pid)}`);
  const here = dirname(fileURLToPath(import.meta.url));
  return {
    dir,
    evidence: join(dir, "run-b-windows.jsonl"),
    preregistration: join(here, "../../preregistration-model-b-windows.json"),
  };
});
vi.mock("../evidence/paths-windows.js", () => ({
  EVIDENCE_FILE_B_WINDOWS: paths.evidence,
  PREREGISTRATION_FILE_B_WINDOWS: paths.preregistration,
}));
import { existsSync, readFileSync, rmSync } from "node:fs";

const { recordModelBWindows, resetWindowsEvidence } = await import("./evidence-windows.js");

const KEY = {
  scenario: "b-win-agent-pipe-exposure",
  context: "ssh",
  surface: "two-account",
  interface: "ssh_agent",
  arm: "harpoc",
} as const;

afterAll(() => {
  rmSync(paths.dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function written(): EvidenceRecord[] {
  return readFileSync(paths.evidence, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as EvidenceRecord);
}

describe("recordModelBWindows", () => {
  it("writes the record into the Windows evidence file, judged against the Windows pre-registration", () => {
    const calls = [{ ok: true, text: "debug1: bound agent to hostkey" }];
    const rec = recordModelBWindows(KEY, "OPAQUE", calls);
    expect(rec).toMatchObject({ ...KEY, expected: "OPAQUE", observed: "OPAQUE", match: true });
    expect(written().slice(-1)[0]?.calls).toEqual(calls);
  });

  it("refuses a record without calls before writing anything", () => {
    const before = written().length;
    expect(() => recordModelBWindows(KEY, "OPAQUE", [])).toThrow(/carries the calls/);
    expect(written().length).toBe(before);
  });

  it("throws for a key the Windows file never registered — the Linux ids included", () => {
    const before = written().length;
    expect(() =>
      recordModelBWindows({ ...KEY, scenario: "b-agent-socket-exposure" }, "OPAQUE", [
        { ok: true, text: "" },
      ]),
    ).toThrow(/not pre-registered/);
    expect(written().length).toBe(before);
  });

  it("removes the previous run's file", () => {
    expect(existsSync(paths.evidence)).toBe(true);
    resetWindowsEvidence();
    expect(existsSync(paths.evidence)).toBe(false);
  });
});
