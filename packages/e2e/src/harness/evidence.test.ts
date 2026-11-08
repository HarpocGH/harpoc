import { afterAll, describe, expect, it, vi } from "vitest";
import type { EvidenceRecord } from "../evidence/record.js";

// `recordArm` writes to the file `./vault.js` names; pointed at a temporary
// file here so the test never touches the package's evidence/run.jsonl. The
// pre-registration is the real one — a key that is not registered throws.
// Everything the mock factory needs is made inside `vi.hoisted`: vitest lifts
// `vi.mock` above the module's imports, so a factory may not reach them. The
// directory is named here and created by `emit` itself on the first record, so
// a collection pass (`vitest list`) leaves nothing in the temporary directory.
// `recordModelB` reads B's two paths from `../evidence/paths.js`, mocked the
// same way so the test never touches evidence/run-b.jsonl either.
const paths = await vi.hoisted(async () => {
  const { tmpdir } = await import("node:os");
  const { dirname, join } = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const dir = join(tmpdir(), `harpoc-record-arm-${String(process.pid)}`);
  const here = dirname(fileURLToPath(import.meta.url));
  return {
    dir,
    evidence: join(dir, "run.jsonl"),
    evidenceB: join(dir, "run-b.jsonl"),
    preregistration: join(here, "../../preregistration.json"),
    preregistrationB: join(here, "../../preregistration-model-b.json"),
  };
});
vi.mock("./vault.js", () => ({
  EVIDENCE_FILE: paths.evidence,
  PREREGISTRATION_FILE: paths.preregistration,
}));
vi.mock("../evidence/paths.js", () => ({
  EVIDENCE_FILE: paths.evidence,
  PREREGISTRATION_FILE: paths.preregistration,
  EVIDENCE_FILE_B: paths.evidenceB,
  PREREGISTRATION_FILE_B: paths.preregistrationB,
}));
import { existsSync, readFileSync, rmSync } from "node:fs";

const { recordArm, recordModelB } = await import("./evidence.js");

const KEY = {
  scenario: "machinery-selfcheck",
  context: "process",
  surface: "engine",
  interface: "engine",
  arm: "harpoc",
} as const;

const KEY_B = {
  scenario: "b-proxy-exposure",
  context: "http",
  surface: "two-identity",
  interface: "proxy",
  arm: "harpoc",
} as const;

afterAll(() => {
  rmSync(paths.dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function written(file = paths.evidence): EvidenceRecord[] {
  return readFileSync(file, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as EvidenceRecord);
}

/**
 * I1 (test-review-2026-10-09): `recordArm` carries the calls into the record
 * it emits, and adds no `calls` key when a caller captured none.
 */
describe("recordArm", () => {
  it("writes the calls it is given into the record", () => {
    const calls = [{ ok: true, text: '{"stdout":"[REDACTED]"}' }];
    const rec = recordArm(KEY, "OPAQUE", calls);
    expect(rec.calls).toEqual(calls);
    expect(rec.match).toBe(true);
    const [last] = written().slice(-1);
    expect(last?.calls).toEqual(calls);
  });

  it("adds no calls key when none are given", () => {
    recordArm(KEY, "OPAQUE");
    const [last] = written().slice(-1);
    expect(last).toBeDefined();
    expect("calls" in (last as object)).toBe(false);
  });
});

/**
 * RD-B6-2: model B's records go to their own file against their own
 * pre-registration, so A's table generation never sees them; and a B record
 * is re-checkable whole (`recheck --require-calls`) or not written at all.
 */
describe("recordModelB", () => {
  it("writes the record into B's evidence file, judged against B's pre-registration", () => {
    const calls = [{ ok: true, text: 'x-echo-credential: [REDACTED]\n{"raw":"[REDACTED]"}' }];
    const rec = recordModelB(KEY_B, "OPAQUE", calls);
    expect(rec).toMatchObject({ ...KEY_B, expected: "OPAQUE", observed: "OPAQUE", match: true });
    const [last] = written(paths.evidenceB).slice(-1);
    expect(last?.calls).toEqual(calls);
    const recordsA = existsSync(paths.evidence) ? written() : [];
    expect(recordsA.some((r) => r.scenario === KEY_B.scenario)).toBe(false);
  });

  it("refuses a record without calls before writing anything", () => {
    const before = existsSync(paths.evidenceB) ? written(paths.evidenceB).length : 0;
    expect(() => recordModelB(KEY_B, "OPAQUE", [])).toThrow(/carries the calls/);
    const after = existsSync(paths.evidenceB) ? written(paths.evidenceB).length : 0;
    expect(after).toBe(before);
  });

  it("throws for a key B never registered — A's keys included — before writing anything", () => {
    const before = existsSync(paths.evidenceB) ? written(paths.evidenceB).length : 0;
    expect(() => recordModelB(KEY, "OPAQUE", [{ ok: true, text: "" }])).toThrow(
      /not pre-registered/,
    );
    const after = existsSync(paths.evidenceB) ? written(paths.evidenceB).length : 0;
    expect(after).toBe(before);
  });
});
