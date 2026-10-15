import { afterAll, describe, expect, it, vi } from "vitest";
import type { EvidenceRecord } from "../evidence/record.js";

// `recordArm` writes to the file `./vault.js` names; pointed at a temporary
// file here so the test never touches the package's evidence/run.jsonl. The
// pre-registration is the real one — a key that is not registered throws.
// Everything the mock factory needs is made inside `vi.hoisted`: vitest lifts
// `vi.mock` above the module's imports, so a factory may not reach them. The
// directory is named here and created by `emit` itself on the first record, so
// a collection pass (`vitest list`) leaves nothing in the temporary directory.
const paths = await vi.hoisted(async () => {
  const { tmpdir } = await import("node:os");
  const { dirname, join } = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const dir = join(tmpdir(), `harpoc-record-arm-${String(process.pid)}`);
  return {
    dir,
    evidence: join(dir, "run.jsonl"),
    preregistration: join(dirname(fileURLToPath(import.meta.url)), "../../preregistration.json"),
  };
});
vi.mock("./vault.js", () => ({
  EVIDENCE_FILE: paths.evidence,
  PREREGISTRATION_FILE: paths.preregistration,
}));
import { readFileSync, rmSync } from "node:fs";

const { recordArm } = await import("./evidence.js");

const KEY = {
  scenario: "machinery-selfcheck",
  context: "process",
  surface: "engine",
  interface: "engine",
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
