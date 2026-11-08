import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { afterAll, describe, expect, it, vi } from "vitest";

const paths = await vi.hoisted(async () => {
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = join(tmpdir(), `harpoc-reset-${String(process.pid)}`);
  return { dir, a: join(dir, "run.jsonl"), b: join(dir, "run-b.jsonl") };
});
vi.mock("./paths.js", () => ({ EVIDENCE_FILE: paths.a, EVIDENCE_FILE_B: paths.b }));

const { default: resetEvidence } = await import("./reset.js");

afterAll(() => {
  rmSync(paths.dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

/** The vitest globalSetup: one run, one evidence file — A's and, since B6, B's. */
describe("the evidence reset", () => {
  it("removes A's and B's evidence files", () => {
    mkdirSync(paths.dir, { recursive: true });
    writeFileSync(paths.a, '{"scenario":"a"}\n');
    writeFileSync(paths.b, '{"scenario":"b"}\n');
    resetEvidence();
    expect(existsSync(paths.a)).toBe(false);
    expect(existsSync(paths.b)).toBe(false);
  });

  it("is a no-op where neither file exists", () => {
    expect(() => resetEvidence()).not.toThrow();
  });
});
