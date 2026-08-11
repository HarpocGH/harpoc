import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { emit, commitSha } from "./record.js";

describe("evidence records", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "harpoc-evidence-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("stamps commit and timestamp and computes the match flag", () => {
    const rec = emit(join(dir, "run.jsonl"), {
      scenario: "url-manipulation",
      context: "database",
      surface: "mcp-http",
      arm: "harpoc",
      expected: "HOST_NOT_ALLOWED",
      observed: "HOST_NOT_ALLOWED",
    });
    expect(rec.match).toBe(true);
    expect(rec.commit).toMatch(/^[0-9a-f]{40}$|^unknown$/);
    expect(() => new Date(rec.at).toISOString()).not.toThrow();
  });

  it("marks a divergence", () => {
    const rec = emit(join(dir, "run.jsonl"), {
      scenario: "s",
      context: "database",
      surface: "mcp-http",
      arm: "harpoc",
      expected: "BLOCKED",
      observed: "SUCCEEDED",
    });
    expect(rec.match).toBe(false);
  });

  it("appends one JSON object per line and creates the directory", () => {
    const file = join(dir, "nested", "run.jsonl");
    const base = {
      scenario: "s",
      context: "database",
      surface: "mcp-http",
      arm: "harpoc" as const,
      expected: "X",
      observed: "X",
    };
    emit(file, base);
    emit(file, base);
    const lines = readFileSync(file, "utf8").trim().split("\n");
    expect(lines).toHaveLength(2);
    const first = JSON.parse(lines[0] ?? "{}") as { scenario?: string };
    expect(first.scenario).toBe("s");
  });

  it("caches the commit sha", () => {
    expect(commitSha()).toBe(commitSha());
  });
});
