import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { emit, commitSha, hostOs, treeDirty, type EvidenceRecord } from "./record.js";

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
      interface: "mcp",
      arm: "harpoc",
      expected: "HOST_NOT_ALLOWED",
      observed: "HOST_NOT_ALLOWED",
    });
    expect(rec.match).toBe(true);
    expect(rec.commit).toMatch(/^[0-9a-f]{40}$|^unknown$/);
    expect(() => new Date(rec.at).toISOString()).not.toThrow();
  });

  it("stamps the host OS so a cross-OS run stays distinguishable (R-1)", () => {
    const rec = emit(join(dir, "run.jsonl"), {
      scenario: "s",
      context: "ssh",
      surface: "mcp-http",
      interface: "mcp",
      arm: "harpoc",
      expected: "SUCCEEDED",
      observed: "SUCCEEDED",
    });
    expect(rec.host_os).toBe(process.platform);
    expect(hostOs()).toBe(process.platform);
    const written = JSON.parse(
      readFileSync(join(dir, "run.jsonl"), "utf8").trim(),
    ) as EvidenceRecord;
    expect(written.host_os).toBe(process.platform);
  });

  it("carries the access interface, so the matrix dimension is read, not re-derived", () => {
    // `surface` cannot answer it: mcp-http and mcp-stdio are one interface with
    // two transports, and a consumer that re-derives the mapping owns a second
    // copy of the rule.
    const rec = emit(join(dir, "run.jsonl"), {
      scenario: "demo-http",
      context: "http",
      surface: "mcp-stdio",
      interface: "mcp",
      arm: "harpoc",
      expected: "SUCCEEDED",
      observed: "SUCCEEDED",
    });
    expect(rec.interface).toBe("mcp");
    const written = JSON.parse(
      readFileSync(join(dir, "run.jsonl"), "utf8").trim(),
    ) as EvidenceRecord;
    expect(written.interface).toBe("mcp");
    expect(written.surface).toBe("mcp-stdio");
  });

  it("stamps whether the tree was dirty, so the C-5 pin cannot be defeated in silence", () => {
    const rec = emit(join(dir, "run.jsonl"), {
      scenario: "s",
      context: "http",
      surface: "mcp-http",
      interface: "mcp",
      arm: "harpoc",
      expected: "SUCCEEDED",
      observed: "SUCCEEDED",
    });
    // The value depends on the checkout, so the assertion is that the record
    // reports the SAME verdict the helper does — the flag is wired, not faked.
    expect(rec.dirty).toBe(treeDirty());
    expect(typeof rec.dirty).toBe("boolean");
    const written = JSON.parse(
      readFileSync(join(dir, "run.jsonl"), "utf8").trim(),
    ) as EvidenceRecord;
    expect(written.dirty).toBe(rec.dirty);
  });

  it("marks a divergence", () => {
    const rec = emit(join(dir, "run.jsonl"), {
      scenario: "s",
      context: "database",
      surface: "mcp-http",
      interface: "mcp",
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
      interface: "mcp",
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

  it("caches the commit sha and the dirty verdict", () => {
    expect(commitSha()).toBe(commitSha());
    expect(treeDirty()).toBe(treeDirty());
  });

  // Without this the ten output-channel arms land in the artifact
  // indistinguishable from one another, and the generated table cannot tell
  // the honest residuals apart from the blocks.
  it("carries the variant into the written record", () => {
    const file = join(dir, "run.jsonl");
    emit(file, {
      scenario: "output-channel-leakage",
      context: "process",
      variant: "chunking",
      surface: "mcp-http",
      interface: "mcp",
      arm: "harpoc",
      expected: "BYPASSED",
      observed: "BYPASSED",
    });
    const written = JSON.parse(readFileSync(file, "utf8").trim()) as EvidenceRecord;
    expect(written.variant).toBe("chunking");
  });

  it("omits variant entirely when an arm has none, keeping pre-Phase-4 records shaped as before", () => {
    const file = join(dir, "run.jsonl");
    emit(file, {
      scenario: "database-happy-path",
      context: "database",
      surface: "mcp-http",
      interface: "mcp",
      arm: "harpoc",
      expected: "SUCCEEDED",
      observed: "SUCCEEDED",
    });
    const raw = readFileSync(file, "utf8").trim();
    expect(raw).not.toContain("variant");
  });
});
