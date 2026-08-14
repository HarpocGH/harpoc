import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import {
  emit,
  commitSha,
  hostOs,
  treeDirty,
  resetDirtyCacheForTests,
  type EvidenceRecord,
} from "./record.js";

// `vi.spyOn` on a bare namespace import of a Node built-in does not work here:
// node:child_process's ESM export is non-configurable, so spying on it throws
// "Cannot redefine property: execFileSync" instead of silently failing to
// intercept (confirmed while writing this suite). `vi.mock` is the pattern the
// rest of the repo already uses for this (see
// core/src/injection/spawn-captured.isolation.test.ts and
// core/src/session/session-manager.permissions.test.ts) — it replaces the
// module for every importer, record.ts included, and defaults to the real
// implementation so every other test in this file still talks to real git.
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, execFileSync: vi.fn(actual.execFileSync) };
});

const execFileSyncMock = vi.mocked(execFileSync);

/** Points the mock back at the real binary once a test is done overriding it. */
async function restoreRealExecFileSync(): Promise<void> {
  const actual = await vi.importActual<typeof import("node:child_process")>("node:child_process");
  execFileSyncMock.mockImplementation(actual.execFileSync);
}

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

  it("re-probes after a transient git failure instead of caching it (F15)", async () => {
    resetDirtyCacheForTests();
    execFileSyncMock.mockImplementationOnce(() => {
      throw new Error("index.lock exists");
    });
    execFileSyncMock.mockImplementation(() => "" as never);

    expect(treeDirty()).toBe(true); // honest answer when it cannot be determined
    expect(treeDirty()).toBe(false); // the next call re-probes and succeeds

    await restoreRealExecFileSync();
    resetDirtyCacheForTests();
  });

  it("caches a successful probe (negative control)", async () => {
    resetDirtyCacheForTests();
    execFileSyncMock.mockClear();
    execFileSyncMock.mockImplementation(() => "" as never);
    treeDirty();
    treeDirty();
    expect(execFileSyncMock).toHaveBeenCalledTimes(1);

    await restoreRealExecFileSync();
    resetDirtyCacheForTests();
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
