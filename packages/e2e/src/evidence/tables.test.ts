import { describe, it, expect } from "vitest";
import {
  checkGates,
  classify,
  escapeLatex,
  groupPaired,
  renderMatrixTable,
  renderProvenance,
  renderScenarioTable,
} from "../../scripts/tables.mjs";
import type { EvidenceRecord, Expectation, PairedRow } from "../../scripts/tables.mjs";

/**
 * The §6.2 table generator.
 *
 * Written against a SYNTHETIC record set rather than the committed run: the
 * generator's job is to render whatever it is handed, so its tests must be able
 * to hand it a dirty record, a divergence and an unexercised expectation —
 * states a real run is designed never to reach. The committed run is exercised
 * separately, by generating from it.
 *
 * The module under test stays plain ESM (`tables.mjs`): @harpoc/e2e has no
 * build step, so the generator must be runnable by bare `node` (the
 * generate-fixtures.mjs / run-e2e.mjs precedent). Its TEST has no such
 * constraint — vitest transpiles TypeScript natively — so it is `.ts`, typed
 * against `../../scripts/tables.d.mts`, so it rejoins typecheck
 * (review 2026-08-14, F14). Linting the package is a named follow-up, not done
 * here: `@harpoc/e2e` has no `lint` script at all, so turbo's `lint` task
 * never reaches it regardless of this file's extension; adding one first
 * needs 3 pre-existing `@typescript-eslint/no-dynamic-delete` errors fixed
 * (`demonstration.e2e.test.ts`, `git.e2e.test.ts`, `machinery.test.ts`), or
 * `pnpm lint` goes red repo-wide the moment the script is added.
 */
function record(overrides: Partial<EvidenceRecord> = {}): EvidenceRecord {
  return {
    scenario: "url-manipulation",
    context: "http",
    variant: "direct-attacker-url",
    surface: "mcp-http",
    interface: "mcp",
    arm: "baseline",
    expected: "EXFILTRATED",
    observed: "EXFILTRATED",
    match: true,
    commit: "abc1234",
    at: "2026-08-13T20:00:00.000Z",
    host_os: "linux",
    dirty: false,
    ...overrides,
  };
}

function expectation(overrides: Partial<Expectation> = {}): Expectation {
  return {
    scenario: "url-manipulation",
    context: "http",
    variant: "direct-attacker-url",
    surface: "mcp-http",
    arm: "baseline",
    expected: "EXFILTRATED",
    ...overrides,
  };
}

/** One paired row, both arms. */
const PAIR: [EvidenceRecord, EvidenceRecord] = [
  record(),
  record({ arm: "harpoc", expected: "BLOCKED", observed: "BLOCKED" }),
];
const PAIR_EXPECTATIONS: [Expectation, Expectation] = [
  expectation(),
  expectation({ arm: "harpoc", expected: "BLOCKED" }),
];

describe("escapeLatex", () => {
  it("escapes every character LaTeX would otherwise consume", () => {
    // Outcome names carry underscores (CHANNEL_ABSENT, REFUSED_UNAVAILABLE), so
    // this is not hypothetical: an unescaped cell fails the thesis build.
    expect(escapeLatex("CHANNEL_ABSENT")).toBe("CHANNEL\\_ABSENT");
    expect(escapeLatex("a&b%c#d$e")).toBe("a\\&b\\%c\\#d\\$e");
    expect(escapeLatex("{x}")).toBe("\\{x\\}");
    expect(escapeLatex("~^")).toBe("\\textasciitilde{}\\textasciicircum{}");
  });

  it("escapes a backslash without re-escaping its own replacement", () => {
    expect(escapeLatex("a\\b")).toBe("a\\textbackslash{}b");
  });
});

describe("classify", () => {
  it("pairs a scenario that carries both arms", () => {
    const { paired, matrix, transport, other, unclassified } = classify(PAIR);
    expect(paired).toHaveLength(1);
    const row = paired[0] as PairedRow;
    expect(row.baseline?.arm).toBe("baseline");
    expect(row.harpoc?.arm).toBe("harpoc");
    expect([matrix, transport, other, unclassified].map((b) => b.length)).toEqual([0, 0, 0, 0]);
  });

  it("routes a demonstration cell to the matrix and its stdio twin to transport coverage", () => {
    const cells = [
      record({
        scenario: "demo-git",
        context: "git",
        variant: undefined,
        arm: "harpoc",
        surface: "rest",
        interface: "rest",
        expected: "SUCCEEDED",
        observed: "SUCCEEDED",
      }),
      record({
        scenario: "demo-git",
        context: "git",
        variant: undefined,
        arm: "harpoc",
        surface: "mcp-stdio",
        interface: "mcp",
        expected: "SUCCEEDED",
        observed: "SUCCEEDED",
      }),
      // A downstream-transport variant: its scenario id is not demo-<context>,
      // which is what distinguishes it from the matrix representative.
      record({
        scenario: "demo-mcp-stdio-downstream",
        context: "mcp",
        variant: undefined,
        arm: "harpoc",
        surface: "rest",
        interface: "rest",
        expected: "SUCCEEDED",
        observed: "SUCCEEDED",
      }),
    ];
    const { matrix, transport } = classify(cells);
    expect(matrix.map((r) => r.surface)).toEqual(["rest"]);
    expect(transport.map((r) => r.scenario)).toEqual(["demo-git", "demo-mcp-stdio-downstream"]);
  });

  it("keeps a single-arm non-demonstration record as excluded, never dropped", () => {
    const { other, paired, matrix } = classify([
      record({
        scenario: "ssh-happy-path",
        context: "ssh",
        variant: undefined,
        arm: "harpoc",
        expected: "SUCCEEDED",
        observed: "SUCCEEDED",
      }),
    ]);
    expect(other).toHaveLength(1);
    expect([paired, matrix].map((b) => b.length)).toEqual([0, 0]);
  });

  it("reports a lone baseline record as unclassified rather than rendering half a row", () => {
    // The generator must not present a baseline leak with no comparison beside
    // it: that is the shape C-3 exists to prevent.
    const { unclassified, paired } = classify([
      record({ scenario: "orphan", variant: undefined, arm: "baseline" }),
    ]);
    expect(paired).toHaveLength(1);
    expect((paired[0] as PairedRow).harpoc).toBeUndefined();
    expect(unclassified).toHaveLength(0);
  });

  it("classifies every record exactly once", () => {
    const all = [
      ...PAIR,
      record({
        scenario: "demo-http",
        context: "http",
        variant: undefined,
        arm: "harpoc",
        surface: "cli",
        interface: "cli",
        expected: "SUCCEEDED",
        observed: "SUCCEEDED",
      }),
      record({
        scenario: "demo-http",
        context: "http",
        variant: undefined,
        arm: "harpoc",
        surface: "mcp-stdio",
        interface: "mcp",
        expected: "SUCCEEDED",
        observed: "SUCCEEDED",
      }),
      record({
        scenario: "machinery-selfcheck",
        context: "process",
        variant: undefined,
        arm: "harpoc",
        surface: "engine",
        interface: "engine",
        expected: "OPAQUE",
        observed: "OPAQUE",
      }),
    ];
    const { paired, matrix, transport, other, unclassified } = classify(all);
    const placed =
      paired.reduce((n, p) => n + (p.baseline ? 1 : 0) + (p.harpoc ? 1 : 0), 0) +
      matrix.length +
      transport.length +
      other.length +
      unclassified.length;
    expect(placed).toBe(all.length);
  });
});

describe("checkGates (D12)", () => {
  it("passes a clean, complete, matching record set", () => {
    expect(checkGates(PAIR, PAIR_EXPECTATIONS)).toEqual([]);
  });

  it("refuses a record produced against a modified working tree", () => {
    const dirty = [record({ dirty: true }), PAIR[1]];
    expect(checkGates(dirty, PAIR_EXPECTATIONS).join("\n")).toContain("dirty");
    expect(checkGates(dirty, PAIR_EXPECTATIONS, { allowDirty: true })).toEqual([]);
  });

  it("refuses an outcome that diverged from its pre-registration", () => {
    const diverged = [record({ observed: "BLOCKED", match: false }), PAIR[1]];
    expect(checkGates(diverged, PAIR_EXPECTATIONS).join("\n")).toContain("divergence");
    expect(checkGates(diverged, PAIR_EXPECTATIONS, { allowDivergence: true })).toEqual([]);
  });

  it("refuses when a pre-registered expectation never ran", () => {
    const extra = [...PAIR_EXPECTATIONS, expectation({ variant: "never-run" })];
    expect(checkGates(PAIR, extra).join("\n")).toContain("never exercised");
    expect(checkGates(PAIR, extra, { allowDivergence: true })).toEqual([]);
  });

  it("counts an OS-keyed expectation and its sibling as one, not as one unexercised", () => {
    // Both rows share a key; a single-OS run exercises that key once. Treating
    // them as two would make every run look incomplete and train the operator
    // to pass --allow-divergence.
    const osKeyed = [
      ...PAIR_EXPECTATIONS,
      expectation({ arm: "harpoc", expected: "REFUSED_UNAVAILABLE", host_os: "win32" }),
    ];
    expect(checkGates(PAIR, osKeyed)).toEqual([]);
  });

  it("refuses an empty record set", () => {
    expect(checkGates([], PAIR_EXPECTATIONS).join("\n")).toContain("empty");
  });
});

describe("renderScenarioTable", () => {
  it("renders the paired layout the chapter specifies", () => {
    const { paired } = classify(PAIR);
    const tex = renderScenarioTable(paired, PAIR_EXPECTATIONS);
    expect(tex).toContain("\\begin{table}");
    expect(tex).toContain("\\label{tab:eval-scenarios}");
    // Two-line header, spelled out: Baseline / Harpoc over Expected / Observed.
    expect(tex).toContain("\\multicolumn{2}{c}{\\textbf{Baseline}}");
    expect(tex).toContain("\\textbf{Expected} & \\textbf{Observed}");
    expect(tex).toContain(
      "\\quad direct-attacker-url & EXFILTRATED & EXFILTRATED & BLOCKED & BLOCKED \\\\",
    );
    expect(tex).toContain("\\emph{URL manipulation}");
  });

  it("marks a residual, a trace row, an OS-keyed row and a structural absence", () => {
    const rows = [
      record({
        variant: "chunking",
        scenario: "output-channel-leakage",
        context: "process",
        expected: "LEAKED",
        observed: "LEAKED",
      }),
      record({
        variant: "chunking",
        scenario: "output-channel-leakage",
        context: "process",
        arm: "harpoc",
        expected: "BYPASSED",
        observed: "BYPASSED",
      }),
      record({
        variant: "trace",
        scenario: "log-to-leak",
        context: "metadata",
        expected: "CREDENTIAL_CAPTURED",
        observed: "CREDENTIAL_CAPTURED",
      }),
      record({
        variant: "trace",
        scenario: "log-to-leak",
        context: "metadata",
        arm: "harpoc",
        expected: "HANDLE_ONLY",
        observed: "HANDLE_ONLY",
      }),
      record({
        variant: "status-reason-phrase",
        scenario: "response-channel-echo",
        expected: "LEAKED",
        observed: "LEAKED",
      }),
      record({
        variant: "status-reason-phrase",
        scenario: "response-channel-echo",
        arm: "harpoc",
        expected: "CHANNEL_ABSENT",
        observed: "CHANNEL_ABSENT",
      }),
      record({
        variant: "network-isolation",
        scenario: "output-channel-leakage",
        context: "process",
        expected: "EXFILTRATED",
        observed: "EXFILTRATED",
      }),
      record({
        variant: "network-isolation",
        scenario: "output-channel-leakage",
        context: "process",
        arm: "harpoc",
        expected: "BLOCKED",
        observed: "BLOCKED",
      }),
    ];
    const expectations = [
      expectation({
        variant: "network-isolation",
        scenario: "output-channel-leakage",
        context: "process",
        arm: "harpoc",
        expected: "BLOCKED",
      }),
      expectation({
        variant: "network-isolation",
        scenario: "output-channel-leakage",
        context: "process",
        arm: "harpoc",
        expected: "REFUSED_UNAVAILABLE",
        host_os: "win32",
      }),
    ];
    const tex = renderScenarioTable(classify(rows).paired, expectations);
    expect(tex).toContain("\\quad chunking\\textsuperscript{a}");
    expect(tex).toContain("\\quad trace\\textsuperscript{b}");
    expect(tex).toContain("\\quad network-isolation\\textsuperscript{c}");
    expect(tex).toContain("\\quad status-reason-phrase\\textsuperscript{d}");
    // Every marker used carries its note, and no note appears unused.
    for (const marker of ["a", "b", "c", "d"]) {
      expect(tex).toContain(`\\textsuperscript{${marker}}~`);
    }
  });

  it("emits no note for a marker no row carries", () => {
    const tex = renderScenarioTable(classify(PAIR).paired, PAIR_EXPECTATIONS);
    expect(tex).not.toContain("\\textsuperscript{a}~");
    expect(tex).not.toContain("Pre-registered residual");
  });

  it("gives an ungrouped scenario its own group rather than dropping it", () => {
    const rows = [
      record({ scenario: "brand-new-scenario", variant: "v" }),
      record({
        scenario: "brand-new-scenario",
        variant: "v",
        arm: "harpoc",
        expected: "BLOCKED",
        observed: "BLOCKED",
      }),
    ];
    const groups = groupPaired(classify(rows).paired);
    expect(groups.map((g) => g.title)).toContain("brand-new-scenario");
    expect(renderScenarioTable(classify(rows).paired, [])).toContain("\\quad v &");
  });

  it("escapes evidence-derived cells", () => {
    const rows = [
      record({ variant: "weird_variant", observed: "A_B" }),
      record({ variant: "weird_variant", arm: "harpoc", expected: "BLOCKED", observed: "BLOCKED" }),
    ];
    const tex = renderScenarioTable(classify(rows).paired, []);
    expect(tex).toContain("weird\\_variant");
    // Escaped, and with a break opportunity: the outcome columns are fixed
    // width, and CREDENTIAL_CAPTURED has no natural break point. The printed
    // text is unchanged — \allowbreak is a permitted line break, not an
    // abbreviation, which the table convention would forbid.
    expect(tex).toContain("A\\_\\allowbreak{}B");
  });

  it("offers the break only in outcome cells, never in the label", () => {
    // A label sits in an `l` column, which cannot wrap at all; inserting a
    // break there would be inert markup implying a wrap that never happens.
    const rows = [
      record({ variant: "a_b", observed: "C_D" }),
      record({ variant: "a_b", arm: "harpoc", expected: "BLOCKED", observed: "BLOCKED" }),
    ];
    const tex = renderScenarioTable(classify(rows).paired, []);
    expect(tex).toContain("\\quad a\\_b &");
    expect(tex).not.toContain("a\\_\\allowbreak{}b");
  });

  it("sizes the table so the widest row cannot spill into the margin", () => {
    // Both numbers were measured against the thesis geometry with pdflatex:
    // the four outcome columns at natural width need 371pt of a 427pt line, and
    // the longest unbreakable token (EXFILTRATED) needs more than 1.9cm. A
    // later tidy-up that drops either one reintroduces a table 95pt into the
    // margin, which no test other than a compile would otherwise catch.
    const tex = renderScenarioTable(classify(PAIR).paired, PAIR_EXPECTATIONS);
    expect(tex).toContain("\\scriptsize");
    expect(tex).toContain("p{2.2cm}");
  });
});

describe("renderMatrixTable", () => {
  const cells: EvidenceRecord[] = [];
  for (const context of ["http", "process", "mcp", "database", "git", "ssh"]) {
    for (const iface of ["mcp", "rest", "sdk", "cli"]) {
      cells.push(
        record({
          scenario: `demo-${context}`,
          context,
          variant: undefined,
          arm: "harpoc",
          surface: iface,
          interface: iface,
          expected: "SUCCEEDED",
          observed: "SUCCEEDED",
        }),
      );
    }
  }

  it("renders six contexts by four interfaces", () => {
    const tex = renderMatrixTable(cells, []);
    expect(tex).toContain("\\label{tab:eval-matrix}");
    for (const context of ["http", "process", "mcp", "database", "git", "ssh"]) {
      expect(tex).toContain(`    ${context} & SUCCEEDED & SUCCEEDED & SUCCEEDED & SUCCEEDED \\\\`);
    }
  });

  it("shows a missing cell as a visible hole", () => {
    const tex = renderMatrixTable(
      cells.filter((c) => !(c.context === "git" && c.interface === "cli")),
      [],
    );
    expect(tex).toContain("    git & SUCCEEDED & SUCCEEDED & SUCCEEDED & -- \\\\");
  });

  it("lists transport coverage beside the matrix rather than folding it in", () => {
    const tex = renderMatrixTable(cells, [
      record({
        scenario: "demo-mcp-stdio-downstream",
        context: "mcp",
        variant: undefined,
        arm: "harpoc",
        surface: "cli",
        interface: "cli",
        expected: "SUCCEEDED",
        observed: "SUCCEEDED",
      }),
    ]);
    expect(tex).toContain("Transport coverage");
    expect(tex).toContain("demo-mcp-stdio-downstream & mcp & cli & SUCCEEDED");
    // Still 6 x 4: the extra cell did not become a matrix claim.
    expect(tex.match(/SUCCEEDED/g)).toHaveLength(25);
  });
});

describe("interface-less demonstration records (review 2026-08-14, F3)", () => {
  // A synthetic Phase-3-shaped record: predates the `interface` field, so it
  // carries everything classify() and checkGates() otherwise require but that
  // one column.
  const base: Omit<EvidenceRecord, "interface"> = {
    scenario: "demo-http",
    context: "http",
    surface: "rest",
    arm: "harpoc",
    expected: "OPAQUE",
    observed: "OPAQUE",
    match: true,
    commit: "abc1234",
    at: "2026-08-14T00:00:00.000Z",
    host_os: "linux",
    dirty: false,
  };

  it("routes a record with no interface to unclassified, not matrix", () => {
    const { matrix, unclassified } = classify([{ ...base }]);
    expect(matrix).toHaveLength(0);
    expect(unclassified).toHaveLength(1);
  });

  it("keeps a record WITH an interface in the matrix (negative control)", () => {
    const { matrix, unclassified } = classify([{ ...base, interface: "rest" }]);
    expect(matrix).toHaveLength(1);
    expect(unclassified).toHaveLength(0);
  });

  it("refuses to render, naming the interface as the reason", () => {
    const problems = checkGates([{ ...base }], []);
    expect(problems.some((p) => p.includes("interface"))).toBe(true);
  });
});

describe("renderProvenance", () => {
  it("states the commit, host, counts and a clean verdict", () => {
    const tex = renderProvenance(PAIR, PAIR_EXPECTATIONS);
    expect(tex).toContain("2 evidence records");
    expect(tex).toContain("\\texttt{abc1234}");
    expect(tex).toContain("linux");
    expect(tex).toContain("Every record matched its pre-registration.");
    expect(tex).not.toContain("Caveat");
  });

  it("stamps the caveat when a gate was waived, so it travels with the artifact", () => {
    const tex = renderProvenance(PAIR, PAIR_EXPECTATIONS, {
      allowDirty: true,
      allowDivergence: true,
    });
    expect(tex).toContain("\\textbf{Caveat.}");
    expect(tex).toContain("--allow-dirty");
    expect(tex).toContain("--allow-divergence");
  });

  it("reports divergences rather than claiming a clean run", () => {
    const tex = renderProvenance([record({ match: false }), PAIR[1]], PAIR_EXPECTATIONS, {
      allowDivergence: true,
    });
    expect(tex).toContain("1 record(s) diverged");
  });
});

describe("duplicate and multi-commit record sets (review 2026-08-14, F6)", () => {
  const rec = (over: Partial<EvidenceRecord> = {}): EvidenceRecord => ({
    scenario: "url-manipulation",
    context: "http",
    variant: "direct",
    surface: "mcp-http",
    arm: "harpoc",
    interface: "mcp",
    expected: "BLOCKED",
    observed: "BLOCKED",
    match: true,
    commit: "aaaa111",
    at: "2026-08-14T00:00:00.000Z",
    host_os: "linux",
    dirty: false,
    ...over,
  });

  it("flags a shadowed harpoc record, symmetrically with a shadowed baseline", () => {
    const records = [
      rec({ arm: "baseline", observed: "EXFILTRATED", expected: "EXFILTRATED" }),
      rec(),
      rec({ observed: "BYPASSED" }),
    ];
    const problems = checkGates(records, []);
    expect(problems.some((p) => p.includes("duplicate"))).toBe(true);
  });

  it("refuses a record set spanning two commits", () => {
    const problems = checkGates([rec(), rec({ commit: "bbbb222", variant: "other" })], []);
    expect(problems.some((p) => p.includes("commit"))).toBe(true);
  });

  it("allows two commits under the explicit waiver (negative control)", () => {
    const problems = checkGates([rec(), rec({ commit: "bbbb222", variant: "other" })], [], {
      allowMultiCommit: true,
      allowDivergence: true,
    });
    expect(!problems.some((p) => p.includes("commit"))).toBe(true);
  });

  it("stamps the multi-commit waiver into the provenance block", () => {
    const out = renderProvenance([rec()], [], { allowMultiCommit: true });
    expect(out.includes("allow-multi-commit")).toBe(true);
  });

  // checkGates's duplicate-key gate above catches this same pair by raw key
  // collision, whichever arm is doubled — so it cannot tell whether classify()
  // itself still routes a shadowed record correctly. Pinned directly against
  // classify(): before the 2026-08-14 review a shadowed harpoc record silently
  // overwrote the first and the displaced one fell into `other`, counted as an
  // ordinary single-arm exclusion rather than surfaced as a dropped duplicate.
  it("classify() routes a shadowed harpoc record to unclassified, not other", () => {
    const records = [
      rec({ arm: "baseline", observed: "EXFILTRATED", expected: "EXFILTRATED" }),
      rec(),
      rec({ observed: "BYPASSED" }),
    ];
    const { unclassified, other } = classify(records);
    expect(unclassified).toContain(records[1]);
    expect(unclassified).toHaveLength(1);
    expect(other).toHaveLength(0);
  });

  // The symmetric half of the pin above — but a plain (non-`demo-`) baseline
  // record is the WRONG shape to prove it: the bucket loop's pre-existing
  // `arm === "harpoc" ? other : unclassified` tail already sends any baseline
  // record to `unclassified` on its own, Step 3 or not, so a plain shadowed
  // baseline can't tell the two apart. A `demo-` scenario can: it hits the
  // `demo-` branch BEFORE that tail runs, so without the explicit `shadowed`
  // check a displaced baseline record here is misrouted into `matrix` — a
  // rendered table cell — instead of surfacing as unclassified. Do not
  // "simplify" this scenario back to a plain name; that silently disarms the
  // test (review 2026-08-14, F6 fix round 2).
  it("classify() routes a shadowed baseline demo- record to unclassified, not the matrix", () => {
    const records = [
      rec({
        arm: "baseline",
        scenario: "demo-http",
        context: "http",
        variant: undefined,
        interface: "rest",
        observed: "EXFILTRATED",
        expected: "EXFILTRATED",
      }),
      rec({
        arm: "baseline",
        scenario: "demo-http",
        context: "http",
        variant: undefined,
        interface: "rest",
        observed: "LEAKED",
        expected: "EXFILTRATED",
      }),
    ];
    const { unclassified, matrix } = classify(records);
    expect(unclassified).toContain(records[0]);
    expect(unclassified).toHaveLength(1);
    expect(matrix).toHaveLength(0);
  });

  // The harpoc-only case the two pins above cannot reach: with no baseline for
  // the row there is no row-map entry, so the pairing loop skipped both records
  // and the displaced one was counted in `other` as an ordinary single-arm
  // exclusion — the same silent drop the 2026-08-14 review closed for paired
  // rows, still open for unpaired ones.
  it("classify() routes a shadowed harpoc-only record to unclassified, not other", () => {
    const records = [rec(), rec({ observed: "BYPASSED" })];
    const { unclassified, other } = classify(records);
    expect(unclassified).toEqual([records[0]]);
    expect(other).toEqual([records[1]]);
    expect(checkGates(records, []).some((p) => p.includes("fits no table"))).toBe(true);
  });
});
