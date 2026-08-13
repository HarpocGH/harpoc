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

/**
 * The §6.2 table generator.
 *
 * Written against a SYNTHETIC record set rather than the committed run: the
 * generator's job is to render whatever it is handed, so its tests must be able
 * to hand it a dirty record, a divergence and an unexercised expectation —
 * states a real run is designed never to reach. The committed run is exercised
 * separately, by generating from it.
 *
 * JavaScript rather than TypeScript because the module under test is: @harpoc/e2e
 * has no build step, so the generator must be runnable by bare `node` (the
 * generate-fixtures.mjs / run-e2e.mjs precedent).
 */
function record(overrides = {}) {
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

function expectation(overrides = {}) {
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
const PAIR = [record(), record({ arm: "harpoc", expected: "BLOCKED", observed: "BLOCKED" })];
const PAIR_EXPECTATIONS = [expectation(), expectation({ arm: "harpoc", expected: "BLOCKED" })];

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
    expect(paired[0].baseline.arm).toBe("baseline");
    expect(paired[0].harpoc.arm).toBe("harpoc");
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
    expect(paired[0].harpoc).toBeUndefined();
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
  const cells = [];
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
    expect(tex.match(/SUCCEEDED/g)?.length).toBe(25);
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
