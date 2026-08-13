// The §6.2 table generator, as pure functions.
//
// Separated from the CLI (generate-tables.mjs) so every rendering decision is
// unit-testable against a synthetic record set, and importing it runs nothing.
//
// Plain ESM rather than TypeScript in src/: @harpoc/e2e has no build step, so a
// TS module cannot be run by `node` without one, and the package's other
// generators (generate-fixtures.mjs, run-e2e.mjs) are deliberately dist-free
// for the same reason — provisioning and artifact production must work before
// anything in the workspace is built. The benchmarks package sets the same
// precedent for artifact-producing scripts.

/**
 * LaTeX-escape a value that came from the evidence, not from the author.
 *
 * Outcome names carry underscores (CHANNEL_ABSENT, REFUSED_UNAVAILABLE) and
 * scenario ids are free-form, so an unescaped cell is a compile error in the
 * thesis at best and a silently mangled table at worst.
 */
export function escapeLatex(value) {
  // Backslashes are PARKED rather than replaced in place: their replacement
  // carries braces of its own, which the brace rule would then escape into
  // \textbackslash\{\}. The sentinel is a NUL, which cannot occur in an
  // evidence string (they are JSON-decoded scenario ids and outcome names).
  return String(value)
    .replace(/\\/g, "\u0000")
    .replace(/([&%$#_{}])/g, "\\$1")
    .replace(/~/g, "\\textasciitilde{}")
    .replace(/\^/g, "\\textasciicircum{}")
    .replace(/\u0000/g, "\\textbackslash{}");
}

/** The pre-registration key an evidence record belongs to. */
export function keyOf(r) {
  return [r.scenario, r.context, r.variant ?? "", r.surface, r.arm].join("|");
}

/** The same key without the arm — the identity of a paired ROW. */
export function rowKeyOf(r) {
  return [r.scenario, r.context, r.variant ?? "", r.surface].join("|");
}

/**
 * §6.2's subsections, in the chapter's own order, with the scenario ids that
 * belong to each. Several ids can share a group: the six targeted refusals are
 * separate scenarios in the data but one story in the table.
 *
 * A scenario that appears in no group is NOT dropped — it gets its own group at
 * the end, titled by its id. Silent omission is the failure mode this whole
 * pipeline exists to prevent.
 */
export const SCENARIO_GROUPS = [
  { title: "Prompt injection credential exfiltration", scenarios: ["prompt-injection"] },
  { title: "URL manipulation", scenarios: ["url-manipulation"] },
  { title: "Tool poisoning", scenarios: ["tool-poisoning"] },
  { title: "Log-to-leak (trace)", scenarios: ["log-to-leak"] },
  { title: "Shadow escape", scenarios: ["shadow-escape"] },
  { title: "Output-channel leakage", scenarios: ["output-channel-leakage"] },
  { title: "Response-channel echo bypass", scenarios: ["response-channel-echo"] },
  {
    title: "Targeted refusals in the database, Git and SSH contexts",
    scenarios: [
      "git-http-redirect-refused",
      "git-http-submodule-denied",
      "database-ip-literal-identity",
      "database-plaintext-target",
      "ssh-host-key-mismatch",
      "ssh-host-not-allowed",
    ],
  },
];

/** The demonstration matrix's axes, in the order Chapter 1 §1.4 states them. */
export const MATRIX_CONTEXTS = ["http", "process", "mcp", "database", "git", "ssh"];
export const MATRIX_INTERFACES = ["mcp", "rest", "sdk", "cli"];

/**
 * Sort every record into exactly one bucket.
 *
 * `unclassified` is returned rather than swallowed: a record the generator does
 * not understand must surface as a refusal, because a table that quietly
 * renders 100 of 113 records looks exactly like a table that rendered all of
 * them.
 *
 * The matrix rule is derived, not hardcoded to a scenario name: a demonstration
 * record is a matrix cell when its scenario is `demo-<its own context>` and its
 * surface is not `mcp-stdio`. Anything else under `demo-` is transport coverage
 * — the stdio surface of a matrix context, or a downstream-transport variant
 * whose scenario id therefore differs from `demo-<context>` (Phase 3 D7).
 */
export function classify(records) {
  const byRow = new Map();
  for (const r of records) {
    if (r.arm === "baseline") {
      const entry = byRow.get(rowKeyOf(r)) ?? {};
      entry.baseline = r;
      byRow.set(rowKeyOf(r), entry);
    }
  }
  // A row is "paired" only if a baseline record exists for it; the Harpoc half
  // is then attached below. A Harpoc record with no baseline is a single-arm
  // demonstration, not half of a comparison.
  for (const r of records) {
    if (r.arm !== "baseline" && byRow.has(rowKeyOf(r))) {
      byRow.get(rowKeyOf(r)).harpoc = r;
    }
  }

  const paired = [];
  const pairedRecords = new Set();
  for (const [key, entry] of byRow) {
    paired.push({ key, ...entry });
    if (entry.baseline) pairedRecords.add(entry.baseline);
    if (entry.harpoc) pairedRecords.add(entry.harpoc);
  }

  const matrix = [];
  const transport = [];
  const other = [];
  const unclassified = [];
  for (const r of records) {
    if (pairedRecords.has(r)) continue;
    if (r.scenario.startsWith("demo-")) {
      if (r.scenario === `demo-${r.context}` && r.surface !== "mcp-stdio") matrix.push(r);
      else transport.push(r);
      continue;
    }
    // Single-arm records that are neither a paired row nor a demonstration
    // cell: the Phase 0-2 happy paths and the machinery self-check. Reported in
    // the provenance block so their exclusion from both tables is stated.
    if (r.arm === "harpoc") other.push(r);
    else unclassified.push(r);
  }

  return { paired, matrix, transport, other, unclassified };
}

/**
 * D12's gates. A table rendered from a compromised record set would undo
 * exactly what pre-registration and the commit stamp buy, so the generator
 * refuses rather than annotates — unless the operator says otherwise, in which
 * case the caveat is stamped into the provenance block and travels with the
 * artifact.
 */
export function checkGates(records, expectations, options = {}) {
  const problems = [];

  if (records.length === 0) problems.push("the record set is empty");

  if (!options.allowDirty) {
    const dirty = records.filter((r) => r.dirty === true).length;
    if (dirty > 0) {
      problems.push(
        `${dirty} record(s) were produced against a modified working tree (dirty: true) — ` +
          "the stamped commit does not contain the code that produced them",
      );
    }
  }

  if (!options.allowDivergence) {
    for (const r of records.filter((r) => r.match !== true)) {
      problems.push(
        `divergence: ${keyOf(r)} expected ${String(r.expected)}, observed ${String(r.observed)}`,
      );
    }
    // Registered but never exercised. Resolved per KEY, so an OS-keyed row and
    // its OS-agnostic sibling count as one expectation — the other OS's row is
    // not "unexercised", it is not applicable to this host.
    const ran = new Set(records.map(keyOf));
    for (const key of new Set(expectations.map(keyOf))) {
      if (!ran.has(key)) problems.push(`pre-registered but never exercised: ${key}`);
    }
  }

  const { unclassified } = classify(records);
  for (const r of unclassified) {
    problems.push(`record fits no table and would be silently dropped: ${keyOf(r)}`);
  }

  return problems;
}

/** Keys carrying an OS-specific expectation, so the table can say so. */
function osKeyedKeys(expectations) {
  const seen = new Map();
  for (const e of expectations) {
    seen.set(keyOf(e), (seen.get(keyOf(e)) ?? 0) + 1);
  }
  return new Set([...seen].filter(([, n]) => n > 1).map(([k]) => k));
}

/** Group the paired rows for rendering, appending anything the map misses. */
export function groupPaired(paired) {
  const byScenario = new Map();
  for (const row of paired) {
    const scenario = (row.baseline ?? row.harpoc).scenario;
    if (!byScenario.has(scenario)) byScenario.set(scenario, []);
    byScenario.get(scenario).push(row);
  }

  const groups = [];
  const placed = new Set();
  for (const group of SCENARIO_GROUPS) {
    const rows = [];
    for (const scenario of group.scenarios) {
      for (const row of byScenario.get(scenario) ?? []) rows.push(row);
      if (byScenario.has(scenario)) placed.add(scenario);
    }
    if (rows.length > 0) groups.push({ title: group.title, rows });
  }
  for (const scenario of [...byScenario.keys()].sort()) {
    if (!placed.has(scenario)) {
      groups.push({ title: scenario, rows: byScenario.get(scenario) });
    }
  }
  return groups;
}

const NOTES = {
  a: "Pre-registered residual: the defence does not hold for this variant, and the chapter reports it rather than omitting it.",
  b: "Trace-level contrast (Section 6.2.4), not a live paired execution: the malicious logging tool is simulated, the captured material is real.",
  c: "The outcome is pre-registered per operating system, because the platform behaviour is itself the designed outcome. The value shown is the one observed on the host named in the provenance block.",
  d: "Not filtered but absent: the vault constructs no such field under any policy, which is a stronger property than redaction.",
};

/** The label a paired row carries in the first column. */
function rowLabel(row) {
  const r = row.baseline ?? row.harpoc;
  return r.variant ?? r.scenario;
}

function markersFor(row, osKeyed) {
  const marks = [];
  if (row.harpoc?.observed === "BYPASSED") marks.push("a");
  if ((row.baseline ?? row.harpoc).variant === "trace") marks.push("b");
  if (row.harpoc && osKeyed.has(keyOf(row.harpoc))) marks.push("c");
  if (row.harpoc?.observed === "CHANNEL_ABSENT") marks.push("d");
  return marks;
}

/**
 * An outcome cell: escaped, plus a break opportunity after each underscore.
 *
 * Measured against the thesis geometry, the four outcome columns of the widest
 * row (CREDENTIAL_CAPTURED twice, HANDLE_ONLY twice) need 371pt of a 427pt
 * line, leaving nothing for the label. They therefore wrap, and a LaTeX word
 * has no break point at `\_` unless one is offered. The printed text is
 * unchanged — this adds a permitted line break, not an abbreviation.
 */
function outcomeCell(record, field) {
  return record ? escapeLatex(record[field]).replace(/\\_/g, "\\_\\allowbreak{}") : "--";
}

/**
 * The §6.2 paired scenario table: one row per variant, four outcome cells, the
 * layout the chapter specifies (06-evaluation.tex:219-223). Header cells are
 * spelled out on two lines rather than abbreviated.
 */
export function renderScenarioTable(paired, expectations) {
  const osKeyed = osKeyedKeys(expectations);
  const groups = groupPaired(paired);
  const used = new Set();
  const lines = [];

  lines.push("% Generated by packages/e2e/scripts/generate-tables.mjs — do not edit by hand.");
  lines.push("\\begin{table}[htbp]");
  lines.push("  \\centering");
  // \scriptsize and a tightened column separation, both load-bearing: the four
  // outcome columns take their natural width, and at \footnotesize a row like
  // CREDENTIAL_CAPTURED / CREDENTIAL_CAPTURED / HANDLE_ONLY / HANDLE_ONLY
  // squeezes the X column until every label wraps character by character
  // (verified against the thesis preamble with pdflatex). Abbreviating the
  // outcome names instead was rejected — they are the evidence, and the
  // chapter's table convention forbids cryptic shorthands.
  lines.push("  \\scriptsize");
  lines.push("  \\setlength{\\tabcolsep}{4pt}");
  lines.push(
    "  \\caption{Attack scenarios, each executed against the status-quo baseline of " +
      "Section~\\ref{sec:credential-landscape} and against \\emph{Harpoc}, with the same " +
      "harness and the same payloads. All four outcome cells were pre-registered before " +
      "the run.}",
  );
  lines.push("  \\label{tab:eval-scenarios}");
  // Fixed-width outcome columns rather than natural ones. Measured against the
  // thesis geometry (\textwidth 427pt), the four outcome columns at their
  // natural width take 371pt and leave the label column nothing — under
  // tabularx that showed up as every label wrapping character by character,
  // under a plain tabular as a table 95pt into the margin. 4 x 2.2cm plus the
  // label's 107pt fits with room to spare.
  lines.push("  \\begin{tabular}{@{}l*{4}{>{\\raggedright\\arraybackslash}p{2.2cm}}@{}}");
  lines.push("    \\toprule");
  lines.push(
    "    & \\multicolumn{2}{c}{\\textbf{Baseline}} & \\multicolumn{2}{c}{\\textbf{Harpoc}} \\\\",
  );
  lines.push("    \\cmidrule(lr){2-3}\\cmidrule(lr){4-5}");
  lines.push(
    "    \\textbf{Scenario / variant} & \\textbf{Expected} & \\textbf{Observed} & " +
      "\\textbf{Expected} & \\textbf{Observed} \\\\",
  );
  lines.push("    \\midrule");

  groups.forEach((group, index) => {
    if (index > 0) lines.push("    \\addlinespace");
    lines.push(`    \\multicolumn{5}{@{}l}{\\emph{${escapeLatex(group.title)}}} \\\\`);
    for (const row of group.rows) {
      const marks = markersFor(row, osKeyed);
      for (const m of marks) used.add(m);
      const suffix = marks.length > 0 ? `\\textsuperscript{${marks.join(",")}}` : "";
      lines.push(
        `    \\quad ${escapeLatex(rowLabel(row))}${suffix} & ` +
          `${outcomeCell(row.baseline, "expected")} & ${outcomeCell(row.baseline, "observed")} & ` +
          `${outcomeCell(row.harpoc, "expected")} & ${outcomeCell(row.harpoc, "observed")} \\\\`,
      );
    }
  });

  lines.push("    \\bottomrule");
  lines.push("  \\end{tabular}");
  for (const marker of ["a", "b", "c", "d"].filter((m) => used.has(m))) {
    lines.push(
      `  \\par\\vspace{2pt}\\raggedright\\scriptsize\\textsuperscript{${marker}}~${NOTES[marker]}`,
    );
  }
  lines.push("\\end{table}");
  return `${lines.join("\n")}\n`;
}

/**
 * The 6x4 demonstration matrix, plus the transport-coverage cells listed BESIDE
 * it (Phase 3 D7). Folding them in would inflate a 24-cell claim to 35 and
 * misstate what Chapter 1 §1.4 promised.
 */
export function renderMatrixTable(matrix, transport) {
  const byCell = new Map();
  for (const r of matrix) byCell.set(`${r.context}|${r.interface}`, r);

  const lines = [];
  lines.push("% Generated by packages/e2e/scripts/generate-tables.mjs — do not edit by hand.");
  lines.push("\\begin{table}[htbp]");
  lines.push("  \\centering");
  lines.push("  \\footnotesize");
  lines.push(
    "  \\caption{Deployment matrix: every execution context demonstrated through every " +
      "access interface, each cell one successful, opacity-checked \\texttt{use\\_secret} " +
      "call through a real surface carrying a scoped token.}",
  );
  lines.push("  \\label{tab:eval-matrix}");
  lines.push(`  \\begin{tabular}{@{}l${"l".repeat(MATRIX_INTERFACES.length)}@{}}`);
  lines.push("    \\toprule");
  lines.push(
    `    \\textbf{Execution context} & ${MATRIX_INTERFACES.map(
      (i) => `\\textbf{${escapeLatex(i)}}`,
    ).join(" & ")} \\\\`,
  );
  lines.push("    \\midrule");
  for (const context of MATRIX_CONTEXTS) {
    const cells = MATRIX_INTERFACES.map((iface) => {
      const record = byCell.get(`${context}|${iface}`);
      // "--" is a visible hole, never an empty cell that reads as formatting.
      return record ? escapeLatex(record.observed) : "--";
    });
    lines.push(`    ${escapeLatex(context)} & ${cells.join(" & ")} \\\\`);
  }
  lines.push("    \\bottomrule");
  lines.push("  \\end{tabular}");

  if (transport.length > 0) {
    lines.push("  \\par\\vspace{6pt}");
    lines.push(
      "  \\footnotesize\\raggedright Transport coverage, reported beside the matrix rather " +
        "than counted in it: MCP is one access interface with two transports, and these cells " +
        "exercise the second.\\par\\vspace{2pt}",
    );
    lines.push("  \\begin{tabular}{@{}llll@{}}");
    lines.push("    \\toprule");
    lines.push(
      "    \\textbf{Scenario} & \\textbf{Context} & \\textbf{Surface} & \\textbf{Observed} \\\\",
    );
    lines.push("    \\midrule");
    const sorted = [...transport].sort((a, b) =>
      `${a.scenario}|${a.surface}`.localeCompare(`${b.scenario}|${b.surface}`),
    );
    for (const r of sorted) {
      lines.push(
        `    ${escapeLatex(r.scenario)} & ${escapeLatex(r.context)} & ` +
          `${escapeLatex(r.surface)} & ${escapeLatex(r.observed)} \\\\`,
      );
    }
    lines.push("    \\bottomrule");
    lines.push("  \\end{tabular}");
  }

  lines.push("\\end{table}");
  return `${lines.join("\n")}\n`;
}

/**
 * Where the numbers came from. Without this the tables are unattributable, and
 * a caveat accepted at generation time would not travel with the artifact.
 */
export function renderProvenance(records, expectations, options = {}) {
  const { paired, matrix, transport, other } = classify(records);
  const hosts = [...new Set(records.map((r) => r.host_os))].sort();
  const commits = [...new Set(records.map((r) => r.commit))].sort();
  const dates = records.map((r) => r.at).sort();
  const day = (dates[0] ?? "").slice(0, 10);

  const lines = [];
  lines.push("% Generated by packages/e2e/scripts/generate-tables.mjs — do not edit by hand.");
  lines.push("\\begin{quote}");
  lines.push("\\footnotesize");
  lines.push(
    `\\textbf{Provenance.} ${String(records.length)} evidence records, produced on ` +
      `${escapeLatex(day)} by the end-to-end harness at commit ` +
      `\\texttt{${escapeLatex(commits.join(", "))}} on ` +
      `${escapeLatex(hosts.join(", "))}, against ${String(new Set(expectations.map(keyOf)).size)} ` +
      "pre-registered expectations committed before the run. " +
      `${String(paired.length)} paired attack rows, ${String(matrix.length)} matrix cells, ` +
      `${String(transport.length)} transport-coverage cells, ${String(other.length)} ` +
      "single-arm records excluded from both tables (the Phase 0--2 happy paths and the " +
      "harness self-check). " +
      (records.every((r) => r.match === true)
        ? "Every record matched its pre-registration."
        : `${String(records.filter((r) => r.match !== true).length)} record(s) diverged from ` +
          "their pre-registration."),
  );
  const caveats = [];
  if (options.allowDirty) {
    caveats.push(
      "generated with \\texttt{--allow-dirty}: at least one record was produced against a " +
        "modified working tree, so the stamped commit does not necessarily contain the code " +
        "that produced it",
    );
  }
  if (options.allowDivergence) {
    caveats.push(
      "generated with \\texttt{--allow-divergence}: an observed outcome differed from its " +
        "pre-registration, or a pre-registered expectation was never exercised",
    );
  }
  if (caveats.length > 0) {
    // Not escaped: these are author-written strings carrying deliberate LaTeX,
    // unlike every cell above, which comes from the evidence.
    lines.push("");
    lines.push(`\\textbf{Caveat.} ${caveats.join("; ")}.`);
  }
  lines.push("\\end{quote}");
  return `${lines.join("\n")}\n`;
}
