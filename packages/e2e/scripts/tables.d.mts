// Types for the plain-ESM table generator. `tables.mjs` must run under bare
// `node` (the package has no build step), so it cannot be TypeScript — but its
// TEST has no such constraint, and leaving it as .mjs put the package's largest
// test file outside both typecheck and lint (review 2026-08-14, F14).
//
// Named tables.d.mts, not tables.d.ts: TypeScript pairs a `.mjs` module with a
// `.d.mts` declaration file specifically (the `.d.ts` extension is for `.js`).
// A `.d.ts` sibling here silently fails to resolve under this package's
// `moduleResolution: "bundler"` and leaves the import back at implicit `any` —
// verified empirically while implementing this file.

export interface EvidenceRecord {
  scenario: string;
  context: string;
  variant?: string;
  surface: string;
  interface?: string;
  arm: "baseline" | "harpoc";
  expected: string;
  observed: string;
  match: boolean;
  commit: string;
  at: string;
  host_os: string;
  dirty: boolean;
}

export interface Expectation {
  scenario: string;
  context: string;
  variant?: string;
  surface: string;
  arm: "baseline" | "harpoc";
  host_os?: string;
  expected: string;
}

export interface PairedRow {
  key: string;
  baseline?: EvidenceRecord;
  harpoc?: EvidenceRecord;
}

export interface Classification {
  paired: PairedRow[];
  matrix: EvidenceRecord[];
  transport: EvidenceRecord[];
  other: EvidenceRecord[];
  unclassified: EvidenceRecord[];
}

export interface GateOptions {
  allowDirty?: boolean;
  allowDivergence?: boolean;
  allowMultiCommit?: boolean;
}

export declare const SCENARIO_GROUPS: Array<{ title: string; scenarios: string[] }>;
export declare const MATRIX_CONTEXTS: string[];
export declare const MATRIX_INTERFACES: string[];

export declare function escapeLatex(value: unknown): string;
export declare function keyOf(r: Partial<EvidenceRecord>): string;
export declare function rowKeyOf(r: Partial<EvidenceRecord>): string;
export declare function classify(records: EvidenceRecord[]): Classification;
export declare function checkGates(
  records: EvidenceRecord[],
  expectations: Expectation[],
  options?: GateOptions,
): string[];
export declare function groupPaired(
  paired: PairedRow[],
): Array<{ title: string; rows: PairedRow[] }>;
export declare function renderScenarioTable(
  paired: PairedRow[],
  expectations: Expectation[],
): string;
export declare function renderMatrixTable(
  matrix: EvidenceRecord[],
  transport: EvidenceRecord[],
): string;
export declare function renderProvenance(
  records: EvidenceRecord[],
  expectations: Expectation[],
  options?: GateOptions,
): string;
