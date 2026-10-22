// Types for the plain-ESM re-check (recheck.mjs); the tables.d.mts precedent —
// a `.d.mts` pairs with a `.mjs` module under this package's `moduleResolution`.
import type { CallEvidence } from "../src/evidence/calls.js";

export type { CallEvidence };
export { keyOf, readJsonl } from "./tables.mjs";

export interface RecheckRecord {
  scenario: string;
  context: string;
  variant?: string;
  surface: string;
  arm: string;
  observed: string;
  calls?: CallEvidence[] | undefined;
}

export interface Inconsistency {
  key: string;
  observed: string;
  reason: string;
}

export interface RecheckResult {
  total: number;
  checked: number;
  unchecked: number;
  partial: number;
  inconsistent: Inconsistency[];
}

export const RECORD_MARKER: string;
export const HELD_OUTCOMES: readonly string[];
export const LEAKED_OUTCOMES: readonly string[];
export const LEAK_NOT_MARKABLE: readonly string[];
export function leakKeyOf(r: { scenario: string; context: string; variant?: string }): string;
export function recheck(records: readonly RecheckRecord[]): RecheckResult;
export function renderRecheck(out: RecheckResult): string;
