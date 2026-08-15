import { encodingsOf } from "./encodings.js";
import { findEscapeTolerant } from "./json-escape.js";

export interface Sighting {
  encoding: string;
  path: string;
  position: "value" | "key";
}

/**
 * Deepest serialization level walked. The MCP shape nests two; the vault's own
 * redaction parses four. Six keeps the measurement strictly deeper than the
 * product, so a band remains in which the harness can still detect a credential
 * the vault does not redact — the relation `drift.test.ts` exists to prove.
 * Symmetric caps would push the shared blind spot to a depth neither side can
 * observe, which is how the V8-only needle survived four reviews (decision D2).
 */
const MAX_PARSE_DEPTH = 6;

/**
 * Walk an arbitrary structure and report every position at which the secret
 * appears in any encoding. Object KEYS are tested as well as values — review
 * findings H3 and L1 leaked through keys and SQL column aliases while the
 * identical string in value position was correctly redacted.
 */
export function scan(secret: string, root: unknown): Sighting[] {
  const encodings = encodingsOf(secret);
  const hits: Sighting[] = [];
  const visited = new WeakSet<object>();

  function test(text: string, path: string, position: "value" | "key"): boolean {
    for (const enc of encodings) {
      const found = findEscapeTolerant(text, enc.needle);
      if (found.length > 0) {
        // First matching encoding wins; the list is ordered raw-first. The
        // suffix records HOW it survived, which is the finding in an echo arm.
        const label = found.some((m) => m.escaped) ? `${enc.label}+jsonEscaped` : enc.label;
        hits.push({ encoding: label, path, position });
        return true;
      }
    }
    return false;
  }

  function walk(node: unknown, path: string, depth: number): void {
    if (typeof node === "string") {
      const foundDirectly = test(node, path, "value");
      // A string leaf can BE a serialized structure — the MCP result carries the
      // HttpResult as a string, and the response body inside it as a second one.
      // Scanning only the envelope under-detects at exactly the depth a body
      // echo lives (review 2026-08-14, F4). Descend only when the direct test
      // above missed: a hit already found at this level is the same occurrence
      // a deeper parse would find again, one JSON.parse further in.
      if (!foundDirectly && depth < MAX_PARSE_DEPTH) {
        const trimmed = node.trim();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
          try {
            const parsed: unknown = JSON.parse(trimmed);
            if (typeof parsed === "object" && parsed !== null) {
              walk(parsed, `${path}<json>`, depth + 1);
            }
          } catch {
            // Not JSON after all — the raw test above already covered it.
          }
        }
      }
      return;
    }
    if (node === null || node === undefined) return;
    if (Buffer.isBuffer(node)) {
      test(node.toString("utf8"), path, "value");
      return;
    }
    if (typeof node !== "object") return;
    if (visited.has(node)) return;
    visited.add(node);

    if (Array.isArray(node)) {
      node.forEach((item, i) => walk(item, `${path}[${i}]`, depth));
      return;
    }
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      test(key, `${path}.${key}`, "key");
      walk(value, `${path}.${key}`, depth);
    }
  }

  walk(root, "$", 0);
  return hits;
}
