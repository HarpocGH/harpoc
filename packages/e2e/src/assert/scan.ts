import { encodingsOf } from "./encodings.js";

export interface Sighting {
  encoding: string;
  path: string;
  position: "value" | "key";
}

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

  function test(text: string, path: string, position: "value" | "key"): void {
    for (const enc of encodings) {
      if (text.includes(enc.needle)) {
        // First matching encoding wins; the list is ordered raw-first.
        hits.push({ encoding: enc.label, path, position });
        return;
      }
    }
  }

  function walk(node: unknown, path: string): void {
    if (typeof node === "string") return test(node, path, "value");
    if (node === null || node === undefined) return;
    if (Buffer.isBuffer(node)) return test(node.toString("utf8"), path, "value");
    if (typeof node !== "object") return;
    if (visited.has(node)) return;
    visited.add(node);

    if (Array.isArray(node)) {
      node.forEach((item, i) => walk(item, `${path}[${i}]`));
      return;
    }
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      test(key, `${path}.${key}`, "key");
      walk(value, `${path}.${key}`);
    }
  }

  walk(root, "$");
  return hits;
}
