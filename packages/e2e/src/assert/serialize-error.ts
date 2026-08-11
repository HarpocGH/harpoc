/**
 * Errors hide their payload from a structural walk: `message` and `stack` are
 * non-enumerable, so `Object.entries(err)` yields nothing. Review finding H2
 * leaked exactly there — a thrown message becomes the MCP tool-result text and
 * the REST error body. Flatten every own property plus the cause chain.
 */
export function serializeError(err: unknown, seen: WeakSet<object> = new WeakSet()): unknown {
  if (!(err instanceof Error)) return { value: err };
  // A self-referencing cause chain must not recurse forever: the harness has
  // to survive whatever a hostile endpoint hands it.
  if (seen.has(err)) return { circular: true };
  seen.add(err);

  const out: Record<string, unknown> = {
    name: err.name,
    message: err.message,
    stack: err.stack ?? "",
  };
  for (const key of Object.getOwnPropertyNames(err)) {
    out[key] = (err as unknown as Record<string, unknown>)[key];
  }
  if (err.cause !== undefined) out["cause"] = serializeError(err.cause, seen);
  return out;
}
