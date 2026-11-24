/** `JSON.stringify` that also writes an error's name and message, which the plain form leaves out. */
export function serialized(value: unknown): string {
  return JSON.stringify(value, (_key, inner: unknown) =>
    inner instanceof Error ? { ...inner, name: inner.name, message: inner.message } : inner,
  );
}
