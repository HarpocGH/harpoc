import { VaultError } from "@harpoc/shared";

/**
 * Compile-time exhaustiveness guard (fail-safe defaults, thesis §5.3.1).
 * A dispatch over a discriminated union funnels its default arm here with the
 * value typed `never`: adding a union member without an explicit arm makes the
 * call a type error. A value that evades the type system anyway (plain-JS
 * callers, corrupted input) is rejected at runtime rather than passed through.
 */
export function assertNever(value: never, what: string): never {
  const type = (value as { type?: string } | null)?.type;
  throw VaultError.invalidInput(`Unsupported ${what}: ${type ?? String(value)}`);
}
