import type { TextPart, VaultText } from "@harpoc/shared";
import { VaultError, renderVaultText, vaultText } from "@harpoc/shared";

/**
 * Compile-time exhaustiveness guard (fail-safe defaults, thesis §5.3.1).
 * A dispatch over a discriminated union funnels its default arm here with the
 * value typed `never`: adding a union member without an explicit arm makes the
 * call a type error. A value that evades the type system anyway (plain-JS
 * callers, corrupted input) is rejected at runtime rather than passed through.
 * A caller that holds the value's type as a part hands it in `named`.
 */
export function assertNever(value: never, what: VaultText, named?: TextPart): never {
  if (named !== undefined) throw VaultError.invalidInput(vaultText`Unsupported ${what}: ${named}`);
  const type = (value as { type?: string } | null)?.type;
  throw VaultError.invalidInput(`Unsupported ${renderVaultText(what)}: ${type ?? String(value)}`);
}
