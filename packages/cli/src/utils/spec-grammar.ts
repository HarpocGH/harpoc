import { VaultError, agentNameSchema, isValidSecretNamePattern } from "@harpoc/shared";

/** `INVALID_INPUT` naming the option: `<flag>: <text>`. */
export function specRefusal(flag: string, text: string): VaultError {
  return VaultError.invalidInput(`${flag}: ${text}`);
}

/**
 * The parts of one `key=value[,key=value…]` spec of a repeatable `server start` option: the spec
 * splits on `,` and each part on its first `=`; every key is one of `keys`, given once, with a
 * value that is not empty, and every `required` key — two or more — is present. Nothing is
 * trimmed. Every refusal is `INVALID_INPUT` under `flag`, the unknown key's naming `keys`
 * (`a, b, c`) and the missing key's naming `required` (`a, b and c are required`).
 */
export function parseSpecParts(
  flag: string,
  spec: string,
  keys: readonly string[],
  required: readonly string[],
): Map<string, string> {
  const known: ReadonlySet<string> = new Set(keys);
  const values = new Map<string, string>();
  for (const part of spec.split(",")) {
    const eq = part.indexOf("=");
    if (eq === -1) throw specRefusal(flag, `${JSON.stringify(part)} is not key=value`);
    const key = part.slice(0, eq);
    const value = part.slice(eq + 1);
    if (!known.has(key)) {
      throw specRefusal(flag, `unknown key ${JSON.stringify(key)} (${keys.join(", ")})`);
    }
    if (values.has(key)) throw specRefusal(flag, `${key} given twice`);
    if (value === "") throw specRefusal(flag, `${key} is empty`);
    values.set(key, value);
  }
  const requiredList = `${required.slice(0, -1).join(", ")} and ${required[required.length - 1] as string}`;
  for (const key of required) {
    if (!values.has(key)) {
      throw specRefusal(flag, `${key} is missing (${requiredList} are required)`);
    }
  }
  return values;
}

/** A spec's `agent` value, refused `INVALID_INPUT` under `flag` unless it is an agent name. */
export function parseSpecAgent(flag: string, value: string): string {
  if (!agentNameSchema.safeParse(value).success) {
    throw specRefusal(
      flag,
      `agent ${JSON.stringify(value)} is not an agent name (letters, digits, _ and -; at most 255)`,
    );
  }
  return value;
}

/**
 * A spec's `secrets` value split on `+`, which no secret-name pattern holds, each member a secret
 * name or pattern — an empty member is refused, so the list never comes out empty; refused
 * `INVALID_INPUT` under `flag`.
 */
export function parseSecretPatterns(flag: string, value: string): string[] {
  return value.split("+").map((member) => {
    if (!isValidSecretNamePattern(member)) {
      throw specRefusal(
        flag,
        `secrets: ${JSON.stringify(member)} is not a secret name or pattern (letters, digits, _, - and the * wildcard)`,
      );
    }
    return member;
  });
}
