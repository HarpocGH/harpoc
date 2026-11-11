import { statSync, type Stats } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import {
  MAX_TOKEN_TTL_MS,
  VaultError,
  agentNameSchema,
  isValidSecretNamePattern,
  permissionSchema,
} from "@harpoc/shared";
import type { Permission } from "@harpoc/shared";
import type { TokenRotationSpec } from "@harpoc/core";
import { parsePositiveInteger } from "./options.js";
import { isLink } from "./runtime-dir.js";

const REQUIRED_KEYS = ["agent", "file", "scope", "secrets"] as const;
const KEYS: ReadonlySet<string> = new Set<string>([...REQUIRED_KEYS, "ttl"]);
/** The token cap in minutes (1440): `ttl`'s bound and its default. */
const MAX_TTL_MINUTES = Math.floor(MAX_TOKEN_TTL_MS / 60_000);

function refuse(text: string): VaultError {
  return VaultError.invalidInput(`--issue-token: ${text}`);
}

/**
 * One `server start --issue-token` value (DB-13):
 * `agent=<name>,file=<absolute path>,scope=<permission>[+<permission>…],secrets=<pattern>[+<pattern>…][,ttl=<minutes>]`.
 * The parts split on `,` and each on its first `=`; the list values split on `+`, which neither a
 * permission nor a secret-name pattern holds (`auth token`'s lists take the `,` the spec splits
 * on). Each key once, `ttl` 1–1440 with the default 1440; nothing is trimmed, so a path holding a
 * comma cannot be named. Every refusal is `INVALID_INPUT` naming the field.
 */
export function parseIssueTokenSpec(spec: string): TokenRotationSpec {
  const values = new Map<string, string>();
  for (const part of spec.split(",")) {
    const eq = part.indexOf("=");
    if (eq === -1) throw refuse(`${JSON.stringify(part)} is not key=value`);
    const key = part.slice(0, eq);
    const value = part.slice(eq + 1);
    if (!KEYS.has(key)) {
      throw refuse(`unknown key ${JSON.stringify(key)} (agent, file, scope, secrets, ttl)`);
    }
    if (values.has(key)) throw refuse(`${key} given twice`);
    if (value === "") throw refuse(`${key} is empty`);
    values.set(key, value);
  }
  for (const key of REQUIRED_KEYS) {
    if (!values.has(key)) {
      throw refuse(`${key} is missing (agent, file, scope and secrets are required)`);
    }
  }

  const agent = values.get("agent") as string;
  if (!agentNameSchema.safeParse(agent).success) {
    throw refuse(
      `agent ${JSON.stringify(agent)} is not an agent name (letters, digits, _ and -; at most 255)`,
    );
  }
  const file = values.get("file") as string;
  if (!isAbsolute(file)) throw refuse(`file ${JSON.stringify(file)} is not an absolute path`);
  const scope = (values.get("scope") as string).split("+").map((member): Permission => {
    if (!permissionSchema.safeParse(member).success) {
      throw refuse(
        `scope: ${JSON.stringify(member)} is not a permission (list, read, use, create, rotate, revoke, admin)`,
      );
    }
    return member as Permission;
  });
  const secrets = (values.get("secrets") as string).split("+").map((member) => {
    if (!isValidSecretNamePattern(member)) {
      throw refuse(
        `secrets: ${JSON.stringify(member)} is not a secret name or pattern (letters, digits, _, - and the * wildcard)`,
      );
    }
    return member;
  });
  const ttl = values.get("ttl");
  const ttlMinutes =
    ttl === undefined
      ? MAX_TTL_MINUTES
      : parsePositiveInteger(ttl, "--issue-token: ttl must be a whole number of minutes (1-1440)");
  if (ttlMinutes > MAX_TTL_MINUTES) {
    throw refuse(`ttl exceeds the 24 h token cap (${String(MAX_TTL_MINUTES)})`);
  }
  return { agent, file, scope, secrets, ttlMinutes };
}

/** Every `--issue-token` value, in order; two specs naming one token file are refused. */
export function parseIssueTokenSpecs(values: readonly string[]): TokenRotationSpec[] {
  const specs = values.map(parseIssueTokenSpec);
  const files = new Set<string>();
  for (const { file } of specs) {
    const resolved = resolve(file);
    if (files.has(resolved)) {
      throw refuse(`file ${JSON.stringify(file)} is named by two specs (one token file per spec)`);
    }
    files.add(resolved);
  }
  return specs;
}

function statOrUndefined(path: string): Stats | undefined {
  try {
    return statSync(path, { throwIfNoEntry: false });
  } catch {
    return undefined;
  }
}

/**
 * Refuses `INVALID_INPUT` unless the token file's directory exists and the file is not a
 * directory, neither being a symbolic link or junction: each rotation writes a temporary beside
 * the file and renames it over the file.
 */
export function assertIssueTokenFile(file: string): void {
  const dir = dirname(file);
  if (isLink(dir)) {
    throw refuse(`file ${file}: the directory is a symbolic link or junction: ${dir}`);
  }
  const dirStat = statOrUndefined(dir);
  if (dirStat === undefined) throw refuse(`file ${file}: no such directory: ${dir}`);
  if (!dirStat.isDirectory()) throw refuse(`file ${file}: not a directory: ${dir}`);
  if (isLink(file)) throw refuse(`file ${file} is a symbolic link or junction`);
  if (statOrUndefined(file)?.isDirectory() === true) throw refuse(`file ${file} is a directory`);
}
