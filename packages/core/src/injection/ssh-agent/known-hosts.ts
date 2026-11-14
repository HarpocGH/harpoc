import { asciiLowerCase } from "../allowlist.js";
import { SshReader } from "./ssh-wire.js";

/**
 * Map a bound host key back to the host names a secret's pinned `known_hosts` lines give
 * it (the SSH context's own no-TOFU pin, `connection_configs.ssh.known_hosts`). The line
 * grammar is `sshd(8)` § SSH_KNOWN_HOSTS FILE FORMAT: `[marker] hostnames keytype
 * base64-key [comment]`. Only a concrete name is bindable — a bare `host` or
 * `[host]:port`; a pattern holding `*` or `?` names no single host, a line holding a `!`
 * negation is skipped whole, a pattern carrying a `|` anywhere in the hosts field (the
 * `HashKnownHosts` form `|1|salt|hash`, which OpenSSH itself recognises only when it leads
 * the field, and then for the whole field) names nothing, fail-closed, and an
 * `@cert-authority` line names no host key. An `@revoked` line holding the key makes the
 * key unbindable.
 */
export interface KnownHost {
  /** The name as the pin spells it (`host_allowlist` matching lowercases it). */
  host: string;
  /** The port of a `[host]:port` name; absent for a bare name. */
  port?: number;
}

interface ParsedLine {
  marker: "cert-authority" | "revoked" | null;
  names: string;
  keyType: string;
  keyBlob: Buffer;
}

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const BRACKETED = /^\[([^\][]+)\]:([0-9]{1,5})$/;

/** The concrete names one unmarked line gives `hostKeyBlob`; empty when it gives none. */
export function matchKnownHostsLine(line: string, hostKeyBlob: Buffer): KnownHost[] {
  const parsed = parseLine(line);
  if (parsed === null || parsed.marker !== null || !holdsKey(parsed, hostKeyBlob)) return [];
  return concreteNames(parsed.names);
}

/** Every concrete name the pin list gives `hostKeyBlob`, in pin order, each once. */
export function hostsForHostKey(lines: readonly string[], hostKeyBlob: Buffer): KnownHost[] {
  const parsed = lines.map(parseLine);
  if (parsed.some((p) => p !== null && p.marker === "revoked" && holdsKey(p, hostKeyBlob))) {
    return [];
  }
  const seen = new Set<string>();
  const hosts: KnownHost[] = [];
  for (const line of lines) {
    for (const known of matchKnownHostsLine(line, hostKeyBlob)) {
      const id = `${asciiLowerCase(known.host)} ${known.port ?? ""}`;
      if (seen.has(id)) continue;
      seen.add(id);
      hosts.push(known);
    }
  }
  return hosts;
}

function parseLine(line: string): ParsedLine | null {
  const fields = line.trim().split(/[ \t]+/);
  if (fields[0] === undefined || fields[0] === "" || fields[0].startsWith("#")) return null;
  let marker: ParsedLine["marker"] = null;
  if (fields[0].startsWith("@")) {
    if (fields[0] === "@cert-authority") marker = "cert-authority";
    else if (fields[0] === "@revoked") marker = "revoked";
    else return null;
    fields.shift();
  }
  const [names, keyType, base64] = fields;
  if (names === undefined || keyType === undefined || base64 === undefined) return null;
  if (!BASE64.test(base64)) return null;
  const keyBlob = Buffer.from(base64, "base64");
  if (keyBlob.toString("base64").replace(/=+$/, "") !== base64.replace(/=+$/, "")) return null;
  return { marker, names, keyType, keyBlob };
}

function holdsKey(parsed: ParsedLine, hostKeyBlob: Buffer): boolean {
  if (!parsed.keyBlob.equals(hostKeyBlob)) return false;
  try {
    return new SshReader(hostKeyBlob).readCString() === parsed.keyType;
  } catch {
    return false;
  }
}

function concreteNames(names: string): KnownHost[] {
  if (names.startsWith("|")) return [];
  const patterns = names.split(",");
  if (patterns.some((p) => p.startsWith("!"))) return [];
  const hosts: KnownHost[] = [];
  for (const pattern of patterns) {
    if (pattern === "" || pattern.includes("*") || pattern.includes("?")) continue;
    if (pattern.includes("|")) continue;
    if (pattern.startsWith("[")) {
      const m = BRACKETED.exec(pattern);
      const port = m ? Number(m[2]) : 0;
      if (m === null || port < 1 || port > 65_535) continue;
      hosts.push({ host: m[1] as string, port });
      continue;
    }
    if (pattern.includes("[") || pattern.includes("]")) continue;
    hosts.push({ host: pattern });
  }
  return hosts;
}
