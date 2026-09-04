import { readFileSync, statSync } from "node:fs";
import { isDecimalInteger, normalizeAllowedHost } from "@harpoc/shared";
import { DEFAULT_MCP_HTTP_PORT } from "./http.js";

export type PortParse = { ok: true; port: number } | { ok: false; message: string };

/**
 * `--port` for the Streamable HTTP transport. Returns a result rather than
 * exiting so the refusal is testable without spawning the binary; `main()`
 * writes the message and exits. Same predicate as every numeric flag of the
 * `harpoc` CLI — `0x10`, `1e2`, `5.0`, `+5` and `""` are typos, not ports.
 */
export function parseHttpPortOption(raw: string | undefined): PortParse {
  if (raw === undefined) return { ok: true, port: DEFAULT_MCP_HTTP_PORT };
  const port = Number(raw);
  if (!isDecimalInteger(raw) || port < 1 || port > 65535) {
    return {
      ok: false,
      message: `Error: Invalid port "${raw}". Must be 1-65535.\n`,
    };
  }
  return { ok: true, port };
}

export const MAX_LAUNCH_TOKEN_FILE_BYTES = 16 * 1024;

export type TokenFileRead = { ok: true; token: string } | { ok: false; message: string };

/**
 * `--token-file <path>` — the on-disk channel for the stdio launch token
 * (R9/A10): argv is readable by every local process for the server's whole
 * lifetime, so the token travels in a file or in `HARPOC_TOKEN`, never as an
 * argument. Read once at start, before any vault is opened; the content is
 * trimmed and never echoed — a refusal names the path only. The same result
 * shape as `parseHttpPortOption`, so `harpoc server start` and `harpoc-mcp`
 * refuse identically.
 */
export function readLaunchTokenFile(path: string): TokenFileRead {
  let size: number;
  try {
    const stat = statSync(path);
    if (!stat.isFile()) {
      return {
        ok: false,
        message: `Error: --token-file ${path} is not a regular file.\n`,
      };
    }
    size = stat.size;
  } catch (err) {
    return {
      ok: false,
      message: `Error: Cannot read --token-file ${path}: ${err instanceof Error ? err.message : String(err)}\n`,
    };
  }
  if (size > MAX_LAUNCH_TOKEN_FILE_BYTES) {
    return {
      ok: false,
      message: `Error: --token-file ${path} exceeds the 16 KiB launch-token limit.\n`,
    };
  }
  let token: string;
  try {
    token = readFileSync(path, "utf8").trim();
  } catch (err) {
    return {
      ok: false,
      message: `Error: Cannot read --token-file ${path}: ${err instanceof Error ? err.message : String(err)}\n`,
    };
  }
  if (token === "") {
    return { ok: false, message: `Error: --token-file ${path} is empty.\n` };
  }
  return { ok: true, token };
}

export type AllowedHostsParse = { ok: true; hosts: string[] } | { ok: false; message: string };

/**
 * `--allowed-host <name>` (repeatable) for the Streamable HTTP transport
 * (R11/D61) — validated before any vault is opened, in the same result shape
 * as the port and token-file parsers. Entries are host names or IP literals
 * only; the listener adds the loopback names itself on a loopback bind. The
 * parameter admits the booleans `parseArgs` yields under `strict: false` — a
 * value-less `--allowed-host` parses as `true` — so such an entry is refused
 * by the flag's own message rather than crashing the launcher.
 */
export function parseAllowedHostsOption(
  raw: string | boolean | readonly (string | boolean)[] | undefined,
): AllowedHostsParse {
  const entries = raw === undefined ? [] : Array.isArray(raw) ? raw : [raw];
  const hosts: string[] = [];
  for (const entry of entries) {
    const normalized = typeof entry === "string" ? normalizeAllowedHost(entry) : null;
    if (normalized === null) {
      return {
        ok: false,
        message: `Error: Invalid --allowed-host "${String(entry)}": a host name or IP address, without scheme, path or port.\n`,
      };
    }
    hosts.push(normalized);
  }
  return { ok: true, hosts };
}
