import { isDecimalInteger } from "@harpoc/shared";
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
