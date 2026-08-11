import { existsSync } from "node:fs";

/**
 * The child binary used to prove process-mediated injection.
 *
 * `printenv` rather than `node`: the command allowlist pins interpreters behind
 * the §4.5.3 acknowledgement gate, so allowlisting `node` would force the
 * harness to acknowledge an interpreter as routine setup and collapse the
 * L2/L3 capability-ladder split in the very fixture that proves the machinery.
 * `printenv` is not an interpreter, needs no acknowledgement, and prints
 * exactly the injected variables — which is the whole assertion.
 *
 * The harness targets Linux; the Windows candidate exists only so the
 * machinery self-check is runnable on a development host.
 */
const PRINTENV_CANDIDATES = [
  "/usr/bin/printenv",
  "/bin/printenv",
  "C:\\Program Files\\Git\\usr\\bin\\printenv.exe",
];

export function resolvePrintenv(): string {
  for (const candidate of PRINTENV_CANDIDATES) {
    if (existsSync(candidate)) return candidate;
  }
  throw new Error(
    `no printenv binary found — looked in:\n${PRINTENV_CANDIDATES.map((c) => `  ${c}`).join("\n")}`,
  );
}
