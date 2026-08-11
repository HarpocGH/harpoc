import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const PKI_DIR = fileURLToPath(new URL("../../fixtures/pki", import.meta.url));

const OUT = join(PKI_DIR, "out");

export function pkiReady(): boolean {
  return existsSync(join(OUT, "ca.crt"));
}

/** The fixture CA, for pinning via the secret's `ca_pem` connection config. */
export function caPem(): string {
  if (!pkiReady()) {
    throw new Error("fixture PKI missing — run: pnpm --filter @harpoc/e2e pki");
  }
  return readFileSync(join(OUT, "ca.crt"), "utf8");
}
