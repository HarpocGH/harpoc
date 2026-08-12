import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const KEYS_DIR = fileURLToPath(new URL("../../fixtures/keys", import.meta.url));

const OUT = join(KEYS_DIR, "out");

export function keysReady(): boolean {
  return existsSync(join(OUT, "client_ed25519"));
}

function requireKeys(): void {
  if (!keysReady()) {
    throw new Error("fixture ssh keys missing — run: pnpm --filter @harpoc/e2e keys");
  }
}

/**
 * The client private key, stored verbatim as the ssh / git-over-ssh secret.
 * The vault's in-process agent loads it and offers the matching identity; the
 * sshd containers authorize exactly its public half.
 */
export function clientKeyPem(): string {
  requireKeys();
  return readFileSync(join(OUT, "client_ed25519"), "utf8");
}

/** The `<type> <base64>` body of a generated public key (comment dropped). */
function pubKeyBody(name: string): string {
  requireKeys();
  const line = readFileSync(join(OUT, `${name}.pub`), "utf8").trim();
  const [type, body] = line.split(/\s+/);
  if (!type || !body) {
    throw new Error(`malformed public key fixture: ${name}.pub`);
  }
  return `${type} ${body}`;
}

/**
 * A known_hosts pin line, written verbatim by the vault (F-2). `host` may be a
 * bare address (`127.0.0.2`) or the bracketed non-22 form (`[127.0.0.1]:2222`).
 * `which` selects whose key is pinned: the happy path pins the server it will
 * actually reach; the mismatch arm pins the pinned server's key at the rogue
 * address, so the rogue server's real key fails verification (D4).
 */
export function knownHostPin(host: string, which: "pinned" | "rogue" = "pinned"): string {
  return `${host} ${pubKeyBody(`hostkey_${which}_ed25519`)}`;
}
