import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/**
 * Canonical SSH key fixtures, read from @harpoc/core — a declared dependency of
 * this package, so the read follows the dependency graph (`cert-fixtures.ts`'s
 * rule for the certificate fixtures). A suite hands the private key's path to
 * the built CLI (`secret set --from-file`), so the key is never copied.
 */
const CORE_SSH = new URL("../../../core/src/injection/__fixtures__/ssh/", import.meta.url);

/** The fixture's path on disk: `secret set <name> --from-file <path>`. */
export function sshKeyFixturePath(name: string): string {
  return fileURLToPath(new URL(name, CORE_SSH));
}

export function sshKeyFixture(name: string): string {
  return readFileSync(new URL(name, CORE_SSH), "utf8");
}

/** The SSH public-key blob of the fixture's `.pub` line. */
export function sshPublicKeyBlob(name: string): Buffer {
  const [, base64] = sshKeyFixture(`${name}.pub`).trim().split(/\s+/);
  return Buffer.from(base64 as string, "base64");
}

/** The fingerprint as `ssh-add -l` and `ssh-keygen -lf` print it. */
export function sshFingerprint(blob: Buffer): string {
  return `SHA256:${createHash("sha256").update(blob).digest("base64").replace(/=+$/, "")}`;
}
