import type { Secret } from "@harpoc/shared";
import { SecretType } from "@harpoc/shared";
import type { SqliteStore } from "../storage/sqlite-store.js";

/**
 * Whether a secret is a vault-managed certificate — one whose material lives
 * KEK-encrypted in the `certificates` table, so the generic value column is not
 * its credential and every generic value path must refuse it.
 *
 * The certificates ROW — not the type alone — is what marks a secret as
 * vault-managed: `certificate` has always been a legal type on the generic
 * create paths (`secret set -t certificate`, REST, MCP), and those secrets
 * carry a real payload. Keying on the type alone would strand them. The lookup
 * is guarded by the type test, so only cert-typed secrets pay for it.
 *
 * @internal Engine seam, not part of the `@harpoc/core` public API.
 */
export function isVaultManagedCertificate(store: SqliteStore, secret: Secret): boolean {
  return secret.type === SecretType.CERTIFICATE && store.getCertificate(secret.id) !== undefined;
}
