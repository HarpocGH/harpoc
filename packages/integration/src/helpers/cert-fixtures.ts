import { readFileSync } from "node:fs";

/**
 * Canonical certificate fixtures, read from @harpoc/core — a declared
 * dependency of this package, so the read follows the dependency graph.
 * Single source: the inline copies these replace drifted silently before
 * (Phase 10 ledger item 2). Test-only cross-package reads are deliberate.
 */
const CORE_CERTS = new URL("../../../core/src/__fixtures__/certs/", import.meta.url);

const read = (dir: URL, name: string): string => readFileSync(new URL(name, dir), "utf8");

export const KEY_PEM = read(CORE_CERTS, "rsa-key.pem");
export const CERT_PEM = read(CORE_CERTS, "rsa-cert.pem");
export const EXPIRED_KEY_PEM = read(CORE_CERTS, "expired-key.pem");
export const EXPIRED_CERT_PEM = read(CORE_CERTS, "expired-cert.pem");
