import { createSecureContext } from "node:tls";
import type { SecureContext } from "node:tls";
import { caSigner, hostPermitted as constraintsPermit, issueLeaf } from "@harpoc/cert-manager";
import type { CaSigner, LeafCertificate, LeafOptions } from "@harpoc/cert-manager";

/** The CA the CONNECT mode terminates TLS with: `secret://harpoc-ca` as the daemon loaded it. */
export interface ProxyCaOptions {
  /** The CA that signs the leaves — the constrained intermediate under the trusted root (R-X1); served after every leaf. */
  certPem: string;
  /** Its private key (the root's was discarded at creation). */
  keyPem: string | Buffer;
  /**
   * The hosts a CONNECT may name — DNS names and IP literals (`harpoc proxy ca init
   * --name-constraints`); they bound the set under every CA, the unconstrained
   * fallback's included (RD-B8-13: `--unconstrained` drops only the certificates'
   * nameConstraints extension).
   */
  hosts: readonly string[];
  /** A leaf's validity; `DEFAULT_LEAF_TTL_MS` by default. */
  leafTtlMs?: number;
  /** The hosts whose leaves are kept; `DEFAULT_LEAF_CACHE_SIZE` by default. */
  leafCacheSize?: number;
}

export const DEFAULT_LEAF_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const DEFAULT_LEAF_CACHE_SIZE = 256;

/** cert-manager's `issueLeaf` — the seam the cache suite records. */
export type LeafIssuer = (ca: CaSigner, options: LeafOptions) => LeafCertificate;

export interface LeafCacheOptions {
  ca: ProxyCaOptions;
  issue?: LeafIssuer;
}

export interface LeafCache {
  /** The TLS context presenting `host`'s leaf: issued on first use, re-issued past half its validity. */
  contextFor(host: string): SecureContext;
  /** The hosts held, least recently used first. */
  hosts(): string[];
  clear(): void;
}

interface Held {
  context: SecureContext;
  issuedAtMs: number;
  renewAtMs: number;
}

/**
 * Per-host leaves under the proxy's CA, parsed once into a signer (the CA key
 * as a `KeyObject`). A leaf's key and certificate go into a `SecureContext` at
 * once and the PEM strings are dropped — a string cannot be zero-filled, so
 * eviction releases the context and nothing more. A leaf is re-issued once
 * half its validity has passed, or when the clock went back past its issue
 * time, so a client never sees one close to its expiry.
 */
export function createLeafCache(options: LeafCacheOptions): LeafCache {
  const { ca } = options;
  const issue = options.issue ?? issueLeaf;
  const ttlMs = ca.leafTtlMs ?? DEFAULT_LEAF_TTL_MS;
  const capacity = ca.leafCacheSize ?? DEFAULT_LEAF_CACHE_SIZE;
  const signer = caSigner({ certPem: ca.certPem, keyPem: ca.keyPem });
  const held = new Map<string, Held>();

  return {
    contextFor(host: string): SecureContext {
      const key = host.toLowerCase();
      const nowMs = Date.now();
      const current = held.get(key);
      held.delete(key);
      if (current !== undefined && nowMs >= current.issuedAtMs && nowMs < current.renewAtMs) {
        held.set(key, current);
        return current.context;
      }
      const leaf = issue(signer, { host: key, validityMs: ttlMs, now: new Date(nowMs) });
      // The chain a client builds to the root it trusts: the leaf, then the signing CA.
      const chain = `${leaf.certPem.trimEnd()}\n${signer.certPem.trimEnd()}\n`;
      const context = createSecureContext({ key: leaf.keyPem, cert: chain });
      const renewAtMs = Math.min(nowMs + ttlMs / 2, leaf.notAfter.getTime());
      held.set(key, { context, issuedAtMs: nowMs, renewAtMs });
      while (held.size > capacity) held.delete(held.keys().next().value as string);
      return context;
    },
    hosts: () => [...held.keys()],
    clear: () => held.clear(),
  };
}

/**
 * Whether a CONNECT to `host` may be answered — the stored hosts under the rule
 * the name constraints encode (cert-manager's `hostPermitted`, RFC 5280
 * § 4.2.1.10: a DNS entry permits itself and every subdomain, an IP entry that
 * address, a DNS entry never an IP literal nor the reverse, case-insensitive),
 * whether or not the CA's certificates carry the extension (RD-B8-13). `host`
 * is the CONNECT line's, brackets stripped.
 */
export function hostPermitted(ca: Pick<ProxyCaOptions, "hosts">, host: string): boolean {
  return constraintsPermit(ca.hosts, host);
}
