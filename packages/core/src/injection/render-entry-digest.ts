import { createHash } from "node:crypto";
import {
  distinctRenderSlots,
  parseRenderTemplate,
  renderEntryCanonicalBytes,
  SSH_HOST_KEY_TYPES,
  VaultError,
} from "@harpoc/shared";
import type { RenderEntry } from "@harpoc/shared";
import { parseSshPublicKey, sshKeyFingerprint } from "./ssh-common-keys.js";

/** A render entry as a `policy.grant` row and the CLI show it: no key line and no template text. */
export interface RenderEntryDetail {
  name: string;
  host: string;
  port: number;
  user: string;
  path: string;
  host_key_fingerprints: string[];
  slots: string[];
  digest: string;
}

/** The SHA-256, in lower-case hex, of the entry's canonical bytes: what an approval binds. */
export function renderEntryDigest(entry: RenderEntry): string {
  return createHash("sha256").update(renderEntryCanonicalBytes(entry)).digest("hex");
}

/** The entry with each host key as its fingerprint and the template as its distinct slots; a stored line or template that does not parse is corruption. */
export function renderEntryDetail(entry: RenderEntry): RenderEntryDetail {
  const hostKeyFingerprints = entry.host_keys.map((line) => {
    const key = parseSshPublicKey(line, SSH_HOST_KEY_TYPES);
    if (key === null) throw VaultError.vaultCorrupted("a render host key line does not parse");
    return sshKeyFingerprint(key.blob);
  });
  const template = parseRenderTemplate(entry.template);
  if (template === null) throw VaultError.vaultCorrupted("a render template does not parse");
  return {
    name: entry.name,
    host: entry.host,
    port: entry.port,
    user: entry.user,
    path: entry.path,
    host_key_fingerprints: hostKeyFingerprints,
    slots: distinctRenderSlots(template),
    digest: renderEntryDigest(entry),
  };
}
