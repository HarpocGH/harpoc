import { createHash } from "node:crypto";
import { sshKeyLineType } from "@harpoc/shared";

/** A public key line of the bootstrap block or action: its type, its wire blob, and the line itself. */
export interface SshPublicKey {
  type: string;
  blob: Buffer;
  line: string;
}

/** The line read through shared's `sshKeyLineType`, so it admits exactly what the stored schema admits. */
export function parseSshPublicKey(line: string, types: readonly string[]): SshPublicKey | null {
  const type = sshKeyLineType(line, types);
  if (type === null) return null;
  return { type, blob: Buffer.from(line.slice(type.length + 1), "base64"), line };
}

/** `ssh-keygen -l`'s SHA256 fingerprint of a public key blob — the one fact a row records about a key no secret holds. */
export function sshKeyFingerprint(blob: Uint8Array): string {
  return `SHA256:${createHash("sha256").update(blob).digest("base64").replace(/=+$/, "")}`;
}

export function sameSshKey(a: SshPublicKey, b: SshPublicKey): boolean {
  return a.type === b.type && a.blob.equals(b.blob);
}
