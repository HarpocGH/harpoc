import type { InjectionPolicyInput, RenderApproval, RenderEntry } from "@harpoc/shared";
import { renderEntryDigest } from "../render-entry-digest.js";
import { HOST_KEY } from "./ssh-public-keys.js";

/** A render entry with three slots, to `h1.example` pinned by `HOST_KEY`. */
export const ENTRY: RenderEntry = {
  name: "env",
  host: "h1.example",
  port: 22,
  user: "deploy",
  path: "/srv/app/.env",
  host_keys: [HOST_KEY],
  template: "TOKEN={{secret://bot-token}}\nAPI={{secret://api-key}}\nDB={{secret://db-pass}}\n",
};

/** A second entry on the same host: one slot that is the whole file. */
export const ENTRY_ONE: RenderEntry = {
  ...ENTRY,
  name: "pem",
  path: "/srv/app/key.pem",
  template: "{{secret://bot-token}}",
};

/** A key secret's policy holding `entries`: `ssh` allowed, the entries' host admitted. */
export function keyPolicy(entries: RenderEntry[]): InjectionPolicyInput {
  return {
    command_allowlist: ["ssh"],
    host_allowlist: ["h1.example"],
    render: { entries, approvals: [] },
  };
}

/** A slot secret's approval of `entry` on the key secret `keyId`. */
export function approval(keyId: string, entry: RenderEntry): RenderApproval {
  return { key: keyId, entry: entry.name, digest: renderEntryDigest(entry) };
}
