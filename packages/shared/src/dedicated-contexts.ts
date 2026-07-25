/**
 * Binaries that have a dedicated injection context, and may therefore not be
 * spawned through the free-argv process context (thesis §4.5.3 capability
 * ladder).
 *
 * The Git and SSH contexts must have their binary in the secret's
 * `command_allowlist` — the allowlist is what pins `git`/`ssh` to a resolved
 * absolute path. But `command_allowlist` is a single, context-agnostic field and
 * `use_secret` dispatches on the caller-chosen `action.type`, so that mandatory
 * entry also made the same binary reachable through `action.type: "process"`,
 * where the vault inspects no arguments. `git -c alias.x=!<command> x` and
 * `ssh -oProxyCommand=<command> host` are then instruction vehicles with the
 * credential in the child environment: the vault's own hardening — the git
 * dangerous-argument denylist and the ssh hardening argv — is bypassed by
 * choosing a different `action.type` for the same secret, and no configuration
 * could enable the Git or SSH context without also granting it.
 *
 * The refusal therefore lives at use time in the process context rather than at
 * policy-write time: it closes the hole for vaults whose policies already list
 * these binaries, needs no policy rewrite and no migration, and — like the
 * network-isolation refusal — is fail-closed with no environment opt-out. The
 * capability is not lost, only routed: `action.type: "git"` and `"ssh"` do the
 * same work under vault-authored arguments.
 *
 * Interpreters are deliberately not listed here. `node`/`npx`/`bash` and the
 * rest are already an explicit, audited administrator decision via the
 * known-interpreter acknowledgement gate ({@link KNOWN_INTERPRETERS}); an
 * administrator who acknowledged one has knowingly granted arbitrary execution.
 * `git` and `ssh` carried no such acknowledgement.
 *
 * Matching is by normalized basename against the *resolved, symlink-followed*
 * path the allowlist check returns, so a symlink to `git` under another name is
 * still refused. A renamed *copy* of the binary evades basename matching by
 * construction — as with the interpreter gate, this targets the mandatory
 * allowlist entry an ordinary Git/SSH configuration produces, not an
 * administrator adversarially planting a renamed binary (L4/L5 territory).
 * Sibling tools (`ssh-keygen`, `git-upload-pack`) normalize to their own names
 * and are unaffected.
 */

import { normalizeBinaryBasename } from "./binary-name.js";

/** Normalized basename → the `action.type` that must be used for that binary. */
export const DEDICATED_CONTEXT_BINARIES: ReadonlyMap<string, "git" | "ssh"> = new Map([
  ["git", "git" as const],
  ["ssh", "ssh" as const],
]);

/**
 * The dedicated context a resolved binary path belongs to, or null when the
 * binary has none and the process context may run it.
 */
export function dedicatedContextForBinary(resolvedPath: string): "git" | "ssh" | null {
  return DEDICATED_CONTEXT_BINARIES.get(normalizeBinaryBasename(resolvedPath)) ?? null;
}
