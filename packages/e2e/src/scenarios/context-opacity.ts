import { storeSecret } from "../harness/vault.js";
import { sightings, redactForDiagnostics } from "../assert/opacity.js";
import { caPem } from "../harness/pki.js";
import { clientKeyPem, knownHostPin } from "../harness/ssh.js";
import { resolveDocker, resolveSftp } from "../harness/fixtures.js";
import { DOCKER_REGISTRY, MAIL, MONGO, REDIS, SSHD_PINNED } from "../harness/backends.js";
import { Outcome } from "./scenario.js";
import type { OutcomeValue, ScenarioArm, ScenarioSetup } from "./scenario.js";
import type { Arm, CallOutcome } from "../arms/arm.js";
import type { HarnessVault } from "../harness/vault.js";

const NONCE = "p4v13";

/**
 * §6.2 — Extended-context result opacity (v1.3).
 *
 * The five new injection contexts — SMTP, IMAP, the database context's Redis
 * and MongoDB engines, SFTP and the docker-registry context — each return a
 * result to the calling agent, and I2/§4.4's opacity model commits to the same
 * claim across every one of them: the credential the vault injected never
 * appears in that result, in any encoding, at any structural position.
 *
 * These are the same two-vocabulary paired rows as §6.2.1 (prompt injection)
 * and §6.2.7 (response-channel echo), one context per arm:
 *
 *   OPAQUE  the vault completed the operation and the caller-visible result —
 *           `{accepted, message_id}` for SMTP, the search UIDs / fetched
 *           envelope for IMAP, the command result for Redis/Mongo, the process
 *           exit + sanitized stdio for SFTP and docker — carried no credential.
 *   LEAKED  the §2.3 status quo: a naive server holding the credential in its
 *           launch environment returns it to the agent that owns it, exactly as
 *           `list_secrets` / `get_secret_info` already do. This is the paired
 *           row's positive control — an anti-vacuity guard, not an exfiltration
 *           claim. Without it an OPAQUE Harpoc result could be an artefact of a
 *           sweep that matches nothing (review 2026-08-14, F9).
 *
 * The Harpoc arm additionally fails loudly if the vault did not COMPLETE the
 * operation: a refusal or an unhealthy fleet leaves the credential absent from
 * the error too, so certifying OPAQUE over a failed call would be vacuous. The
 * §6.4 success-path opacity these arms measure is proven in-process by the
 * integration suite (`v13-posture.test.ts`); these arms drive it end to end,
 * through a real MCP client over Streamable HTTP against the live fleet.
 */
function opacityVerdict(arm: Arm, outcome: CallOutcome, credential: string): OutcomeValue {
  const leaked =
    sightings(credential, {
      result: outcome.result,
      error: outcome.errorText,
      stderr: outcome.stderr,
    }).length > 0;

  if (arm.name === "baseline") {
    if (!leaked) {
      throw new Error(
        "baseline did not return the credential: the status-quo server exposed nothing, so the " +
          "paired opacity row would be vacuous",
      );
    }
    return Outcome.LEAKED;
  }

  // Harpoc: the operation must genuinely have completed. A pre-decrypt refusal
  // or a fleet that never answered would report OPAQUE trivially — the
  // credential is absent from an error text as well — so a failed call throws
  // rather than certifying opacity over nothing.
  if (!outcome.ok) {
    throw new Error(
      "harpoc did not complete the operation, so the opacity row would be vacuous (text=" +
        `${redactForDiagnostics(outcome.text.slice(0, 300), credential)})`,
    );
  }
  return leaked ? Outcome.LEAKED : Outcome.OPAQUE;
}

/** Store the credential and return the setup shell; per-context policy is layered on by the caller. */
async function baseSetup(
  vault: HarnessVault,
  name: string,
  credential: string,
): Promise<{ handle: string; setup: ScenarioSetup }> {
  const handle = await storeSecret(vault, `p4-ctx-${name}-${NONCE}`, credential);
  return { handle, setup: { handle, credential, marker: `p4-ctx-marker-${NONCE}` } };
}

export const CONTEXT_OPACITY_ARMS: ScenarioArm[] = [
  {
    scenario: "context-opacity",
    context: "smtp",
    variant: "smtp",
    services: ["mail"],
    async setup(vault) {
      const { handle, setup } = await baseSetup(vault, "smtp", MAIL.credential);
      await vault.engine.setInjectionPolicy(handle, {
        url_allowlist: [],
        command_allowlist: [],
        env_allowlist: [],
        host_allowlist: [`${MAIL.host}:${String(MAIL.smtpPort)}`],
      });
      // Implicit TLS against the fixture CA — the mail server presents the same
      // localhost leaf echo-https does, so trust comes from the pinned bundle.
      await vault.engine.setConnectionConfig(handle, { mail: { tls: { ca: caPem() } } });
      return setup;
    },
    async observe(arm, setup) {
      const outcome = await arm.invoke(setup.handle, {
        type: "smtp",
        host: MAIL.host,
        port: MAIL.smtpPort,
        security: "tls",
        from: "sender@harpoc.test",
        to: ["recipient@harpoc.test"],
        subject: `opacity probe ${NONCE}`,
        text: `benign body ${setup.marker}`,
      });
      return opacityVerdict(arm, outcome, setup.credential);
    },
  },
  {
    scenario: "context-opacity",
    context: "imap",
    variant: "imap",
    services: ["mail"],
    async setup(vault) {
      const { handle, setup } = await baseSetup(vault, "imap", MAIL.credential);
      await vault.engine.setInjectionPolicy(handle, {
        url_allowlist: [],
        command_allowlist: [],
        env_allowlist: [],
        host_allowlist: [`${MAIL.host}:${String(MAIL.imapPort)}`],
        // A read-only search is a read and passes the gate; setting it anyway
        // exercises the v1.3 policy field on the opacity path.
        imap_read_only: true,
      });
      await vault.engine.setConnectionConfig(handle, { mail: { tls: { ca: caPem() } } });
      return setup;
    },
    async observe(arm, setup) {
      const outcome = await arm.invoke(setup.handle, {
        type: "imap",
        host: MAIL.host,
        port: MAIL.imapPort,
        mailbox: "INBOX",
        operation: { kind: "search", unseen: true },
      });
      return opacityVerdict(arm, outcome, setup.credential);
    },
  },
  {
    scenario: "context-opacity",
    context: "database",
    variant: "redis",
    services: ["redis"],
    async setup(vault) {
      const { handle, setup } = await baseSetup(vault, "redis", REDIS.credential);
      await vault.engine.setInjectionPolicy(handle, {
        url_allowlist: [],
        command_allowlist: [],
        env_allowlist: [],
        host_allowlist: [`${REDIS.host}:${String(REDIS.port)}`],
      });
      // Loopback plaintext: TLS on a throwaway loopback container buys nothing,
      // and the opacity claim is orthogonal to transport (postgres-plain sets
      // the same precedent for the SQL engines).
      await vault.engine.setConnectionConfig(handle, { database: { tls_mode: "disable" } });
      return setup;
    },
    async observe(arm, setup) {
      const outcome = await arm.invoke(setup.handle, {
        type: "database",
        engine: "redis",
        host: REDIS.host,
        port: REDIS.port,
        database: REDIS.database,
        // ECHO returns a benign marker: a live command result to sweep, and a
        // negative control that blanket redaction would flatten.
        command: ["ECHO", setup.marker],
      });
      return opacityVerdict(arm, outcome, setup.credential);
    },
  },
  {
    scenario: "context-opacity",
    context: "database",
    variant: "mongodb",
    services: ["mongo"],
    async setup(vault) {
      const { handle, setup } = await baseSetup(vault, "mongo", MONGO.credential);
      await vault.engine.setInjectionPolicy(handle, {
        url_allowlist: [],
        command_allowlist: [],
        env_allowlist: [],
        host_allowlist: [`${MONGO.host}:${String(MONGO.port)}`],
      });
      await vault.engine.setConnectionConfig(handle, { database: { tls_mode: "disable" } });
      return setup;
    },
    async observe(arm, setup) {
      const outcome = await arm.invoke(setup.handle, {
        type: "database",
        engine: "mongodb",
        host: MONGO.host,
        port: MONGO.port,
        database: MONGO.database,
        command: { ping: 1 },
      });
      return opacityVerdict(arm, outcome, setup.credential);
    },
  },
  {
    scenario: "context-opacity",
    context: "sftp",
    variant: "sftp",
    services: ["sshd-pinned"],
    async setup(vault) {
      const { handle, setup } = await baseSetup(vault, "sftp", clientKeyPem());
      await vault.engine.setInjectionPolicy(handle, {
        url_allowlist: [],
        // Pinned to the resolved sftp path, resolved with the injector's own
        // resolver so the allowlist entry and the spawn land on one real file.
        command_allowlist: [resolveSftp()],
        // ProgramData is a no-op on the Linux fleet; harmless, and it keeps the
        // policy identical to the ssh dedicated-context arm on a Windows host.
        env_allowlist: ["ProgramData"],
        host_allowlist: [SSHD_PINNED.host],
      });
      await vault.engine.setConnectionConfig(handle, {
        ssh: { known_hosts: [knownHostPin(SSHD_PINNED.host, "pinned")] },
      });
      return setup;
    },
    async observe(arm, setup) {
      // A directory listing: process-shaped result (exit + sanitized stdio),
      // and the private key served through the in-process agent never touches
      // the wire or the output.
      const outcome = await arm.invoke(setup.handle, {
        type: "sftp",
        host: SSHD_PINNED.host,
        user: SSHD_PINNED.user,
        operation: "list",
        remote_path: "/srv",
      });
      return opacityVerdict(arm, outcome, setup.credential);
    },
  },
  {
    scenario: "context-opacity",
    context: "docker_registry",
    variant: "docker-registry",
    services: ["registry"],
    async setup(vault) {
      const { handle, setup } = await baseSetup(vault, "docker", DOCKER_REGISTRY.credential);
      await vault.engine.setInjectionPolicy(handle, {
        url_allowlist: [],
        command_allowlist: [resolveDocker()],
        env_allowlist: [],
        host_allowlist: [`${DOCKER_REGISTRY.host}:${String(DOCKER_REGISTRY.port)}`],
      });
      return setup;
    },
    async observe(arm, setup) {
      // An explicit-registry pull: the credential reaches docker only through
      // the vault-authored credential helper (env, never argv), so the process
      // result carries the exit status and sanitized stdio, never the password.
      const outcome = await arm.invoke(setup.handle, {
        type: "docker_registry",
        operation: "pull",
        image: `${DOCKER_REGISTRY.host}:${String(DOCKER_REGISTRY.port)}/${DOCKER_REGISTRY.image}`,
      });
      return opacityVerdict(arm, outcome, setup.credential);
    },
  },
];
