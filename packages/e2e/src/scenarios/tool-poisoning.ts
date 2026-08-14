import { storeSecret } from "../harness/vault.js";
import { sightings } from "../assert/opacity.js";
import { ECHO_HTTPS, MCP_POISONED } from "../harness/backends.js";
import {
  classifyExfiltration,
  resetSink,
  sinkRequests,
  sinkSawCredential,
} from "../harness/attacker.js";
import {
  attackerUrlFromDescription,
  poisonedAuthorizations,
  poisonedToolDescription,
  resetPoisonedRecorder,
} from "../harness/mcp-poisoned.js";
import { Outcome } from "./scenario.js";
import type { ScenarioArm } from "./scenario.js";

const NONCE = "p4s3";
const ECHO_ORIGIN = `https://${ECHO_HTTPS.host}:${String(ECHO_HTTPS.port)}`;

/**
 * §6.2.3 — Tool Poisoning (hasan2025).
 *
 * The injection is not in the data an agent processes; it is in the TOOL
 * DESCRIPTION a third-party MCP server serves. Nothing about that server is
 * malformed, so no protocol-level check can catch it: a host that renders
 * descriptions into a model's context has handed the model an instruction
 * written by whoever operates the server.
 *
 * Tier 1 throughout: the scripted client force-issues the call the description
 * induces, so the enforcement claim does not rest on whether a given model
 * follows it. What keeps that honest is that the attacker URL is PARSED OUT of
 * the live description rather than hardcoded — remove the poisoning and the arm
 * errors instead of quietly passing.
 *
 * The two variants attack the two ways a description can move a credential:
 *
 *   induced-http-exfiltration  the description names an endpoint and the agent
 *                              makes the request. The vault's answer is the
 *                              per-secret URL allowlist.
 *   downstream-target-fixed    the description tries to move the MCP proxy's
 *                              own target. The vault's answer is structural:
 *                              the endpoint comes from the secret's stored
 *                              server configuration (the trusted admin path)
 *                              and any target in the action is ignored.
 */
export const TOOL_POISONING_ARMS: ScenarioArm[] = [
  {
    scenario: "tool-poisoning",
    context: "http",
    variant: "induced-http-exfiltration",
    services: ["attacker", "mcp-poisoned", "echo-https"],
    async setup(vault) {
      const credential = `p4-tool-poisoning-http-${NONCE}`;
      const handle = await storeSecret(vault, `p4-poison-http-${NONCE}`, credential);
      // Allowlisted to the legitimate backend only. The attacker sink is
      // reachable and CA-trusted (P4-R3), so a refusal can come from nothing
      // but this list.
      await vault.engine.setInjectionPolicy(handle, {
        url_allowlist: [`${ECHO_ORIGIN}/*`],
        command_allowlist: [],
        env_allowlist: [],
        host_allowlist: [],
      });
      return { handle, credential, marker: `p4-poison-marker-${NONCE}` };
    },
    async observe(arm, setup) {
      await resetSink();
      // The payload is DERIVED from the live poisoning: read the description
      // off the wire, take the endpoint it names, issue the call it asks for.
      const induced = attackerUrlFromDescription(await poisonedToolDescription());
      const outcome = await arm.invoke(setup.handle, {
        type: "http",
        method: "POST",
        url: induced,
        injection: { type: "bearer" },
        headers: { "content-type": "text/plain" },
        body: "compliance-validation",
      });
      return classifyExfiltration(outcome, setup.credential, await sinkRequests());
    },
  },
  {
    scenario: "tool-poisoning",
    context: "mcp",
    variant: "downstream-target-fixed",
    services: ["attacker", "mcp-poisoned"],
    async setup(vault) {
      const credential = `p4-tool-poisoning-mcp-${NONCE}`;
      const handle = await storeSecret(vault, `p4-poison-mcp-${NONCE}`, credential);
      await vault.engine.setInjectionPolicy(handle, {
        url_allowlist: [`${MCP_POISONED.endpoint}*`],
        command_allowlist: [],
        env_allowlist: [],
        host_allowlist: [],
      });
      // The downstream endpoint is CONFIGURATION, written through the trusted
      // admin path. This is the mechanism under test: no MCP tool can set it,
      // and nothing in the action can override it.
      await vault.engine.setMcpServerConfig(handle, {
        server_name: MCP_POISONED.serverName,
        transport: "http",
        url: MCP_POISONED.endpoint,
      });
      return { handle, credential, marker: MCP_POISONED.benignMarker };
    },
    async observe(arm, setup) {
      await resetSink();
      await resetPoisonedRecorder();

      // One payload, both arms: a tool call carrying the target the poisoned
      // description asks for. The vault's schema has no such field and its
      // proxy dials the configured endpoint; the naive server forwards
      // wherever the call says.
      const induced = attackerUrlFromDescription(await poisonedToolDescription());
      const outcome = await arm.invoke(setup.handle, {
        type: "mcp",
        server: MCP_POISONED.serverName,
        tool: MCP_POISONED.tool,
        url: induced,
      });

      const arrived = await sinkRequests();
      if (sinkSawCredential(setup.credential, arrived)) return Outcome.EXFILTRATED;
      if (arrived.length > 0) {
        // Reaching the attacker without the credential is not exfiltration. The
        // paired row's "baseline leaked" cell must be satisfied by the
        // credential leaving, not by any request arriving — otherwise a broken
        // attack path (an encoding the scan misses, a misdirected payload)
        // certifies the comparison (review 2026-08-14, F7).
        throw new Error(
          `arm is not discriminating: ${String(arrived.length)} request(s) reached the attacker ` +
            "but none carried the credential",
        );
      }

      // Nothing reached the attacker. For that to mean "the description could
      // not move the target" rather than "the call never happened", the
      // configured downstream must show it was reached WITH the credential —
      // read out of band, so it cannot be an artifact of the vault's own
      // reporting.
      const authorizations = await poisonedAuthorizations();
      if (!authorizations.includes(`Bearer ${setup.credential}`)) {
        throw new Error(
          "arm is not discriminating: the credential reached neither the attacker nor the " +
            "configured downstream, so the call did not exercise the proxy path at all",
        );
      }
      // And the caller still learns nothing: the downstream reflects the
      // Authorization it received straight back into the tool result.
      const hits = sightings(setup.credential, {
        result: outcome.result,
        error: outcome.errorText,
        stderr: outcome.stderr,
      });
      return hits.length > 0 ? Outcome.LEAKED : Outcome.BLOCKED;
    },
  },
];
