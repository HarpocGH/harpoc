import type { Client } from "@modelcontextprotocol/client";
import type { Permission } from "@harpoc/shared";
import type { HarnessVault } from "../harness/vault.js";
import { startMcpHttpSurface } from "../harness/surfaces/mcp-http.js";
import type { McpHttpSurface } from "../harness/surfaces/mcp-http.js";
import type { Arm, CallOutcome } from "./arm.js";

/**
 * The treatment arm: Harpoc's own MCP server over the real Streamable HTTP
 * wire, reached by a scripted client carrying a scoped, vault-signed Bearer
 * token (C-1, C-2). A thin wrapper over the Phase 3 surface, so the arm and the
 * demonstration matrix exercise the same driver rather than two similar ones
 * that could drift.
 *
 * Never `--allow-tokenless`: under a null token the ScopeGuard returns early
 * and token expiry, the per-call revocation recheck, per-secret policy,
 * configuration gating, enumeration filtering and audit scope filtering are all
 * skipped — the arm would measure a configuration in which most of the
 * authorization machinery under evaluation is inert.
 */
export async function startHarpocArm(
  vault: HarnessVault,
  principal: string,
  scopes: Permission[],
): Promise<Arm> {
  const surface = await startMcpHttpSurface(vault, principal, scopes);

  return {
    name: "harpoc",
    invoke: (handle, action) => surface.callUseSecret(handle, action),
    probeMetadata: (handle?: string) => probeHarpocSurface(surface, handle),
    close: () => surface.close(),
  };
}

/** What the surface probe drives: the connected MCP client and the `use_secret` call. */
export interface ProbeSurface {
  client: Pick<Client, "callTool" | "readResource" | "listTools">;
  callUseSecret: McpHttpSurface["callUseSecret"];
}

/**
 * The §6.2.1 surface probe: the same surface the baseline arm probes, tool for
 * tool, so the paired row compares like with like — the listing, the
 * per-secret metadata, all five MCP resources, the `use_secret` argument
 * surface (the input schema `tools/list` advertises and a malformed action's
 * refusal) and a failing call's error text. `use_secret` against a nonexistent
 * handle supplies the error channel the baseline's `failing_request` supplies:
 * a thrown message is model-visible and no result-shaped redaction sees it
 * (H2). Its action is schema-valid, so the refusal is the engine's not-found,
 * not the argument validation the malformed call probes. Every sub-call is
 * caught, so a refused read — `secret://vault/audit/recent` for a token
 * without `admin` — is an outcome the scan sees, never a throw.
 */
export async function probeHarpocSurface(
  surface: ProbeSurface,
  handle?: string,
): Promise<CallOutcome> {
  const probed = handle ?? "secret://unknown";
  const name = probed.slice(probed.lastIndexOf("/") + 1);
  const read = (uri: string): Promise<unknown> =>
    surface.client
      .readResource({ uri })
      .then((r) => r as unknown)
      .catch((err: unknown) => err);

  const list = await surface.client
    .callTool({ name: "list_secrets", arguments: {} })
    .then((r) => r as unknown)
    .catch((err: unknown) => err);
  const info = await surface.client
    .callTool({ name: "get_secret_info", arguments: { handle: probed } })
    .then((r) => r as unknown)
    .catch((err: unknown) => err);
  const resource = await read("secret://vault/secrets");
  const secret = await read(`secret://vault/secrets/${name}`);
  const health = await read("secret://vault/health");
  const projects = await read("secret://vault/projects");
  const auditRecent = await read("secret://vault/audit/recent");
  const tools = await surface.client
    .listTools()
    .then((r) => r as unknown)
    .catch((err: unknown) => err);
  const malformed = await surface.client
    .callTool({
      name: "use_secret",
      arguments: { handle: probed, action: { type: "not-a-context" } },
    })
    .then((r) => r as unknown)
    .catch((err: unknown) => err);
  const failing = await surface
    .callUseSecret("secret://does-not-exist", {
      type: "http",
      method: "GET",
      url: "https://127.0.0.1/",
      injection: { type: "bearer" },
    })
    .catch((err: unknown) => ({ result: err, text: String(err) }) as CallOutcome);

  const shown = (value: unknown): string =>
    value instanceof Error ? String(value) : JSON.stringify(value);
  return {
    ok: true,
    result: {
      list,
      info,
      resource,
      resources: { secret, health, projects, auditRecent },
      useSecretArgs: { tools, malformed },
      failing: failing.errorText ?? failing.result,
    },
    text: [
      ...[list, info, resource, secret, health, projects, auditRecent, tools, malformed].map(shown),
      failing.text,
    ].join("\n"),
  };
}
