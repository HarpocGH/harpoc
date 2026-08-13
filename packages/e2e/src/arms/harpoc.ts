import type { Permission } from "@harpoc/shared";
import type { HarnessVault } from "../harness/vault.js";
import { startMcpHttpSurface } from "../harness/surfaces/mcp-http.js";
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
    async probeMetadata(handle?: string): Promise<CallOutcome> {
      // The same surface the baseline arm probes, tool for tool, so §6.2.1's
      // paired row compares like with like. `use_secret` against a nonexistent
      // handle supplies the error channel the baseline's `failing_request`
      // supplies: a thrown message is model-visible and no result-shaped
      // redaction sees it (H2).
      const list = await surface.client
        .callTool({ name: "list_secrets", arguments: {} })
        .then((r) => r as unknown)
        .catch((err: unknown) => err);
      const info = await surface.client
        .callTool({ name: "get_secret_info", arguments: { handle: handle ?? "secret://unknown" } })
        .then((r) => r as unknown)
        .catch((err: unknown) => err);
      const resource = await surface.client
        .readResource({ uri: "secret://vault/secrets" })
        .then((r) => r as unknown)
        .catch((err: unknown) => err);
      const failing = await surface
        .callUseSecret("secret://does-not-exist", { type: "http", url: "https://127.0.0.1/" })
        .catch((err: unknown) => ({ result: err, text: String(err) }) as CallOutcome);

      return {
        ok: true,
        result: { list, info, resource, failing: failing.errorText ?? failing.result },
        text: [JSON.stringify(list), JSON.stringify(info), failing.text].join("\n"),
      };
    },
    close: () => surface.close(),
  };
}
