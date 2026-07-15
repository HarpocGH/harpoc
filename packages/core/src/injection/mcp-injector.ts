import { createHash } from "node:crypto";
import type { FetchLike } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { InjectionPolicy, McpAction, McpResult, McpServerConfig } from "@harpoc/shared";
import {
  DEFAULT_MCP_TIMEOUT_MS,
  ErrorCode,
  MAX_MCP_RESULT_BYTES,
  MCP_INIT_TIMEOUT_MS,
  McpTransport,
  VAULT_VERSION,
  VaultError,
} from "@harpoc/shared";
import { Agent, fetch as undiciFetch } from "undici";
import type { RequestInit as UndiciRequestInit } from "undici";
import type { AuditLogger } from "../audit/audit-logger.js";
import { controlledPathDirs, matchesUrlAllowlist, resolveAndMatchCommand } from "./allowlist.js";
import { buildCleanEnv } from "./clean-env.js";
import { createPinnedLookup } from "./http-injector.js";
import type { McpConnectionEntry, McpConnectionRegistry } from "./mcp-registry.js";
import { StdioChildTransport } from "./mcp-stdio-transport.js";
import { mapStringLeaves, redactSecretEncodings } from "./output-sanitizer.js";
import { validateUrl } from "./url-validator.js";

/** Hard ceiling on a per-invocation timeout override (parity with http/process). */
const MAX_TIMEOUT_MS = 300_000;

type McpSdkClientModule = typeof import("@modelcontextprotocol/sdk/client/index.js");
type McpSdkHttpModule = typeof import("@modelcontextprotocol/sdk/client/streamableHttp.js");
type McpSdkTypesModule = typeof import("@modelcontextprotocol/sdk/types.js");

/** The slice of the MCP SDK the injector uses at runtime. */
interface McpSdk {
  Client: McpSdkClientModule["Client"];
  StreamableHTTPClientTransport: McpSdkHttpModule["StreamableHTTPClientTransport"];
  CallToolResultSchema: McpSdkTypesModule["CallToolResultSchema"];
  McpError: McpSdkTypesModule["McpError"];
  McpErrorCode: McpSdkTypesModule["ErrorCode"];
}

/**
 * The MCP SDK is imported lazily (dependency confinement, §5.2): a process
 * embedding core that never executes an MCP action — the REST API among
 * them — must not load SDK code. Same seam as the db-adapters driver
 * imports; the ESM module registry caches, so only the first MCP action
 * pays the load cost.
 */
async function loadMcpSdk(): Promise<McpSdk> {
  const [client, http, types] = await Promise.all([
    import("@modelcontextprotocol/sdk/client/index.js"),
    import("@modelcontextprotocol/sdk/client/streamableHttp.js"),
    import("@modelcontextprotocol/sdk/types.js"),
  ]);
  return {
    Client: client.Client,
    StreamableHTTPClientTransport: http.StreamableHTTPClientTransport,
    CallToolResultSchema: types.CallToolResultSchema,
    McpError: types.McpError,
    McpErrorCode: types.ErrorCode,
  };
}

/**
 * MCP proxy injector (thesis §4.5.4). The vault interposes between the agent
 * and a downstream MCP server, authenticating at the transport layer:
 *
 *  - stdio (process-mediated): the downstream server is spawned with the
 *    credential in a clean environment; the launch command is validated
 *    against the secret's command allowlist (fail-safe deny, pinned resolved
 *    absolute path) on EVERY call.
 *  - Streamable HTTP (request-mediated): the credential is injected as an
 *    `Authorization: Bearer` header; the endpoint is validated against the
 *    secret's URL allowlist and SSRF checks on every outbound request, the
 *    connection is pinned to the validated addresses (DNS rebinding), and
 *    redirects are refused.
 *
 * Lifecycle: spawn on first use, reuse across calls, terminate on session end
 * (McpConnectionRegistry). Crashes fail visibly with a structured error and
 * respawn only on the next invocation. Tool results are sanitized (raw value
 * + encodings across every string leaf) before returning to the agent.
 */
export class McpInjector {
  constructor(
    private readonly auditLogger: AuditLogger | null,
    private readonly registry: McpConnectionRegistry,
  ) {}

  async executeWithSecret(
    action: McpAction,
    secretValue: Uint8Array,
    policy: InjectionPolicy,
    config: McpServerConfig,
    secretId: string,
  ): Promise<McpResult> {
    if (action.server !== config.server_name) {
      const err = VaultError.mcpServerMismatch(action.server, config.server_name);
      this.audit(action, secretId, config, { error: err.code }, false);
      throw err;
    }

    // Target validation on every call — complete mediation, independent of
    // whether a live connection is reused.
    let resolvedCommand: string | undefined;
    try {
      if (config.transport === McpTransport.STDIO) {
        resolvedCommand = resolveAndMatchCommand(
          config.command as string,
          policy.command_allowlist,
          controlledPathDirs(),
        );
      } else {
        const url = config.url as string;
        if (!matchesUrlAllowlist(url, policy.url_allowlist)) {
          throw VaultError.urlNotAllowed(url);
        }
        await validateUrl(url);
      }
    } catch (err) {
      if (err instanceof VaultError) {
        this.audit(action, secretId, config, { error: err.code }, false);
      }
      throw err;
    }

    const sdk = await loadMcpSdk();
    const valueStr = Buffer.from(secretValue).toString("utf8");
    const credentialFingerprint = sha256Hex(secretValue);
    const configFingerprint = sha256Hex(Buffer.from(JSON.stringify(config), "utf8"));

    // Staleness: a live server holding a rotated/refreshed credential or an
    // outdated config is deliberately terminated; the fresh connect below
    // re-injects the newly resolved credential.
    const existing = this.registry.get(secretId);
    if (existing) {
      if (existing.credentialFingerprint !== credentialFingerprint) {
        await this.registry.terminate(secretId, "credential_rotated");
      } else if (existing.configFingerprint !== configFingerprint) {
        await this.registry.terminate(secretId, "config_changed");
      }
    }

    let entry: McpConnectionEntry;
    try {
      entry = await this.registry.acquire(secretId, () =>
        this.establish(sdk, secretId, config, resolvedCommand, valueStr, policy, {
          credentialFingerprint,
          configFingerprint,
        }),
      );
    } catch (err) {
      // A structured refusal from the outbound-request guards (SSRF, redirect
      // policy) keeps its own code — flattening it to a generic connect
      // failure would hide the security decision from the caller and audit.
      if (err instanceof VaultError) {
        this.audit(action, secretId, config, { error: err.code }, false);
        throw err;
      }
      const detail =
        err instanceof Error ? redactSecretEncodings(err.message, valueStr) : undefined;
      const vaultErr = VaultError.mcpConnectFailed(config.server_name, detail);
      this.audit(action, secretId, config, { error: vaultErr.code }, false);
      throw vaultErr;
    }

    const timeout = Math.min(action.timeout_ms ?? DEFAULT_MCP_TIMEOUT_MS, MAX_TIMEOUT_MS);
    let rawResult: { content?: unknown; structuredContent?: unknown; isError?: unknown };
    try {
      rawResult = (await entry.client.callTool(
        { name: action.tool, arguments: action.arguments ?? {} },
        sdk.CallToolResultSchema,
        { timeout },
      )) as { content?: unknown; structuredContent?: unknown; isError?: unknown };
    } catch (err) {
      const vaultErr = this.mapCallError(sdk, err, entry, config.server_name, valueStr);
      this.audit(action, secretId, config, { error: vaultErr.code }, false);
      throw vaultErr;
    }

    const result = this.sanitizeResult(rawResult, valueStr);
    this.audit(
      action,
      secretId,
      config,
      { is_error: result.is_error ?? false, truncated: result.truncated ?? false },
      true,
    );
    return result;
  }

  /** Factory for a fresh downstream connection — the only injection moment. */
  private async establish(
    sdk: McpSdk,
    secretId: string,
    config: McpServerConfig,
    resolvedCommand: string | undefined,
    valueStr: string,
    policy: InjectionPolicy,
    fingerprints: { credentialFingerprint: string; configFingerprint: string },
  ): Promise<McpConnectionEntry> {
    const client = new sdk.Client({ name: "harpoc-vault", version: VAULT_VERSION });

    let stdioTransport: StdioChildTransport | undefined;
    let dispose: (() => void) | undefined;
    if (config.transport === McpTransport.STDIO) {
      stdioTransport = new StdioChildTransport({
        resolvedCommand: resolvedCommand as string,
        args: config.args ?? [],
        env: buildCleanEnv(config.env_var as string, valueStr, policy.env_allowlist),
        cwd: config.working_directory,
      });
      await client.connect(stdioTransport, { timeout: MCP_INIT_TIMEOUT_MS });
    } else {
      // DNS-rebinding TOCTOU protection (parity with the HTTP injector): every
      // outbound request connects through a dispatcher whose connection-time
      // lookup serves only the addresses the per-request validateUrl approved.
      const pins = new Map<string, readonly string[]>();
      const dispatcher = new Agent({ connect: { lookup: createPinnedLookup(pins) } });
      dispose = (): void => void dispatcher.close().catch(() => undefined);
      const transport = new sdk.StreamableHTTPClientTransport(new URL(config.url as string), {
        fetch: this.validatingAuthFetch(valueStr, pins, dispatcher),
        reconnectionOptions: {
          // A lost connection must fail visibly (no-auto-respawn semantics),
          // not be silently re-established mid-call.
          maxRetries: 0,
          maxReconnectionDelay: 30_000,
          initialReconnectionDelay: 1_000,
          reconnectionDelayGrowFactor: 1.5,
        },
      });
      try {
        await client.connect(transport, { timeout: MCP_INIT_TIMEOUT_MS });
      } catch (err) {
        dispose();
        throw err;
      }
    }

    this.auditLogger?.log({
      eventType: "mcp.spawn",
      secretId,
      detail: {
        server: config.server_name,
        transport: config.transport,
        ...(config.transport === McpTransport.STDIO
          ? { command: config.command, pid: stdioTransport?.pid ?? null }
          : { url: config.url }),
      },
      success: true,
    });

    return {
      secretId,
      serverName: config.server_name,
      transportKind: config.transport,
      client,
      stdioTransport,
      dispose,
      state: "connecting",
      crashed: false,
      ...fingerprints,
      spawnedAt: Date.now(),
    };
  }

  /**
   * Every outbound request (POST send, GET stream, DELETE terminate) is
   * re-validated against SSRF rules, pinned at the socket layer to the
   * addresses that validation resolved (the driver-level lookup serves only
   * pinned addresses, closing the DNS-rebinding TOCTOU window), and carries
   * the bearer credential — injected here, never visible upstream. Redirects
   * are refused outright (fail closed): the downstream endpoint is
   * admin-configured and exact, and a followed hop would silently escape both
   * the URL allowlist and SSRF validation.
   */
  private validatingAuthFetch(
    valueStr: string,
    pins: Map<string, readonly string[]>,
    dispatcher: Agent,
  ): FetchLike {
    return async (url, init) => {
      const validated = await validateUrl(String(url));
      if (validated.resolvedAddresses) {
        pins.set(validated.url.hostname.toLowerCase(), validated.resolvedAddresses);
      }
      const headers = new Headers(init?.headers);
      headers.set("Authorization", `Bearer ${valueStr}`);
      const response = await undiciFetch(String(url), {
        ...(init as UndiciRequestInit | undefined),
        headers: [...headers.entries()],
        redirect: "manual",
        dispatcher,
      });
      if (response.status >= 300 && response.status < 400) {
        await response.body?.cancel().catch(() => undefined);
        throw new VaultError(
          ErrorCode.REDIRECT_POLICY_VIOLATION,
          `Downstream MCP server redirected (${response.status}); redirects are refused — configure the final endpoint URL`,
        );
      }
      return response as unknown as Response;
    };
  }

  /** Map SDK call failures to structured vault errors — never secret material. */
  private mapCallError(
    sdk: McpSdk,
    err: unknown,
    entry: McpConnectionEntry,
    server: string,
    valueStr: string,
  ): VaultError {
    if (err instanceof sdk.McpError) {
      if (err.code === (sdk.McpErrorCode.ConnectionClosed as number)) {
        if (entry.crashed) {
          const exit = entry.stdioTransport?.exitInfo ?? null;
          return VaultError.mcpServerCrashed(server, exit?.code ?? null, exit?.signal ?? null);
        }
        return VaultError.mcpConnectFailed(server, "connection closed");
      }
      if (err.code === (sdk.McpErrorCode.RequestTimeout as number)) {
        // A slow tool is not a crash: the server stays alive and the agent may retry.
        return VaultError.mcpTimeout(server);
      }
      return VaultError.mcpProtocolError(server, redactSecretEncodings(err.message, valueStr));
    }
    if (err instanceof VaultError) return err;
    const detail = err instanceof Error ? redactSecretEncodings(err.message, valueStr) : undefined;
    return VaultError.mcpProtocolError(server, detail);
  }

  /**
   * Redact the credential (raw + encodings) from every string leaf of the tool
   * result, then enforce the serialized size cap: structured_content is dropped
   * first, then trailing content blocks, with `truncated` flagged.
   */
  private sanitizeResult(
    raw: { content?: unknown; structuredContent?: unknown; isError?: unknown },
    valueStr: string,
  ): McpResult {
    const redact = (s: string): string => redactSecretEncodings(s, valueStr);

    const content = mapStringLeaves(
      Array.isArray(raw.content) ? raw.content : [],
      redact,
    ) as unknown[];
    const structuredContent =
      raw.structuredContent !== undefined && raw.structuredContent !== null
        ? (mapStringLeaves(raw.structuredContent, redact) as Record<string, unknown>)
        : undefined;

    const result: McpResult = {
      type: "mcp",
      content,
      ...(structuredContent !== undefined ? { structured_content: structuredContent } : {}),
      ...(raw.isError === true ? { is_error: true } : {}),
    };

    if (byteLength(result) > MAX_MCP_RESULT_BYTES) {
      result.truncated = true;
      delete result.structured_content;
      while (result.content.length > 0 && byteLength(result) > MAX_MCP_RESULT_BYTES) {
        result.content.pop();
      }
    }

    return result;
  }

  private audit(
    action: McpAction,
    secretId: string,
    config: McpServerConfig,
    detail: Record<string, unknown>,
    success: boolean,
  ): void {
    this.auditLogger?.log({
      eventType: "secret.use",
      secretId,
      detail: {
        context: "mcp",
        server: action.server,
        tool: action.tool,
        transport: config.transport,
        ...detail,
      },
      success,
    });
  }
}

function sha256Hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

function byteLength(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value), "utf8");
}
