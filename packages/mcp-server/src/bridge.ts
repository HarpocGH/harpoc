import { McpServer, ResourceTemplate } from "@modelcontextprotocol/server";
import { RestClient } from "@harpoc/sdk";
import type { VaultClient } from "@harpoc/sdk";
import { ErrorCode, HARPOC_VERSION, VaultError, formatHandle, parseHandle } from "@harpoc/shared";
import { readLaunchTokenFile } from "./cli-options.js";
import { decodeHandlePath } from "./resources/secrets.js";
import {
  CHECK_SECRET_HEALTH_TOOL,
  CREATE_SECRET_TOOL,
  GET_SECRET_INFO_TOOL,
  LIST_SECRETS_TOOL,
  RENEW_CERTIFICATE_TOOL,
  REVOKE_SECRET_TOOL,
  ROTATE_SECRET_TOOL,
  START_OAUTH_FLOW_TOOL,
  USE_SECRET_TOOL,
} from "./tools/definitions.js";

const EXPIRING_SOON_DAYS = 7;

export interface CreateBridgeServerOptions {
  /**
   * The REST client for one call — invoked once per tool or resource call, so
   * a token file rewritten by the issuer-side rotation is read on every request.
   */
  client: () => VaultClient;
  /** The REST base URL, named when the server cannot be reached (never a credential). */
  baseUrl: string;
}

function text(payload: unknown): { content: [{ type: "text"; text: string }] } {
  return { content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }] };
}

function json(
  uri: URL,
  payload: unknown,
): { contents: [{ uri: string; mimeType: string; text: string }] } {
  return {
    contents: [
      { uri: uri.href, mimeType: "application/json", text: JSON.stringify(payload, null, 2) },
    ],
  };
}

/**
 * The bridge never collects a value: it runs under the agent's identity, where
 * a collected credential would be plaintext in the agent's process (design
 * § 2, model B). The tools that need one name the vault-user command instead.
 */
function notOverTheBridge(detail: string): VaultError {
  return new VaultError(ErrorCode.REST_MODE_UNSUPPORTED, detail);
}

function summarize(
  secrets: ReadonlyArray<{ handle: string; status: string; expiresAt: number | null }>,
): {
  byStatus: Record<string, number>;
  expiringSoon: Array<{ handle: string; expires_at: number }>;
} {
  const byStatus: Record<string, number> = {};
  const expiringSoon: Array<{ handle: string; expires_at: number }> = [];
  const threshold = Date.now() + EXPIRING_SOON_DAYS * 24 * 60 * 60 * 1000;
  for (const s of secrets) {
    byStatus[s.status] = (byStatus[s.status] ?? 0) + 1;
    if (s.expiresAt && s.expiresAt <= threshold && s.status === "active") {
      expiringSoon.push({ handle: s.handle, expires_at: s.expiresAt });
    }
  }
  return { byStatus, expiringSoon };
}

/**
 * `harpoc-mcp --url`'s server: the in-process server's nine tools and four
 * resources, registered from the same definitions, each handler forwarding to
 * the REST API through `VaultClient` — no engine, no launch gate, no scope
 * guard and no rate limiter of its own: the REST server authenticates, scopes,
 * rate-limits and audits every request, and sanitizes every `use` result
 * (`rest-api/src/routes/secrets.ts`).
 */
export function createBridgeServer(options: CreateBridgeServerOptions): McpServer {
  const forward = async <T>(run: (client: VaultClient) => Promise<T>): Promise<T> => {
    const client = options.client();
    try {
      return await run(client);
    } catch (err) {
      if (err instanceof VaultError) throw err;
      // `RestClient` re-throws fetch's own failure (`fetch failed`) unwrapped.
      throw new VaultError(
        ErrorCode.CONNECTION_REFUSED,
        `Harpoc REST server unreachable: ${options.baseUrl}`,
      );
    }
  };

  const server = new McpServer(
    { name: "harpoc", version: HARPOC_VERSION },
    {
      capabilities: {
        tools: { listChanged: false },
        resources: { subscribe: false, listChanged: false },
      },
    },
  );

  server.registerTool(LIST_SECRETS_TOOL.name, LIST_SECRETS_TOOL.config, async (args) => {
    let secrets = await forward((client) => client.listSecrets(args.project));
    if (args.type) {
      secrets = secrets.filter((s) => s.type === args.type);
    }
    if (args.status) {
      secrets = secrets.filter((s) => s.status === args.status);
    }
    return text(
      secrets.map((s) => ({
        handle: s.handle,
        name: s.name,
        type: s.type,
        project: s.project,
        status: s.status,
        version: s.version,
        created_at: s.createdAt,
        updated_at: s.updatedAt,
        expires_at: s.expiresAt,
      })),
    );
  });

  server.registerTool(GET_SECRET_INFO_TOOL.name, GET_SECRET_INFO_TOOL.config, async (args) => {
    parseHandle(args.handle);
    const info = await forward((client) => client.getSecretInfo(args.handle));
    return text({
      handle: info.handle,
      name: info.name,
      type: info.type,
      project: info.project,
      status: info.status,
      version: info.version,
      created_at: info.createdAt,
      updated_at: info.updatedAt,
      expires_at: info.expiresAt,
      rotated_at: info.rotatedAt,
    });
  });

  server.registerTool(USE_SECRET_TOOL.name, USE_SECRET_TOOL.config, async (args) => {
    parseHandle(args.handle);
    return text(await forward((client) => client.useSecret(args.handle, args.action)));
  });

  server.registerTool(CREATE_SECRET_TOOL.name, CREATE_SECRET_TOOL.config, async (args) => {
    // Created without a value — the in-process server's deferred path; the
    // value is set by the vault user (`harpoc secret set`).
    const result = await forward((client) =>
      client.createSecret({ name: args.name, type: args.type, project: args.project }),
    );
    const message =
      result.status === "pending"
        ? `Secret created. Set the value with: harpoc secret set ${args.name}`
        : result.message;
    return text({ handle: result.handle, status: result.status, message });
  });

  server.registerTool(ROTATE_SECRET_TOOL.name, ROTATE_SECRET_TOOL.config, async (args) => {
    parseHandle(args.handle);
    throw notOverTheBridge(
      `rotate_secret is not available through the REST bridge: the new value would pass through the agent's process. Rotate it as the vault user: harpoc secret rotate ${args.handle}`,
    );
  });

  server.registerTool(REVOKE_SECRET_TOOL.name, REVOKE_SECRET_TOOL.config, async (args) => {
    parseHandle(args.handle);
    await forward((client) => client.revokeSecret(args.handle));
    return text({
      handle: args.handle,
      status: "revoked",
      message: "Secret has been permanently revoked",
    });
  });

  server.registerTool(
    CHECK_SECRET_HEALTH_TOOL.name,
    CHECK_SECRET_HEALTH_TOOL.config,
    async (args) => {
      // One call at a time: a refused first call is the one access.denied row.
      const secrets = await forward((client) => client.listSecrets());
      const report = await forward((client) => client.getExpiringReport());
      const health = await forward((client) => client.getHealth());
      const filtered = args.handle ? secrets.filter((s) => s.handle === args.handle) : secrets;
      const { byStatus, expiringSoon } = summarize(filtered);
      return text({
        vault_state: health.state,
        total_secrets: filtered.length,
        by_status: byStatus,
        expiring_soon: expiringSoon,
        oauth_refresh_needed: args.handle
          ? report.oauth_refresh_needed.filter((i) => i.handle === args.handle)
          : report.oauth_refresh_needed,
        certificates_nearing_renewal: args.handle
          ? report.certificates_nearing_renewal.filter((i) => i.handle === args.handle)
          : report.certificates_nearing_renewal,
      });
    },
  );

  server.registerTool(START_OAUTH_FLOW_TOOL.name, START_OAUTH_FLOW_TOOL.config, async (args) => {
    if (args.grant_type === "device_code") {
      // The REST route runs the same shared arm (`startOAuthFlowResult`) in
      // the vault's process, which polls and completes in the background.
      return text(await forward((client) => client.startOAuthFlow({ ...args })));
    }
    const command =
      args.grant_type === "client_credentials"
        ? `harpoc oauth connect ${args.name} --client-credentials --provider ${args.provider} --client-id ${args.client_id}`
        : `harpoc oauth connect ${args.name} --provider ${args.provider} --client-id ${args.client_id}`;
    throw notOverTheBridge(
      `start_oauth_flow's ${args.grant_type} grant is not available through the REST bridge. Complete it as the vault user: ${command}`,
    );
  });

  server.registerTool(RENEW_CERTIFICATE_TOOL.name, RENEW_CERTIFICATE_TOOL.config, async (args) => {
    parseHandle(args.handle);
    return text(await forward((client) => client.renewCertificate(args.handle)));
  });

  server.registerResource(
    "secrets-list",
    "secret://vault/secrets",
    {
      description: "List of all secret handles with metadata (never values)",
      mimeType: "application/json",
    },
    async (uri) => {
      const secrets = await forward((client) => client.listSecrets());
      return json(
        uri,
        secrets.map((s) => ({
          handle: s.handle,
          name: s.name,
          type: s.type,
          project: s.project,
          status: s.status,
          version: s.version,
        })),
      );
    },
  );

  server.registerResource(
    "secret-by-name",
    new ResourceTemplate("secret://vault/secrets/{name}", {
      list: async () => {
        const secrets = await forward((client) => client.listSecrets());
        return {
          resources: secrets.map((s) => {
            const path = s.handle.slice("secret://".length);
            return {
              uri: `secret://vault/secrets/${encodeURIComponent(path)}`,
              name: s.name,
              description: `Secret: ${path} (${s.type}, ${s.status})`,
              mimeType: "application/json",
            };
          }),
        };
      },
    }),
    {
      description: "Metadata for a specific secret (never the value)",
      mimeType: "application/json",
    },
    async (uri, variables) => {
      const { project, name } = parseHandle(
        `secret://${decodeHandlePath(variables.name as string)}`,
      );
      const secret = await forward((client) => client.getSecretInfo(formatHandle(name, project)));
      return json(uri, {
        handle: secret.handle,
        name: secret.name,
        type: secret.type,
        project: secret.project,
        status: secret.status,
        version: secret.version,
        created_at: secret.createdAt,
        updated_at: secret.updatedAt,
        expires_at: secret.expiresAt,
        rotated_at: secret.rotatedAt,
      });
    },
  );

  server.registerResource(
    "vault-health",
    "secret://vault/health",
    { description: "Vault state and secret health summary", mimeType: "application/json" },
    async (uri) => {
      const secrets = await forward((client) => client.listSecrets());
      const health = await forward((client) => client.getHealth());
      const { byStatus, expiringSoon } = summarize(secrets);
      return json(uri, {
        vault_state: health.state,
        total_secrets: secrets.length,
        by_status: byStatus,
        expiring_soon: expiringSoon,
      });
    },
  );

  server.registerResource(
    "audit-recent",
    "secret://vault/audit/recent",
    { description: "Last 50 audit log entries (metadata only)", mimeType: "application/json" },
    async (uri) => {
      const events = await forward((client) => client.queryAudit({ limit: 50 }));
      return json(
        uri,
        events.map((e) => ({
          id: e.id,
          timestamp: e.timestamp,
          event_type: e.event_type,
          secret_id: e.secret_id,
          principal_type: e.principal_type,
          principal_id: e.principal_id,
          success: e.success,
          detail: e.detail,
        })),
      );
    },
  );

  server.registerResource(
    "projects",
    "secret://vault/projects",
    { description: "Distinct projects with secret counts", mimeType: "application/json" },
    async (uri) => {
      const secrets = await forward((client) => client.listSecrets());
      const counts = new Map<string, number>();
      for (const s of secrets) {
        const project = s.project ?? "(none)";
        counts.set(project, (counts.get(project) ?? 0) + 1);
      }
      return json(
        uri,
        Array.from(counts.entries()).map(([project, count]) => ({ project, secret_count: count })),
      );
    },
  );

  return server;
}

/**
 * The bridge's client for `--token-file <path>`: the file is re-read for every
 * call, so a token the issuer rewrote in place (write temp + rename) is the one
 * sent; a file that can no longer be read refuses the call by path, never by
 * content.
 */
export function restClientFromTokenFile(baseUrl: string, tokenFile: string): () => VaultClient {
  return () => {
    const read = readLaunchTokenFile(tokenFile);
    if (!read.ok) {
      throw new VaultError(ErrorCode.FILE_IO_ERROR, read.message.replace(/^Error: /, "").trim());
    }
    return new RestClient({ baseUrl, token: read.token });
  };
}
