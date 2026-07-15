# Harpoc

Secure secret management for LLMs and AI agents. Secrets are encrypted at rest, never exposed to the model — only injected at the execution layer via opaque `secret://` handles.

## Why

The MCP specification has no built-in credential management. In practice, 79% of MCP servers pass credentials via environment variables and 48% recommend `.env` files. Harpoc solves this with a zero-knowledge vault where the LLM never sees raw credentials — it only references opaque handles like `secret://github-token`, and the vault injects credentials at execution time — into an HTTP request, a subprocess environment, a downstream MCP server, a database connection, or a Git/SSH invocation — never exposing them to the model.

## Features

- **Zero-knowledge to LLM** — models see `secret://` handles, never raw values
- **Encrypted at rest** — AES-256-GCM with Argon2id key derivation, 3-tier key hierarchy (master → KEK → per-secret DEK)
- **MCP-native** — first-class MCP server (`harpoc-mcp`) over stdio and Streamable HTTP, for Claude, GPT, and any MCP-capable client
- **HTTP secret injection** — bearer tokens, custom headers, query parameters, basic auth — injected at fetch time with SSRF prevention, optional per-secret URL allowlisting, and response shaping (`response_mode`: `full` / `filtered` / `status_only`)
- **Process secret injection** — run a command with the credential in its environment: no shell, clean environment, output sanitization, fail-safe per-secret command allowlisting, and an acknowledgement gate for interpreter binaries
- **MCP proxy injection** — forward a tool call to a downstream MCP server that the vault spawns (stdio) or reaches over HTTP, authenticating it with the credential
- **Database, Git & SSH injection** — in-vault PostgreSQL/MySQL connections (TLS by default), Git over HTTPS or SSH, and SSH sessions via an in-process ephemeral key agent — the private key never touches disk
- **Audit trail** — every vault operation logged, detail fields encrypted at rest, rows HMAC-chained (`harpoc audit verify`); `harpoc audit anchor` exports the chain tail for off-host storage so tail truncation and rollback are detectable (`verify --anchor`)
- **Access control** — per-secret policies and scoped tokens with wildcard secret-name patterns
- **Multiple interfaces** — MCP server, REST API, TypeScript SDK, CLI

## Architecture

```
Consumer    MCP Host  ·  REST Client  ·  SDK  ·  CLI
               │             │           │       │
Interface   MCP Server · REST API  ·   SDK  ·  CLI
               │             │           │       │
Core        ┌──┴─────────────┴───────────┴───────┘
            │  VaultEngine
            │  ├── Crypto (AES-256-GCM, Argon2id, HKDF, key hierarchy)
            │  ├── SecretManager (CRUD, rotation, handle resolution)
            │  ├── Injectors: HTTP · Process · MCP proxy · Database · Git · SSH
            │  │   (SSRF prevention, URL/command/host allowlists, output sanitization,
            │  │    response shaping, in-process ephemeral ssh-agent)
            │  ├── PolicyEngine (per-secret access control)
            │  ├── AuditLogger (encrypted audit trail)
            │  └── SessionManager (JWT auth, sliding window TTL)
            │
Storage     SQLite (WAL mode, encrypted payloads)
```

## Packages

| Package              | Description                                                  | Status   |
| -------------------- | ------------------------------------------------------------ | -------- |
| `@harpoc/shared`     | Types, Zod schemas, error codes, constants                   | Complete |
| `@harpoc/core`       | VaultEngine, crypto, storage, secrets, audit, access control, six-context injection (HTTP, process, MCP, database, Git, SSH) | Complete |
| `@harpoc/cli`        | `harpoc` CLI (Commander.js)                                  | Complete |
| `@harpoc/mcp-server` | MCP tools, resources, guards (stdio + Streamable HTTP transports) | Complete |
| `@harpoc/rest-api`   | Hono HTTP API, JWT auth, rate limiting, audit middleware     | Complete |
| `@harpoc/sdk`        | TypeScript client (REST + in-process modes)                  | Complete |
| `@harpoc/oauth-proxy` | OAuth 2.1 proxy — PKCE, provider presets, callback server, token refresh scheduler (CLI: `harpoc oauth connect/status/refresh`, `server start --oauth-refresh`) | Complete |
| `@harpoc/integration` | Cross-package integration tests                             | Complete |

## Quick Start

**Prerequisites:** Node.js 22+, pnpm 10+

```bash
git clone https://github.com/HarpocGH/harpoc.git
cd harpoc
pnpm install
pnpm build
pnpm test
```

## MCP Configuration

To use Harpoc as an MCP server with Claude Desktop or Claude Code:

```bash
# 1. Initialize and unlock a vault
npx harpoc init
npx harpoc unlock

# 2. Add a secret
npx harpoc secret set MY_API_KEY

# 3. Generate a scoped launch token
npx harpoc auth token --scope list,read,use --agent claude --ttl 480

# 4. Start the MCP server
npx harpoc server start --mcp --token <YOUR_TOKEN>
```

Add to your **Claude Desktop** config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows) or **Claude Code** config (`.mcp.json` in the project root, or `claude mcp add --scope user` for user-wide registration):

```json
{
  "mcpServers": {
    "harpoc": {
      "command": "npx",
      "args": ["harpoc", "server", "start", "--mcp", "--token", "<YOUR_TOKEN>"]
    }
  }
}
```

Prefer passing the token via the `HARPOC_TOKEN` environment variable instead of argv — command lines are visible to every local process (an explicit `--token` flag wins if both are set):

```json
{
  "mcpServers": {
    "harpoc": {
      "command": "npx",
      "args": ["harpoc", "server", "start", "--mcp"],
      "env": { "HARPOC_TOKEN": "<YOUR_TOKEN>" }
    }
  }
}
```

### Minimal Configuration (no token)

```json
{
  "mcpServers": {
    "harpoc": {
      "command": "npx",
      "args": ["harpoc", "server", "start", "--mcp"]
    }
  }
}
```

### Custom Vault Directory

By default, Harpoc looks for a `.harpoc` directory in the current working directory, then in `~/.harpoc`. To use a vault in a different location:

```json
{
  "mcpServers": {
    "harpoc": {
      "command": "npx",
      "args": ["harpoc", "server", "start", "--mcp", "--vault-dir", "/path/to/.harpoc"]
    }
  }
}
```

### Streamable HTTP Transport

For clients that connect to a URL instead of spawning a process:

```bash
npx harpoc server start --mcp-http --mcp-http-port 3001
```

The endpoint is `http://127.0.0.1:3001/mcp`. Every request requires a vault-issued JWT (`Authorization: Bearer`) — there is no tokenless mode over HTTP.

### Launch Token Options

A launch token restricts what the MCP server can do — which permissions, secrets, and project scope are available:

```bash
npx harpoc auth token \
  --scope list,read,use \
  --agent claude \
  --project my-project \
  --secrets "api-*,DB_PASSWORD" \
  --ttl 480
```

Flags:

- `--scope` — Comma-separated permissions: `list`, `read`, `use`, `create`, `rotate`, `revoke`, `admin`
- `--agent` — Agent name (sets JWT subject)
- `--project` — Project scope
- `--secrets` — Comma-separated secret-name patterns the token can access (`*` wildcards, e.g. `db-*`; full-anchored, case-sensitive)
- `--ttl` — Token lifetime in minutes (default: 60)

## OAuth Secrets

Connect an OAuth provider interactively — the vault runs the flow and stores the tokens; the agent only ever sees the `secret://` handle:

```bash
# Authorization code + PKCE (prints the authorization URL; --open also launches the browser)
npx harpoc oauth connect github-token --provider github --client-id <CLIENT_ID>

# Headless device-code flow
npx harpoc oauth connect gh-headless --provider github --client-id <CLIENT_ID> --device

# Machine-to-machine client credentials
npx harpoc oauth connect m2m-token --provider custom --client-id <CLIENT_ID> \
  --token-endpoint https://auth.example.com/token --client-credentials
```

The client secret is never passed via argv: set `HARPOC_OAUTH_CLIENT_SECRET` or enter it at the hidden prompt (leave empty for a public client). Inspect and maintain tokens with `harpoc oauth status <handle>` and `harpoc oauth refresh <handle>`, or refresh them continuously in a long-lived server:

```bash
npx harpoc server start --rest --oauth-refresh   # or --oauth-refresh alone as a refresh daemon
```

## Development

```bash
pnpm build           # Build all packages (Turborepo)
pnpm test            # Run all tests
pnpm lint            # Lint all packages
pnpm format:check    # Check formatting
pnpm format          # Fix formatting
```

## Security Model

- **3-tier key hierarchy**: password → master key (Argon2id) → KEK (AES-256-GCM key wrap) → per-secret DEK (random). JWT and audit keys are independently generated and wrapped with the KEK. Password change is O(1) — only re-wraps the KEK; all other keys remain unchanged.
- **AES-256-GCM** with authenticated additional data (AAD) binding per secret ID, preventing ciphertext substitution.
- **Argon2id** with OWASP-recommended parameters (64 MB memory, 3 iterations, 4 parallelism).
- **Password validation**: minimum 8-character length enforced on vault creation and password change.
- **SSRF prevention**: private IP blocking (RFC 1918, link-local, IPv4-mapped IPv6), DNS rebinding protection via pre-flight resolution with socket-level IP pinning, HTTPS enforcement, redirect validation with credential stripping on cross-origin hops and per-hop URL-allowlist re-validation.
- **Injection allowlisting** (per-secret, KEK-encrypted): a URL allowlist bounds request-mediated targets (optional; re-validated on each redirect hop), a command allowlist bounds process-mediated binaries (fail-safe deny, pinned to a resolved absolute path; known interpreter binaries like `sh`, `python`, `node` require explicit acknowledgement), and a host allowlist bounds database/SSH/Git targets (fail-safe for SSH and Git-over-SSH). Endpoint authentication is pinned per secret: database TLS/CA policy and SSH host keys. Process execution spawns with no shell, a clean environment, and best-effort output sanitization of the credential and its common encodings.
- **HTTP response shaping**: a per-secret `response_mode` (`full` / `filtered` / `status_only`, default `filtered`) bounds what an HTTP invocation returns; `status_only` never reads the response body, and per-invocation overrides may only tighten the policy, never loosen it.
- **Tamper-evident audit log**: detail fields are encrypted and bound to their row, and rows are HMAC-chained — `harpoc audit verify` detects modification or deletion. Deleting the newest rows leaves a valid shorter chain, so `harpoc audit anchor` exports the tail link for comparison with `verify --anchor` — the anchor must be stored **off-host** (another machine, a sync target, or paper); the vault cannot supply that independent trust domain itself.
- **Session-file protection**: the session key is DPAPI-wrapped at rest on Windows (fail-closed reads; `HARPOC_SESSION_KEYSTORE=off` opts out), and the session file is created owner-only (0600) on POSIX.
- **Secret names encrypted** with vault-level KEK — database inspection reveals nothing about stored services. HMAC-SHA256 name index enables O(1) handle resolution without decrypting all names.
- **Lazy secret expiry**: secrets with an `expires_at` timestamp are checked on access and automatically transitioned to expired status.
- **JWT sessions** with sliding window TTL (15 min default, 24 h maximum), store-based token revocation with automatic pruning of expired entries.

## Tech Stack

TypeScript (strict mode, ESM-only) · pnpm + Turborepo · SQLite (better-sqlite3, WAL mode) · AES-256-GCM + Argon2id (`node:crypto` + `argon2`) · Zod · undici · `@modelcontextprotocol/sdk` · pg / mysql2 (lazy-loaded) · Vitest

## License

[BSL 1.1](LICENSE) — code is publicly visible and auditable. Commercial use as a hosted service is restricted. Each release converts to Apache 2.0 after 3 years.
