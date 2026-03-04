# Harpoc

Secure secret management for LLMs and AI agents. Secrets are encrypted at rest, never exposed to the model — only injected at the execution layer via opaque `secret://` handles.

## Why

The MCP specification has no built-in credential management. In practice, 79% of MCP servers pass credentials via environment variables and 48% recommend `.env` files. Harpoc solves this with a zero-knowledge vault where the LLM never sees raw credentials — it only references opaque handles like `secret://github-token`, and the vault injects credentials into HTTP requests at execution time.

## Features

- **Zero-knowledge to LLM** — models see `secret://` handles, never raw values
- **Encrypted at rest** — AES-256-GCM with Argon2id key derivation, 3-tier key hierarchy (master → KEK → per-secret DEK)
- **MCP-native** — first-class MCP server (`harpoc-mcp`) for Claude, GPT, and any MCP-capable client
- **HTTP secret injection** — bearer tokens, custom headers, query parameters, basic auth — injected at fetch time with SSRF prevention
- **Audit trail** — every vault operation logged, detail fields encrypted at rest
- **Access control** — per-secret policies with scoped permissions
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
            │  ├── HttpInjector (secret injection, SSRF prevention)
            │  ├── PolicyEngine (per-secret access control)
            │  ├── AuditLogger (encrypted audit trail)
            │  └── SessionManager (JWT auth, sliding window TTL)
            │
Storage     SQLite (WAL mode, encrypted payloads)
```

## Packages

| Package | Description | Status |
|---------|-------------|--------|
| `@harpoc/shared` | Types, Zod schemas, error codes, constants | Complete |
| `@harpoc/core` | VaultEngine, crypto, storage, secrets, audit, access control | Complete |
| `@harpoc/cli` | `harpoc` CLI (Commander.js) | Complete |
| `@harpoc/mcp-server` | MCP tools, resources, guards (stdio transport) | Complete |
| `@harpoc/rest-api` | Hono HTTP API, JWT auth, rate limiting, audit middleware | Complete |
| `@harpoc/sdk` | TypeScript client (REST + in-process modes) | Complete |

## Quick Start

**Prerequisites:** Node.js 22+, pnpm 10+

```bash
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

Add to your **Claude Desktop** config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows) or **Claude Code** config (`.mcp.json` in project root):

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

See [`docs/examples/`](../docs/examples/) for full configuration examples with vault directory and token options.

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
- **SSRF prevention**: private IP blocking (RFC 1918, link-local, IPv4-mapped IPv6), DNS rebinding protection via pre-flight DNS resolution, HTTPS enforcement, redirect validation with credential stripping on cross-origin hops.
- **Secret names encrypted** with vault-level KEK — database inspection reveals nothing about stored services. HMAC-SHA256 name index enables O(1) handle resolution without decrypting all names.
- **Lazy secret expiry**: secrets with an `expires_at` timestamp are checked on access and automatically transitioned to expired status.
- **JWT sessions** with sliding window TTL (15 min default, 24 h maximum), store-based token revocation with automatic pruning of expired entries.

## Roadmap

| Version | Scope |
|---------|-------|
| **v1.0** | Core vault + MCP + REST + SDK + CLI. API keys and static tokens. Local single-user. HTTP-only injection. |
| **v1.1** | OAuth 2.1 proxy (PKCE, provider presets, auto-refresh). Certificate lifecycle (ACME). |
| **v2.0** | Cloud sync (vector clocks, conflict resolution). Team vaults (Shamir's Secret Sharing). |
| **v2.1+** | Non-HTTP injection: database connection strings, SSH key agent, SMTP, WebSocket auth. |

## Tech Stack

TypeScript (strict mode, ESM-only) · pnpm + Turborepo · SQLite (better-sqlite3, WAL mode) · AES-256-GCM + Argon2id (`node:crypto` + `argon2`) · Zod · Vitest

## License

[BSL 1.1](LICENSE) — code is publicly visible and auditable. Commercial use as a hosted service is restricted. Each release converts to Apache 2.0 after 3 years.
