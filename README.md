# Harpoc

Secure secret management for LLMs and AI agents. Secrets are encrypted at rest, never exposed to the model — only injected at the execution layer via opaque `secret://` handles.

## Why

The MCP specification has no built-in credential management. In practice, 79% of MCP servers pass credentials via environment variables and 48% recommend `.env` files. Harpoc solves this with a zero-knowledge vault where the LLM never sees raw credentials — it only references opaque handles like `secret://github-token`, and the vault injects credentials at execution time — into an HTTP request, a subprocess environment, a downstream MCP server, a database connection, or a Git/SSH invocation — never exposing them to the model.

## Features

- **Zero-knowledge to LLM** — models see `secret://` handles, never raw values
- **Encrypted at rest** — AES-256-GCM with Argon2id key derivation, 3-tier key hierarchy (master → KEK → per-secret DEK)
- **MCP-native** — first-class MCP server (`harpoc-mcp`) over stdio and Streamable HTTP, for Claude, GPT, and any MCP-capable client
- **HTTP secret injection** — bearer tokens, custom headers, query parameters, basic auth — injected at fetch time with SSRF prevention, optional per-secret URL allowlisting, and response shaping (`response_mode`: `full` / `filtered` / `status_only`)
- **Process secret injection** — run a command with the credential in its environment: no shell, clean environment, output sanitization, fail-safe per-secret command allowlisting, an acknowledgement gate for interpreter binaries, and opt-in per-secret network isolation (the spawned child gets no network, loopback included — Linux `unshare`, macOS `sandbox-exec`; unsupported platforms refuse fail-closed)
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

| Package               | Description                                                                                                                                                     | Status   |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| `@harpoc/shared`      | Types, Zod schemas, error codes, constants                                                                                                                      | Complete |
| `@harpoc/core`        | VaultEngine, crypto, storage, secrets, audit, access control, six-context injection (HTTP, process, MCP, database, Git, SSH)                                    | Complete |
| `@harpoc/cli`         | `harpoc` CLI (Commander.js)                                                                                                                                     | Complete |
| `@harpoc/mcp-server`  | MCP tools, resources, guards (stdio + Streamable HTTP transports)                                                                                               | Complete |
| `@harpoc/rest-api`    | Hono HTTP API, JWT auth, rate limiting, audit middleware                                                                                                        | Complete |
| `@harpoc/sdk`         | TypeScript client (REST + in-process modes)                                                                                                                     | Complete |
| `@harpoc/oauth-proxy` | OAuth 2.1 proxy — PKCE, provider presets, callback server, token refresh scheduler (CLI: `harpoc oauth connect/status/refresh`, `server start --oauth-refresh`) | Complete |
| `@harpoc/integration` | Cross-package integration tests                                                                                                                                 | Complete |

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

The client secret is never passed via argv: set `HARPOC_OAUTH_CLIENT_SECRET` or enter it at the hidden prompt (leave empty for a public client). The token-endpoint auth method chosen at connect time (`--auth-method client_secret_basic` sends credentials in the `Authorization` header, never the request body) is stored with the secret and honored by every later refresh. Inspect and maintain tokens with `harpoc oauth status <handle>` and `harpoc oauth refresh <handle>`, or refresh them continuously in a long-lived server:

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
- **Per-secret access policies, enforced at the engine**: stored policy rows grant permissions (`read`, `use`, `rotate`, `revoke`, or `admin` implying all) to principals — an agent, tool or user (the token's subject under its issued `principal_type`, default agent), or a project (derived from the token's `project` claim). Enforcement is presence-gated restriction: a secret with at least one active policy row requires the token-derived caller to hold a matching grant — checked inside the engine on every credential operation, before anything is decrypted or injected — while a secret with no rows stays governed by token scope alone. Denials are audited under the requesting principal. The trusted admin path (CLI, in-process SDK, tokenless stdio MCP) authenticates via master password/session file and is not subject to per-secret policies, mirroring the administration-versus-operation split.
- **Injection allowlisting** (per-secret, KEK-encrypted): a URL allowlist bounds request-mediated targets (optional; re-validated on each redirect hop), a command allowlist bounds process-mediated binaries (fail-safe deny, pinned to a resolved absolute path; known interpreter binaries like `sh`, `python`, `node` require explicit acknowledgement), and a host allowlist bounds database/SSH/Git targets (fail-safe for SSH and Git-over-SSH). Endpoint authentication is pinned per secret: database TLS/CA policy and SSH host keys. Process execution spawns with no shell, a clean environment, and best-effort output sanitization of the credential and its common encodings.
- **Ephemeral in-process ssh-agent** (SSH and Git-over-SSH): the private key is parsed in memory and served over the OpenSSH agent protocol on a per-invocation socket — only signatures cross it, and the private key never touches disk. The identity's _public_ line is written to a per-invocation 0600 temp file and passed as ssh's IdentityFile: under `IdentitiesOnly=yes` ssh offers only file-backed identities, so this file is what makes the agent-held key eligible at all — and it drops the default `~/.ssh/id_*` candidates, so ssh offers exactly the vault identity, never the host user's ambient keys. On Windows the agent listens on a named pipe that only the **native Win32-OpenSSH client** consumes — pin `C:\Windows\System32\OpenSSH\ssh.exe` in the command allowlist; an MSYS build (e.g. the Git-bundled `ssh`) silently finds no agent.
- **HTTP response shaping**: a per-secret `response_mode` (`full` / `filtered` / `status_only`, default `filtered`) bounds what an HTTP invocation returns; `status_only` never reads the response body, and per-invocation overrides may only tighten the policy, never loosen it.
- **Network isolation** (opt-in, per-secret `network_isolation`): every child process spawned with the secret — process, Git and SSH contexts — runs without network access, loopback included (the vault's own listeners live there). Linux: `unshare -rn` (unprivileged user + network namespaces); macOS: `sandbox-exec` with a constant deny-network profile (deprecated by Apple but functional; availability is probed live and a failed probe refuses rather than degrades — only a successful probe is cached, so a transient failure re-probes on the next use); Windows: **unsupported by design** (real isolation needs an AppContainer native addon) — a policy demanding isolation refuses every process-mediated use there, fail-closed with an audited `NETWORK_ISOLATION_UNAVAILABLE`, never silently un-isolated. The isolation prefix is vault-authored and applied after command-allowlist resolution; there is no environment-variable opt-out — only the admin path (`secret allow --no-network-isolation`) removes the requirement. Setting the flag also terminates any live stdio MCP downstream child already holding the secret (audited `mcp.terminate`), and stdio MCP invocations under the flag are refused until that transport can be isolated. Note the honest limit: isolation blocks the child's own sockets; a child can still drop the value into a file that a cooperating other process exfiltrates later. Enabling isolation on an SSH/Git secret makes those actions fail at connect — the remote host is unreachable from inside the namespace by definition — so the flag is primarily for process-context secrets whose commands need no egress. Ubuntu 24.04+ restricts unprivileged user namespaces via AppArmor out of the box (`kernel.apparmor_restrict_unprivileged_userns = 1`) — the probe then fails and isolation-demanding uses are refused until the restriction is relaxed (`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`) or an AppArmor profile grants `userns`.
- **Tamper-evident audit log**: detail fields are encrypted and bound to their row, and rows are HMAC-chained — `harpoc audit verify` detects modification or deletion. Every vault mutation commits in the same SQLite transaction as its audit entry, so a crash cannot leave a completed-but-unaudited operation and an unwritable audit log blocks the mutation (fail-closed). Deleting the newest rows leaves a valid shorter chain, so `harpoc audit anchor` exports the tail link for comparison with `verify --anchor` — the anchor must be stored **off-host** (another machine, a sync target, or paper); the vault cannot supply that independent trust domain itself.
- **Session-file protection**: the session key is wrapped at rest with an OS-user-bound key store — DPAPI on Windows, the Keychain on macOS, Secret Service or the kernel keyring on Linux (desktop/headless tiers; kernel-keyring keys die at reboot, forcing a fresh unlock) — so a session file copied off the host is inert. Reads fail closed on tampering, a foreign user, or a scheme mismatch; a write-time keystore failure falls back to file permissions with a CLI warning; `HARPOC_SESSION_KEYSTORE=off` opts out. The session file is created owner-only (0600) on POSIX either way.
- **Secret names encrypted** with vault-level KEK — database inspection reveals nothing about stored services. HMAC-SHA256 name index enables O(1) handle resolution without decrypting all names.
- **Lazy secret expiry**: secrets with an `expires_at` timestamp are checked on access and automatically transitioned to expired status.
- **JWT sessions** with sliding window TTL (15 min default, 24 h maximum), store-based token revocation with automatic pruning of expired entries.

## Tech Stack

TypeScript (strict mode, ESM-only) · pnpm + Turborepo · SQLite (better-sqlite3, WAL mode) · AES-256-GCM + Argon2id (`node:crypto` + `argon2`) · Zod · undici · `@modelcontextprotocol/sdk` · pg / mysql2 (lazy-loaded) · Vitest

## License

[BSL 1.1](LICENSE) — code is publicly visible and auditable. Commercial use as a hosted service is restricted. Each release converts to Apache 2.0 after 3 years.
