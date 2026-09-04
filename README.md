# Harpoc

Secure secret management for LLMs and AI agents. Secrets are encrypted at rest, never exposed to the model — only injected at the execution layer via opaque `secret://` handles.

## Why

The MCP specification has no built-in credential management. In practice, 79% of MCP servers pass credentials via environment variables and 48% recommend `.env` files. Harpoc solves this with a zero-knowledge vault where the LLM never sees raw credentials — it only references opaque handles like `secret://github-token`, and the vault injects credentials at execution time — into an HTTP request, a subprocess environment, a downstream MCP server, a database connection, or a Git/SSH invocation — never exposing them to the model.

## Features

- **Zero-knowledge to LLM** — models see `secret://` handles, never raw values
- **Encrypted at rest** — AES-256-GCM with Argon2id key derivation, 3-tier key hierarchy (master → KEK → per-secret DEK)
- **MCP-native** — first-class MCP server (`harpoc-mcp`) over stdio and Streamable HTTP, for Claude, GPT, and any MCP-capable client
- **HTTP secret injection** — bearer tokens, custom headers, query parameters, basic auth — injected at fetch time with SSRF prevention, mandatory per-secret URL allowlisting (deny-by-default), and response shaping (`response_mode`: `full` / `filtered` / `status_only`)
- **Process secret injection** — run a command with the credential in its environment: no shell, clean environment, output sanitization, fail-safe per-secret command allowlisting, an acknowledgement gate for interpreter binaries, and opt-in per-secret network isolation (the spawned child gets no network, loopback included — Linux `unshare`, macOS `sandbox-exec`; unsupported platforms refuse fail-closed)
- **MCP proxy injection** — forward a tool call to a downstream MCP server that the vault spawns (stdio) or reaches over HTTP, authenticating it with the credential
- **Database, Git & SSH injection** — in-vault PostgreSQL/MySQL connections (TLS by default), Git over HTTPS or SSH, and SSH sessions via an in-process ephemeral key agent — the private key never touches disk
- **Audit trail** — every vault operation logged, detail fields encrypted at rest, rows HMAC-chained (`harpoc audit verify`); `harpoc audit anchor` exports the chain tail for off-host storage so tail truncation and rollback are detectable (`verify --anchor`). Token-authenticated accesses — every `use_secret` invocation included — are attributed to the requesting principal and access interface (REST / MCP stdio / MCP HTTP); trusted-local (CLI/SDK) rows stay principal-less by design
- **Access control** — per-secret policies and scoped tokens with wildcard secret-name patterns
- **Web UI** — a browser dashboard, secret manager, and audit viewer served by the REST API at `/ui` (`server start --rest --ui`); secret values are write-only in the browser — the UI can create and rotate them but never fetches or displays one
- **Multiple interfaces** — MCP server, REST API, TypeScript SDK, CLI, Web UI

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

| Package                | Description                                                                                                                                                                           | Status   |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| `@harpoc/shared`       | Types, Zod schemas, error codes, constants                                                                                                                                            | Complete |
| `@harpoc/core`         | VaultEngine, crypto, storage, secrets, audit, access control, six-context injection (HTTP, process, MCP, database, Git, SSH)                                                          | Complete |
| `@harpoc/cli`          | `harpoc` CLI (Commander.js)                                                                                                                                                           | Complete |
| `@harpoc/mcp-server`   | MCP tools, resources, guards (stdio + Streamable HTTP transports)                                                                                                                     | Complete |
| `@harpoc/rest-api`     | Hono HTTP API, JWT auth, rate limiting, audit middleware                                                                                                                              | Complete |
| `@harpoc/sdk`          | TypeScript client (REST + in-process modes)                                                                                                                                           | Complete |
| `@harpoc/oauth-proxy`  | OAuth 2.1 proxy — PKCE, provider presets, callback server, token refresh scheduler (CLI: `harpoc oauth connect/status/refresh`, `server start --oauth-refresh`)                       | Complete |
| `@harpoc/cert-manager` | Certificate lifecycle — PKCS#10 CSR builder + RFC 8555 ACME client (`node:crypto` only), http-01/dns-01 solvers, renewal scheduler (CLI: `harpoc cert import/csr/issue/renew/status`) | Complete |
| `@harpoc/web-ui`       | Web UI — Preact + Vite SPA (dashboard, secret management, audit viewer) served by the REST API at `/ui` (CLI: `harpoc server start --rest --ui`)                                      | Complete |
| `@harpoc/integration`  | Cross-package integration tests                                                                                                                                                       | Complete |

## Quick Start

**Prerequisites:** Node.js 22+, pnpm 10 or 11 (the repository pins `packageManager`)

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

# 2b. Register the agent and grant it the secret — every secret needs an explicit grant
npx harpoc agent register claude
npx harpoc policy grant secret://MY_API_KEY --principal-type agent --principal-id claude --permissions list,read,use
npx harpoc secret allow secret://MY_API_KEY --url "https://api.example.com/*"

# 3. Generate a scoped launch token
npx harpoc auth token --scope list,read,use --agent claude --ttl 480

# 4. Start the MCP server
HARPOC_TOKEN=<YOUR_TOKEN> npx harpoc server start --mcp
# or: npx harpoc server start --mcp --token-file ./launch-token
```

Add to your **Claude Desktop** config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows) or **Claude Code** config (`.mcp.json` in the project root, or `claude mcp add --scope user` for user-wide registration) — the token travels via the `HARPOC_TOKEN` environment variable or a `--token-file <path>` (a regular file, at most 16 KiB, kept owner-only — `chmod 600`), never on the command line, which is visible to every local process, and an explicit `--token-file` wins if both are set:

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

### Local Full-Access Mode (explicit opt-in, no token)

The stdio server refuses to start without a token (`TOKEN_REQUIRED`). To deliberately run unrestricted on a trusted local host, pass the explicit `--allow-tokenless` opt-in (see [Launch Token Options](#launch-token-options)):

```json
{
  "mcpServers": {
    "harpoc": {
      "command": "npx",
      "args": ["harpoc", "server", "start", "--mcp", "--allow-tokenless"]
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

A launch token restricts what the MCP server can do — which permissions, secrets, and project scope are available — and the stdio server **requires one by default**: `harpoc server start --mcp` and `harpoc-mcp` refuse to start without a token (`TOKEN_REQUIRED`); the token arrives via `HARPOC_TOKEN` or `--token-file <path>`, never argv. To deliberately run unrestricted on a trusted local host — no scope enforcement, no per-secret policy checks — pass the explicit opt-in flag `--allow-tokenless` (a warning is printed to stderr; the flag conflicts with a supplied token):

```bash
npx harpoc server start --mcp --allow-tokenless
```

The waiver is recorded: each such start writes a `server.start` audit event (`{ tokenless: true, transport: "stdio" }`) into the tamper-evident trail, visible with `harpoc audit --event server.start`. It is fail-closed — if the row cannot be written, the server does not start. Every start writes the row (token-bearing stdio starts carry the token's subject; the MCP HTTP and REST listeners carry their bound port), and every graceful stop writes a `server.stop` — so the waiver row is the one carrying `tokenless: true`, and `harpoc audit --event server.start` lists every server that ran.

Create a scoped token with:

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

`npx harpoc oauth providers` lists the built-in presets with the endpoints and default scopes they supply (`--json` for exact output) — static data, so it needs neither an unlocked vault nor a token.

The client secret is never passed via argv: set `HARPOC_OAUTH_CLIENT_SECRET` or enter it at the hidden prompt (leave empty for a public client). The token-endpoint auth method chosen at connect time (`--auth-method client_secret_basic` sends credentials in the `Authorization` header, never the request body) is stored with the secret and honored by every later refresh. Inspect and maintain tokens with `harpoc oauth status <handle>` and `harpoc oauth refresh <handle>`, or refresh them continuously in a long-lived server:

```bash
npx harpoc server start --rest --oauth-refresh   # or --oauth-refresh alone as a refresh daemon
```

## Certificates

Import an existing key pair, request a CSR the vault holds the key for, or let the vault run a full ACME order — the private key stays under vault encryption throughout:

```bash
# Import an existing certificate and its private key
npx harpoc cert import web-cert --key ./privkey.pem --cert ./fullchain.pem

# Generate a key in-vault and print a PKCS#10 CSR for an external CA
npx harpoc cert csr web-cert --subject www.example.com --sans www.example.com,example.com

# Issue via ACME (Let's Encrypt); --staging targets the staging directory
npx harpoc cert issue web-cert --domains www.example.com,example.com --email ops@example.com --staging

# ...or issue an RSA key instead of the EC P-256 default (`--algorithm rsa`)
npx harpoc cert issue web-cert --domains www.example.com --email ops@example.com --algorithm rsa --bits 4096

# Renew an ACME-issued certificate, and inspect health
npx harpoc cert renew secret://web-cert
npx harpoc cert status secret://web-cert
```

Private keys are stored under the vault's own encryption and never travel via argv — `cert import --key` reads the PEM from a file, and a passphrase-protected key prompts once for the passphrase and is decrypted in memory at import (the same path as `secret set --from-file`). Each certificate gets its own ACME account, stored encrypted alongside it; `--dns` selects dns-01 instead of the http-01 responder and prints the TXT record for you to place manually. Both `cert csr` and `cert issue` take `--algorithm rsa|ec` with `--bits 2048|4096` or `--curve P-256|P-384`; both generate EC P-256 by default, and a flag that does not pair with the chosen algorithm is refused rather than silently ignored.

Renew continuously in a long-lived process — alongside any server, or standalone as a renewal daemon:

```bash
npx harpoc server start --rest --cert-renew   # or --cert-renew alone as a renewal daemon
npx harpoc server start --cert-renew --cert-renew-port 8080
```

The scheduler checks hourly (the first tick one interval after start) and renews **only** certificates created with `--auto-renew`, and only once they are inside their `--renew-before-days` window (default 30). `--cert-renew-port` (default 80, requires `--cert-renew`) is the port the http-01 responder binds for the duration of a renewal. A failed renewal is audited as a failed `cert.renew`, warned on stderr, and quarantined with exponential backoff; an in-flight renewal is drained on shutdown before the vault seals. Without the daemon, `harpoc cert renew <handle>` (from cron, a timer, or by hand) remains the only thing that renews. A `--cert-renew-port` equal to `--port` or `--mcp-http-port` is refused at start.

## Web UI

Serve the browser dashboard from the REST API:

```bash
npx harpoc server start --rest --ui
```

The server prints a one-time launch link to stderr — `http://127.0.0.1:3000/ui#token=…` — carrying an admin-scoped token in the URL **fragment** (it never appears in a request line or a server log). The SPA keeps the token in `sessionStorage` for the life of the tab and sends it as a Bearer header on every API call; a paste-token sign-in screen is the fallback for a fresh tab or an expired token (24 h cap), and a sealed vault takes the UI over with re-unlock instructions.

Three pages: a **dashboard** (attention queue — secret counts, expiring secrets, OAuth tokens needing refresh, certificates nearing renewal, recent audit failures), **secrets** (metadata, injection-policy editing with the interpreter acknowledgement gate, create/rotate/delete — values are write-only: the UI never fetches or displays one, and its API client has no method that could), and **audit** (filterable feed plus a chain-verify button backed by `POST /api/v1/audit/verify`). Static assets are served unauthenticated at `/ui` under a strict same-origin CSP; all data crosses the authenticated `/api/v1` surface. OAuth and certificate lifecycles remain CLI affordances — the UI shows their status and points at `harpoc oauth` / `harpoc cert`.

## Development

```bash
pnpm build           # Build all packages (Turborepo)
pnpm test            # Run all tests
pnpm lint            # Lint all packages
pnpm format:check    # Check formatting
pnpm format          # Fix formatting
```

## Security Model

Summary — the detailed security policy, design overview and accepted risks live in [SECURITY.md](SECURITY.md).

- **3-tier key hierarchy**: password → master key (Argon2id) → KEK (AES-256-GCM key wrap) → per-secret DEK (random). JWT and audit keys are independently generated and wrapped with the KEK. Password change is O(1) — only re-wraps the KEK; all other keys remain unchanged.
- **AES-256-GCM** with authenticated additional data (AAD) binding per secret ID, preventing ciphertext substitution.
- **Argon2id** with the RFC 9106 first recommended (high-security) profile (2 GiB memory, 1 iteration, 4 lanes) — sized against the offline at-rest attacker, for whom memory per guess is the security margin; the cost is paid once per session unlock.
- **Password validation**: minimum 8-character length enforced on vault creation and password change.
- **SSRF prevention**: private IP blocking (RFC 1918, link-local, IPv4-mapped IPv6), DNS rebinding protection via pre-flight resolution with socket-level IP pinning, HTTPS enforcement, redirect validation with credential stripping on cross-origin hops and per-hop URL-allowlist re-validation.
- **Per-secret access policies, enforced at the engine**: stored policy rows grant permissions (`list`, `read`, `use`, `rotate`, `revoke`, or `admin` implying all) to principals. Every secret requires the token-derived caller to hold a matching grant — checked inside the engine on every credential operation, before anything is decrypted or injected, and covering the secret's own configuration and every enumeration surface too; a secret with no policy rows is reachable by no agent- or tool-type token until a grant exists, and a caller holding none of `read`/`list`/`admin` is told `SECRET_NOT_FOUND` exactly as for an unknown handle while the audit row records `ACCESS_DENIED`. The trusted admin path (tokenless CLI, in-process SDK, stdio MCP explicitly started `--allow-tokenless`) is exempt; `--token <jwt>` (or an ambient `HARPOC_TOKEN`) opts a CLI invocation into the token path on every command with a REST counterpart — `secret use/get/list/set/rotate/delete/allow/mcp-server/connection`, `policy grant/revoke/list`, `audit` and `oauth status/refresh` — each under the same permission the matching REST route enforces. The stdio MCP server otherwise requires a launch token at startup (`TOKEN_REQUIRED`) — the unrestricted local mode is an explicit opt-in, never a silent default.
- **Injection allowlisting** (per-secret, KEK-encrypted): a deny-by-default URL allowlist bounds request-mediated targets (http, websocket, MCP-over-HTTP, Git-HTTPS; re-validated on each redirect hop; an empty list refuses every target), a fail-safe command allowlist bounds process-mediated binaries (pinned to a resolved absolute path; known interpreters require explicit acknowledgement), and a deny-by-default host allowlist bounds database, SMTP, IMAP, SSH, SFTP, Git-SSH and docker-registry targets, with endpoint authentication pinned per secret (database TLS/CA policy, SSH host keys). Process execution spawns with no shell and a clean environment; the process context refuses any binary that has a dedicated context (`DEDICATED_CONTEXT_REQUIRED`), and Git-over-HTTPS keeps the credential bound to the validated host (host-bound askpass, redirects off, submodule recursion denied, denied-argument matching mirroring git's option abbreviation).
- **Ephemeral in-process ssh-agent** (SSH and Git-over-SSH): the private key is parsed in memory and served over the OpenSSH agent protocol on a per-invocation socket — only signatures cross it, and the private key never touches disk; ssh is restricted to offering exactly the vault identity, never the host user's ambient keys. On Windows the agent listens on a named pipe that only the **native Win32-OpenSSH client** consumes — pin `C:\Windows\System32\OpenSSH\ssh.exe` in the command allowlist; an MSYS build (e.g. the Git-bundled `ssh`) silently finds no agent.
- **HTTP response shaping**: a per-secret `response_mode` (`full` / `filtered` / `status_only`, default `filtered`) bounds what an HTTP invocation returns; `status_only` never reads the response body, and per-invocation overrides may only tighten the policy, never loosen it.
- **Network isolation** (opt-in, per-secret `network_isolation`): every child process spawned with the secret — process, Git and SSH contexts — runs without network access, loopback included. Linux: `unshare -rn`; macOS: `sandbox-exec`; Windows: **unsupported by design** — a policy demanding isolation refuses fail-closed (`NETWORK_ISOLATION_UNAVAILABLE`), never silently un-isolated. Isolation on an SSH/Git secret makes those actions fail at connect, so the flag is primarily for process-context secrets whose commands need no egress. Ubuntu 24.04+ restricts unprivileged user namespaces via AppArmor out of the box (`kernel.apparmor_restrict_unprivileged_userns = 1`) — the probe then fails and isolation-demanding uses are refused until the restriction is relaxed (`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`) or an AppArmor profile grants `userns`.
- **Filesystem isolation** (opt-in, per-secret `fs_isolation`): every child process spawned with the secret — process, Git and SSH contexts — is denied filesystem writes. Linux: `setpriv` + Landlock (util-linux ≥ 2.40; `/dev/null` writes exempt); macOS: `sandbox-exec` deny-write profile (blanket — no `/dev/null` exemption); Windows: **unsupported by design** — refuses fail-closed (`FS_ISOLATION_UNAVAILABLE`), never silently un-isolated. Combined with network isolation the two wrap into one spawn. Only `secret allow --no-fs-isolation` (or the REST PUT) lifts it; enabling it terminates any live stdio MCP downstream child already holding the secret.
- **Tamper-evident audit log**: detail fields are encrypted and bound to their row, rows are HMAC-chained (`harpoc audit verify`), and every vault mutation commits in the same SQLite transaction as its audit entry — fail-closed, so a crash cannot leave a completed-but-unaudited operation. `harpoc audit anchor` exports the chain tail for comparison with `verify --anchor`; the anchor must be stored **off-host** (another machine, a sync target, or paper), since the vault cannot supply that independent trust domain itself.
- **Session-file protection**: the session key is wrapped at rest with an OS-user-bound key store — DPAPI on Windows, the Keychain on macOS, Secret Service or the kernel keyring on Linux — so a session file copied off the host is inert; reads fail closed, a keystore that cannot protect the session key fails the unlock (`SESSION_KEYSTORE_UNAVAILABLE`) rather than downgrading the file, and `HARPOC_SESSION_KEYSTORE=off` is the explicit opt-out.
- **Secret names encrypted** with vault-level KEK — database inspection reveals nothing about stored services. HMAC-SHA256 name index enables O(1) handle resolution without decrypting all names.
- **Lazy secret expiry**: secrets with an `expires_at` timestamp are checked on access and automatically transitioned to expired status.
- **JWT sessions** with sliding window TTL (15 min default, 24 h maximum), store-based token revocation with automatic pruning of expired entries.

## Tech Stack

TypeScript (strict mode, ESM-only) · pnpm + Turborepo · SQLite (better-sqlite3, WAL mode) · AES-256-GCM + Argon2id (`node:crypto` + `argon2`) · Zod · undici · `@modelcontextprotocol/sdk` · pg / mysql2 (lazy-loaded) · Vitest

## License

[BSL 1.1](LICENSE) — code is publicly visible and auditable. Commercial use as a hosted service is restricted. Each release converts to Apache 2.0 after 3 years.
