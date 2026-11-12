# Harpoc

Secure secret management for LLMs and AI agents. Secrets are encrypted at rest, never exposed to the model — only injected at the execution layer via opaque `secret://` handles.

## Why

The MCP specification has no built-in credential management. In practice, 79% of MCP servers pass credentials via environment variables and 48% recommend `.env` files. Harpoc solves this with a zero-knowledge vault where the LLM never sees raw credentials — it only references opaque handles like `secret://github-token`, and the vault injects credentials at execution time — into an HTTP request, a subprocess environment, a downstream MCP server, a database connection, or a Git/SSH invocation — never exposing them to the model.

## Features

- **Zero-knowledge to LLM** — models see `secret://` handles, never raw values
- **Encrypted at rest** — AES-256-GCM with Argon2id key derivation, 3-tier key hierarchy (master → KEK → per-secret DEK)
- **MCP-native** — first-class MCP server (`harpoc-mcp`) over stdio and Streamable HTTP, for Claude, GPT, and any MCP-capable client
- **HTTP secret injection** — bearer tokens, custom headers, query parameters, basic auth — injected at fetch time with SSRF prevention, mandatory per-secret URL allowlisting (deny-by-default), and response shaping (`response_mode`: `full` / `filtered` / `status_only`)
- **Process secret injection** — run a command with the credential in its environment: no shell, clean environment, output sanitization, fail-safe per-secret command allowlisting, an acknowledgement gate for interpreter binaries and exec wrappers (`sudo`, `xargs`, `find`, …), and opt-in per-secret network isolation (the spawned child gets no network, loopback included — Linux `unshare` or, behind it, `bwrap`; macOS `sandbox-exec`; unsupported platforms refuse fail-closed)
- **MCP proxy injection** — forward a tool call to a downstream MCP server that the vault spawns (stdio) or reaches over HTTP, authenticating it with the credential
- **Database, Git & SSH injection** — in-vault PostgreSQL/MySQL connections (TLS by default), Git over HTTPS or SSH (`clone`, `pull`, `push`, `fetch` and `ls-remote`, each credential-bearing step in a relay repository the vault writes for the call, no hook of the caller's tree run), and SSH sessions via an in-process ephemeral key agent — the private key never touches disk
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

| Package                | Description                                                                                                                                                                                                     | Status   |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| `@harpoc/shared`       | Types, Zod schemas, error codes, constants                                                                                                                                                                      | Complete |
| `@harpoc/core`         | VaultEngine, crypto, storage, secrets, audit, access control, six-context injection (HTTP, process, MCP, database, Git, SSH)                                                                                    | Complete |
| `@harpoc/cli`          | `harpoc` CLI (Commander.js)                                                                                                                                                                                     | Complete |
| `@harpoc/mcp-server`   | MCP tools, resources, guards (stdio + Streamable HTTP transports)                                                                                                                                               | Complete |
| `@harpoc/rest-api`     | Hono HTTP API, JWT auth, rate limiting, audit middleware                                                                                                                                                        | Complete |
| `@harpoc/sdk`          | TypeScript client (REST + in-process modes)                                                                                                                                                                     | Complete |
| `@harpoc/oauth-proxy`  | OAuth 2.1 proxy — PKCE, provider presets, callback server, token refresh scheduler (CLI: `harpoc oauth connect/status/refresh`, `server start --oauth-refresh`)                                                 | Complete |
| `@harpoc/cert-manager` | Certificate lifecycle — PKCS#10 CSR builder, X.509 CA and leaf issuer + RFC 8555 ACME client (`node:crypto` only), http-01/dns-01 solvers, renewal scheduler (CLI: `harpoc cert import/csr/issue/renew/status`) | Complete |
| `@harpoc/egress-proxy` | Egress credential proxy — swaps a placeholder for the credential at the egress hop, rewrite and CONNECT mode (CLI: `harpoc server start --proxy`, `harpoc proxy env/ca`)                                        | Complete |
| `@harpoc/web-ui`       | Web UI — Preact + Vite SPA (dashboard, secret management, audit viewer) served by the REST API at `/ui` (CLI: `harpoc server start --rest --ui`)                                                                | Complete |
| `@harpoc/integration`  | Cross-package integration tests                                                                                                                                                                                 | Complete |

## Quick Start

**Prerequisites:** Node.js 22+, pnpm 10 or 11 (the repository pins `packageManager`)

```bash
git clone https://github.com/HarpocGH/harpoc.git
cd harpoc
pnpm install
pnpm build
pnpm test
```

The next release is `v1.5.0`, prepared on `main` (`CHANGELOG.md` § `[1.5.0]`, `.github/releases/v1.5.0.md`); its tag is not yet pushed, so `main` is the reference state until it is. `npx harpoc --version` prints the version you built.

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

`--vault-dir` opens a local vault; `harpoc --url <base> --token-file <path> <command>` instead sends the command to a running REST server (see [Deployment models](#deployment-models)) — the two exclude each other.

### Streamable HTTP Transport

For clients that connect to a URL instead of spawning a process:

```bash
npx harpoc server start --mcp-http --mcp-http-port 3001
```

The endpoint is `http://127.0.0.1:3001/mcp`. Every request requires a vault-issued JWT (`Authorization: Bearer`) — there is no tokenless mode over HTTP. Since 2026-09-16 the same endpoint also serves the `2026-07-28` revision: a client that speaks it gets a per-request server with no session; a client that sends `initialize` gets the session path exactly as before.

### REST Bridge (Deployment Model B)

When the vault runs under its own user and the agent under another (see [Deployment models](#deployment-models)), the agent's host does not spawn the in-process server — it cannot read the vault's session. It spawns `harpoc-mcp --url` instead: a stdio server that holds no engine and reaches the vault only through its REST API, with the agent's token file as the bearer, read again for every call so a rotated token is picked up:

```json
{
  "mcpServers": {
    "harpoc": {
      "command": "harpoc-mcp",
      "args": ["--url", "http://127.0.0.1:3000", "--token-file", "/run/harpoc/<consumer>/token.jwt"]
    }
  }
}
```

The tools and resources are the stdio server's. The bridge runs as the agent, so it never collects a value: `create_secret` creates the secret without one (the vault user sets it with `harpoc secret set`), and `rotate_secret` and the `authorization_code` and `client_credentials` grants of `start_oauth_flow` refuse, naming the command to run as the vault user. The REST server scopes and audits every call. `--url` is refused together with `--http`, `--vault-dir` or `--allow-tokenless`, and plain `http:` is accepted for a loopback host only.

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
- `--project` — Project scope (a project-scoped token administers no governance route or command)
- `--secrets` — Comma-separated secret-name patterns the token can access (`*` wildcards, e.g. `db-*`; full-anchored, case-sensitive)
- `--ttl` — Token lifetime in minutes (default: 60)

A token written with `auth token --out <file>` is also the bearer of the CLI's REST mode: `harpoc --url http://127.0.0.1:3000 --token-file <file> secret list` (see [Deployment models](#deployment-models)).

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

Private keys are stored under the vault's own encryption and never travel via argv — `cert import --key` reads the PEM from a file, and a passphrase-protected key prompts once for the passphrase and is decrypted in memory at import (the same path as `secret set --from-file`). Each certificate gets its own ACME account, stored encrypted alongside it; Let's Encrypt allows 10 new accounts per IP per 3 hours, which bounds how many certificates one host can issue in that window (one shared account per directory URL is deferred until multi-certificate issuance from one host is a demonstrated use case); `--dns` selects dns-01 instead of the http-01 responder and prints the TXT record for you to place manually (an interactive terminal is required — a piped stdin is refused). Both `cert csr` and `cert issue` take `--algorithm rsa|ec` with `--bits 2048|4096` or `--curve P-256|P-384`; both generate EC P-256 by default, and a flag that does not pair with the chosen algorithm is refused rather than silently ignored.

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

- **3-tier key hierarchy**: password → master key (Argon2id) → KEK (AES-256-GCM key wrap) → per-secret DEK (random). JWT and audit keys are independently generated and wrapped with the KEK. Password change is O(1) — only re-wraps the KEK; all other keys remain unchanged. Once enrolled (`harpoc unlock-key enroll`), the KEK is also wrapped under a random 256-bit unlock key in a second slot — no key derivation on that path — for a daemon that starts without a person (deployment model B).
- **AES-256-GCM** with authenticated additional data (AAD) binding per secret ID, preventing ciphertext substitution.
- **Argon2id** with the RFC 9106 first recommended (high-security) profile (2 GiB memory, 1 iteration, 4 lanes) — sized against the offline at-rest attacker, for whom memory per guess is the security margin; the cost is paid once per session unlock.
- **Password validation**: minimum 8-character length enforced on vault creation and password change.
- **SSRF prevention**: private IP blocking (RFC 1918, link-local, IPv4-mapped IPv6), DNS rebinding protection via pre-flight resolution with socket-level IP pinning, HTTPS enforcement, redirect validation with credential stripping on cross-origin hops and per-hop URL-allowlist re-validation.
- **Per-secret access policies, enforced at the engine**: stored policy rows grant permissions (`list`, `read`, `use`, `rotate`, `revoke`, or `admin` implying all) to principals. Every secret requires the token-derived caller to hold a matching grant — checked inside the engine on every credential operation, before anything is decrypted or injected, and covering the secret's own configuration and every enumeration surface too; a secret with no policy rows is reachable by no agent- or tool-type token until a grant exists, and a caller holding none of `read`/`list`/`admin` is told `SECRET_NOT_FOUND` exactly as for an unknown handle while the audit row records `ACCESS_DENIED`. The trusted admin path (tokenless CLI, in-process SDK, stdio MCP explicitly started `--allow-tokenless`) is exempt; `--token <jwt>` (or an ambient `HARPOC_TOKEN`) opts a CLI invocation into the token path on every command with a REST counterpart — `secret use/get/list/set/rotate/delete/allow/mcp-server/connection`, `policy grant/revoke/list`, `audit` and `oauth status/refresh` — each under the same permission the matching REST route enforces. The stdio MCP server otherwise requires a launch token at startup (`TOKEN_REQUIRED`) — the unrestricted local mode is an explicit opt-in, never a silent default.
- **Injection allowlisting** (per-secret, KEK-encrypted): a deny-by-default URL allowlist bounds request-mediated targets (http, websocket, MCP-over-HTTP, Git-HTTPS; re-validated on each redirect hop; an empty list refuses every target), a fail-safe command allowlist bounds process-mediated binaries (pinned to a resolved absolute path; known interpreters require explicit acknowledgement, and so do exec wrappers such as `sudo` or `xargs`), and a deny-by-default host allowlist bounds database, SMTP, IMAP, SSH, SFTP, Git-SSH and docker-registry targets, with endpoint authentication pinned per secret (database TLS/CA policy, SSH host keys). Host matching folds the ASCII letters `A`–`Z` only, so a target host with a character outside ASCII matches no pattern and an allowlist entry with a non-ASCII host matches no ASCII target: write a non-ASCII host as its `xn--` form in an allowlist (an SDK direct-client caller's non-ASCII host in the database, SMTP, IMAP or docker context is refused `HOST_NOT_ALLOWED`). Process execution spawns with no shell and a clean environment; the process context refuses any binary that has a dedicated context (`DEDICATED_CONTEXT_REQUIRED`), and Git-over-HTTPS keeps the credential bound to the validated host (host-bound askpass, redirects off, submodule recursion denied, denied-argument matching mirroring git's option abbreviation).
- **Ephemeral in-process ssh-agent** (SSH and Git-over-SSH): the private key is parsed in memory and served over the OpenSSH agent protocol on a per-invocation socket — only signatures cross it, and the private key never touches disk; ssh is restricted to offering exactly the vault identity, never the host user's ambient keys. On Windows the agent listens on a named pipe that only the **native Win32-OpenSSH client** consumes — pin `C:\Windows\System32\OpenSSH\ssh.exe` in the command allowlist; an MSYS or Cygwin build (e.g. the Git-bundled `ssh`) is refused before the spawn with `SSH_CLIENT_UNSUPPORTED`.
- **HTTP response shaping**: a per-secret `response_mode` (`full` / `filtered` / `status_only`, default `filtered`) bounds what an HTTP invocation returns; `status_only` never reads the response body, and per-invocation overrides may only tighten the policy, never loosen it.
- **Network isolation** (opt-in, per-secret `network_isolation`): every child process spawned with the secret — process, Git, SSH and SFTP contexts, and stdio MCP downstream servers — runs without network access, loopback included. Linux: `unshare -rn`, or bubblewrap (`bwrap --unshare-net`, a fresh namespace with an empty loopback of its own) behind it when `unshare` is absent or refused; macOS: `sandbox-exec`; Windows: **unsupported by design** — a policy demanding isolation refuses fail-closed (`NETWORK_ISOLATION_UNAVAILABLE`), never silently un-isolated. Isolation on an SSH/SFTP/Git secret makes those actions fail at connect, so the flag is primarily for process-context secrets whose commands need no egress. Ubuntu 24.04+ restricts unprivileged user namespaces via AppArmor out of the box (`kernel.apparmor_restrict_unprivileged_userns = 1`) — both tiers need the grant, so the probes fail and isolation-demanding uses are refused until the restriction is relaxed (`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`) or an AppArmor profile grants `userns` to the wrapper (Getting Started carries a five-line profile for `/usr/bin/bwrap`).
- **Filesystem isolation** (opt-in, per-secret `fs_isolation`): every child process spawned with the secret — process, Git, SSH and SFTP contexts, and stdio MCP downstream servers — is denied filesystem writes. Linux: `setpriv` + Landlock (util-linux ≥ 2.40), or bubblewrap (`bwrap --ro-bind / /`, the whole tree read-only) behind it — which is what delivers the flag on Ubuntu 24.04 LTS, whose `setpriv` predates Landlock; macOS: `sandbox-exec` deny-write profile; Windows: **unsupported by design** — refuses fail-closed (`FS_ISOLATION_UNAVAILABLE`), never silently un-isolated. Writes to `/dev/null` are allowed on every mechanism. Combined with network isolation the two wrap into one spawn. Only `secret allow --no-fs-isolation` (or the REST PUT) lifts it; enabling it terminates any live stdio MCP downstream child already holding the secret, and the next use respawns it wrapped.
- **Strict tree exit** (opt-in, per-secret `strict_tree_exit`): nothing a process-mediated child started outlives the call — process, Git, SSH, SFTP and Docker contexts, and stdio MCP downstream servers. Windows runs the child inside the vault's kill-on-close job wrapper in strict mode, so the child's own exit takes every survivor, grandchildren included, and a host without the wrapper refuses the use fail-closed (`STRICT_TREE_EXIT_UNAVAILABLE`); POSIX kills the child's process group after it exits (a descendant that called `setsid` escapes, as on the timeout path).
- **Tamper-evident audit log**: detail fields are encrypted and bound to their row, rows are HMAC-chained (`harpoc audit verify`), and every vault mutation commits in the same SQLite transaction as its audit entry — fail-closed, so a crash cannot leave a completed-but-unaudited operation. `harpoc audit anchor` exports the chain tail for comparison with `verify --anchor`; the anchor must be stored **off-host** (another machine, a sync target, or paper), since the vault cannot supply that independent trust domain itself.
- **Session-file protection**: the session key is wrapped at rest with an OS-user-bound key store — DPAPI on Windows, the Keychain on macOS, Secret Service or the kernel keyring on Linux — so a session file copied off the host is inert; reads fail closed, a keystore that cannot protect the session key fails the unlock (`SESSION_KEYSTORE_UNAVAILABLE`) rather than downgrading the file, and `HARPOC_SESSION_KEYSTORE=off` is the explicit opt-out.
- **Secret names encrypted** with vault-level KEK — database inspection reveals nothing about stored services. HMAC-SHA256 name index enables O(1) handle resolution without decrypting all names.
- **Lazy secret expiry**: secrets with an `expires_at` timestamp are checked on access and automatically transitioned to expired status.
- **JWT sessions** with sliding window TTL (15 min default, 24 h maximum), store-based token revocation with automatic pruning of expired entries.
- **Listener host allowlist**: both HTTP listeners validate every request's `Host` (and `Origin`) against `--allowed-host` plus, on a loopback bind, the loopback names; a non-loopback bind without the flag is refused. Terminate TLS at a reverse proxy and list its public name — forwarded headers are never trusted.

## Deployment models

Harpoc runs in one of two deployment models. They differ in who runs what, not in the cryptography — and that decides what a subverted or shell-wielding agent can read.

### Model A — attended, single-identity

One OS user unlocks the vault; the CLI, the MCP server and the REST API each embed the vault engine and coordinate through the SQLite file and the `0600` session file, so all of them run as that user. A **tool-only agent** — an MCP host holding a launch token, or a REST / MCP-over-HTTP client holding a bearer — holds a use-scoped token and nothing else. An agent that runs shell commands **under the same user** holds everything that user holds: it can read the session file and unwrap the key-encryption key from it, load the engine in-process, call `harpoc secret get --value`, and read `/proc/<pid>/environ` of every process the vault spawned for it. File modes cannot separate two processes of one user. Model A is the default — every default of `init`, `unlock`, `server start` and the stdio MCP server is model A — and stays the model for attended use.

### Model B — two identities

The vault runs as a dedicated system user, `harpoc`; each agent runs under an OS user of its own and reaches the vault only over REST or MCP over HTTP, with a token. Nothing an agent user can read holds a key or a plaintext: the vault directory is `0700 harpoc`, the session file `0600 harpoc`, and every child the vault spawns runs as `harpoc`, so its environment is out of the agent's reach. On Windows the same boundary is drawn with access lists in place of modes (**The Windows deployment**, below).

An agent's own tools use a credential without holding it through the egress proxy — its base-URL form for `git`, `curl` and SDKs whose base URL can be pointed at it, its CONNECT mode for clients that honour only `HTTPS_PROXY` — and, for SSH, through a signature from the agent socket (all below).

**The layout.** Run the recipe as root once per host, naming the agent users (each needs its own primary group — `useradd --create-home agent1` makes one):

```bash
sudo deploy/linux/install-two-identity.sh agent1 agent2
```

It is idempotent and creates the system group `harpoc-clients`, the system user `harpoc` (primary group `harpoc`, no login shell, home `/var/lib/harpoc`), the vault directory `/var/lib/harpoc` (`0700 harpoc:harpoc`), the runtime directory `/run/harpoc` (`0750 harpoc:harpoc-clients`, so only agent users can enter it) and one consumer directory per agent user, `/run/harpoc/<agent>` (`02750 harpoc:<agent's group>`): the set-group-ID bit gives every file the vault writes there the agent's group without `harpoc` belonging to it. Each agent user joins `harpoc-clients`. An agent user's name is its consumer name — lowercase letters, digits, `_` and `-`, not dash-led — and the recipe refuses any other. `/run` is a tmpfs: on a systemd host the recipe also writes `/etc/tmpfiles.d/harpoc.conf`, which `systemd-tmpfiles` applies at every boot; elsewhere run the recipe again at boot. Do not let a unit's `RuntimeDirectory=` own `/run/harpoc`: systemd removes that directory, consumer directories included, whenever the unit stops.

**Administration — attended, as the vault user.** Every administrative command runs in-process under `harpoc`, as model A does under one user: the session file `unlock` writes is `harpoc`'s own and unreadable to every agent user. Token issuance stays CLI-only, so the administrator mints each consumer's token into its consumer directory and gives the agent's group read access:

```bash
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc init
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc agent register agent1
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc secret set api-key
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc secret allow secret://api-key --url "https://api.example.com/*"
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc policy grant secret://api-key --principal-type agent --principal-id agent1 --permissions use,list
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc auth token --agent agent1 --scope use,list --ttl 1440 --out /run/harpoc/agent1/token.jwt
sudo -u harpoc chmod 0640 /run/harpoc/agent1/token.jwt
```

`harpoc` here is the built CLI and `harpoc-mcp` the built MCP server (`packages/cli/dist/index.js` and `packages/mcp-server/dist/index.js` of a checkout every one of these users can read), linked into a directory on `sudo`'s `secure_path` such as `/usr/local/bin`. Pass `--vault-dir` on every command: without it the CLI looks for `.harpoc` in the administrator's working directory first. Under `sudo` there is no D-Bus session and the kernel keyring is not one the vault user possesses, so `init` and `unlock` answer `SESSION_KEYSTORE_UNAVAILABLE` (measured on Debian 12): run the administrative commands as `sudo -u harpoc env HARPOC_SESSION_KEYSTORE=off harpoc …` — the session file is then protected by its `0600` mode under the `harpoc` UID alone, which is the boundary model B draws. A failed `init` leaves `default.vault.db` behind and a retry reports an existing vault; remove the file before retrying. A token expires within 24 hours; re-mint it the same way (`--out` refuses an existing file, so remove the old one first), or let the daemon issue and rotate it with `--issue-token` (**The memory session and token rotation**, below).

**The daemon**, as the vault user (loopback only, port 3000 by default; `--session memory` takes the keys from the administrator's session once, at the start, and leaves the file to the administrator — **The memory session and token rotation**, below; `--runtime-dir` refuses a runtime directory that is a symbolic link or junction (under `--proxy` or `--ssh-agent` also an entry of it that is one, where a consumer directory belongs) and one that is not `harpoc`'s own and `0750` or stricter, reads systemd's `$RUNTIME_DIRECTORY` only under `--proxy` or `--ssh-agent`, and on Windows checks the directory's access list instead of its owner and mode (**The Windows deployment**, below)):

```bash
sudo -u harpoc env HARPOC_SESSION_KEYSTORE=off harpoc --vault-dir /var/lib/harpoc server start --rest --session memory --runtime-dir /run/harpoc
```

**The consumers**, as an agent user — the CLI in its REST mode, and the stdio→REST bridge as an MCP host entry; neither opens a vault, the bearer comes from `--token-file` only (an ambient `HARPOC_TOKEN` is refused by the CLI and ignored by the bridge), and commands that have no REST route (`init`, `unlock`, token issuance) refuse with `REST_MODE_UNSUPPORTED`:

```bash
harpoc --url http://127.0.0.1:3000 --token-file /run/harpoc/agent1/token.jwt secret list
```

```json
{
  "mcpServers": {
    "harpoc": {
      "command": "harpoc-mcp",
      "args": ["--url", "http://127.0.0.1:3000", "--token-file", "/run/harpoc/agent1/token.jwt"]
    }
  }
}
```

**The egress proxy** (the base-URL form; CONNECT mode, for clients that honour only `HTTPS_PROXY`, follows it). An agent's own HTTPS client — `git`, `curl`, an SDK whose base URL is configurable — holds a placeholder where the credential would go, `harpoc:<name>` for a secret without a project (`secret://<name>`), `harpoc://<project>/<name>` for one in a project, and sends the request in plain HTTP to the vault's proxy, which opens the TLS connection itself: `http://127.0.0.1:3128/<host>/<path>` stands for `https://<host>/<path>`. Every request carries the consumer's use-scoped token as `Proxy-Authorization: Bearer <token>` — missing it is refused `407`, an invalid one `401`, before anything goes upstream — and the proxy strips the header before forwarding. A request whose `Authorization` header (a Bearer token, or the Basic password with the request's own user kept), whose whole value of another header or whose whole value of a query parameter is a placeholder is brokered: the proxy checks the caller's `use` grant, the secret's proxy opt-in and its URL allowlist, swaps the real value in where the placeholder stood, sends the request through the SSRF floor and writes one `secret.use` row (`context: "proxy"`; the method, the origin and the path — no body, no query, no header value). For a Basic placeholder the secret's value is the password alone — the client supplies the user, as `git` does with `x-access-token`; a secret stored as `user:password` for `use_secret`'s own basic auth would be sent as `base64(<client user>:user:password)` and answered `401`. A placeholder bound for an origin outside the allowlist is refused `403` before that origin is contacted; a request without a placeholder passes through and is not audited. The proxy follows no redirect: a `3xx` goes back to the client with its `Location` pointed back at the proxy, so the next request is judged on its own origin. Each secret is rate-limited as `use_secret` is — 120 brokered requests a minute, the next refused `429`. The vault user opts a secret in and starts the listener beside the REST API:

```bash
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc secret allow secret://gh-pat --url "https://github.com/*" --proxy
sudo -u harpoc env HARPOC_SESSION_KEYSTORE=off harpoc --vault-dir /var/lib/harpoc server start --rest --session memory --runtime-dir /run/harpoc --proxy
```

`git` reaches the proxy as its remote. The rewrite and the token header go into the environment (git 2.31 or later), never onto a command line, which every local user can read in `/proc/<pid>/cmdline`:

```bash
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0='url.http://x-access-token:harpoc:gh-pat@127.0.0.1:3128/github.com/.insteadOf'
export GIT_CONFIG_VALUE_0='https://github.com/'
export GIT_CONFIG_KEY_1='http.http://127.0.0.1:3128/.extraHeader'
export GIT_CONFIG_VALUE_1="Proxy-Authorization: Bearer $(cat /run/harpoc/agent1/token.jwt)"
git clone https://github.com/org/repo.git
```

The clone's `origin` stays `https://github.com/org/repo.git`. git asks each operation's first question without a credential and sends the placeholder only after the remote answers `401`, so that first request passes through unbrokered and unaudited — a public repository answers it and never sees the placeholder — and a private repository's clone or push writes one row per request that carried it (`http.proactiveAuth=basic`, git 2.46 or later, sends the placeholder at once). That first request carries no secret, so the proxy opens its TLS connection against the host's own CA store — a remote behind a private CA needs that CA in the store, or the proactive form; the secret's `--http-ca` pin applies to the brokered requests. `harpoc proxy env <consumer> <handle>… --runtime-dir /run/harpoc` prints the consumer's environment block — the proxy's address, the base-URL form, the token file's and the socket's paths, CONNECT mode's CA file and trust variables (below) and one `HARPOC_PLACEHOLDER_<NAME>` per handle; it opens no vault and prints no value and no token. `curl` takes the same base-URL form, its token header read from standard input rather than its command line; `curl --proxy` with an `https://` URL opens a CONNECT tunnel instead, which the proxy answers once a Harpoc CA is enrolled (below) and refuses `501` until then:

```bash
printf 'Proxy-Authorization: Bearer %s\n' "$(cat /run/harpoc/agent1/token.jwt)" |
  curl -H @- -H "Authorization: Bearer harpoc:gh-pat" http://127.0.0.1:3128/api.github.com/user
```

**CONNECT mode and the Harpoc CA.** A client with a built-in API host that honours only `HTTPS_PROXY` — the GitHub CLI is one — cannot be pointed at the base-URL form: for an `https://` URL it sends `CONNECT <host>:443` to the proxy and then speaks TLS to the host through the tunnel. Once a Harpoc CA is enrolled the proxy answers the tunnel: it ends the client's TLS with a certificate for that host — a leaf the CA issues —, reads the requests inside as it reads a base-URL request (the same placeholder positions, with `Authorization: token <placeholder>` — the GitHub CLI's form — beside the Bearer one), swaps the credential in and opens its own TLS connection to the host, verified as in the base-URL form; without a CA it refuses every CONNECT `501`, naming `harpoc proxy ca init`. The vault user creates the CA once, naming every host the consumers' clients reach through a tunnel (`--name-constraints`, required and repeatable — a DNS name admits the host and its subdomains, an IP literal itself alone; a CA that lists DNS names only refuses every IP literal and one that lists IP literals only every DNS name, so list the IP literal too if a client addresses the host by IP). `proxy ca init` makes a root certificate, whose key is discarded at creation, and signs with it one intermediate; both carry those names as RFC 5280 name constraints; the vault keeps the intermediate and its key as the certificate secret `secret://harpoc-ca`, and the consumers trust the root — two tiers because Java 8 ignores the name constraints of a self-signed trust anchor and enforces an intermediate's, where OpenSSL, Schannel, Node, Python and — by its source — Go enforce both. A client whose TLS stack honours the constraints accepts the CA's leaves for those hosts alone, and the proxy refuses a CONNECT to any other host `403` (`PROXY_CONNECT_DENIED`, naming the host and the port) before any TLS. The root and the intermediate are valid for 10 years unless `--days` says less; the intermediate's key is generated in the administrator's command and never written to a file, printed or returned, `use_secret` and the proxy refuse it like every vault-managed certificate (`CERT_VALUE_UNSUPPORTED`), and the daemon reads it at each start, one audited read. `proxy ca init` prints the handle, the hosts, each certificate's end and SHA-256 fingerprint, never a key. Each leaf is issued in the daemon's memory on the first tunnel to its host, valid for 7 days — never past the CA's own end — and issued anew once half of that has passed; its key never leaves the daemon, which sends it with the intermediate. A second `proxy ca init` is refused (`DUPLICATE_SECRET`) unless `--force` revokes the old CA and imports the new one, and a running daemon takes a new CA only when it is restarted; a daemon whose CA has expired starts without CONNECT and says so (`[harpoc] Harpoc CA expired at <time> — CONNECT disabled until harpoc proxy ca init --force`) — and one whose CA expires while it runs refuses each later CONNECT `410`:

```bash
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc proxy ca init --name-constraints api.github.com --name-constraints github.com
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc secret allow secret://gh-pat --url "https://api.github.com/*" --url "https://github.com/*" --proxy
sudo -u harpoc env HARPOC_SESSION_KEYSTORE=off harpoc --vault-dir /var/lib/harpoc server start --rest --session memory --runtime-dir /run/harpoc --proxy
```

At its start the daemon writes the CA's root certificate — public, no key — into every consumer directory as `/run/harpoc/<consumer>/ca.pem`, `0640` with the consumer's group from the set-group-ID directory as the token file has it; a write that fails refuses the start. `ca.pem` and `harpoc proxy ca export` carry the root alone, and a consumer trusts the root, never the intermediate: Node, Python 3.11 and OpenSSL refuse the intermediate as a trust anchor, while Java, Python 3.13's defaults and Schannel accept it — and Java then ignores its constraints. `harpoc proxy env <consumer> <handle>… --runtime-dir /run/harpoc` prints its path as `HARPOC_PROXY_CA_FILE` and five variables pointing at it, the ones the common TLS stacks read a CA file from — `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `GIT_SSL_CAINFO` —, whether or not a CA is enrolled (the file appears at the first start of a daemon that has one), and last a comment naming the `HTTPS_PROXY` form, since it prints no token. Four of the variables — `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `GIT_SSL_CAINFO` — replace a client's own CA list rather than extend it (`NODE_EXTRA_CA_CERTS` extends Node's, and Python on Windows adds the system stores to `SSL_CERT_FILE`'s): a client given one trusts the Harpoc root alone, since `ca.pem` carries no system bundle, so set them for the clients that go through the proxy. The token goes into `HTTPS_PROXY=http://harpoc:<token>@127.0.0.1:3128`, which the shell sets from the token file when the client starts, and from that URL a client builds the CONNECT request's `Proxy-Authorization: Basic base64(harpoc:<token>)` — curl, the GitHub CLI and Python's `urllib` send it at once, git after the proxy's `407`, which offers `Basic realm="harpoc"` and then `Bearer realm="harpoc"`; the proxy ignores the user name and takes `Proxy-Authorization: Bearer <token>` as well, and answers an invalid token `401` before the tunnel opens — and every request inside the tunnel checks the token again, so a token that expires or is revoked while the tunnel is open ends it. A client keeps the token it was started with: the daemon's rotation reaches it at its next start, and the token it holds stays valid until its own expiry (**The memory session and token rotation.**, below). A consumer outside the runtime directory — a container — gets the root from the vault user's `harpoc proxy ca export --out <file>`, which writes it `0644`, replacing an earlier export:

```bash
set -a; . <(harpoc proxy env agent1 secret://gh-pat --runtime-dir /run/harpoc); set +a
export HTTPS_PROXY="http://harpoc:$(cat "$HARPOC_PROXY_TOKEN_FILE")@127.0.0.1:3128"
GH_TOKEN=harpoc:gh-pat gh api user
curl -H "Authorization: Bearer harpoc:gh-pat" https://api.github.com/user
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=http.proxy GIT_CONFIG_VALUE_0="$HTTPS_PROXY"
git clone https://x-access-token:harpoc:gh-pat@github.com/org/repo.git
```

Each client reads its own settings. curl takes `HTTPS_PROXY` and, built on OpenSSL, `CURL_CA_BUNDLE`; built on Schannel, as on Windows, it ignores `CURL_CA_BUNDLE` and `SSL_CERT_FILE` and takes the root only from `--cacert`, with `--ssl-revoke-best-effort` since a Harpoc certificate names no revocation endpoint. git takes the token in `http.proxy`'s userinfo through `GIT_CONFIG_COUNT`, never on a command line, the root from `GIT_SSL_CAINFO` (an absolute path) and the placeholder as the clone URL's password, as in the base-URL form; Git for Windows' Schannel backend uses `GIT_SSL_CAINFO` only with `http.schannelUseSSLCAInfo=true`, and checks revocation strictly — which no Harpoc certificate passes — unless `http.sslBackend=schannel` is set explicitly; `http.sslBackend=openssl` needs neither. The GitHub CLI takes `GH_TOKEN=harpoc:<name>`, which it sends as `Authorization: token harpoc:<name>`, and trusts the root through `SSL_CERT_FILE` on Linux (Go's documented rule); on Windows and macOS only a CLI built on Go 1.27 reads that variable — the runners' 2.103.3 is one, this host's 2.87.0 on Go 1.25.7 is not — and an older build needs the root in the user's certificate store, an interactive step for the operator (the CLI, as every Go client, never sends a loopback target through a proxy — no concern when its target is GitHub). Node's global `fetch` ignores `HTTPS_PROXY` (`NODE_USE_ENV_PROXY` had no effect on 24.13.1): a Node client sets undici's `EnvHttpProxyAgent`, or a `ProxyAgent` with the proxy's URL, as its dispatcher and reads the root from `NODE_EXTRA_CA_CERTS`. Python's `urllib` takes `HTTPS_PROXY` and `SSL_CERT_FILE`; `REQUESTS_CA_BUNDLE` is read by `requests` alone. Every stack measured accepted the 10-year root and the 7-day leaves and honours the name constraints — Java 8 through the intermediate alone:

| Client                    | TLS stack        | Proxy credential from the proxy URL's userinfo                                         | Trusts the root through                                                                                                                   | Honours the name constraints              | Measured on                                                      |
| ------------------------- | ---------------- | -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- | ---------------------------------------------------------------- |
| curl 8.16, 8.21           | Schannel         | Basic, at once (`HTTPS_PROXY` or `--proxy`)                                            | `--cacert` with `--ssl-revoke-best-effort` — `CURL_CA_BUNDLE` and `SSL_CERT_FILE` ignored                                                 | yes                                       | Windows 11                                                       |
| curl                      | OpenSSL          | Basic, at once (measured on Schannel)                                                  | `CURL_CA_BUNDLE`                                                                                                                          | yes (the OpenSSL 3.5 command line)        | unmeasured here                                                  |
| Git for Windows 2.51      | Schannel         | Basic, after the `407` (`anyauth`)                                                     | `GIT_SSL_CAINFO` with `http.sslBackend=schannel` and `http.schannelUseSSLCAInfo=true` (the explicit backend makes revocation best-effort) | yes                                       | Windows 11                                                       |
| git 2.51                  | OpenSSL          | Basic, after the `407` (`anyauth`)                                                     | `GIT_SSL_CAINFO`, an absolute path                                                                                                        | yes                                       | Windows 11                                                       |
| GitHub CLI 2.87 (Go 1.25) | Go `crypto/x509` | Basic, at once                                                                         | `SSL_CERT_FILE` on Linux; on Windows and macOS the user's certificate store (Go 1.27 builds: `SSL_CERT_FILE`)                             | yes (cited)                               | cited (Go 1.27 docs); measured up to the handshake on Windows 11 |
| Node 24.13, undici 8.12   | OpenSSL 3.5      | Basic, from `EnvHttpProxyAgent` or `ProxyAgent` — global `fetch` ignores `HTTPS_PROXY` | `NODE_EXTRA_CA_CERTS`                                                                                                                     | yes                                       | Windows 11                                                       |
| Python 3.11 `urllib`      | OpenSSL 3.0      | Basic, at once                                                                         | `SSL_CERT_FILE` or `cafile`                                                                                                               | yes                                       | Windows 11                                                       |
| Python `requests`         | OpenSSL          | cited                                                                                  | `REQUESTS_CA_BUNDLE`                                                                                                                      | cited                                     | unmeasured here                                                  |
| Java 8                    | JSSE             | unmeasured                                                                             | a trust store holding the root                                                                                                            | through the intermediate — trust the root | Windows 11                                                       |

**The unconstrained fallback.** No stack measured rejects the constrained CA; a client that did — one that refuses a user-added root whose intermediate carries name constraints — could not use CONNECT mode with it. For such a client, and only once the operator has seen it refuse, `harpoc proxy ca init --name-constraints api.github.com --unconstrained --days 7 --force` replaces the CA with one whose two tiers carry no name constraints, valid for `--days` days (7 by default, 30 at most — a longer value is refused, never clamped), its leaves ending with it. `--name-constraints` stays required: the hosts it names still bound the proxy, which refuses a CONNECT to any other host `403` as before, so the fallback widens only what a leaked key could sign. There is one CA at a time: the fallback replaces the constrained CA for every consumer, each of which trusts it once the daemon's next start has written the new `ca.pem` (or from a fresh `proxy ca export`). Whoever holds an unconstrained CA's key can impersonate any host to a client that trusts it for as long as it is valid, and a Harpoc CA names no revocation endpoint: create a constrained CA again as soon as the client is fixed, and restart the daemon.

**The agent socket.** An agent's own `ssh` — and `git` over SSH — authenticates with a key it never holds. `server start --ssh-agent` serves one ssh-agent socket per consumer directory, `/run/harpoc/<consumer>/ssh-agent.sock` (`0660` in the consumer's `02750` directory), offering every key the consumer holds a `use` grant on whose secret is opted in with `secret allow --ssh-agent-socket`, and it signs; it never hands a key out. Before it lists the agent's keys, OpenSSH 8.9 or later binds the agent connection to the server's host key with `session-bind@openssh.com` — the server's own signature over the session, which the vault verifies — and the socket signs only on a bound connection, only that session's authentication request, and only when the bound host key is one the secret pins (`secret connection --known-host`) for a host its `--host` allowlist admits. It refuses a sign request on an unbound connection — from `ssh-keygen -Y sign`, from a client older than 8.9 or from any other program that opens the socket — and a bound one for a host outside the pins or the allowlist; an unbound connection still lists the keys (`ssh-add -L`). Each signature writes one `secret.use` row (`context: "ssh_agent"`, the host as the pin names it, the key type) and each refusal a failed row with its code (`SSH_AGENT_UNBOUND`, `HOST_NOT_ALLOWED`) — never the key, the signature or the session identifier. The vault user generates the key without a passphrase (an encrypted OpenSSH key is refused at import), imports it and removes the private file — the `.pub` beside it is what the remote registers, as a repository's deploy key for instance; then pins the remote's host keys — each type it publishes, or at least the one the consumer's own `known_hosts` holds, since the client binds with the key type that file selects (`--known-host` repeats) — opts the secret in, grants it and starts the socket beside the other listeners:

```bash
sudo -u harpoc ssh-keygen -q -t ed25519 -N '' -C gh-deploy -f /var/lib/harpoc/gh-deploy
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc secret set gh-deploy --from-file /var/lib/harpoc/gh-deploy
sudo -u harpoc rm /var/lib/harpoc/gh-deploy
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc secret connection secret://gh-deploy --known-host "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc secret allow secret://gh-deploy --host github.com --ssh-agent-socket
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc policy grant secret://gh-deploy --principal-type agent --principal-id agent1 --permissions use
sudo -u harpoc env HARPOC_SESSION_KEYSTORE=off harpoc --vault-dir /var/lib/harpoc server start --rest --session memory --runtime-dir /run/harpoc --ssh-agent
```

The consumer points `SSH_AUTH_SOCK` at its socket and gives each key a `Host` alias that offers that key alone: a remote that binds one key to one resource — a GitHub deploy key opens one repository — would otherwise be offered the agent's keys in order, and authenticating with one key does not open the other's resource. `harpoc ssh-agent status` lists each consumer socket and its keys (type, fingerprint, handle) and opens no vault; `ssh-add -L` prints the public halves with the handle as the comment, which the alias's `IdentityFile` names:

```bash
export SSH_AUTH_SOCK=/run/harpoc/agent1/ssh-agent.sock
harpoc ssh-agent status --runtime-dir /run/harpoc --consumer agent1
ssh-add -L | grep ' secret://gh-deploy$' > ~/.ssh/gh-deploy.pub
```

```text
Host github-deploy
  HostName github.com
  User git
  IdentitiesOnly yes
  IdentityFile ~/.ssh/gh-deploy.pub
```

`git clone git@github-deploy:org/repo.git` then offers that one key, and the socket signs for it. A `Permission denied (publickey)` preceded by `Load key "…/gh-deploy.pub": invalid format` means the socket offered no key for the host the client reached: the secret pins none of the host keys the client accepted, allowlists another host, or is not granted.

**The unlock key.** A daemon that must come back after a reboot without a person unlocks from a machine-bound key instead of the password. `harpoc unlock-key enroll` gives the key-encryption key a second slot: wrapped with AES-256-GCM under a random 256-bit unlock key, beside the slot the password-derived master key wraps — no key derivation, so what the database alone gives a reader is unchanged. Enrolment unlocks with the password and writes the key once, to the file `--out` names (`0400`), never to the terminal; the key is handed to a sealer the vault never learns about, and `server start --unlock-credential <name>` reads it back from `$CREDENTIALS_DIRECTORY/<name>` before the vault opens — refused when the variable is unset. On Linux the sealer is systemd's credential store: enrol as the vault user, seal the key as root with `deploy/linux/enroll-unlock-key.sh` — `systemd-creds encrypt` into `/etc/credstore.encrypted/harpoc-unlock.cred`, checked to decrypt, the plaintext file then removed with `shred -u` — and install `deploy/systemd/harpoc.service`, whose `LoadCredentialEncrypted=` decrypts the key into the unit's `$CREDENTIALS_DIRECTORY` at every start (systemd 250 or later):

```bash
sudo -u harpoc env HARPOC_SESSION_KEYSTORE=off harpoc --vault-dir /var/lib/harpoc unlock-key enroll --out /var/lib/harpoc/unlock.key
sudo deploy/linux/enroll-unlock-key.sh /var/lib/harpoc/unlock.key
sudo install -m 0644 deploy/systemd/harpoc.service /etc/systemd/system/harpoc.service
sudo systemctl daemon-reload
sudo systemctl enable --now harpoc
sudo -u harpoc env HARPOC_SESSION_KEYSTORE=off harpoc --vault-dir /var/lib/harpoc unlock-key status
```

The recipe seals in systemd-creds' own default mode, `auto` — the TPM2 and the host key where a TPM2 is usable, the host key alone otherwise — and prints what systemd reports about the TPM2; `tpm2` and `host+tpm2` can be named, and `host`, the root-readable `/var/lib/systemd/credential.secret` alone, only explicitly. As systemd documents it, from systemd 262 on `systemd-creds` also pins a credential it seals with the TPM2 to that TPM's storage root key, so a man-in-the-middle between the machine and its TPM cannot read the unsealed key — a physical attack the threat model already excludes, so no residual below changes; this project has not measured it. A credential sealed that way does not decrypt under an older systemd, and one sealed before 262 keeps decrypting without the pin until its key is sealed again; `host` mode involves no TPM2 and is unaffected. The unit runs `server start --rest --session memory --unlock-credential harpoc-unlock --runtime-dir /run/harpoc` as `harpoc`, restarts it on failure and gives up after three starts in two minutes — a wrong or revoked key fails every start, and each failure counts against the lockout the password shares; it expects the CLI at `/usr/local/bin/harpoc` and the checkout outside `/home` and `/root` (it sets `ProtectHome=yes`): adjust `ExecStart=` otherwise. The daemon writes no session file (**The memory session and token rotation**, below), so the administrator's commands after it, `unlock-key status` among them, run on the administrator's own session — the one `enroll` wrote, or a new `unlock`. Elsewhere any sealer that writes the 32 bytes to a file only the vault user can read serves through `server start --unlock-key-file <path>` — a Compose secret under `/run/secrets/`, a LaunchDaemon reading the key from the macOS System keychain, a file a KMS key unwraps at boot: documented, not built. On Windows the sealer is DPAPI under the vault's own account, read in process by `server start --unlock-key-dpapi <path>` (**The Windows deployment**, below). `--unlock-key-file` refuses a symbolic link, a file that is not exactly 32 bytes and one its group or other users can read (on Windows, one whose access list grants another account), and warns at every start: `Warning: --unlock-key-file is a password file by another name: without a sealer, whoever can read <path> unlocks the vault.` Every unlock from the key writes the `vault.unlock` row with `method: "credential"` (the password unlock's row is unchanged), enrolment and revocation write `vault.unlock_key.enroll` and `vault.unlock_key.revoke`, and a wrong key is refused `INVALID_UNLOCK_KEY` and counts against the same lockout as a wrong password. `unlock-key enroll` on a vault that has a key replaces it: seal the new file and restart the unit. `unlock-key revoke` deletes the slot, after which the credential opens nothing: `systemctl disable --now harpoc` and remove `/etc/credstore.encrypted/harpoc-unlock.cred`.

**The memory session and token rotation.** `server start --session memory` keeps the keys of the daemon's unlock in the daemon's memory alone. Started from the unlock key it writes no session file; started after an administrator's `unlock` it reads that session file once, at the start, and leaves it to the administrator. Nothing then seals the daemon but an explicit lock — no idle timeout, no 24-hour ceiling: an unlocked daemon is bounded by its uptime and the lock (**Locking.**, below) instead of by a session clock. Every model B flag requires it: `--issue-token`, `--unlock-credential`, `--unlock-key-file`, `--proxy` and `--ssh-agent` without `--session memory` are refused `SESSION_MODE_CONFLICT` before the vault opens, since a daemon on a session file seals when that file expires or an administrator's unlock replaces it. `--session file` stays the default and model A's mode; `--runtime-dir` alone does not need the memory session. With `--issue-token <spec>` — repeatable, one per consumer — the daemon issues each consumer's token itself: it mints the token into the named file once at the start, before any listener accepts a request, and again at half its lifetime, so the file always holds a token with at least half its lifetime left. The file is written under a temporary name and renamed over the old one, mode `0640`, and takes the consumer's group from the set-group-ID consumer directory, as `auth token --out` and `chmod 0640` give it above:

```bash
sudo -u harpoc env HARPOC_SESSION_KEYSTORE=off harpoc --vault-dir /var/lib/harpoc server start --rest --session memory --runtime-dir /run/harpoc --issue-token agent=agent1,file=/run/harpoc/agent1/token.jwt,scope=use+list,secrets=api-key
```

A spec is comma-separated `key=value` pairs, each key once: `agent` (a registered, active agent), `file` (an absolute path in an existing directory), `scope` and `secrets` — lists joined with `+`, as in `scope=use+list` or `secrets=db-*+api-key` — and `ttl`, the lifetime in minutes (1 to 1440, the default 1440); the daemon refuses to start when a spec's agent is unknown or deactivated or its file cannot be written, or when the file or its directory is a symbolic link or junction — only the final component of the directory is judged, so a link higher up is accepted, and a file placed directly in a directory the system links (`file=/tmp/x.jwt` on macOS, where `/tmp` is a link to `/private/tmp`; `file=/var/run/x.jwt` on Linux, where `/var/run` is a link to `/run`) is refused: name the real directory. The directory that holds the file is judged, under every flag and before the vault opens, as a consumer directory is (since 2026-11-11): on POSIX its owner must be the daemon's uid and its mode must grant nothing to others and no write to the group (`0700`, `0750` and `02750` start; `0755` and `0770` are refused); on Windows see **The Windows deployment**, below. The POSIX group of a token directory, like a consumer directory's, is not judged. Each mint writes the `token.create` row `auth token` writes, with `rotation: true` — the `jti` and the principal, never the token. The consumers read the file at every use — `harpoc --url … --token-file` once per command, `harpoc-mcp --url … --token-file` once per tool call — so neither needs a restart after a rotation; a shell that exported the token, as the git recipe's `GIT_CONFIG_VALUE_1` does, keeps the one it read until that token expires, and should read the file per command instead. A rotation revokes nothing: the previous token stays valid until its own expiry. Revocation ends a consumer's rotation: `auth revoke <jti>` of the token in the file (`auth list --agent <agent>` shows the jti), or `agent deactivate` or `agent delete`, which revoke every live token of the agent, refuses the consumer's next call at once and the next re-mint — a failed `token.create` row with the code and one `Warning: --issue-token agent=<agent>: <code>` line on the daemon's standard error — and the daemon rotates that consumer no more. At its next start the daemon mints a fresh token for a consumer whose token was revoked, while a deactivated or deleted agent's spec refuses the start until it is removed — under the unit three failed starts in two minutes stop the service, so remove a consumer's `--issue-token` from `ExecStart=` before deactivating or deleting its agent. Under the unit the specs join its `ExecStart=` line — a drop-in from `systemctl edit harpoc` first clears the unit's own with an empty `ExecStart=`, since a `Type=exec` service takes exactly one command. On Windows the token file inherits the consumer directory's access list in place of its group (**The Windows deployment**, below).

**Locking.** A daemon in the memory session holds no session file after its start, so `harpoc lock` as the vault user — which erases the session file — locks the administrator's own session and leaves the daemon serving, and so does every command that unlocks with the password (`unlock`, `unlock-key enroll`, `unlock-key revoke`): it writes the administrator's session, not the daemon's. Lock the daemon over REST, at once, with an admin-scoped token — `harpoc --url http://127.0.0.1:3000 --token-file <admin token file> lock`, which is `POST /api/v1/vault/lock` — or stop it with `SIGTERM` (`systemctl stop harpoc` for the unit); a use-scoped token is refused (`403`). The REST lock seals the daemon in place: it keeps listening and answers `VAULT_LOCKED` until it is started again. `SIGTERM` writes each listener's `server.stop` row, wipes the keys and exits. A daemon without `--session memory` — model A's `server start`, or `--runtime-dir` alone — runs on the session file as before: `harpoc lock` and the administrator's password unlocks seal it at its next session check (within 30 seconds), and so does the session's own expiry (15 minutes idle, 24 hours at most).

**The consumer rule.** The `process` context of `use_secret` stays for vault-owned work — anything that may run as `harpoc`. For agent-owned work a consumer must not call it: the child would run the agent's command under the vault's UID. The corollary is stricter: a secret whose command allowlist holds an acknowledged interpreter or exec wrapper (`secret allow --acknowledge-interpreter`) runs agent-authored programs as `harpoc`, and **model B collapses to model A for that secret** — such a program can read the vault directory and the session file.

**Vault-owned git.** The `git` context of `use_secret` runs git as `harpoc` too, so under model B it serves the vault's own working trees — a mirror or a deploy checkout the vault user owns — while an agent's own `git` takes the egress proxy or the agent socket (above) and runs its own hooks under its own UID. In every operation the credential reaches only the steps that talk to the remote, each in a relay repository the vault writes for the call and re-checks before and after the step; every step that runs in the working tree runs without it, and no hook of the tree runs in any step. A `fetch` brings the remote's branches into the relay — every branch, or those each `--refspec` names: `refs/heads/<name>` or `refs/tags/<name>`, one `*` allowed, a leading `+` to take a rewritten branch and a leading `^` to leave one out, never a short name or a destination — and then, in a step without the credential, moves the remote-tracking refs of the tree's remote for that repository (`refs/remotes/<remote>/…`) and the tags that come with them; the tree's local branches, its checked-out files and its configuration stay as they were, and no submodule is fetched. Quote each `--refspec` value on the command line, since a POSIX shell expands an unquoted `*`; and a leading `^` is cmd.exe's escape character, so wherever the command passes through cmd.exe — a `.cmd` launcher included — the `^` has to reach cmd.exe inside double quotes: `"^refs/heads/wip"` typed in cmd.exe, `'"^refs/heads/wip"'` typed in Windows PowerShell 5.1 (both measured); an unprotected `^` is dropped without an error and the exclusion becomes a ref to fetch, and `--action-file <path>` takes the whole action from a JSON file no shell rewrites. That remote is the one whose URL is exactly the `--repository` value: a URL that differs by a trailing `/` or `.git` does not match, and a tree with no such remote, or with two, is refused; and a pull, a push or a fetch refuses a working tree whose ref listing exceeds the vault's 1 MiB output cap (`GIT_OPERATION_FAILED`). Git's own fetch options go in as `--arg` values — `--arg --prune` (it prunes only within what the refspecs name), `--arg --depth=<n>`, `--arg --tags`. An `ls-remote` lists the remote's refs and needs no working tree: the refnames and object ids come back as the remote sent them, the credential redacted and the output capped like every git result, and since the command's summary previews an output on one line, `--json` carries the listing whole. Refused, each with a failed audit row: a repository that begins with `-`, a repository whose SSH host is not a host name or, in an `ssh://` URL, an IPv6 literal, a repository whose SSH user is not a name of letters, digits, `.`, `_` and `-` that begins with a letter or a digit (one leading `[` of an scp-form user is dropped first, so `[git@host:2222]:org/repo.git` still passes; a percent-encoded user is refused), an `ssh://` address with a password, a repository that is not a string or that begins or ends with whitespace, and `--upload-pack`, on both as on every operation; on a fetch the options that would move the checked-out branch (`--update-head-ok`), fetch other remotes (`--multiple`, `--all`), read refspecs from standard input (`--stdin`), pick their own destinations (`--refmap`) or write the tree's configuration (`--set-upstream`, `--filter`); a positional argument on either; a `--cwd` on an `ls-remote`; a `--refspec` on any other operation. A consumer fetches one branch with a prune, and lists the remote's branches as JSON, through the REST mode:

```bash
harpoc --url http://127.0.0.1:3000 --token-file /run/harpoc/agent1/token.jwt secret use secret://gh-pat --action git --operation fetch --repository https://github.com/org/repo.git --cwd /var/lib/harpoc/mirrors/repo --refspec "refs/heads/main" --arg --prune
harpoc --url http://127.0.0.1:3000 --token-file /run/harpoc/agent1/token.jwt secret use secret://gh-pat --action git --operation ls-remote --repository https://github.com/org/repo.git --arg --heads --json
```

**What model B does not close.** The confused deputy: an agent uses every secret its grant allows, inside the allowlists, as far as the credential's own permissions reach. Root and any code under the `harpoc` UID read the unlocked key-encryption key, as in model A. An agent's own `/proc`, its environment and its loopback traffic are its own to read — other agent users see none of them, root sees all. The REST listener is loopback TCP, which every local user can reach: the token is the authentication on every request, and the consumer directory's mode is the second factor on the egress proxy's `proxy.sock` and the only factor on the agent socket's `ssh-agent.sock`, which takes no token; the proxy's TCP listener is token-only. Model B is single-host; a vault on another host is future work.

**What the egress proxy does not close.** The proxy is the vault: it sees every brokered request and response in the clear — the known trust-boundary expansion of every egress credential proxy. `response_mode` does not apply to a proxied response; the upstream's body reaches the client, uncapped and streamed (no `status_only`, no response-size limit). The proxy redacts the swapped value, and for a Basic credential its base64 form, where it appears as literal bytes in a brokered response's headers or body — defence in depth, never a guarantee: a compressed or otherwise encoded copy passes (a value committed to a repository travels inside git's zlib-compressed pack and reaches the clone), and a literal copy inside a framed protocol is replaced, which breaks that response (a git ref named after the value fails the clone). The base-URL form's loopback leg is plain HTTP: the request body and the token cross it, the credential never does. A client built on WHATWG `fetch` (Node's included) reports the proxy's `407` as a network error rather than a status.

**What CONNECT mode does not close.** The proxy ends the tunnel's TLS: every request and response a consumer sends through CONNECT mode — brokered or not — is in the clear inside the vault, the client's own TLS reaching the proxy rather than the host; it is the egress proxy's trust-boundary expansion (above), here over traffic the client takes for end-to-end. The CA bounds what its key can impersonate only for a client that honours name constraints: whoever reads the intermediate's key — root and code under the `harpoc` UID, which read it in the vault and in the daemon's memory as they read the unlocked key-encryption key — can issue a leaf for any listed host and its subdomains, and for any host at all to a client that ignores the constraints; every stack in the table honours them — measured, or cited where the table says so —, Java 8 only because they sit on the intermediate. An unconstrained fallback's key has no such bound for as long as it is valid — the proxy itself still tunnels the listed hosts alone, so the leaked key is the fallback's whole residual. The daemon holds the intermediate's signing key from its start until it exits: a lock seals the vault and drains the leases but leaves the proxy's copy — CONNECT then fails at authentication —, so stop the daemon to drop it. CONNECT mode is token-only, as every TCP path is: the token crosses the loopback in the clear in each CONNECT request's `Proxy-Authorization` — Basic is an encoding, not a cipher — and no directory stands as a second factor. A token in `HTTPS_PROXY` lives in the client's environment — the agent's own to read, other agent users' not — and stays valid until its expiry after the daemon has rotated the file, as an exported token does; on a command line (`curl --proxy http://harpoc:<token>@…`) every local user could read it. A host outside the constraints is refused before any TLS: a consumer whose client needs one uses the base-URL form, or the vault user creates the CA again with the host added — a new root every consumer must trust anew. Inside the tunnel the proxy speaks HTTP/1.1 alone: a client that offers only HTTP/2 there cannot use CONNECT mode (every client measured speaks HTTP/1.1 there — Python by offering no ALPN at all). The response redaction and the absence of `response_mode` are as in the base-URL form.

**What the agent socket does not close.** The socket pins the host, not the resource: a key that opens several repositories on one host signs for each of them, and choosing the key per repository is the consumer's `Host` alias. Every process in the consumer's group can have the socket sign while it runs — the directory's mode is its only factor, since the ssh-agent protocol (RFC 9987) carries no caller identity and no token — and an agent uses each granted key as far as the remote lets it, as with every grant. Polling the socket keeps nothing alive: the daemon runs in the memory session, which has no idle timer. A host is usable only when the secret pins its key and allowlists its name. Agent forwarding through the socket is refused: a forwarded connection's bind is declined, so `ssh -A` with the socket as the agent signs nothing on the remote host — and a connection that refused a bind never binds afterwards, and one that refused a forwarding bind also lists no key. A bastion is reached with `ssh -J` (ProxyJump) instead: ssh opens each hop as a direct session of its own, so the socket signs for a hop when the secret pins that hop's host key and allowlists its host — measured with OpenSSH, a jump host and its target each signed for, one `secret.use` row per host and no row of reason `forwarding`; a hop whose host key the secret does not pin is denied without a signature. A server disconnects a client after `MaxAuthTries` failed keys (six by default) and the client offers the agent's keys in order; a bound connection lists only the keys that pin the connected host, and a consumer granted more than six of those for one host needs the `IdentitiesOnly` alias above. The socket signs SSH authentication requests only — `ssh-keygen -Y sign` (and commit signing through it) is refused. A bind presenting a host certificate, an `ssh-mldsa44-ed25519` host key or a SHA-1 `ssh-rsa` signature is refused, and a hashed `known_hosts` pin (`HashKnownHosts`) never binds — the pin must spell the host. On Windows the socket is a named pipe per consumer, whose reach is its access list (**What the Windows deployment does not close**, below).

**What the unlock key does not close.** Whoever has the machine boots it and the credential unseals: the unlock key relies on the threat model's exclusion of physical access. The recipe sets no PCR policy (`systemd-creds --tpm2-pcrs=`), so a modified boot of the same machine unseals too. In `host` mode the sealed key is as safe as the root-only `/var/lib/systemd/credential.secret`: whoever reads both unseals the key on any machine. `--unlock-key-file` without a sealer is a password file by another name, and its mode check means nothing on a file system that does not enforce modes — on Linux the daemon warns when the key file sits on such a mount. `shred -u` is best effort on journaling, copy-on-write and flash storage. The daemon runs in the memory session, so no idle seal or 24-hour ceiling intervenes; a daemon locked over REST keeps running sealed — `Restart=on-failure` restarts only a process that has exited — answering `VAULT_LOCKED` until `systemctl restart harpoc` unlocks it from the key again.

**What the memory session and token rotation do not close.** The keys the daemon unlocked stay in its memory as long as it runs: no idle seal and no 24-hour ceiling stand between a long-running daemon and root or code under the `harpoc` UID, which read them as they read the unlocked key-encryption key before — the bound is the daemon's uptime and an explicit lock, and a locked or stopped daemon unlocks again only at its next start. A token file read by anyone but its consumer — another member of the consumer's group, root, a backup — yields a token valid until its own expiry, at most the spec's `ttl` and never more than 24 hours, whether or not the daemon has rotated it since: rotation bounds how long a token lives and revokes none; revocation is unchanged. A daemon that is not running rotates nothing, and its consumers' tokens run out at most one `ttl` after its last mint. A host that sleeps delays a re-mint by the time it slept: a sleep longer than half the lifetime leaves the consumer with `TOKEN_EXPIRED` until the late re-mint. A daemon killed between the temporary's write and its rename leaves `<file>.<hex>.tmp` beside the token file, at the token file's mode and group, holding a complete token that dies at its `exp`; nothing sweeps it — an operator removes it by hand.

**Identity tokens and third-party secrets.** An agent's own identity — its chat-channel bot token, its model provider's OAuth token — is what makes the process the agent: the agent must present it, so it cannot be hidden from the agent, only kept off its disk, and whoever controls the agent process can act as the agent in either model. Model B brokers **third-party** secrets — the credentials an agent uses on someone else's API — and leaves identity tokens with the principal that holds them by definition.

**The Linux loop.** `deploy/dev-container/run.sh` (bash; Git Bash on Windows) builds a Debian container with Node 24, runs the recipe in it twice (the idempotence check), copies the working tree in, installs and builds, and runs the whole suite (`pnpm test --force --concurrency=1`) as a local Linux leg requiring the ubuntu leg's tiers (`HARPOC_DEV_TIERS` narrows them) — the two-UID suite included, as the vault user `harpoc` and the agent user `agent`; `run.sh shell` opens a shell there instead (it needs a terminal). It refuses, exit 75, when another container is running on the `harpoc-dev-work` volume or, on a Linux or Git Bash host, when the host's available memory is under `HARPOC_DEV_MIN_AVAILABLE_MB` megabytes (default `8192`; `0` switches the check off).

**The Windows deployment.** Model B runs on Windows with access lists in place of modes: the vault runs as a local account of its own, `harpoc`, and each agent under a local account of its own. Run the recipe once per host from an elevated Windows PowerShell, naming the agent accounts — existing local users; the recipe creates none of them:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File deploy\windows\install-two-identity.ps1 -AgentUser agent1,agent2
```

The three recipes (`install-two-identity.ps1`, `enroll-unlock-key.ps1`, `register-service.ps1`) run under Windows PowerShell 5.1: each turns module auto-loading off and imports the in-box modules it calls by full path under `$PSHOME`, and a module that is not found there — PowerShell 7 lacks two of them — ends the script with exit 1 (`the in-box module <name> was not found under <PSHOME>`) before any account, grant, registration or write. `install-two-identity.ps1` is idempotent, asks once for the password of the `harpoc` account it creates (a `SecureString` prompt, never a command-line argument; the account's password never expires, it joins Users alone and must not be an administrator, and an existing account's password is left as it is), and creates the vault directory `%ProgramData%\harpoc\vault` and the runtime directory `%ProgramData%\harpoc\run`, each with its inherited entries removed (`icacls /inheritance:r`) and full control, with inheritance, for `harpoc`, SYSTEM and Administrators alone (`%ProgramData%\harpoc` itself is set the same way, and no agent holds an entry on it or on `run`), and one consumer directory per agent account, `%ProgramData%\harpoc\run\<agent>`, which adds read-and-execute, with inheritance, for that agent alone — nothing on `run` itself: a file the vault writes there, the token file among them, inherits these entries, so its agent reads it and no other account does. An agent account's name is its consumer name: lowercase letters, digits, `_` and `-`, not dash-led, and never a Windows reserved device name (`con`, `prn`, `aux`, `nul`, `com1`–`com9`, `lpt1`–`lpt9`), which the recipe and the daemon refuse — a consumer so named works on Linux and is refused here. `server start --runtime-dir` lists these access lists before the vault opens and refuses a directory whose owner is not `harpoc`, SYSTEM or Administrators and one whose access list grants any other account — on a consumer directory, its own agent excepted, with read-and-execute at most. The directory of an `--issue-token` file is judged the same way since 2026-11-11, under every flag: its owner must be the account the daemon runs as (`harpoc` here), SYSTEM or Administrators, and its access list may grant no account beyond those three but the token's own agent, with read-and-execute at most; the agent's name is read as a local account's name, so register the agent under its consumer account's name; an agent name that resolves to no local account is accepted only when the list grants nobody else, and one that resolves to something that is not a user account is refused (`INVALID_INPUT`, `--issue-token: file <file>: <reason>: <directory>`). A junction is refused there as on every platform: as the runtime directory, as the token file's directory and in place of the token file, and, under `--proxy` or `--ssh-agent`, as a consumer directory or any other entry of the runtime directory; `%ProgramData%\harpoc\run` is the default under `--ssh-agent`.

Administer as `harpoc` in a console of its own — `runas /user:harpoc powershell`, or `Start-Process -Credential` — where the session file `unlock` writes is protected by DPAPI under `harpoc`'s own key, so `HARPOC_SESSION_KEYSTORE=off` is not needed; enrol the unlock key there, sealed by DPAPI under `harpoc` and never written in the clear (`deploy\windows\enroll-unlock-key.ps1` asks for the vault account's Windows password and then, in a console running as that account, for the master password, and writes `%ProgramData%\harpoc\vault\unlock.key.dpapi` sealed with DPAPI for that account — no plaintext key file at any step), then register the startup task as an administrator:

```powershell
# as harpoc (runas /user:harpoc powershell)
harpoc --vault-dir C:\ProgramData\harpoc\vault init
harpoc --vault-dir C:\ProgramData\harpoc\vault agent register agent1
harpoc --vault-dir C:\ProgramData\harpoc\vault unlock-key enroll --out C:\ProgramData\harpoc\vault\unlock.key.dpapi --dpapi
# as an administrator
powershell.exe -NoProfile -ExecutionPolicy Bypass -File deploy\windows\register-service.ps1 -Proxy -SshAgent -IssueToken agent=agent1,file=C:\ProgramData\harpoc\run\agent1\token.jwt,scope=use+list,secrets=api-key
```

`register-service.ps1` registers the scheduled task `Harpoc`, started at boot as `harpoc` with the password the Task Scheduler stores for it (it asks for that password as a `SecureString`, never on a command line; the task has no execution time limit, runs on battery, allows one instance and restarts at most twice, a minute apart), which runs the built CLI, `node <cli>\dist\index.js` — `<cli>` is `%ProgramFiles%\harpoc\packages\cli` unless `-Cli` names it — as `--vault-dir C:\ProgramData\harpoc\vault server start --rest --session memory --unlock-key-dpapi C:\ProgramData\harpoc\vault\unlock.key.dpapi --runtime-dir C:\ProgramData\harpoc\run` with `--proxy`, `--ssh-agent` and the `--issue-token` specs it is given (`-Proxy`, `-SshAgent`, `-IssueToken`). Before it asks for that password it grants `harpoc` the user right Log on as a batch job (`SeBatchLogonRight`), unless the account holds it already — the Task Scheduler starts a task with a stored password through a batch logon, which a member of Users alone may not make by default — and stops if the account itself is denied that right; the right stays granted if the registration then fails or is aborted, until `-Unregister` removes it. `register-service.ps1 -Unregister` (`-VaultUser` alone, elevated) removes the task `Harpoc` from the Task Scheduler's root folder and takes the right from the account — also where the account held it before the script ran — (for an account that no longer exists it removes the task alone: run it before the account is deleted) and leaves the account, the layout and the sealed key; it does not stop a running daemon. `--unlock-key-dpapi` refuses a sealed file whose access list grants another account, as `--unlock-key-file` does on Windows, and unseals it under the task's account through the Windows PowerShell host that already protects the session file — the plaintext key reaches no disk, and a file another account sealed is refused `INVALID_UNLOCK_KEY`, a refusal that does not count against the lockout. `Stop-ScheduledTask -TaskName Harpoc` ends the process at once — no `server.stop` row is written, as `SIGTERM` writes on Linux — so lock the daemon first (`harpoc --url … lock`, **Locking.**, above), then stop it; `Start-ScheduledTask` after a reboot or a stop unlocks from the sealed key again.

The agent's side is the Linux one with Windows paths — `harpoc --url http://127.0.0.1:3000 --token-file C:\ProgramData\harpoc\run\agent1\token.jwt secret list`, and `harpoc-mcp` with the same pair. The egress proxy is its TCP listener alone: Windows has no `proxy.sock`, so `harpoc proxy env agent1 secret://api-key --runtime-dir C:\ProgramData\harpoc\run` prints the proxy's address, the base-URL form, the token file's path, CONNECT mode's CA file and trust variables and the placeholder, and no `HARPOC_PROXY_SOCKET`: on Windows the proxy is the loopback TCP listener with the token, there is no `proxy.sock`, and the token is the only factor, so every request carries it. In CONNECT mode `ca.pem` inherits the consumer directory's entries as the token file does, and `proxy env` prints two `#` lines for the two settings no variable carries on Windows: curl, built on Schannel, takes the root only from `--cacert` with `--ssl-revoke-best-effort` — or from the two lines `cacert = C:\ProgramData\harpoc\run\agent1\ca.pem` and `ssl-revoke-best-effort` in `%USERPROFILE%\.curlrc` —, and Git for Windows reads `GIT_SSL_CAINFO` only with `http.schannelUseSSLCAInfo=true` and, unless its backend is set explicitly, checks revocation strictly (`git config --global http.sslBackend schannel` and `git config --global http.schannelUseSSLCAInfo true`, or `-c` both per command). A GitHub CLI built on Go 1.26 or older — 2.87.0 on Go 1.25.7, for instance — ignores `SSL_CERT_FILE` on Windows: the operator imports the root into the agent account's own certificate store, which Windows asks the account to confirm. The agent socket is one named pipe per consumer, `\\.\pipe\harpoc-<agent>-ssh-agent`, which `harpoc ssh-agent status` names and probes and which the consumer sets in `SSH_AUTH_SOCK` (an `ssh_config` `IdentityAgent` line must double every backslash); only the native `C:\Windows\System32\OpenSSH\ssh.exe` speaks the pipe, so `C:\Windows\System32\OpenSSH` goes ahead of Git's `usr\bin` on the agent's `PATH` (Git Bash callers also need `MSYS_NO_PATHCONV=1`), and the `Host` alias of the Linux recipe applies unchanged:

```powershell
$env:SSH_AUTH_SOCK = '\\.\pipe\harpoc-agent1-ssh-agent'
harpoc ssh-agent status --runtime-dir C:\ProgramData\harpoc\run --consumer agent1
ssh-add -L
```

A host with one account cannot show the boundary between two: the evidence is the `two-identity-windows` job of `e2e.yml` on `windows-latest`, which creates the vault and agent accounts, runs the recipe twice and drives the daemon from the agent account, and measures the command-line channel — the agent account's process listing shows the vault process's command line, its paths, ports and each `--issue-token` spec (the consumer, its token file, the names of the secrets it may use, scope and lifetime) but never a secret, since none is ever passed on a command line — while it cites the environment block's protection (`PROCESS_VM_READ` is denied without `SeDebugPrivilege`) rather than reading it.

**What the Windows deployment does not close.** Administrators and SYSTEM read everything, as root does on Linux: the recipe grants them full control of every directory, and `SeDebugPrivilege` — a right Windows gives the Administrators group by default — opens any process for full access, the daemon's memory included. Whoever can run code as the vault account unseals the unlock key: DPAPI's `CurrentUser` scope binds the sealed key to that account's logon credentials on this machine, not to a boot measurement — there is no TPM binding, and a modified boot of the same machine unseals it too — while the `LocalMachine` scope, under which any process on the computer could unseal it, is never used. The `harpoc` account's password unseals as well: the Task Scheduler stores it to start the task, the administrator who chose it knows it, and whoever holds it can log on as `harpoc`. The agent socket's pipe has its access list replaced by the daemon after it opens the pipe — the vault account, SYSTEM and Administrators, and the consumer's account for reading and writing — and the daemon refuses to start if it cannot; pipe names are a global namespace every local account can list, a process may create the name while the daemon is down (the daemon then refuses to start), and the list is set a moment after the pipe opens, during which the consumer cannot yet connect; the ssh-agent protocol carries no token, so that access list is the pipe's only factor. The egress proxy and the REST API are loopback TCP and token-only: with no `proxy.sock` on Windows, no directory stands as a second factor. A token file is readable by its agent, the vault account, SYSTEM and Administrators — the consumer directory's inherited entries — and, read by anyone else, stays valid until its expiry, as on Linux. The agent account can read the vault process's command line through the process list; it carries its paths, ports and each `--issue-token` spec (the consumer, its token file, the names of the secrets it may use, scope and lifetime) but no secret, and on a daemon that issues tokens for several consumers every agent account reads every consumer's spec. A stop of the task ends the process at once and writes no `server.stop` row (lock the daemon first); the keys end with the process. The startup task's start is measured on the `windows-latest` runner alone (Windows Server 2025, 2026-11-10), and on demand: with the right to log on as a batch job granted by `register-service.ps1`, `Start-ScheduledTask` launched `Harpoc` as `harpoc` and the daemon unsealed the key and answered `unlocked`, and `register-service.ps1 -Unregister` removed the task and the right again; six earlier runs, without the grant, registered the task and never launched it (`LastTaskResult` 0x00041303), and before the grant a batch logon as `harpoc` was refused (Win32 error 1385) — a member of Users alone does not hold that right by default. The start at a real boot is not measured — after one, `Get-ScheduledTaskInfo -TaskName Harpoc` shows whether the task ran, and the health route answers `unlocked` once the daemon is up. A denial of the batch logon that reaches `harpoc` through a group, or a domain policy that defines that right without `harpoc`, still keeps the task from starting: the script sees only the account's own entries. The install recipe lists the Administrators and Users groups with `Get-LocalGroupMember`, which fails on a host whose groups hold members the machine cannot resolve; the install then stops before it sets any directory — nothing of the layout is half-applied, though a vault account the run has just created stays. The boundary between two accounts is measured on the `windows-latest` runner, not on a developer's single-account host, and the dev container's Linux loop has no Windows counterpart.

## Tech Stack

TypeScript (strict mode, ESM-only) · pnpm + Turborepo · SQLite (better-sqlite3, WAL mode) · AES-256-GCM + Argon2id (`node:crypto` + `argon2`) · Zod · undici · `@modelcontextprotocol/server` / `client` (MCP SDK v2) · pg / mysql2 (lazy-loaded) · Vitest

## License

[BSL 1.1](LICENSE) — code is publicly visible and auditable. Commercial use as a hosted service is restricted. Each release converts to Apache 2.0 after 3 years.
