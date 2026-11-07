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
| `@harpoc/egress-proxy` | Egress credential proxy — swaps a placeholder for the credential at the egress hop, plain-HTTP rewrite mode (CLI: `harpoc server start --proxy`, `harpoc proxy env`)                  | Complete |
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

- **3-tier key hierarchy**: password → master key (Argon2id) → KEK (AES-256-GCM key wrap) → per-secret DEK (random). JWT and audit keys are independently generated and wrapped with the KEK. Password change is O(1) — only re-wraps the KEK; all other keys remain unchanged.
- **AES-256-GCM** with authenticated additional data (AAD) binding per secret ID, preventing ciphertext substitution.
- **Argon2id** with the RFC 9106 first recommended (high-security) profile (2 GiB memory, 1 iteration, 4 lanes) — sized against the offline at-rest attacker, for whom memory per guess is the security margin; the cost is paid once per session unlock.
- **Password validation**: minimum 8-character length enforced on vault creation and password change.
- **SSRF prevention**: private IP blocking (RFC 1918, link-local, IPv4-mapped IPv6), DNS rebinding protection via pre-flight resolution with socket-level IP pinning, HTTPS enforcement, redirect validation with credential stripping on cross-origin hops and per-hop URL-allowlist re-validation.
- **Per-secret access policies, enforced at the engine**: stored policy rows grant permissions (`list`, `read`, `use`, `rotate`, `revoke`, or `admin` implying all) to principals. Every secret requires the token-derived caller to hold a matching grant — checked inside the engine on every credential operation, before anything is decrypted or injected, and covering the secret's own configuration and every enumeration surface too; a secret with no policy rows is reachable by no agent- or tool-type token until a grant exists, and a caller holding none of `read`/`list`/`admin` is told `SECRET_NOT_FOUND` exactly as for an unknown handle while the audit row records `ACCESS_DENIED`. The trusted admin path (tokenless CLI, in-process SDK, stdio MCP explicitly started `--allow-tokenless`) is exempt; `--token <jwt>` (or an ambient `HARPOC_TOKEN`) opts a CLI invocation into the token path on every command with a REST counterpart — `secret use/get/list/set/rotate/delete/allow/mcp-server/connection`, `policy grant/revoke/list`, `audit` and `oauth status/refresh` — each under the same permission the matching REST route enforces. The stdio MCP server otherwise requires a launch token at startup (`TOKEN_REQUIRED`) — the unrestricted local mode is an explicit opt-in, never a silent default.
- **Injection allowlisting** (per-secret, KEK-encrypted): a deny-by-default URL allowlist bounds request-mediated targets (http, websocket, MCP-over-HTTP, Git-HTTPS; re-validated on each redirect hop; an empty list refuses every target), a fail-safe command allowlist bounds process-mediated binaries (pinned to a resolved absolute path; known interpreters require explicit acknowledgement, and so do exec wrappers such as `sudo` or `xargs`), and a deny-by-default host allowlist bounds database, SMTP, IMAP, SSH, SFTP, Git-SSH and docker-registry targets, with endpoint authentication pinned per secret (database TLS/CA policy, SSH host keys). Process execution spawns with no shell and a clean environment; the process context refuses any binary that has a dedicated context (`DEDICATED_CONTEXT_REQUIRED`), and Git-over-HTTPS keeps the credential bound to the validated host (host-bound askpass, redirects off, submodule recursion denied, denied-argument matching mirroring git's option abbreviation).
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

The vault runs as a dedicated system user, `harpoc`; each agent runs under an OS user of its own and reaches the vault only over REST or MCP over HTTP, with a token. Nothing an agent user can read holds a key or a plaintext: the vault directory is `0700 harpoc`, the session file `0600 harpoc`, and every child the vault spawns runs as `harpoc`, so its environment is out of the agent's reach.

Not in this build (2026-11-06, later): the memory session that keeps the daemon's keys out of any file (`server start --session memory`), the machine-bound unlock credential that starts the daemon after a reboot without a human, issuer-side token rotation into the consumer directories, and the egress proxy's CONNECT mode for clients that honour only `HTTPS_PROXY`. Until they land the daemon runs in file session mode — it reads the session file the administrator's unlock wrote, seals when that session expires (15 minutes idle, 24 hours at most) and needs a person to unlock again — and an agent's own tools get a credential from the vault only through the egress proxy's rewrite mode (`git`, `curl`, SDKs whose base URL can be pointed at it) and, for SSH, a signature through the agent socket (both below).

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
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc policy grant secret://api-key --principal-type agent --principal-id agent1 --permissions use
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc auth token --agent agent1 --scope use --ttl 1440 --out /run/harpoc/agent1/token.jwt
sudo -u harpoc chmod 0640 /run/harpoc/agent1/token.jwt
```

`harpoc` here is the built CLI and `harpoc-mcp` the built MCP server (`packages/cli/dist/index.js` and `packages/mcp-server/dist/index.js` of a checkout every one of these users can read), linked into a directory on `sudo`'s `secure_path` such as `/usr/local/bin`. Pass `--vault-dir` on every command: without it the CLI looks for `.harpoc` in the administrator's working directory first. Under `sudo` there is no D-Bus session and the kernel keyring is not one the vault user possesses, so `init` and `unlock` answer `SESSION_KEYSTORE_UNAVAILABLE` (measured on Debian 12): run the administrative commands as `sudo -u harpoc env HARPOC_SESSION_KEYSTORE=off harpoc …` — the session file is then protected by its `0600` mode under the `harpoc` UID alone, which is the boundary model B draws. A failed `init` leaves `default.vault.db` behind and a retry reports an existing vault; remove the file before retrying. A token expires within 24 hours; re-mint it the same way (`--out` refuses an existing file, so remove the old one first).

**The daemon**, as the vault user (loopback only, port 3000 by default; `--runtime-dir` refuses a runtime directory that is not `harpoc`'s own and `0750` or stricter, reads systemd's `$RUNTIME_DIRECTORY` only under `--proxy` or `--ssh-agent`, and is refused on Windows):

```bash
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc server start --rest --runtime-dir /run/harpoc
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

**The egress proxy** (plain-HTTP rewrite mode). An agent's own HTTPS client — `git`, `curl`, an SDK whose base URL is configurable — holds a placeholder where the credential would go, `harpoc:<name>` for a secret without a project (`secret://<name>`), `harpoc://<project>/<name>` for one in a project, and sends the request in plain HTTP to the vault's proxy, which opens the TLS connection itself: `http://127.0.0.1:3128/<host>/<path>` stands for `https://<host>/<path>`. Every request carries the consumer's use-scoped token as `Proxy-Authorization: Bearer <token>` — missing it is refused `407`, an invalid one `401`, before anything goes upstream — and the proxy strips the header before forwarding. A request whose `Authorization` header (a Bearer token, or the Basic password with the request's own user kept), whose whole value of another header or whose whole value of a query parameter is a placeholder is brokered: the proxy checks the caller's `use` grant, the secret's proxy opt-in and its URL allowlist, swaps the real value in where the placeholder stood, sends the request through the SSRF floor and writes one `secret.use` row (`context: "proxy"`; the method, the origin and the path — no body, no query, no header value). For a Basic placeholder the secret's value is the password alone — the client supplies the user, as `git` does with `x-access-token`; a secret stored as `user:password` for `use_secret`'s own basic auth would be sent as `base64(<client user>:user:password)` and answered `401`. A placeholder bound for an origin outside the allowlist is refused `403` before that origin is contacted; a request without a placeholder passes through and is not audited. The proxy follows no redirect: a `3xx` goes back to the client with its `Location` pointed back at the proxy, so the next request is judged on its own origin. Each secret is rate-limited as `use_secret` is — 120 brokered requests a minute, the next refused `429`. The vault user opts a secret in and starts the listener beside the REST API:

```bash
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc secret allow secret://gh-pat --url "https://github.com/*" --proxy
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc server start --rest --runtime-dir /run/harpoc --proxy
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

The clone's `origin` stays `https://github.com/org/repo.git`. git asks each operation's first question without a credential and sends the placeholder only after the remote answers `401`, so that first request passes through unbrokered and unaudited — a public repository answers it and never sees the placeholder — and a private repository's clone or push writes one row per request that carried it (`http.proactiveAuth=basic`, git 2.46 or later, sends the placeholder at once). That first request carries no secret, so the proxy opens its TLS connection against the host's own CA store — a remote behind a private CA needs that CA in the store, or the proactive form; the secret's `--http-ca` pin applies to the brokered requests. `harpoc proxy env <consumer> <handle>… --runtime-dir /run/harpoc` prints the consumer's environment block — the proxy's address, the base-URL form, the token file's and the socket's paths and one `HARPOC_PLACEHOLDER_<NAME>` per handle; it opens no vault and prints no value and no token. `curl` takes the same base-URL form, its token header read from standard input rather than its command line; `curl --proxy` with an `https://` URL opens a CONNECT tunnel, which this build refuses (`501`):

```bash
printf 'Proxy-Authorization: Bearer %s\n' "$(cat /run/harpoc/agent1/token.jwt)" |
  curl -H @- -H "Authorization: Bearer harpoc:gh-pat" http://127.0.0.1:3128/api.github.com/user
```

**The agent socket.** An agent's own `ssh` — and `git` over SSH — authenticates with a key it never holds. `server start --ssh-agent` serves one ssh-agent socket per consumer directory, `/run/harpoc/<consumer>/ssh-agent.sock` (`0660` in the consumer's `02750` directory), offering every key the consumer holds a `use` grant on whose secret is opted in with `secret allow --ssh-agent-socket`, and it signs; it never hands a key out. Before it lists the agent's keys, OpenSSH 8.9 or later binds the agent connection to the server's host key with `session-bind@openssh.com` — the server's own signature over the session, which the vault verifies — and the socket signs only on a bound connection, only that session's authentication request, and only when the bound host key is one the secret pins (`secret connection --known-host`) for a host its `--host` allowlist admits. It refuses a sign request on an unbound connection — from `ssh-keygen -Y sign`, from a client older than 8.9 or from any other program that opens the socket — and a bound one for a host outside the pins or the allowlist; an unbound connection still lists the keys (`ssh-add -L`). Each signature writes one `secret.use` row (`context: "ssh_agent"`, the host as the pin names it, the key type) and each refusal a failed row with its code (`SSH_AGENT_UNBOUND`, `HOST_NOT_ALLOWED`) — never the key, the signature or the session identifier. The vault user generates the key without a passphrase (an encrypted OpenSSH key is refused at import), imports it and removes the private file — the `.pub` beside it is what the remote registers, as a repository's deploy key for instance; then pins the remote's host keys — each type it publishes, or at least the one the consumer's own `known_hosts` holds, since the client binds with the key type that file selects (`--known-host` repeats) — opts the secret in, grants it and starts the socket beside the other listeners:

```bash
sudo -u harpoc ssh-keygen -q -t ed25519 -N '' -C gh-deploy -f /var/lib/harpoc/gh-deploy
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc secret set gh-deploy --from-file /var/lib/harpoc/gh-deploy
sudo -u harpoc rm /var/lib/harpoc/gh-deploy
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc secret connection secret://gh-deploy --known-host "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc secret allow secret://gh-deploy --host github.com --ssh-agent-socket
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc policy grant secret://gh-deploy --principal-type agent --principal-id agent1 --permissions use
sudo -u harpoc harpoc --vault-dir /var/lib/harpoc server start --rest --runtime-dir /run/harpoc --ssh-agent
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

**Locking.** In this build the daemon runs on the administrator's session, so `harpoc lock` as the vault user — which erases the session file — seals the daemon as well, at its next session check (within 30 seconds); so does a fresh `unlock`, whose new session is not the daemon's. Without a shell as `harpoc`, lock the daemon over REST, at once, with an admin-scoped token — `harpoc --url http://127.0.0.1:3000 --token-file <admin token file> lock`, which is `POST /api/v1/vault/lock` — or stop it with `SIGTERM`; a use-scoped token is refused (`403`). With the memory session of a later build the daemon reads no session file, and `harpoc lock` reaches only the administrator's own session.

**The consumer rule.** The `process` context of `use_secret` stays for vault-owned work — anything that may run as `harpoc`. For agent-owned work a consumer must not call it: the child would run the agent's command under the vault's UID. The corollary is stricter: a secret whose command allowlist holds an acknowledged interpreter or exec wrapper (`secret allow --acknowledge-interpreter`) runs agent-authored programs as `harpoc`, and **model B collapses to model A for that secret** — such a program can read the vault directory and the session file.

**What model B does not close.** The confused deputy: an agent uses every secret its grant allows, inside the allowlists, as far as the credential's own permissions reach. Root and any code under the `harpoc` UID read the unlocked key-encryption key, as in model A. An agent's own `/proc`, its environment and its loopback traffic are its own to read — other agent users see none of them, root sees all. The REST listener is loopback TCP, which every local user can reach: the token is the authentication on every request, and the consumer directory's mode is the second factor on the egress proxy's `proxy.sock` and the only factor on the agent socket's `ssh-agent.sock`, which takes no token; the proxy's TCP listener is token-only. Model B is single-host; a vault on another host is future work.

**What the egress proxy does not close.** The proxy is the vault: it sees every brokered request and response in the clear — the known trust-boundary expansion of every egress credential proxy. `response_mode` does not apply to a proxied response; the upstream's body reaches the client, uncapped and streamed (no `status_only`, no response-size limit). The proxy redacts the swapped value, and for a Basic credential its base64 form, where it appears as literal bytes in a brokered response's headers or body — defence in depth, never a guarantee: a compressed or otherwise encoded copy passes (a value committed to a repository travels inside git's zlib-compressed pack and reaches the clone), and a literal copy inside a framed protocol is replaced, which breaks that response (a git ref named after the value fails the clone). The loopback leg is plain HTTP: the request body and the token cross it, the credential never does. A client that honours only `HTTPS_PROXY` needs CONNECT mode, a later build. A client built on WHATWG `fetch` (Node's included) reports the proxy's `407` as a network error rather than a status.

**What the agent socket does not close.** The socket pins the host, not the resource: a key that opens several repositories on one host signs for each of them, and choosing the key per repository is the consumer's `Host` alias. Every process in the consumer's group can have the socket sign while it runs — the directory's mode is its only factor, since the ssh-agent protocol (RFC 9987) carries no caller identity and no token — and an agent uses each granted key as far as the remote lets it, as with every grant. Such a process cannot keep the daemon's session alive by polling the socket: listing the keys and a refused sign request slide nothing, only a signature slides the idle timer. A host is usable only when the secret pins its key and allowlists its name. Agent forwarding through the socket is refused: a forwarded connection's bind is declined, so `ssh -A` with the socket as the agent signs nothing on the remote host — and a connection that refused a bind never binds afterwards, and one that refused a forwarding bind also lists no key. A server disconnects a client after `MaxAuthTries` failed keys (six by default) and the client offers the agent's keys in order; a bound connection lists only the keys that pin the connected host, and a consumer granted more than six of those for one host needs the `IdentitiesOnly` alias above. The socket signs SSH authentication requests only — `ssh-keygen -Y sign` (and commit signing through it) is refused. A bind presenting a host certificate, an `ssh-mldsa44-ed25519` host key or a SHA-1 `ssh-rsa` signature is refused, and a hashed `known_hosts` pin (`HashKnownHosts`) never binds — the pin must spell the host. The sockets are not served on Windows in this build.

**Identity tokens and third-party secrets.** An agent's own identity — its chat-channel bot token, its model provider's OAuth token — is what makes the process the agent: the agent must present it, so it cannot be hidden from the agent, only kept off its disk, and whoever controls the agent process can act as the agent in either model. Model B brokers **third-party** secrets — the credentials an agent uses on someone else's API — and leaves identity tokens with the principal that holds them by definition.

**The Linux loop.** `deploy/dev-container/run.sh` (bash; Git Bash on Windows) builds a Debian container with Node 24, runs the recipe in it twice (the idempotence check), copies the working tree in, installs and builds, and runs the whole suite as a local Linux leg requiring the ubuntu leg's tiers (`HARPOC_DEV_TIERS` narrows them) — the two-UID suite included, as the vault user `harpoc` and the agent user `agent`; `run.sh shell` opens a shell there instead (it needs a terminal).

## Tech Stack

TypeScript (strict mode, ESM-only) · pnpm + Turborepo · SQLite (better-sqlite3, WAL mode) · AES-256-GCM + Argon2id (`node:crypto` + `argon2`) · Zod · undici · `@modelcontextprotocol/server` / `client` (MCP SDK v2) · pg / mysql2 (lazy-loaded) · Vitest

## License

[BSL 1.1](LICENSE) — code is publicly visible and auditable. Commercial use as a hosted service is restricted. Each release converts to Apache 2.0 after 3 years.
