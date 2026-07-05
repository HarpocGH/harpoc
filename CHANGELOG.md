# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Process execution context** for `use_secret` — process-mediated injection alongside HTTP. The vault runs a command as a subprocess (no shell) with the credential in its environment, then captures and sanitizes stdout/stderr. Carries the thesis's output-channel leakage analysis and the I2b invariant.
- Per-secret injection policy (`injection_policies` table, migration 006, KEK-encrypted): a **URL allowlist** for request-mediated injection (optional; re-validated on each redirect hop) and a **command allowlist** for process-mediated injection (fail-safe deny, pinned to a resolved absolute path)
- Output sanitization for process output — redacts the credential and its base64 / base64url / hex / percent-encoded forms
- Clean-environment injection with a controlled PATH; output size cap and execution timeout
- CLI: `harpoc secret use` (`--action http | process | mcp | database | git | ssh`) and `harpoc secret allow` (set/show injection policy)
- REST: `GET` / `PUT /api/v1/secrets/:handle/injection-policy` (trusted administrative path)
- SDK: `setInjectionPolicy` / `getInjectionPolicy`
- Six error codes: `URL_NOT_ALLOWED`, `COMMAND_NOT_ALLOWED`, `PROCESS_SPAWN_FAILED`, `PROCESS_TIMEOUT`, `PROCESS_OUTPUT_LIMIT`, `INVALID_PROCESS_CONFIG`
- **MCP proxy context** for `use_secret` (`action.type: "mcp"`) — the vault as a transparent MCP proxy: forwards a single tool call (`{ server, tool, arguments }`) to a downstream MCP server, authenticating via **stdio** (downstream server spawned with the credential in a clean environment; launch command validated against the command allowlist — fail-safe deny, pinned absolute path) or **Streamable HTTP** (`Authorization: Bearer` injection; URL allowlist + SSRF/DNS validation on every outbound request). No secret value ever enters the agent's context.
- Per-secret downstream MCP server configuration (`mcp_servers` table, migration 007, KEK-encrypted), set via CLI `harpoc secret mcp-server` or REST `GET`/`PUT`/`DELETE /api/v1/secrets/:handle/mcp-server` — never via an MCP tool; `action.server` must match the configured `server_name`
- Downstream connection lifecycle (`McpConnectionRegistry`): spawn on first use, reuse across calls, terminate on every seal path (lock/destroy/session expiry/key wipe); a crash fails visibly (`MCP_SERVER_CRASHED` with exit code and signal), is audit-logged, and never auto-respawns — respawn happens on the next invocation; credential/config staleness is detected via SHA-256 fingerprints and triggers an audited terminate + fresh spawn
- Custom `StdioChildTransport` for spawning downstream servers — the MCP SDK's own stdio transport is not used because cross-spawn shell-wraps commands on Windows and force-inherits the environment; the SDK (`@modelcontextprotocol/sdk`) is now a `core` dependency. Tool results are sanitized across every string leaf (content + structured content) and size-capped
- Three audit events (`mcp.spawn`, `mcp.crash`, `mcp.terminate`) and six error codes: `MCP_SERVER_NOT_CONFIGURED`, `MCP_SERVER_MISMATCH`, `MCP_CONNECT_FAILED`, `MCP_SERVER_CRASHED`, `MCP_PROTOCOL_ERROR`, `MCP_TIMEOUT`
- **Database, Git and SSH contexts** for `use_secret` (`action.type: "database" | "git" | "ssh"`), completing the thesis's six-context taxonomy. Database (request-mediated): in-vault connection assembly for PostgreSQL (`pg`) and MySQL/MariaDB (`mysql2`) behind a lazily-loaded adapter, TLS with server-certificate verification by default and an audited per-secret `tls_mode: "disable"` opt-out, host:port allowlist + SSRF pre-check; the secret value is `username:password`. SSH (process-mediated): an ephemeral **in-process** ssh-agent (`ssh2`; unix socket on POSIX, named pipe on Windows) so the private key never touches disk, spawning the real `ssh` with strict host-key checking against pinned keys. Git (both mechanisms, derived from the repository transport): HTTPS authenticates via a vault-authored `GIT_ASKPASS` helper (credential through the child environment, never argv), SSH reuses the ephemeral agent via `GIT_SSH_COMMAND`; command-executing transports (`ext::`, `file:`, `fd::`, `git+`) and dangerous arguments (`-c`, `--config`, `--upload-pack`, `--receive-pack`, `--exec`) are rejected.
- `host_allowlist` on the injection policy for host targets — fail-safe deny for SSH and Git-over-SSH, optional for database — and per-secret endpoint-authentication pins (database TLS policy, SSH host keys) in a `connection_configs` table (migration 008, KEK-encrypted), set via CLI `harpoc secret connection` or REST `GET`/`PUT`/`DELETE /api/v1/secrets/:handle/connection-config`
- Fourteen error codes for the three contexts: `HOST_NOT_ALLOWED`, `DB_CONNECTION_FAILED`, `DB_QUERY_FAILED`, `DB_TLS_REQUIRED`, `UNSUPPORTED_DB_ENGINE`, `INVALID_DATABASE_CONFIG`, `SSH_CONNECT_FAILED`, `SSH_HOST_KEY_MISMATCH`, `SSH_AGENT_FAILED`, `SSH_NOT_CONFIGURED`, `INVALID_SSH_CONFIG`, `GIT_OPERATION_FAILED`, `GIT_UNSUPPORTED_TRANSPORT`, `INVALID_GIT_CONFIG` (80 total)
- **Streamable HTTP transport for the vault's own MCP server** — `harpoc server start --mcp-http [--mcp-http-port 3001]` (combinable with `--mcp` and `--rest`) and `harpoc-mcp --http` serve the full MCP tool/resource surface at `/mcp`. Every request requires a vault-issued JWT (`Authorization: Bearer`, same scoped tokens as REST; no tokenless mode over HTTP); the session is pinned to the initializing token via SHA-256 fingerprint and re-verified on every request, so expiry/revocation apply mid-session. DNS-rebinding protection on loopback binds; per-session `McpServer` instances share one process-wide rate limiter

- **Out-of-band value collection for `create_secret` / `rotate_secret`** — the thesis's full channel chain. Channel 1, URL-mode elicitation: when the client declares the `elicitation.url` capability, the vault serves a one-time local form (256-bit single-use token, timing-safe compare, 5-minute expiry, JS-free page) and the browser posts the value directly into the vault process — it never traverses the MCP channel. Channel 2, controlling-terminal prompt (stdio launches only, `enableTtyPrompt`): a masked prompt opened directly on `/dev/tty` (POSIX) or `CONIN$`/`CONOUT$` (Windows) — the server's stdin carries JSON-RPC and is never read; unavailable terminals degrade gracefully. Channel 3, deferred/pending (CLI `harpoc secret set` / `harpoc secret rotate`), unchanged. `rotate_secret` now performs the rotation when a value is collected

### Changed

- **Breaking:** `use_secret` request shape changed from `{ request, injection, follow_redirects }` to `{ action }`, a discriminated union on `action.type` (`http` | `process` | `mcp` | `database` | `git` | `ssh`), across MCP, REST and SDK. Responses are discriminated too (`HttpResult` | `ProcessResult` | `McpResult` | `DatabaseResult` | `GitResult` | `SshResult`). The existing HTTP path is now `action.type: "http"`.

### Notes

- Network isolation for process execution (thesis §4.5.3 layer 4 — Linux network namespaces, macOS Seatbelt, Windows AppContainers) is deferred.

## [1.0.0] - 2026-03-05

### Added

- Zero-knowledge secret vault with AES-256-GCM encryption and Argon2id key derivation
- 3-tier key hierarchy: Master Key, Key Encryption Key (KEK), per-secret Data Encryption Keys (DEK)
- MCP server with 7 tools, 4 resources, and 3 guards (scope, rate-limit, injection)
- REST API with JWT authentication, rate limiting, and audit middleware
- SDK with direct (in-process) and REST (HTTP) client modes
- CLI (`harpoc`) with commands for vault management, secrets, audit, auth, and policies
- HTTP injection for bearer tokens, headers, query parameters, and basic auth
- Immutable append-only audit trail for all vault mutations
- Access policies with scope-based restrictions and expiration
- HMAC-SHA256 secret name indexing for O(1) handle resolution
- Lazy secret expiry with automatic status transitions on access
- SSRF protection via pre-flight DNS lookup and IP pinning
- 7-package monorepo: shared, core, cli, mcp-server, rest-api, sdk, integration
- 1009 tests across all packages

[1.0.0]: https://github.com/HarpocGH/harpoc/releases/tag/v1.0.0
