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
- CLI: `harpoc secret use` (HTTP or process action) and `harpoc secret allow` (set/show injection policy)
- REST: `GET` / `PUT /api/v1/secrets/:handle/injection-policy` (trusted administrative path)
- SDK: `setInjectionPolicy` / `getInjectionPolicy`
- Six error codes: `URL_NOT_ALLOWED`, `COMMAND_NOT_ALLOWED`, `PROCESS_SPAWN_FAILED`, `PROCESS_TIMEOUT`, `PROCESS_OUTPUT_LIMIT`, `INVALID_PROCESS_CONFIG`

### Changed

- **Breaking:** `use_secret` request shape changed from `{ request, injection, follow_redirects }` to `{ action }`, a discriminated union on `action.type` (`http` | `process`), across MCP, REST and SDK. Responses are discriminated too (`HttpResult` | `ProcessResult`). The existing HTTP path is now `action.type: "http"`.

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
