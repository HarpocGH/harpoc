# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
