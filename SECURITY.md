# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | Yes       |
| < 1.0   | No        |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Please report vulnerabilities through [GitHub Security Advisories](https://github.com/HarpocGH/harpoc/security/advisories/new).

### Response Timeline

- **Acknowledgement**: within 48 hours
- **Assessment**: within 7 days
- **Fix (critical)**: within 30 days
- **Fix (non-critical)**: within 90 days

We will coordinate disclosure with the reporter once a fix is available.

## Security Design Overview

Harpoc is a zero-knowledge secret vault designed so that secrets are never exposed to the AI model. Key security properties include:

- **Encryption**: All secrets are encrypted at rest using AES-256-GCM with unique per-secret Data Encryption Keys (DEK)
- **Key hierarchy**: 3-tier hierarchy — Master Key (derived via Argon2id) wraps a KEK, which wraps individual DEKs
- **Minimal in-process cryptography**: All cryptographic operations run on Node's built-in `node:crypto`, with Argon2id (a native KDF) the only exception — no third-party cryptographic library is loaded into the vault process. The SSH context's ephemeral in-process agent parses keys and generates signatures on `node:crypto` (unencrypted Ed25519/RSA/ECDSA keys; passphrase-protected PKCS#8/legacy-PEM keys are decrypted at **import** on the CLI — in memory, `node:crypto` only, the passphrase never persisted — while encrypted OpenSSH-format keys stay unsupported, since bcrypt-pbkdf would re-introduce third-party crypto); the private key stays in the vault process and only signatures cross the agent socket
- **SSRF prevention**: Pre-flight DNS lookup with IP pinning blocks requests to private/internal network addresses
- **Audit trail**: Immutable append-only audit log records every vault mutation; detail fields are encrypted and bound to their row, and rows are HMAC-chained — `harpoc audit verify` detects tampering. `harpoc audit anchor` exports the chain tail; `verify --anchor` detects tail truncation and rollback **provided the anchor is stored off-host** — an attacker who can modify the vault database can likely also modify files beside it, so the vault cannot supply that independent trust domain itself
- **Execution-layer injection**: Secrets are injected at the execution layer across six contexts — an HTTP request, a spawned subprocess's environment, a downstream MCP server, a database connection, a Git operation, or an SSH session — and never returned to the LLM context. Per-secret allowlists bound where a credential may be injected: an optional URL allowlist for HTTP, a fail-safe command allowlist for process execution (with an explicit acknowledgement gate for known interpreter binaries), and a host allowlist for database/SSH/Git targets (fail-safe for SSH and Git-over-SSH). Endpoint authentication is pinned per secret: database TLS/CA policy and SSH host keys
- **HTTP response mode**: A per-secret `response_mode` bounds what an HTTP invocation returns. `status_only` returns only the status code (plus an admin-allowlisted header set) and never reads the response body — the response-echo channel is removed structurally, not filtered. The default `filtered` redacts the credential and its base64/base64url/hex/percent encodings; per-invocation overrides may only tighten the policy mode, never loosen it
- **Session-file protection**: The session file's key is wrapped at rest with an OS-user-bound platform key store — DPAPI (Windows), the Keychain (macOS), Secret Service or the kernel `@u` keyring (Linux desktop/headless tiers) — so a session file copied off the host is inert. Reads fail closed: a tampered blob, a foreign user, or a scheme mismatch invalidates the session and requires a fresh `harpoc unlock`; kernel-keyring keys die at reboot, which likewise forces a fresh unlock rather than degrading. A write-time keystore failure falls back to the file-permission-only session with a CLI warning (`HARPOC_SESSION_KEYSTORE=off` is the explicit opt-out), and the file is created owner-only (0600) in all cases. The key-store bridges are OS-shipped or distro-standard binaries invoked from pinned paths with key material on stdin/stdout only — no native addon, nothing on an argument vector

For a summary of the security model, see the [Security Model](README.md#security-model) section of the README.

## Known Accepted Risks

- **Memory wiping**: JavaScript does not guarantee immediate memory clearing of strings. Wiping of sensitive material in memory is best-effort. Process-mediated injection necessarily passes the credential through a JavaScript string (the subprocess environment) and the child's kernel environment, both outside the vault's zeroization discipline.
- **Injection trust boundary**: Injection assumes a trusted local host. The execution layer that performs injection must be protected from unauthorized access. Process-mediated injection spawns subprocesses without a shell in a clean environment, but the spawned process runs with the credential in its environment.
- **Process output-channel leakage**: Output sanitization redacts the credential and its common encodings (base64/hex/percent) from captured stdout/stderr, but is best-effort. A crafted command can still exfiltrate the credential via an arbitrary encoding, character-by-character chunking, or an indirect file write. The fail-safe command allowlist bounds which binaries can be run at all; optional network isolation (future work) would further contain this channel.
- **`full` response mode**: Setting a secret's `response_mode` to `full` disables the vault-layer redaction of that credential (including OAuth access tokens resolved for injection) from HTTP responses — an echoing endpoint then hands the raw value back to the caller. It is settable only via the trusted admin path (CLI/REST, never an MCP tool) and cannot be requested per-invocation unless the policy already allows it. The pattern-based interface guard at the REST/MCP boundaries remains active; CLI and SDK-direct callers receive the truly raw response. Note that REST `PUT .../injection-policy` replaces the whole policy — a client omitting `response_mode` resets it to the `filtered` default; every policy write is audited with its effective mode.
