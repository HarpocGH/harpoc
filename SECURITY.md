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
- **SSRF prevention**: Pre-flight DNS lookup with IP pinning blocks requests to private/internal network addresses
- **Audit trail**: Immutable append-only audit log records every vault mutation
- **Execution-layer injection**: Secrets are injected at the execution layer — into an HTTP request (request-mediated) or a spawned subprocess's environment (process-mediated) — and never returned to the LLM context. Per-secret allowlists bound where a credential may be injected: an optional URL allowlist for HTTP, and a fail-safe command allowlist for process execution
- **HTTP response mode**: A per-secret `response_mode` bounds what an HTTP invocation returns. `status_only` returns only the status code (plus an admin-allowlisted header set) and never reads the response body — the response-echo channel is removed structurally, not filtered. The default `filtered` redacts the credential and its base64/base64url/hex/percent encodings; per-invocation overrides may only tighten the policy mode, never loosen it

For full architectural details, see [docs/architecture.md](https://github.com/HarpocGH/harpoc/blob/main/docs/architecture.md).

## Known Accepted Risks

- **Memory wiping**: JavaScript does not guarantee immediate memory clearing of strings. Wiping of sensitive material in memory is best-effort. Process-mediated injection necessarily passes the credential through a JavaScript string (the subprocess environment) and the child's kernel environment, both outside the vault's zeroization discipline.
- **Injection trust boundary**: Injection assumes a trusted local host. The execution layer that performs injection must be protected from unauthorized access. Process-mediated injection spawns subprocesses without a shell in a clean environment, but the spawned process runs with the credential in its environment.
- **Process output-channel leakage**: Output sanitization redacts the credential and its common encodings (base64/hex/percent) from captured stdout/stderr, but is best-effort. A crafted command can still exfiltrate the credential via an arbitrary encoding, character-by-character chunking, or an indirect file write. The fail-safe command allowlist bounds which binaries can be run at all; optional network isolation (future work) would further contain this channel.
- **`full` response mode**: Setting a secret's `response_mode` to `full` disables the vault-layer redaction of that credential (including OAuth access tokens resolved for injection) from HTTP responses — an echoing endpoint then hands the raw value back to the caller. It is settable only via the trusted admin path (CLI/REST, never an MCP tool) and cannot be requested per-invocation unless the policy already allows it. The pattern-based interface guard at the REST/MCP boundaries remains active; CLI and SDK-direct callers receive the truly raw response. Note that REST `PUT .../injection-policy` replaces the whole policy — a client omitting `response_mode` resets it to the `filtered` default; every policy write is audited with its effective mode.
