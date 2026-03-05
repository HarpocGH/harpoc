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
- **HTTP injection**: Secrets are injected at the execution layer, never returned to the LLM context

For full architectural details, see [docs/architecture.md](https://github.com/HarpocGH/harpoc/blob/main/docs/architecture.md).

## Known Accepted Risks

- **Memory wiping**: JavaScript does not guarantee immediate memory clearing of strings. Wiping of sensitive material in memory is best-effort.
- **HTTP injection trust boundary**: HTTP injection assumes a trusted local environment. The execution layer that performs injection must be protected from unauthorized access.
