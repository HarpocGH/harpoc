# Contributing to Harpoc

Thank you for your interest in contributing to Harpoc! This document provides guidelines and instructions for contributing.

## Prerequisites

- Node.js 22+
- pnpm 10+

## Setup

```bash
git clone https://github.com/HarpocGH/harpoc.git
cd harpoc
pnpm install
pnpm build
pnpm test
```

## Project Structure

| Package               | Path                   | Description                                         |
| --------------------- | ---------------------- | --------------------------------------------------- |
| `@harpoc/shared`      | `packages/shared`      | Types, error codes, Zod schemas, constants          |
| `@harpoc/core`        | `packages/core`        | VaultEngine, crypto, SQLite storage, HTTP injection |
| `@harpoc/cli`         | `packages/cli`         | `harpoc` CLI binary (Commander.js)                  |
| `@harpoc/mcp-server`  | `packages/mcp-server`  | MCP server with tools, resources, and guards        |
| `@harpoc/rest-api`    | `packages/rest-api`    | Hono HTTP API with JWT auth and rate limiting       |
| `@harpoc/sdk`         | `packages/sdk`         | VaultClient with direct and REST modes              |
| `@harpoc/integration` | `packages/integration` | Cross-package integration tests                     |

## Code Style

- **ESM-only** — no CommonJS
- **Strict TypeScript** — all strict checks enabled
- **No `!.` non-null assertions** — use `as Type` casts instead
- **Prettier** — semicolons, double quotes, 100 character width, LF line endings
- Run `pnpm format` to auto-fix formatting, or `pnpm format:check` to verify

## Testing

- Test framework: [Vitest](https://vitest.dev/)
- Passwords in tests must be at least 8 characters (`MIN_PASSWORD_LENGTH`)
- Mock Argon2 in unit tests for performance (see existing test suites for examples)
- Run all tests: `pnpm test`

## Security Rules

Harpoc is a security-critical project. When contributing, ensure that secret values are:

- **Never logged** — not in console output, debug logs, or error messages
- **Never returned to the LLM** — no MCP tool accepts or returns secret values
- **Never exposed** — not in error objects, stack traces, or API responses

## Pull Request Process

1. Fork the repository and create a feature branch from `main`
2. Make your changes following the code style and security guidelines above
3. Ensure all checks pass:
   ```bash
   pnpm build
   pnpm typecheck
   pnpm lint
   pnpm test
   pnpm format:check
   ```
4. Submit a pull request against `main`

## License

By contributing to Harpoc, you agree that your contributions will be licensed under the [Business Source License 1.1](LICENSE).
