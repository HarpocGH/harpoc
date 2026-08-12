import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

/**
 * `host` is what the happy path connects to — it is in the certificate SAN.
 * `ip` is the M3 arm: the same server addressed as an IP literal, which no
 * DNS SAN covers.
 */
export const PG = {
  host: "localhost",
  ip: "127.0.0.1",
  port: 55432,
  plainPort: 55433,
  user: "harpoc",
  password: "harpoc-e2e-pw",
  database: "app",
} as const;

export const MYSQL = {
  host: "localhost",
  ip: "127.0.0.1",
  port: 55306,
  user: "harpoc",
  password: "harpoc-e2e-pw",
  database: "app",
} as const;

/**
 * The sshd containers are published on loopback ALIASES at port 22, not the
 * 55xxx offset the database services use: the `ssh` context is port-22-only
 * (F-1), so two servers cannot share one address. `127.0.0.2` and `127.0.0.3`
 * are distinct loopback addresses — all of 127/8 is loopback on Linux and
 * Windows (verified reachable through a Docker alias bind on this host), but
 * stock macOS configures only 127.0.0.1 on lo0: `fleet:up` runs a preflight
 * (scripts/fleet-preflight.mjs) that fails loudly with the
 * `sudo ifconfig lo0 alias` recovery before compose can die on the bind.
 */
export const SSHD_PINNED = {
  host: "127.0.0.2",
  port: 22,
  user: "harpoc",
  repoPath: "/srv/repo.git",
} as const;

export const SSHD_ROGUE = {
  host: "127.0.0.3",
  port: 22,
  user: "harpoc",
} as const;

/**
 * git smart-HTTP over loopback with basic auth. The credential matches the
 * container's baked htpasswd; it is deliberately distinct from the database
 * password so a git-path leak cannot be masked by a coincidental match.
 */
export const GIT_HTTP = {
  host: "127.0.0.1",
  port: 55080,
  user: "harpoc",
  password: "git-e2e-pw",
} as const;

/**
 * TLS echo backend for the `http` context. `host` is the SAN-covered name the
 * cells connect to; the certificate also carries an IP SAN for 127.0.0.1, so
 * addressing the literal stays available if a host resolves localhost to ::1
 * ahead of the bound address. Trust comes from the fixture CA via
 * NODE_EXTRA_CA_CERTS, which `test:e2e` sets before vitest starts (the variable
 * is read once per process, at first use of the default root store).
 */
export const ECHO_HTTPS = {
  host: "localhost",
  ip: "127.0.0.1",
  port: 55443,
  markerHeader: "x-harpoc-marker",
} as const;

/**
 * Downstream MCP server over Streamable HTTP. `endpoint` is what the secret's
 * server config points at; `recordedUrl` is the harness-only side channel that
 * reports which Authorization values the downstream actually received — read
 * directly, never through the vault, so it can corroborate the half of the
 * claim a redacted result cannot.
 */
export const MCP_DOWNSTREAM = {
  host: "127.0.0.1",
  port: 55090,
  serverName: "e2e-downstream",
  endpoint: "http://127.0.0.1:55090/mcp",
  recordedUrl: "http://127.0.0.1:55090/recorded",
  tool: "reveal",
} as const;

export type FleetService =
  | "postgres-tls"
  | "postgres-plain"
  | "mysql-tls"
  | "sshd-pinned"
  | "sshd-rogue"
  | "git-http"
  | "echo-https"
  | "mcp-downstream";

const COMPOSE_DIR = fileURLToPath(new URL("../..", import.meta.url));

/** Overridable for hosts where Docker is installed outside PATH. */
const DOCKER = process.env["HARPOC_E2E_DOCKER"] ?? "docker";

/**
 * A missing container must fail loudly, never skip. A silently skipped backend
 * would drop real-path coverage to zero while the suite stays green — the exact
 * failure mode HARPOC_REQUIRE_PLATFORM_TESTS exists to prevent elsewhere.
 */
export function assertFleetUp(service: FleetService): void {
  let running = "";
  try {
    running = execFileSync(DOCKER, ["compose", "ps", "--services", "--filter", "status=running"], {
      cwd: COMPOSE_DIR,
      encoding: "utf8",
    });
  } catch (cause) {
    throw new Error(
      "cannot query the fleet — is Docker running? Start it with:\n" +
        "  pnpm --filter @harpoc/e2e fleet:up",
      { cause },
    );
  }
  // \r?\n, not \n: on a Windows host `docker compose ps` emits CRLF line
  // endings, and "postgres-tls\r" would read a healthy fleet as down.
  const services = running.split(/\r?\n/).map((line) => line.trim());
  if (!services.includes(service)) {
    throw new Error(
      `backend "${service}" is not running. Start the fleet with:\n` +
        "  pnpm --filter @harpoc/e2e fleet:up",
    );
  }
}
