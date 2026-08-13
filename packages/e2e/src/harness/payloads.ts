import { GIT_HTTP, PG, SSHD_PINNED, SSHD_ROGUE } from "./backends.js";

/**
 * The calls the targeted refusal arms issue, written once.
 *
 * Phase 1–2 landed these as Harpoc-only blocks; Phase 4B pairs each with the
 * §2.3 baseline running the SAME call, which is what turns a block into a
 * controlled comparison (C-3). Two hand-written copies of "the same" payload is
 * exactly how a paired row starts comparing two different attacks — the
 * mechanism `ScenarioArm.observe` already uses on the deep scenarios, applied
 * to the arms whose two halves live in different files.
 *
 * The credentials are the fleet's own: the git and database services validate
 * them, so the baseline arm demonstrably authenticates rather than merely
 * reaching a socket.
 */
export const GIT_HTTP_BASE = `http://${GIT_HTTP.host}:${String(GIT_HTTP.port)}`;
export const GIT_HTTP_CREDENTIAL = `${GIT_HTTP.user}:${GIT_HTTP.password}`;
export const DB_CREDENTIAL = `${PG.user}:${PG.password}`;
export const DB_QUERY = "SELECT 42 AS answer";

/** H6a — the origin is allowlisted; the endpoint answers 302 to the attacker. */
export function gitRedirectPayload(workingDirectory: string): Record<string, unknown> {
  return {
    type: "git",
    operation: "clone",
    repository: `${GIT_HTTP_BASE}/redirect/clean.git`,
    working_directory: workingDirectory,
  };
}

/** H6b — the repository's own .gitmodules chooses the second target. */
export function gitSubmodulePayload(workingDirectory: string): Record<string, unknown> {
  return {
    type: "git",
    operation: "clone",
    repository: `${GIT_HTTP_BASE}/git/submodule.git`,
    args: ["--recurse-submodules"],
    working_directory: workingDirectory,
  };
}

/** M3 — an IP-literal target, which no DNS SAN covers. */
export const DB_IP_LITERAL_PAYLOAD: Record<string, unknown> = {
  type: "database",
  engine: "postgresql",
  host: `${PG.ip}:${String(PG.port)}`,
  database: PG.database,
  query: DB_QUERY,
};

/** The plaintext port: no TLS is on offer at all. */
export const DB_PLAINTEXT_PAYLOAD: Record<string, unknown> = {
  type: "database",
  engine: "postgresql",
  host: `${PG.host}:${String(PG.plainPort)}`,
  database: PG.database,
  query: DB_QUERY,
};

/** The rogue server answers with a host key that matches no pin. */
export const SSH_ROGUE_PAYLOAD: Record<string, unknown> = {
  type: "ssh",
  host: SSHD_ROGUE.host,
  user: SSHD_ROGUE.user,
  command: "id -un",
};

/** The legitimate server, withheld by the allowlist alone. */
export const SSH_PINNED_PAYLOAD: Record<string, unknown> = {
  type: "ssh",
  host: SSHD_PINNED.host,
  user: SSHD_PINNED.user,
  command: "id -un",
};
