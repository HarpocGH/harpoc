import type { Agent, RegisterAgentInput, UpdateAgentInput } from "@harpoc/shared";
import {
  AgentStatus,
  registerAgentInputSchema,
  updateAgentInputSchema,
  VaultError,
} from "@harpoc/shared";
import { generateUUIDv7 } from "../crypto/random.js";
import type { AgentRow, SqliteStore } from "../storage/sqlite-store.js";
import { isUniqueConstraintError } from "../storage/sqlite-store.js";

function formatIssues(issues: { path: (string | number)[]; message: string }[]): string {
  return issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ");
}

/**
 * The agent registry (v1.4 § 5.1): the named identities a token may be issued
 * to, and the only place their lifecycle is decided.
 *
 * Thin over the storage layer by design — it owns input validation (the same
 * Zod schemas the REST bodies parse, so an engine-direct caller cannot store a
 * name or metadata a wire caller could not), the lookup refusals
 * (`AGENT_NOT_FOUND` / `AGENT_INACTIVE` / `AGENT_EXISTS`) and the projection of
 * a stored row onto the shared `Agent` wire type with its derived counts.
 * Everything transactional — the deactivation and deletion cascades and their
 * audit rows — belongs to the engine: only the engine can commit a state change
 * and its audit row together (NM3).
 */
export class AgentRegistry {
  constructor(private readonly store: SqliteStore) {}

  register(input: RegisterAgentInput, now = Date.now()): AgentRow {
    const parsed = registerAgentInputSchema.safeParse(input);
    if (!parsed.success) {
      throw VaultError.invalidInput(formatIssues(parsed.error.issues));
    }

    const row: AgentRow = {
      id: generateUUIDv7(),
      name: parsed.data.name,
      description: parsed.data.description ?? null,
      owner: parsed.data.owner ?? null,
      status: AgentStatus.ACTIVE,
      created_at: now,
      updated_at: now,
      deactivated_at: null,
    };

    try {
      this.store.insertAgent(row);
    } catch (err) {
      // The name is UNIQUE across both statuses: a deactivated agent is
      // reactivated, never re-registered.
      if (isUniqueConstraintError(err)) throw VaultError.agentExists(row.name);
      throw err;
    }

    return row;
  }

  getByName(name: string): AgentRow {
    const row = this.store.getAgentByName(name);
    if (!row) throw VaultError.agentNotFound(name);
    return row;
  }

  findByName(name: string): AgentRow | undefined {
    return this.store.getAgentByName(name);
  }

  list(status: AgentStatus | "all"): AgentRow[] {
    return this.store.listAgents(status);
  }

  /** The registration gate: an agent must exist and be active to be acted on. */
  assertActive(name: string): AgentRow {
    const row = this.getByName(name);
    if (row.status !== AgentStatus.ACTIVE) throw VaultError.agentInactive(name);
    return row;
  }

  /** Replace semantics: an omitted field is cleared, not kept. */
  updateMetadata(name: string, input: UpdateAgentInput, now = Date.now()): AgentRow {
    const parsed = updateAgentInputSchema.safeParse(input);
    if (!parsed.success) {
      throw VaultError.invalidInput(formatIssues(parsed.error.issues));
    }

    const row = this.getByName(name);
    const description = parsed.data.description ?? null;
    const owner = parsed.data.owner ?? null;
    this.store.updateAgentMetadata(row.id, description, owner, now);

    return { ...row, description, owner, updated_at: now };
  }

  setStatus(name: string, status: AgentStatus, now = Date.now()): AgentRow {
    const row = this.getByName(name);
    this.store.setAgentStatus(row.id, status, now);

    return {
      ...row,
      status,
      updated_at: now,
      deactivated_at: status === AgentStatus.INACTIVE ? now : null,
    };
  }

  /** Remove the agent, returning the row that was removed. */
  delete(name: string): AgentRow {
    const row = this.getByName(name);
    this.store.deleteAgent(row.id);
    return row;
  }

  /**
   * Project a stored row onto the wire type, adding the three fields that are
   * counted rather than stored: last activity (the newest audit row attributed
   * to the agent), live tokens and unexpired grants.
   */
  toAgent(row: AgentRow, now = Date.now()): Agent {
    return {
      ...row,
      last_active_at: this.store.agentLastActiveAt(row.name),
      active_tokens: this.store.countActiveTokensForAgent(row.id, now),
      grants: this.store.countActivePoliciesForPrincipal("agent", row.name, now),
    };
  }
}
