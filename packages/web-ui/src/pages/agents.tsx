import { useState } from "preact/hooks";
import type { ApiClient } from "../api/client";
import { StatusChip } from "../components/status-chip";
import { useAsync } from "../hooks";
import { navigate } from "../router";

const timestamp = (value: number | null): string =>
  value === null ? "-" : new Date(value).toISOString();

/**
 * The agent registry: who holds tokens against this vault, and how much each of
 * them can reach. Registration is the only mutation here — a token is never
 * minted from the UI, so an agent starts with nothing until a grant or a
 * CLI-issued token attaches to it.
 */
export function AgentsPage({ api }: { api: ApiClient }) {
  const [showInactive, setShowInactive] = useState(false);
  const agents = useAsync(() => api.listAgents(showInactive ? "all" : "active"), [showInactive]);

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [owner, setOwner] = useState("");
  const [error, setError] = useState<Error | null>(null);
  const [busy, setBusy] = useState(false);

  const onSubmit = (event: Event): void => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    // Empty is absent, not a description of "": the schemas cap the length of
    // these two but store whatever arrives.
    api
      .registerAgent({
        name,
        ...(description === "" ? {} : { description }),
        ...(owner === "" ? {} : { owner }),
      })
      .then(
        () => {
          setName("");
          setDescription("");
          setOwner("");
          setBusy(false);
          agents.reload();
        },
        (err: unknown) => {
          setError(err instanceof Error ? err : new Error(String(err)));
          setBusy(false);
        },
      );
  };

  const rows = agents.data ?? [];

  return (
    <>
      <h1>Agents</h1>
      <label for="show-inactive">
        <input
          id="show-inactive"
          type="checkbox"
          checked={showInactive}
          onChange={(e) => setShowInactive(e.currentTarget.checked)}
        />
        Show inactive agents
      </label>
      {agents.error && <p class="error-text">{agents.error.message}</p>}
      {agents.data?.length === 0 && (
        <p class="empty">
          No agents registered. Register one with <code>harpoc agent register &lt;name&gt;</code> or
          the form below.
        </p>
      )}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>name</th>
              <th>status</th>
              <th>owner</th>
              <th>last active</th>
              <th>tokens</th>
              <th>grants</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => (
              <tr
                key={a.id}
                data-clickable="true"
                onClick={() => navigate(`/agents/${encodeURIComponent(a.name)}`)}
              >
                <td>{a.name}</td>
                <td>
                  <StatusChip status={a.status} />
                </td>
                <td>{a.owner ?? "-"}</td>
                <td>{timestamp(a.last_active_at)}</td>
                <td>{a.active_tokens}</td>
                <td>{a.grants}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <form class="panel" onSubmit={onSubmit}>
        <h2>Register an agent</h2>
        <p class="empty">
          Registering names an identity; it issues nothing. Tokens are minted with{" "}
          <code>harpoc auth token</code> — never from this UI.
        </p>
        <label for="agent-name">Name</label>
        <input
          id="agent-name"
          autocomplete="off"
          value={name}
          onInput={(e) => setName(e.currentTarget.value)}
          required
        />
        <label for="agent-description">Description</label>
        <input
          id="agent-description"
          autocomplete="off"
          value={description}
          onInput={(e) => setDescription(e.currentTarget.value)}
        />
        <label for="agent-owner">Owner</label>
        <input
          id="agent-owner"
          autocomplete="off"
          value={owner}
          onInput={(e) => setOwner(e.currentTarget.value)}
        />
        {error && <p class="error-text">{error.message}</p>}
        <p>
          <button type="submit" disabled={busy || name === ""}>
            Register agent
          </button>
        </p>
      </form>
    </>
  );
}
