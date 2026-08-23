import type { Agent } from "@harpoc/shared";
import { useState } from "preact/hooks";
import type { ApiClient } from "../api/client";
import { secretPath } from "../api/client";
import { MetaTable } from "../components/meta-table";
import { StatusChip } from "../components/status-chip";
import { TokenStatusChip } from "../components/token-status-chip";
import { useAsync } from "../hooks";
import { navigate } from "../router";

const timestamp = (value: number | null): string =>
  value === null ? "-" : new Date(value).toISOString();

const toError = (err: unknown): Error => (err instanceof Error ? err : new Error(String(err)));

/**
 * Description and owner, prefilled from the loaded agent. The route is PUT
 * replace semantics, so both fields go out on every save — editing one must not
 * clear the other — and an emptied field is omitted, which is how a value is
 * cleared rather than stored as the empty string.
 */
function AgentEditForm({
  api,
  name,
  initial,
  onDone,
}: {
  api: ApiClient;
  name: string;
  initial: Agent;
  onDone: () => void;
}) {
  const [description, setDescription] = useState(initial.description ?? "");
  const [owner, setOwner] = useState(initial.owner ?? "");
  const [error, setError] = useState<Error | null>(null);
  const [busy, setBusy] = useState(false);

  const onSubmit = (event: Event): void => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    api
      .updateAgent(name, {
        ...(description === "" ? {} : { description }),
        ...(owner === "" ? {} : { owner }),
      })
      .then(
        () => {
          setBusy(false);
          onDone();
        },
        (err: unknown) => {
          setError(toError(err));
          setBusy(false);
        },
      );
  };

  return (
    <form class="panel" onSubmit={onSubmit}>
      <h2>Edit</h2>
      <p class="empty">
        Saving replaces both fields (REST PUT semantics) — an emptied field is cleared. The name is
        the agent's identity and cannot be changed.
      </p>
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
        <button type="submit" disabled={busy}>
          Save
        </button>
      </p>
    </form>
  );
}

/**
 * One agent: its metadata, what it may reach (grants), what it currently holds
 * (tokens) and what it has done (recent activity). Every panel is
 * metadata-only — the registry stores claims, never a JWT, and no route here
 * hands one back.
 */
export function AgentDetailPage({ api, name }: { api: ApiClient; name: string }) {
  const agent = useAsync(() => api.getAgent(name), [name]);
  const policies = useAsync(() => api.listAgentPolicies(name), [name]);
  // `all`: a deactivation revokes every live token this page lists, and the
  // rows it just killed are exactly what the operator looks for afterwards.
  const tokens = useAsync(() => api.listTokens({ agent: name, status: "all" }), [name]);
  const activity = useAsync(
    () => api.queryAudit({ principal_type: "agent", principal_id: name, limit: 50 }),
    [name],
  );

  const [actionError, setActionError] = useState<Error | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = (action: () => Promise<string | null>): void => {
    setBusy(true);
    setActionError(null);
    setNotice(null);
    action().then(
      (message) => {
        setNotice(message);
        setBusy(false);
      },
      (err: unknown) => {
        setActionError(toError(err));
        setBusy(false);
      },
    );
  };

  const onDeactivate = (): void =>
    run(async () => {
      const { revoked_tokens } = await api.deactivateAgent(name);
      agent.reload();
      tokens.reload();
      return `Deactivated — ${String(revoked_tokens)} token(s) revoked.`;
    });

  const onActivate = (): void =>
    run(async () => {
      await api.activateAgent(name);
      agent.reload();
      return "Activated.";
    });

  const onDelete = (): void => {
    const loaded = agent.data;
    if (loaded === null) return;
    const confirmed = window.confirm(
      `Delete agent "${loaded.name}"? This revokes its ${String(loaded.active_tokens)} active token(s) and removes its ${String(loaded.grants)} grant(s). There is no undo.`,
    );
    if (!confirmed) return;
    run(async () => {
      await api.deleteAgent(name);
      navigate("/agents");
      return null;
    });
  };

  if (agent.error) return <p class="error-text">{agent.error.message}</p>;
  if (!agent.data) return <p class="empty">Loading…</p>;

  const auditLink = `#/audit?principal_type=agent&principal_id=${encodeURIComponent(name)}`;

  return (
    <>
      <h1>
        <span>{agent.data.name}</span> <StatusChip status={agent.data.status} />
      </h1>
      <MetaTable entries={{ ...agent.data }} />

      <AgentEditForm api={api} name={name} initial={agent.data} onDone={agent.reload} />

      <section id="actions" class="panel">
        <h2>Actions</h2>
        {agent.data.status === "active" ? (
          <button type="button" onClick={onDeactivate} disabled={busy}>
            Deactivate
          </button>
        ) : (
          <button type="button" onClick={onActivate} disabled={busy}>
            Activate
          </button>
        )}{" "}
        <button type="button" class="danger" onClick={onDelete} disabled={busy}>
          Delete agent
        </button>
        <p class="empty">
          Deactivating revokes every live token the agent holds and refuses new ones; its grants
          stay. Deleting removes the agent, its grants and its tokens — the audit trail stays.
        </p>
        {notice !== null && <p class="mono">{notice}</p>}
        {actionError && <p class="error-text">{actionError.message}</p>}
      </section>

      <h2>Grants</h2>
      {policies.error && <p class="error-text">{policies.error.message}</p>}
      {policies.data?.length === 0 && (
        <p class="empty">
          No grants — this agent reaches only what its token scope allows on ungated secrets.
        </p>
      )}
      {policies.data !== null && policies.data.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>secret</th>
              <th>permissions</th>
              <th>expires</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {policies.data.map((p) => {
              const segment = encodeURIComponent(secretPath(p.handle));
              return (
                <tr key={p.policy_id}>
                  <td>
                    <a href={`#/secrets/${segment}`}>{p.handle}</a>
                  </td>
                  <td>
                    {p.permissions.map((permission) => (
                      <span key={permission} class="chip">
                        {permission}
                      </span>
                    ))}
                  </td>
                  <td>{timestamp(p.expires_at)}</td>
                  <td>
                    <a href={`#/permissions?secret=${segment}`}>open in matrix</a>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      <h2>Tokens</h2>
      {tokens.error && <p class="error-text">{tokens.error.message}</p>}
      {tokens.data?.length === 0 && (
        <p class="empty">
          No tokens issued to this agent. Mint one with <code>harpoc auth token</code> — never from
          this UI.
        </p>
      )}
      {tokens.data !== null && tokens.data.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>jti</th>
              <th>scope</th>
              <th>label</th>
              <th>expires</th>
              <th>status</th>
            </tr>
          </thead>
          <tbody>
            {tokens.data.map((t) => (
              <tr key={t.jti}>
                <td>{t.jti}</td>
                <td>{t.scope.join(", ")}</td>
                <td>{t.label ?? "-"}</td>
                <td>{timestamp(t.expires_at)}</td>
                <td>
                  <TokenStatusChip status={t.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>Recent activity</h2>
      {activity.error && <p class="error-text">{activity.error.message}</p>}
      {activity.data?.length === 0 && <p class="empty">No recent activity for this agent.</p>}
      {activity.data !== null && activity.data.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>time</th>
              <th>event</th>
              <th>outcome</th>
            </tr>
          </thead>
          <tbody>
            {activity.data.map((e) => (
              <tr key={e.id}>
                <td>{new Date(e.timestamp).toISOString()}</td>
                <td>{e.event_type}</td>
                <td>
                  <span class="chip" data-tone={e.success ? "ok" : "bad"}>
                    {e.success ? "ok" : "failed"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p>
        <a href={auditLink}>open in Audit</a>
      </p>
    </>
  );
}
