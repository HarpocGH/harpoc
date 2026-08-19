import { useState } from "preact/hooks";
import type { ApiClient } from "../api/client";
import { secretPath } from "../api/client";
import { StatusChip } from "../components/status-chip";
import { useAsync } from "../hooks";
import { navigate } from "../router";
import { CreateSecretForm } from "./secret-forms";

export function SecretsPage({ api }: { api: ApiClient }) {
  const secrets = useAsync(() => api.listSecrets(), []);
  const [filter, setFilter] = useState("");

  const loaded = secrets.data ?? [];
  const visible = loaded.filter(
    (s) => filter === "" || s.name.includes(filter) || (s.project?.includes(filter) ?? false),
  );

  return (
    <>
      <h1>Secrets</h1>
      <label for="filter">Filter</label>
      <input id="filter" value={filter} onInput={(e) => setFilter(e.currentTarget.value)} />
      {secrets.error && <p class="error-text">{secrets.error.message}</p>}
      {secrets.data?.length === 0 && (
        <p class="empty">
          No secrets yet. Create one with <code>harpoc secret set &lt;name&gt;</code> or the form
          below.
        </p>
      )}
      {loaded.length > 0 && visible.length === 0 && (
        <p class="empty">No secrets match the filter.</p>
      )}
      {visible.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>name</th>
              <th>project</th>
              <th>type</th>
              <th>status</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((s) => (
              <tr
                key={s.handle}
                data-clickable="true"
                onClick={() => navigate(`/secrets/${encodeURIComponent(secretPath(s.handle))}`)}
              >
                <td>{s.name}</td>
                <td>{s.project ?? "-"}</td>
                <td>{s.type}</td>
                <td>
                  <StatusChip status={s.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <section id="create">
        <CreateSecretForm api={api} onDone={secrets.reload} />
      </section>
    </>
  );
}
