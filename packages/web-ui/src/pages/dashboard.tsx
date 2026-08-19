import type { ApiClient } from "../api/client";
import { secretPath } from "../api/client";
import { StatusChip } from "../components/status-chip";
import { useAsync } from "../hooks";
import { navigate } from "../router";

export function DashboardPage({ api }: { api: ApiClient }) {
  const secrets = useAsync(() => api.listSecrets(), []);
  const report = useAsync(() => api.expiringReport(), []);
  const failures = useAsync(() => api.queryAudit({ success: false, limit: 5 }), []);

  const counts = new Map<string, number>();
  for (const s of secrets.data ?? []) {
    counts.set(s.status, (counts.get(s.status) ?? 0) + 1);
  }
  const attention =
    (report.data?.expiring.length ?? 0) +
    (report.data?.oauth_refresh_needed.length ?? 0) +
    (report.data?.certificates_nearing_renewal.length ?? 0) +
    (failures.data?.length ?? 0);

  return (
    <>
      <h1>Dashboard</h1>
      {secrets.error && <p class="error-text">{secrets.error.message}</p>}
      {report.error && <p class="error-text">{report.error.message}</p>}
      {failures.error && <p class="error-text">{failures.error.message}</p>}

      {secrets.data && (
        <p class="mono">
          {secrets.data.length} secrets
          {[...counts.entries()].map(([status, n]) => (
            <span key={status}>
              {" · "}
              {n} <StatusChip status={status} />
            </span>
          ))}
        </p>
      )}

      {report.data && failures.data && attention === 0 && (
        <p class="empty">Nothing needs attention.</p>
      )}

      {report.data && report.data.expiring.length > 0 && (
        <>
          <h2>Expiring secrets</h2>
          <table>
            <thead>
              <tr>
                <th>name</th>
                <th>status</th>
                <th>expires_at</th>
              </tr>
            </thead>
            <tbody>
              {report.data.expiring.map((s) => (
                <tr
                  key={s.handle}
                  data-clickable="true"
                  onClick={() => navigate(`/secrets/${encodeURIComponent(secretPath(s.handle))}`)}
                >
                  <td>{s.name}</td>
                  <td>
                    <StatusChip status="expiring" />
                  </td>
                  <td>{s.expiresAt ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {report.data && report.data.oauth_refresh_needed.length > 0 && (
        <>
          <h2>OAuth tokens needing refresh</h2>
          <table>
            <thead>
              <tr>
                <th>name</th>
                <th>provider</th>
                <th>access_token_expires_at</th>
              </tr>
            </thead>
            <tbody>
              {report.data.oauth_refresh_needed.map((t) => (
                <tr key={t.handle}>
                  <td>{t.name}</td>
                  <td>{t.provider}</td>
                  <td>{t.access_token_expires_at ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {report.data && report.data.certificates_nearing_renewal.length > 0 && (
        <>
          <h2>Certificates nearing renewal</h2>
          <table>
            <thead>
              <tr>
                <th>name</th>
                <th>subject</th>
                <th>not_after</th>
              </tr>
            </thead>
            <tbody>
              {report.data.certificates_nearing_renewal.map((c) => (
                <tr key={c.handle}>
                  <td>{c.name}</td>
                  <td>{c.subject}</td>
                  <td>{c.not_after ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {failures.data && failures.data.length > 0 && (
        <>
          <h2>Recent audit failures</h2>
          <table>
            <thead>
              <tr>
                <th>time</th>
                <th>event</th>
                <th>principal</th>
                <th>outcome</th>
              </tr>
            </thead>
            <tbody>
              {failures.data.map((e) => (
                <tr key={e.id}>
                  <td>{new Date(e.timestamp).toISOString()}</td>
                  <td>{e.event_type}</td>
                  <td>{e.principal_id ?? "-"}</td>
                  <td>
                    <span class="chip" data-tone="bad">
                      failed
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </>
  );
}
