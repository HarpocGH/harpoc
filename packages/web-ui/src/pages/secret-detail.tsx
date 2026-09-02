import { useState } from "preact/hooks";
import type { ApiClient } from "../api/client";
import { secretPath } from "../api/client";
import { MetaTable } from "../components/meta-table";
import { StatusChip } from "../components/status-chip";
import { useAsync } from "../hooks";
import { DeleteForm, PolicyEditor, RotateForm } from "./secret-forms";

/**
 * Read-only view of one secret: metadata, injection policy, per-secret grants
 * and — for the two typed lifecycles — the metadata-only OAuth/certificate
 * status the API returns. The value is not among them: no route here fetches
 * one, and every panel renders exactly what the metadata route answered.
 * Mutations mount into `#actions`.
 */
export function SecretDetailPage({ api, handle }: { api: ApiClient; handle: string }) {
  const secret = useAsync(() => api.getSecret(handle), [handle]);
  const policy = useAsync(() => api.getInjectionPolicy(handle), [handle]);
  const grants = useAsync(() => api.getAccessPolicies(handle), [handle]);
  // Keyed on the loaded type as well as the handle: the status routes exist
  // only for their own secret type, so the fetch waits for the type to arrive
  // and re-decides when it changes. The type is read only off a secret that IS
  // the one being displayed — on a route change the props update a render
  // before the reload lands, and a type carried over from the previous secret
  // would send the new handle to a route its type never claimed.
  const type =
    secret.data !== null && secretPath(secret.data.handle) === secretPath(handle)
      ? secret.data.type
      : undefined;
  const oauth = useAsync(
    () => (type === "oauth_token" ? api.getOAuthStatus(handle) : Promise.resolve(null)),
    [handle, type],
  );
  const cert = useAsync(
    () => (type === "certificate" ? api.getCertificateStatus(handle) : Promise.resolve(null)),
    [handle, type],
  );

  const [actionError, setActionError] = useState<Error | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = (action: () => Promise<string | null>, confirmMessage?: string): void => {
    setActionError(null);
    setNotice(null);
    if (confirmMessage !== undefined && !window.confirm(confirmMessage)) return;
    setBusy(true);
    action().then(
      (message) => {
        setNotice(message);
        setBusy(false);
      },
      (err: unknown) => {
        setActionError(err instanceof Error ? err : new Error(String(err)));
        setBusy(false);
      },
    );
  };

  // Both lifecycle actions are metadata-only round trips: the route answers a
  // status projection, never a token or a key, and the reload re-reads the same
  // status panel the button sits under.
  const onRefreshOAuth = (): void =>
    run(async () => {
      const result = await api.refreshOAuth(handle);
      oauth.reload();
      return result.expires_at === null
        ? "Token refreshed."
        : `Token refreshed — expires ${new Date(result.expires_at).toISOString()}`;
    });

  // A renewal is a live ACME order against the CA, not a local write: the
  // confirm is what keeps a stray click off a rate-limited endpoint.
  const onRenewCert = (): void =>
    run(async () => {
      await api.renewCertificate(handle);
      cert.reload();
      return "Certificate renewed.";
    }, "Renew this certificate now? This performs a live ACME order against the stored account (CA rate limits apply).");

  if (secret.error) return <p class="error-text">{secret.error.message}</p>;
  if (!secret.data) return <p class="empty">Loading…</p>;

  // The same link the agent-detail page emits: one route segment, the scheme
  // stripped and the project separator percent-encoded.
  const matrixLink = `#/permissions?secret=${encodeURIComponent(secretPath(secret.data.handle))}`;

  return (
    <>
      <h1>
        <span>{secret.data.name}</span> <StatusChip status={secret.data.status} />
      </h1>
      <MetaTable
        entries={{
          handle: secret.data.handle,
          project: secret.data.project ?? "-",
          type: secret.data.type,
          version: secret.data.version,
          created_at: secret.data.createdAt,
          updated_at: secret.data.updatedAt,
          rotated_at: secret.data.rotatedAt ?? "-",
          expires_at: secret.data.expiresAt ?? "-",
        }}
      />

      <h2>Injection policy</h2>
      {policy.data && <MetaTable entries={policy.data} />}

      <h2>Access policies</h2>
      {grants.data && grants.data.length === 0 && (
        <p class="empty">
          No per-secret grants — no agent or tool token can reach this secret. Grant with{" "}
          <code>harpoc policy grant</code> or in the <a href={matrixLink}>permission matrix</a>.
        </p>
      )}
      {grants.data && grants.data.length > 0 && (
        <table>
          <tbody>
            {grants.data.map((g) => (
              <tr key={g.id}>
                <td>{JSON.stringify(g)}</td>
                <td>
                  <a href={matrixLink}>open in matrix</a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {oauth.data && (
        <>
          <h2>OAuth status</h2>
          {/* Spread, not cast: the shared status types are interfaces, which
              carry no implicit index signature and so are not assignable to
              MetaTable's Record. A cast would silence the same mismatch
              without keeping the field types checked. */}
          <MetaTable entries={{ ...oauth.data }} />
          <p>
            <button type="button" onClick={onRefreshOAuth} disabled={busy}>
              Refresh token
            </button>
          </p>
          <p class="empty">
            Re-authorize with <code>harpoc oauth connect</code>.
          </p>
        </>
      )}
      {cert.data && (
        <>
          <h2>Certificate status</h2>
          <MetaTable entries={{ ...cert.data }} />
          <p>
            <button type="button" onClick={onRenewCert} disabled={busy}>
              Renew certificate
            </button>
          </p>
          <p class="empty">
            Renews on http-01 port 80 — non-default ports via{" "}
            <code>harpoc cert renew --http-port</code>.
          </p>
        </>
      )}

      {notice !== null && <p class="empty">{notice}</p>}
      {actionError !== null && <p class="error-text">{actionError.message}</p>}

      <section id="actions">
        <RotateForm api={api} handle={handle} onDone={secret.reload} />
        {/* Mounted only once the stored policy has arrived: the editor seeds its
            fields from `initial`, and a policy that lands after the first render
            would be edited from an empty form and PUT away. */}
        {policy.data && (
          <PolicyEditor api={api} handle={handle} initial={policy.data} onDone={policy.reload} />
        )}
        <DeleteForm
          api={api}
          handle={handle}
          secretName={secret.data.name}
          onDone={secret.reload}
        />
      </section>
    </>
  );
}
