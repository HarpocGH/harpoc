import type { IssuedToken, IssuedTokenStatusFilter } from "@harpoc/shared";
import { useState } from "preact/hooks";
import type { ApiClient } from "../api/client";
import { decodeJwtClaims } from "../auth/jwt-claims";
import { getToken } from "../auth/token-store";
import { TokenStatusChip } from "../components/token-status-chip";
import { useAsync } from "../hooks";

const MINUTE = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;

const STATUS_FILTERS: IssuedTokenStatusFilter[] = ["active", "expired", "revoked", "all"];

const SELF_REVOKE_WARNING =
  "This is the token this session is using — revoking it signs you out. Revoke anyway?";

const timestamp = (value: number): string => new Date(value).toISOString();

/** An absent OR empty secret-name pattern list is the unrestricted claim. */
const patterns = (values: string[] | null): string =>
  values === null || values.length === 0 ? "-" : values.join(", ");

/** Coarse remaining-time text: minutes inside the hour, then hours, then days. */
function countdown(expiresAt: number, now: number): string {
  const remaining = expiresAt - now;
  if (remaining <= 0) return "expired";
  if (remaining < HOUR) return `in ${String(Math.round(remaining / MINUTE))} min`;
  if (remaining < 2 * DAY) return `in ${String(Math.round(remaining / HOUR))} h`;
  return `in ${String(Math.round(remaining / DAY))} d`;
}

/**
 * The issued-token registry: what is currently authenticating against this
 * vault, and the one control that changes it — revoke. No token is minted from
 * here (spec § 9); the registry itself stores claims metadata only, never a
 * JWT, so every column below is metadata the API already held.
 */
export function TokensPage({ api }: { api: ApiClient }) {
  const [status, setStatus] = useState<IssuedTokenStatusFilter>("active");
  const [agent, setAgent] = useState("");
  const [error, setError] = useState<Error | null>(null);
  const [busy, setBusy] = useState(false);

  const tokens = useAsync(
    () => api.listTokens({ status, ...(agent === "" ? {} : { agent }) }),
    [status, agent],
  );

  const onRevoke = (row: IssuedToken): void => {
    // The session's own bearer is decoded here, not fetched: the page already
    // holds it, and revoking it logs this tab out on the next call.
    const held = getToken();
    const sessionJti = held === null ? undefined : decodeJwtClaims(held)?.jti;
    const confirmed = window.confirm(
      sessionJti === row.jti
        ? SELF_REVOKE_WARNING
        : `Revoke token ${row.jti}? Its bearer is refused from the next call on, and there is no undo.`,
    );
    if (!confirmed) return;
    setBusy(true);
    setError(null);
    api.revokeToken(row.jti).then(
      () => {
        setBusy(false);
        tokens.reload();
      },
      (err: unknown) => {
        setError(err instanceof Error ? err : new Error(String(err)));
        setBusy(false);
      },
    );
  };

  const rows = tokens.data ?? [];
  const now = Date.now();

  return (
    <>
      <h1>Tokens</h1>
      <p class="empty">
        What is currently authenticating against this vault. The registry keeps claims metadata only
        — the JWT itself is never stored, and none is ever minted from this UI.
      </p>
      <div class="panel">
        <label for="token-status">Status</label>
        <select
          id="token-status"
          value={status}
          onChange={(e) => setStatus(e.currentTarget.value as IssuedTokenStatusFilter)}
        >
          {STATUS_FILTERS.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
        <label for="token-agent">Agent</label>
        <input
          id="token-agent"
          autocomplete="off"
          value={agent}
          onInput={(e) => setAgent(e.currentTarget.value)}
        />
      </div>

      {tokens.error && <p class="error-text">{tokens.error.message}</p>}
      {error && <p class="error-text">{error.message}</p>}
      {tokens.data?.length === 0 && (
        <p class="empty">
          No tokens match the filter. Mint one with <code>harpoc auth token</code> — never from this
          UI.
        </p>
      )}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>subject</th>
              <th>type</th>
              <th>agent</th>
              <th>scopes</th>
              <th>project</th>
              <th>patterns</th>
              <th>label</th>
              <th>issued</th>
              <th>expires</th>
              <th>status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((t) => {
              const remaining = t.expires_at - now;
              return (
                <tr key={t.jti}>
                  <td>{t.subject}</td>
                  <td>{t.principal_type}</td>
                  <td>
                    {t.agent === null ? (
                      "-"
                    ) : (
                      <a href={`#/agents/${encodeURIComponent(t.agent)}`}>{t.agent}</a>
                    )}
                  </td>
                  <td>{t.scope.join(", ")}</td>
                  <td>{t.project ?? "-"}</td>
                  <td>{patterns(t.secrets)}</td>
                  <td>{t.label ?? "-"}</td>
                  <td>{timestamp(t.issued_at)}</td>
                  <td>
                    <span
                      class="countdown"
                      title={timestamp(t.expires_at)}
                      data-tone={remaining > 0 && remaining < HOUR ? "warn" : undefined}
                    >
                      {countdown(t.expires_at, now)}
                    </span>
                  </td>
                  <td>
                    <TokenStatusChip status={t.status} />
                  </td>
                  <td>
                    {t.status === "active" && (
                      <button type="button" disabled={busy} onClick={() => onRevoke(t)}>
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </>
  );
}
