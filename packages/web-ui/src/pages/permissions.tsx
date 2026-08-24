import type { Agent, AgentPolicy, Permission, SetAgentPermissionsResult } from "@harpoc/shared";
import { useState } from "preact/hooks";
import type { ApiClient, SecretInfo } from "../api/client";
import { secretPath } from "../api/client";
import { decodeJwtClaims } from "../auth/jwt-claims";
import { getToken } from "../auth/token-store";
import { StatusChip } from "../components/status-chip";
import { useAsync } from "../hooks";
import { useHashRoute } from "../router";

/**
 * The grantable permissions, in the order a cell writes them. `create` is
 * deliberately absent: it is never grantable per secret — token scope alone
 * governs it, and the engine refuses it with `INVALID_INPUT`.
 */
const GRANTABLE: Permission[] = ["list", "read", "use", "rotate", "revoke", "admin"];

type GrantMap = Map<string, Map<string, AgentPolicy>>;

interface Matrix {
  agents: Agent[];
  secrets: SecretInfo[];
  grants: GrantMap;
}

interface EditorTarget {
  agent: Agent;
  secret: SecretInfo;
}

/**
 * The `?secret=` column preselect. `URLSearchParams` already decodes, so the
 * value arrives as the scheme-less `project/name` path `secretPath` yields —
 * decoding it a second time would corrupt a name carrying a percent sign.
 */
function preselectedSecret(route: string): string | null {
  const query = route.indexOf("?");
  if (query === -1) return null;
  return new URLSearchParams(route.slice(query + 1)).get("secret");
}

/**
 * The command that lifts a refusal on a policy-gated secret. Once the secret
 * holds its first agent row, a token caller needs a grant of its own on it —
 * an agent- or tool-type admin token included — and only the trusted local CLI
 * path can write that first one. The principal is read off the session's own
 * bearer; an absent `principal_type` claim is the CLI's default, `agent`.
 */
function grantCommand(handle: string): string {
  const held = getToken();
  const claims = held === null ? null : decodeJwtClaims(held);
  const principalType = claims?.principal_type ?? "agent";
  const principalId = claims?.sub ?? "<sub>";
  return `harpoc policy grant ${handle} --principal-type ${principalType} --principal-id ${principalId} --permissions admin`;
}

/** The refusal code a wire error carries, whatever shape it arrived in. */
function errorCode(err: unknown): string | null {
  if (typeof err !== "object" || err === null) return null;
  const code = (err as { code?: unknown }).code;
  return typeof code === "string" ? code : null;
}

/** Epoch ms → the local-time string a `datetime-local` input round-trips. */
function toLocalInput(ms: number): string {
  const local = new Date(ms - new Date(ms).getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

/**
 * One matrix cell. The gating flip is predicted here and confirmed before the
 * `PUT` — advisory only: the response's `gated_before`/`gated_after` is the
 * truth, and the page states it afterwards.
 */
function CellEditor({
  api,
  agent,
  secret,
  current,
  secretGated,
  onlyHolder,
  onClose,
  onSaved,
}: {
  api: ApiClient;
  agent: Agent;
  secret: SecretInfo;
  current: AgentPolicy | undefined;
  secretGated: boolean;
  onlyHolder: boolean;
  onClose: () => void;
  onSaved: (result: SetAgentPermissionsResult, predicted: boolean) => void;
}) {
  const [selected, setSelected] = useState<Permission[]>(current?.permissions ?? []);
  const [expiry, setExpiry] = useState(
    current !== undefined && current.expires_at !== null ? toLocalInput(current.expires_at) : "",
  );
  const [pending, setPending] = useState<{
    permissions: Permission[];
    expiresAt: number | undefined;
    message: string;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [denied, setDenied] = useState(false);
  const [busy, setBusy] = useState(false);

  const toggle = (permission: Permission): void =>
    setSelected((prev) =>
      prev.includes(permission)
        ? prev.filter((p) => p !== permission)
        : GRANTABLE.filter((p) => p === permission || prev.includes(p)),
    );

  const write = (
    permissions: Permission[],
    expiresAt: number | undefined,
    predicted: boolean,
  ): void => {
    setBusy(true);
    setError(null);
    setDenied(false);
    api.setAgentPermissions(agent.name, secret.handle, { permissions, expires_at: expiresAt }).then(
      (result) => {
        setBusy(false);
        onSaved(result, predicted);
      },
      (err: unknown) => {
        setError(err instanceof Error ? err.message : String(err));
        setDenied(errorCode(err) === "ACCESS_DENIED");
        setPending(null);
        setBusy(false);
      },
    );
  };

  const attempt = (next: Permission[]): void => {
    setError(null);
    setDenied(false);
    // Empty cells are never written: there is no row to delete and none to
    // insert, so the editor just closes.
    if (next.length === 0 && current === undefined) {
      onClose();
      return;
    }
    const expiresAt = expiry === "" ? undefined : new Date(expiry).getTime();
    // A `datetime-local` input sanitizes its own value to "" or a parseable
    // one, so this is for the browser that degrades the type to a text field:
    // without it the unparseable value goes out as `NaN` → JSON `null` and
    // comes back a schema 400, which describes the wrong thing.
    if (expiresAt !== undefined && Number.isNaN(expiresAt)) {
      setError("Expiry is not a valid date and time.");
      return;
    }
    const willGate = !secretGated && next.length > 0;
    const willUngate = secretGated && next.length === 0 && onlyHolder;
    if (willGate || willUngate) {
      setPending({
        permissions: next,
        expiresAt,
        message: willGate
          ? `${secret.handle} becomes policy-gated: token callers without a grant are refused`
          : `${secret.handle} becomes ungated: token scope alone governs`,
      });
      return;
    }
    write(next, expiresAt, false);
  };

  const frozen = pending !== null || busy;

  return (
    <section id="cell-editor" class="panel">
      <h2>
        {agent.name} × {secret.handle}
      </h2>
      <div class="perm-grid">
        {GRANTABLE.map((permission) => (
          <label key={permission} for={`perm-${permission}`}>
            <input
              id={`perm-${permission}`}
              type="checkbox"
              checked={selected.includes(permission)}
              disabled={frozen}
              onChange={() => toggle(permission)}
            />
            {permission}
          </label>
        ))}
      </div>
      <label for="grant-expires">Expires</label>
      <input
        id="grant-expires"
        type="datetime-local"
        value={expiry}
        disabled={frozen}
        onInput={(e) => setExpiry(e.currentTarget.value)}
      />
      <p class="empty">
        <code>create</code> is not grantable per secret — token scope alone governs it.{" "}
        <code>admin</code> implies every other permission.
      </p>
      {pending === null ? (
        <p>
          <button type="button" disabled={busy} onClick={() => attempt(selected)}>
            Save
          </button>{" "}
          <button type="button" disabled={busy} onClick={() => attempt([])}>
            Clear
          </button>{" "}
          <button type="button" disabled={busy} onClick={onClose}>
            Cancel
          </button>
        </p>
      ) : (
        <>
          <p class="mono">{pending.message}</p>
          <p>
            <button
              type="button"
              disabled={busy}
              onClick={() => write(pending.permissions, pending.expiresAt, true)}
            >
              Confirm
            </button>{" "}
            <button type="button" disabled={busy} onClick={() => setPending(null)}>
              Cancel
            </button>
          </p>
        </>
      )}
      {error !== null && <p class="error-text">{error}</p>}
      {denied && (
        <p class="empty">
          This session's token holds no grant on {secret.handle}; once a secret is policy-gated,
          token callers need their own grant. From a trusted CLI:{" "}
          <code>{grantCommand(secret.handle)}</code>
        </p>
      )}
    </section>
  );
}

/**
 * The permission matrix: agents down, secrets across. One `listAgentPolicies`
 * per agent is loaded alongside the two listings, so the gated marker on each
 * column is computed from rows actually on screen — it therefore sees `agent`
 * principals only, which is what the marker says.
 */
export function PermissionsPage({ api }: { api: ApiClient }) {
  const route = useHashRoute();
  const [showInactive, setShowInactive] = useState(false);
  const [filter, setFilter] = useState("");
  const [target, setTarget] = useState<EditorTarget | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const matrix = useAsync<Matrix>(async () => {
    const [agents, secrets] = await Promise.all([
      api.listAgents(showInactive ? "all" : "active"),
      api.listSecrets(),
    ]);
    const lists = await Promise.all(agents.map((a) => api.listAgentPolicies(a.name)));
    const grants: GrantMap = new Map();
    agents.forEach((a, index) => {
      const byHandle = new Map<string, AgentPolicy>();
      for (const p of lists[index] ?? []) byHandle.set(p.handle, p);
      grants.set(a.name, byHandle);
    });
    return { agents, secrets, grants };
  }, [showInactive]);

  const agents = matrix.data?.agents ?? [];
  const loadedSecrets = matrix.data?.secrets ?? [];
  const preselect = preselectedSecret(route);
  const visibleSecrets = loadedSecrets.filter((s) => {
    if (preselect !== null) return secretPath(s.handle) === preselect;
    if (filter === "") return true;
    return s.name.includes(filter) || (s.project?.includes(filter) ?? false);
  });

  const holders = (handle: string): Agent[] =>
    agents.filter((a) => matrix.data?.grants.get(a.name)?.has(handle) === true);

  // `predicted` says a confirmation step was shown. A prediction the engine
  // then disproves is stated rather than dropped: the operator confirmed one
  // outcome and got another.
  const onSaved = (
    secret: SecretInfo,
    result: SetAgentPermissionsResult,
    predicted: boolean,
  ): void => {
    setNotice(
      result.gated_before !== result.gated_after
        ? result.gated_after
          ? `${secret.handle} is now policy-gated: token callers without a grant are refused.`
          : `${secret.handle} is now ungated: token scope alone governs.`
        : predicted
          ? result.gated_after
            ? `No change: ${secret.handle} is still policy-gated.`
            : `No change: ${secret.handle} is still ungated.`
          : null,
    );
    setTarget(null);
    matrix.reload();
  };

  const targetHolders = target === null ? [] : holders(target.secret.handle);

  return (
    <>
      <h1>Permissions</h1>
      <p class="empty">
        Rows are agents, columns secrets. A secret any agent holds a grant on is policy-gated: a
        token caller without a matching grant is refused. Empty cells are never written.
      </p>
      <div class="panel">
        <label for="secret-filter">Filter secrets</label>
        <input
          id="secret-filter"
          autocomplete="off"
          value={filter}
          disabled={preselect !== null}
          onInput={(e) => setFilter(e.currentTarget.value)}
        />
        <label for="show-inactive">
          <input
            id="show-inactive"
            type="checkbox"
            checked={showInactive}
            onChange={(e) => setShowInactive(e.currentTarget.checked)}
          />
          Show inactive agents
        </label>
        {preselect !== null && (
          <p class="empty">
            Showing one secret. <a href="#/permissions">Show all secrets</a>
          </p>
        )}
      </div>

      {notice !== null && <p class="empty">{notice}</p>}
      {matrix.error && <p class="error-text">{matrix.error.message}</p>}
      {matrix.data !== null && agents.length === 0 && (
        <p class="empty">
          No agents to show. Register one with <code>harpoc agent register &lt;name&gt;</code>.
        </p>
      )}
      {matrix.data !== null && loadedSecrets.length === 0 && (
        <p class="empty">No secrets to show.</p>
      )}
      {loadedSecrets.length > 0 && visibleSecrets.length === 0 && (
        <p class="empty">No secrets match the filter.</p>
      )}

      {agents.length > 0 && visibleSecrets.length > 0 && (
        <div class="matrix">
          <table>
            <thead>
              <tr>
                <th>agent</th>
                {visibleSecrets.map((s) => (
                  <th key={s.handle}>
                    <span class="mono">{s.name}</span>
                    <br />
                    <span class="muted">{s.project ?? "-"}</span>
                    <br />
                    {holders(s.handle).length > 0 ? (
                      <span class="chip" data-tone="warn">
                        agent-gated
                      </span>
                    ) : (
                      <span class="chip">ungated</span>
                    )}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {agents.map((a) => {
                const readonly = a.status !== "active";
                const row = matrix.data?.grants.get(a.name);
                return (
                  <tr key={a.id}>
                    <th scope="row">
                      <a href={`#/agents/${encodeURIComponent(a.name)}`}>{a.name}</a>{" "}
                      {readonly && <StatusChip status={a.status} />}
                    </th>
                    {visibleSecrets.map((s) => {
                      const grant = row?.get(s.handle);
                      return (
                        <td
                          key={s.handle}
                          data-agent={a.name}
                          data-secret={s.handle}
                          data-readonly={readonly ? "true" : undefined}
                          data-clickable={readonly ? undefined : "true"}
                          onClick={
                            readonly
                              ? undefined
                              : () => {
                                  setNotice(null);
                                  setTarget({ agent: a, secret: s });
                                }
                          }
                        >
                          {grant === undefined
                            ? "—"
                            : grant.permissions.map((p) => (
                                <span key={p} class="chip">
                                  {p}
                                </span>
                              ))}
                        </td>
                      );
                    })}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {target !== null && (
        <CellEditor
          key={`${target.agent.name}|${target.secret.handle}`}
          api={api}
          agent={target.agent}
          secret={target.secret}
          current={matrix.data?.grants.get(target.agent.name)?.get(target.secret.handle)}
          secretGated={targetHolders.length > 0}
          onlyHolder={targetHolders.length === 1 && targetHolders[0]?.name === target.agent.name}
          onClose={() => setTarget(null)}
          onSaved={(result, predicted) => onSaved(target.secret, result, predicted)}
        />
      )}
    </>
  );
}
