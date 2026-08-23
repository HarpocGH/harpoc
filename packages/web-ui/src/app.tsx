import { useEffect, useMemo, useState } from "preact/hooks";
import type { ApiClient } from "./api/client";
import { createApiClient } from "./api/client";
import { clearToken, getToken } from "./auth/token-store";
import { Nav } from "./components/nav";
import { SealBar } from "./components/seal-bar";
import { useAsync } from "./hooks";
import { AgentDetailPage } from "./pages/agent-detail";
import { AgentsPage } from "./pages/agents";
import { AuditPage } from "./pages/audit";
import { DashboardPage } from "./pages/dashboard";
import { PermissionsPage } from "./pages/permissions";
import { SecretDetailPage } from "./pages/secret-detail";
import { SecretsPage } from "./pages/secrets";
import { TokensPage } from "./pages/tokens";
import { useHashRoute } from "./router";
import { Sealed } from "./screens/sealed";
import { Unauthorized } from "./screens/unauthorized";

export function App({ api }: { api?: ApiClient }) {
  const [authTick, setAuthTick] = useState(0);
  const [sealed, setSealed] = useState(false);
  // The session signals are wired once, not per render: a client rebuilt on
  // every render would hand each page a fresh identity and defeat any memo a
  // page hangs off it.
  const client = useMemo(
    () =>
      api ??
      createApiClient(
        getToken,
        fetch,
        () => {
          clearToken();
          setAuthTick((t) => t + 1);
        },
        () => setSealed(true),
      ),
    [api],
  );
  const route = useHashRoute();
  const health = useAsync(() => client.health(), [authTick]);

  // A new token is a new session: whatever the last one learned about the
  // vault's state is stale, so the takeover lifts and `health` re-answers.
  useEffect(() => setSealed(false), [authTick]);

  if (getToken() === null) {
    return <Unauthorized onToken={() => setAuthTick((t) => t + 1)} />;
  }
  // Before the first health response the shell assumes unlocked: a sealed
  // takeover flashed on every load would be a lie more often than not.
  const state = sealed ? "sealed" : (health.data?.state ?? "unlocked");
  if (state !== "unlocked") {
    return (
      <>
        <SealBar state={state} />
        <Sealed />
      </>
    );
  }

  // `currentRoute()` hands over the whole hash, `?query` included — the
  // prefiltered links the governance pages emit are exactly that shape. Routes
  // are therefore matched on the path alone, and a page that wants the query
  // reads it off `window.location.hash` itself.
  const path = route.split("?")[0] ?? route;
  const detailMatch = /^\/secrets\/(?<handle>.+)$/.exec(path);
  const detailHandle = detailMatch?.groups?.["handle"];
  const agentMatch = /^\/agents\/(?<name>[^/]+)$/.exec(path);
  const agentName = agentMatch?.groups?.["name"];

  return (
    <>
      <SealBar state={state} />
      <div class="layout">
        <Nav route={path} />
        <main class="content">
          {path === "/" && <DashboardPage api={client} />}
          {path === "/secrets" && <SecretsPage api={client} />}
          {detailHandle !== undefined && (
            <SecretDetailPage api={client} handle={decodeURIComponent(detailHandle)} />
          )}
          {path === "/audit" && <AuditPage api={client} />}
          {path === "/agents" && <AgentsPage api={client} />}
          {path === "/permissions" && <PermissionsPage api={client} />}
          {path === "/tokens" && <TokensPage api={client} />}
          {agentName !== undefined && (
            <AgentDetailPage api={client} name={decodeURIComponent(agentName)} />
          )}
        </main>
      </div>
    </>
  );
}
