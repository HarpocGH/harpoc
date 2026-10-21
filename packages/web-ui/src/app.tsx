import { useEffect, useMemo, useState } from "preact/hooks";
import type { ApiClient } from "./api/client";
import { createApiClient } from "./api/client";
import { adoptLaunchToken, clearToken, getToken } from "./auth/token-store";
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

const PAGES = new Set(["/", "/secrets", "/audit", "/agents", "/permissions", "/tokens"]);

function decodeSegment(raw: string): string | null {
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

function NotFound() {
  return (
    <>
      <h1>Not found</h1>
      <p class="empty">
        No such page. <a href="#/">Back to the dashboard</a>
      </p>
    </>
  );
}

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

  useEffect(() => {
    const onHashChange = (): void => {
      if (adoptLaunchToken()) setAuthTick((t) => t + 1);
    };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

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
  const rawHandle = /^\/secrets\/(?<handle>.+)$/.exec(path)?.groups?.["handle"];
  const rawName = /^\/agents\/(?<name>[^/]+)$/.exec(path)?.groups?.["name"];
  const detailHandle = rawHandle === undefined ? null : decodeSegment(rawHandle);
  const agentName = rawName === undefined ? null : decodeSegment(rawName);
  const notFound = !PAGES.has(path) && detailHandle === null && agentName === null;

  return (
    <>
      <SealBar state={state} />
      <div class="layout" key={authTick}>
        <Nav route={path} />
        <main class="content">
          {path === "/" && <DashboardPage api={client} />}
          {path === "/secrets" && <SecretsPage api={client} />}
          {detailHandle !== null && <SecretDetailPage api={client} handle={detailHandle} />}
          {path === "/audit" && <AuditPage api={client} />}
          {path === "/agents" && <AgentsPage api={client} />}
          {path === "/permissions" && <PermissionsPage api={client} />}
          {path === "/tokens" && <TokensPage api={client} />}
          {agentName !== null && <AgentDetailPage api={client} name={agentName} />}
          {notFound && <NotFound />}
        </main>
      </div>
    </>
  );
}
