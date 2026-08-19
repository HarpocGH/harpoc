import { useEffect, useMemo, useState } from "preact/hooks";
import type { ApiClient } from "./api/client";
import { createApiClient } from "./api/client";
import { clearToken, getToken } from "./auth/token-store";
import { Nav } from "./components/nav";
import { SealBar } from "./components/seal-bar";
import { useAsync } from "./hooks";
import { AuditPage } from "./pages/audit";
import { DashboardPage } from "./pages/dashboard";
import { SecretDetailPage } from "./pages/secret-detail";
import { SecretsPage } from "./pages/secrets";
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

  const detailMatch = /^\/secrets\/(?<handle>.+)$/.exec(route);
  const detailHandle = detailMatch?.groups?.["handle"];

  return (
    <>
      <SealBar state={state} />
      <div class="layout">
        <Nav route={route} />
        <main class="content">
          {route === "/" && <DashboardPage api={client} />}
          {route === "/secrets" && <SecretsPage api={client} />}
          {detailHandle !== undefined && (
            <SecretDetailPage api={client} handle={decodeURIComponent(detailHandle)} />
          )}
          {route === "/audit" && <AuditPage api={client} />}
        </main>
      </div>
    </>
  );
}
