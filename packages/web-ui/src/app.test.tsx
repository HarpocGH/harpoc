import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ApiClient } from "./api/client";
import { ApiError } from "./api/client";
import { clearToken, getToken, setToken } from "./auth/token-store";
import { App } from "./app";

function fakeApi(overrides: Partial<ApiClient> = {}): ApiClient {
  return {
    health: vi.fn().mockResolvedValue({ state: "unlocked", version: "1.0.0" }),
    expiringReport: vi.fn().mockResolvedValue({
      expiring: [],
      oauth_refresh_needed: [],
      certificates_nearing_renewal: [],
    }),
    listSecrets: vi.fn().mockResolvedValue([]),
    getSecret: vi.fn().mockResolvedValue({
      handle: "secret://myproj/test-key",
      name: "test-key",
      type: "api_key",
      project: "myproj",
      status: "active",
      version: 1,
      createdAt: 0,
      updatedAt: 0,
      expiresAt: null,
      rotatedAt: null,
    }),
    createSecret: vi.fn().mockResolvedValue({ handle: "secret://k", secret_id: "id-1" }),
    rotateSecret: vi.fn().mockResolvedValue(undefined),
    deleteSecret: vi.fn().mockResolvedValue(undefined),
    getInjectionPolicy: vi.fn().mockResolvedValue({}),
    putInjectionPolicy: vi.fn().mockResolvedValue(undefined),
    getAccessPolicies: vi.fn().mockResolvedValue([]),
    getOAuthStatus: vi.fn().mockResolvedValue({}),
    getCertificateStatus: vi.fn().mockResolvedValue({}),
    queryAudit: vi.fn().mockResolvedValue([]),
    verifyAuditChain: vi
      .fn()
      .mockResolvedValue({ valid: true, checked: 0, legacy: 0, first_broken_id: null }),
    listAgents: vi.fn().mockResolvedValue([]),
    getAgent: vi.fn().mockResolvedValue({
      id: "id-1",
      name: "ci-bot",
      description: null,
      owner: null,
      status: "active",
      created_at: 0,
      updated_at: 0,
      deactivated_at: null,
      last_active_at: null,
      active_tokens: 0,
      grants: 0,
    }),
    registerAgent: vi.fn().mockResolvedValue({}),
    updateAgent: vi.fn().mockResolvedValue({}),
    deactivateAgent: vi.fn().mockResolvedValue({ revoked_tokens: 0 }),
    activateAgent: vi.fn().mockResolvedValue({}),
    deleteAgent: vi.fn().mockResolvedValue({ revoked_tokens: 0, removed_grants: 0 }),
    listAgentPolicies: vi.fn().mockResolvedValue([]),
    setAgentPermissions: vi
      .fn()
      .mockResolvedValue({ policy: null, gated_before: false, gated_after: false }),
    listTokens: vi.fn().mockResolvedValue([]),
    revokeToken: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  } as ApiClient;
}

const jsonResponse = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), { status });

const HEALTHY = { data: { state: "unlocked", version: "1.0.0" } };

/**
 * Wraps a per-test `/api/v1/health` stub. DashboardPage renders as soon as the
 * shell reaches "unlocked" and immediately calls `listSecrets()`/
 * `expiringReport()`/`queryAudit()`, so every health-focused stub below also
 * needs those three routes answered with array-shaped envelopes — a
 * path-agnostic stub that only knows about health responses feeds the dashboard
 * a non-array `data` and throws mid-render (unhandled rejection) once it
 * iterates the result. Routing them away from `healthHandler` also keeps the
 * call-counting handlers below counting health calls only.
 */
function routeFetch(healthHandler: () => Response): typeof fetch {
  return vi.fn((input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.includes("/api/v1/health/expiring")) {
      return Promise.resolve(
        jsonResponse(200, {
          data: [],
          oauth_refresh_needed: [],
          certificates_nearing_renewal: [],
        }),
      );
    }
    if (url.includes("/api/v1/secrets")) {
      return Promise.resolve(jsonResponse(200, { data: [] }));
    }
    if (url.includes("/api/v1/audit")) {
      return Promise.resolve(jsonResponse(200, { data: [] }));
    }
    return Promise.resolve(healthHandler());
  }) as unknown as typeof fetch;
}

beforeEach(() => {
  window.sessionStorage.clear();
  history.replaceState(null, "", "/ui");
  window.location.hash = "";
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  document.documentElement.removeAttribute("data-theme");
});

describe("App shell", () => {
  it("shows the sign-in screen without a token", () => {
    render(<App api={fakeApi()} />);
    expect(screen.getByText("Sign in")).toBeTruthy();
  });

  it("shows the seal bar UNLOCKED with a token and healthy vault", async () => {
    setToken("t");
    render(<App api={fakeApi()} />);
    await waitFor(() => expect(screen.getByText("UNLOCKED")).toBeTruthy());
  });

  it("shows the sealed takeover when health reports sealed", async () => {
    setToken("t");
    render(
      <App
        api={fakeApi({ health: vi.fn().mockResolvedValue({ state: "sealed", version: "1" }) })}
      />,
    );
    await waitFor(() => expect(screen.getByText(/harpoc unlock/)).toBeTruthy());
  });

  it("names the sealed state in the seal bar, not UNLOCKED", async () => {
    setToken("t");
    render(
      <App
        api={fakeApi({ health: vi.fn().mockResolvedValue({ state: "sealed", version: "1" }) })}
      />,
    );
    await waitFor(() => expect(screen.getByText("SEALED", { selector: ".state" })).toBeTruthy());
    expect(screen.queryByText("UNLOCKED")).toBeNull();
  });

  it("does not drop the token from a health error during render", async () => {
    // The token drop is event-driven (the client's onUnauthorized), never a
    // side effect of rendering a stale `health.error`. Rendering must stay pure:
    // the render-time `clearToken()` this replaces also swallowed the first
    // re-pasted token, because the error outlived the paste.
    setToken("stale");
    render(
      <App
        api={fakeApi({
          health: vi.fn().mockRejectedValue(new ApiError(401, "UNAUTHORIZED", "nope")),
        })}
      />,
    );
    await waitFor(() => expect(screen.getByRole("heading", { name: "Dashboard" })).toBeTruthy());
    expect(getToken()).toBe("stale");
    expect(screen.queryByText("Sign in")).toBeNull();
  });

  it("keeps the shell up on a non-401 health failure", async () => {
    setToken("t");
    render(
      <App
        api={fakeApi({ health: vi.fn().mockRejectedValue(new ApiError(500, "INTERNAL", "boom")) })}
      />,
    );
    await waitFor(() => expect(screen.getByRole("heading", { name: "Dashboard" })).toBeTruthy());
    expect(getToken()).toBe("t");
  });

  it("stores a pasted token and re-renders the shell", async () => {
    const { container } = render(<App api={fakeApi()} />);
    fireEvent.input(screen.getByLabelText("API token"), { target: { value: "pasted.jwt" } });
    const form = container.querySelector("form");
    if (form === null) throw new Error("sign-in form missing");
    fireEvent.submit(form);
    await waitFor(() => expect(screen.getByText("UNLOCKED")).toBeTruthy());
    expect(getToken()).toBe("pasted.jwt");
  });

  it("routes the hash to the matching page", async () => {
    setToken("t");
    window.location.hash = "#/secrets";
    render(<App api={fakeApi()} />);
    await waitFor(() => expect(screen.getByRole("heading", { name: "Secrets" })).toBeTruthy());
  });

  it("routes a secret detail hash and decodes the handle", async () => {
    setToken("t");
    window.location.hash = "#/secrets/myproj%2Ftest-key";
    const api = fakeApi();
    render(<App api={api} />);
    await waitFor(() => expect(screen.getByRole("heading", { name: /test-key/ })).toBeTruthy());
    // The decode is what the assertion is about: the API addresses a
    // project-scoped secret as one `project/name` segment, so the page must be
    // handed the decoded handle, not the raw `myproj%2Ftest-key` route text.
    expect(api.getSecret).toHaveBeenCalledWith("myproj/test-key");
    expect(screen.queryByRole("heading", { name: "Secrets" })).toBeNull();
  });

  it("marks the active nav link for the current route", async () => {
    setToken("t");
    window.location.hash = "#/audit";
    render(<App api={fakeApi()} />);
    await waitFor(() => expect(screen.getByRole("heading", { name: "Audit" })).toBeTruthy());
    const active = document.querySelectorAll('nav.rail a[data-active="true"]');
    expect(active.length).toBe(1);
    expect(active[0]?.textContent).toBe("Audit");
  });

  it("follows a hashchange without a remount", async () => {
    setToken("t");
    render(<App api={fakeApi()} />);
    await waitFor(() => expect(screen.getByRole("heading", { name: "Dashboard" })).toBeTruthy());
    window.location.hash = "#/audit";
    window.dispatchEvent(new HashChangeEvent("hashchange"));
    await waitFor(() => expect(screen.getByRole("heading", { name: "Audit" })).toBeTruthy());
  });

  it("never renders a page while the vault is sealed", async () => {
    setToken("t");
    window.location.hash = "#/secrets";
    render(
      <App
        api={fakeApi({ health: vi.fn().mockResolvedValue({ state: "sealed", version: "1" }) })}
      />,
    );
    await waitFor(() => expect(screen.getByText(/harpoc unlock/)).toBeTruthy());
    expect(screen.queryByRole("navigation")).toBeNull();
    expect(screen.queryByRole("heading", { name: "Secrets" })).toBeNull();
  });
});

/**
 * These render `<App />` with no `api` prop, so the production client is the one
 * under test: `GET /health` is unauthenticated on the real server, so a stale
 * token can only surface as a 401 on some other call, and the shell has to learn
 * it from the client's callbacks rather than from `health`.
 */
describe("App session signals", () => {
  it("returns to sign-in and drops the token when a call answers 401", async () => {
    setToken("stale");
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(jsonResponse(401, { error: "UNAUTHORIZED", message: "no" }))),
    );
    render(<App />);
    await waitFor(() => expect(screen.getByText("Sign in")).toBeTruthy());
    expect(getToken()).toBeNull();
  });

  it("accepts the re-pasted token on the FIRST submit after a 401", async () => {
    setToken("stale");
    let calls = 0;
    vi.stubGlobal(
      "fetch",
      routeFetch(() => {
        calls += 1;
        return calls === 1
          ? jsonResponse(401, { error: "UNAUTHORIZED", message: "no" })
          : jsonResponse(200, HEALTHY);
      }),
    );
    const { container } = render(<App />);
    await waitFor(() => expect(screen.getByText("Sign in")).toBeTruthy());

    fireEvent.input(screen.getByLabelText("API token"), { target: { value: "fresh.jwt" } });
    const form = container.querySelector("form");
    if (form === null) throw new Error("sign-in form missing");
    fireEvent.submit(form);

    // One submit, one transition: a stale render-time error must not bounce the
    // user back to sign-in and discard the token they just pasted.
    await waitFor(() => expect(screen.getByText("UNLOCKED")).toBeTruthy());
    expect(getToken()).toBe("fresh.jwt");
    expect(screen.queryByText("Sign in")).toBeNull();
  });

  it("shows the sealed takeover when a call answers VAULT_LOCKED", async () => {
    setToken("t");
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve(jsonResponse(423, { error: "VAULT_LOCKED", message: "Vault is locked" })),
      ),
    );
    render(<App />);
    await waitFor(() => expect(screen.getByText(/harpoc unlock/)).toBeTruthy());
    expect(screen.getByText("SEALED", { selector: ".state" })).toBeTruthy();
    expect(screen.queryByRole("navigation")).toBeNull();
  });

  it("keeps the token when the vault is merely sealed", async () => {
    setToken("keep-me");
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve(jsonResponse(423, { error: "VAULT_LOCKED", message: "Vault is locked" })),
      ),
    );
    render(<App />);
    await waitFor(() => expect(screen.getByText(/harpoc unlock/)).toBeTruthy());
    // Sealed is not unauthorized: the token survives the re-unlock (spec § 3.4
    // keeps the two degraded screens distinct in remedy, not just in wording).
    expect(getToken()).toBe("keep-me");
  });

  it("leaves the sealed takeover when a new token is adopted and the vault answers", async () => {
    let locked = true;
    vi.stubGlobal(
      "fetch",
      routeFetch(() =>
        locked
          ? jsonResponse(423, { error: "VAULT_LOCKED", message: "Vault is locked" })
          : jsonResponse(200, HEALTHY),
      ),
    );
    setToken("t");
    const { container } = render(<App />);
    await waitFor(() => expect(screen.getByText(/harpoc unlock/)).toBeTruthy());

    locked = false;
    clearToken();
    cleanup();
    const second = render(<App />);
    fireEvent.input(second.getByLabelText("API token"), { target: { value: "after.unlock" } });
    const form = second.container.querySelector("form") ?? container.querySelector("form");
    if (form === null) throw new Error("sign-in form missing");
    fireEvent.submit(form);
    await waitFor(() => expect(screen.getByText("UNLOCKED")).toBeTruthy());
  });

  it("clears a stale sealed flag when a new token is adopted", async () => {
    // One envelope fires both signals, which compresses into a single call the
    // state the effect guards: a session that saw VAULT_LOCKED and then lost its
    // token. Without the authTick-keyed reset, `sealed` outlives that session
    // and the fresh token lands straight back on the takeover — the vault is
    // fine, the screen says otherwise, and only a reload clears it.
    setToken("stale");
    let calls = 0;
    vi.stubGlobal(
      "fetch",
      routeFetch(() => {
        calls += 1;
        return calls === 1
          ? jsonResponse(401, { error: "VAULT_LOCKED", message: "Vault is locked" })
          : jsonResponse(200, HEALTHY);
      }),
    );
    const { container } = render(<App />);
    await waitFor(() => expect(screen.getByText("Sign in")).toBeTruthy());

    fireEvent.input(screen.getByLabelText("API token"), { target: { value: "fresh.jwt" } });
    const form = container.querySelector("form");
    if (form === null) throw new Error("sign-in form missing");
    fireEvent.submit(form);

    await waitFor(() => expect(screen.getByText("UNLOCKED")).toBeTruthy());
    expect(screen.queryByText(/harpoc unlock/)).toBeNull();
  });

  it("does not fire the session signals when an api prop is injected", async () => {
    setToken("t");
    const fetchSpy = vi.fn(() => Promise.resolve(jsonResponse(200, HEALTHY)));
    vi.stubGlobal("fetch", fetchSpy);
    render(<App api={fakeApi()} />);
    await waitFor(() => expect(screen.getByText("UNLOCKED")).toBeTruthy());
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("App shell v1.4 routes", () => {
  it("routes #/agents to the agents page", async () => {
    setToken("t");
    window.location.hash = "#/agents";
    render(<App api={fakeApi()} />);
    await waitFor(() => expect(screen.getByRole("heading", { name: "Agents" })).toBeTruthy());
  });

  it("routes an agent detail hash and decodes the name", async () => {
    setToken("t");
    window.location.hash = "#/agents/ci-bot";
    const api = fakeApi();
    render(<App api={api} />);
    await waitFor(() => expect(screen.getByRole("heading", { name: /ci-bot/ })).toBeTruthy());
    expect(api.getAgent).toHaveBeenCalledWith("ci-bot");
    expect(screen.queryByRole("heading", { name: "Agents" })).toBeNull();
  });

  it("routes #/permissions to the matrix, the ?secret= preselect included", async () => {
    setToken("t");
    window.location.hash = "#/permissions?secret=myproj%2Ftest-key";
    render(<App api={fakeApi()} />);
    await waitFor(() => expect(screen.getByRole("heading", { name: "Permissions" })).toBeTruthy());
  });

  it("matches a route on its path, not on the query the page reads", async () => {
    // `currentRoute()` carries the whole hash, query included — the prefiltered
    // links the agent detail emits are exactly that shape, and a route matched
    // on the raw hash would render nothing for them.
    setToken("t");
    window.location.hash = "#/audit?principal_type=agent&principal_id=ci-bot";
    render(<App api={fakeApi()} />);
    await waitFor(() => expect(screen.getByRole("heading", { name: "Audit" })).toBeTruthy());
  });

  it("routes #/tokens to the issued-token registry", async () => {
    setToken("t");
    window.location.hash = "#/tokens";
    const api = fakeApi();
    render(<App api={api} />);
    await waitFor(() => expect(screen.getByRole("heading", { name: "Tokens" })).toBeTruthy());
    expect(api.listTokens).toHaveBeenCalled();
  });

  it("carries the governance links in the nav rail", () => {
    setToken("t");
    render(<App api={fakeApi()} />);
    const labels = [...document.querySelectorAll("nav.rail a")].map((a) => a.textContent);
    expect(labels).toEqual(["Dashboard", "Secrets", "Audit", "Agents", "Permissions", "Tokens"]);
  });

  it("cycles the theme from the nav toggle", () => {
    setToken("t");
    render(<App api={fakeApi()} />);
    const toggle = screen.getByRole("button", { name: /theme:/ });
    expect(toggle.textContent).toBe("theme: system");
    fireEvent.click(toggle);
    expect(toggle.textContent).toBe("theme: light");
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
    fireEvent.click(toggle);
    expect(toggle.textContent).toBe("theme: dark");
    fireEvent.click(toggle);
    expect(toggle.textContent).toBe("theme: system");
    expect(document.documentElement.hasAttribute("data-theme")).toBe(false);
  });

  // RED while Nav seeds its label from storedTheme(): under a storage that
  // refuses writes the attribute is the only truth, and a remount used to
  // relabel "system" while the page stayed dark.
  it("a remounted nav labels the applied theme, not the stored one", () => {
    setToken("t");
    document.documentElement.setAttribute("data-theme", "dark");
    render(<App api={fakeApi()} />);
    expect(screen.getByRole("button", { name: /theme:/ }).textContent).toBe("theme: dark");
  });
});
