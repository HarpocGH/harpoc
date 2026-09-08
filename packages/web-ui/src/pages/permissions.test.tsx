import type { AccessPolicy, Agent, AgentPolicy } from "@harpoc/shared";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ApiClient, SecretInfo } from "../api/client";
import { ApiError } from "../api/client";
import { PermissionsPage } from "./permissions";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
beforeEach(() => {
  window.location.hash = "";
  window.sessionStorage.clear();
});

/** A three-segment token whose payload decodes — nothing here verifies one. */
const jwt = (payload: Record<string, unknown>): string =>
  `h.${btoa(JSON.stringify(payload)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}.s`;

const agent = (over: Partial<Agent> = {}): Agent => ({
  id: "a-1",
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
  ...over,
});

const ACTIVE = agent();
const INACTIVE = agent({ id: "a-2", name: "old-bot", status: "inactive" });

const secret = (over: Partial<SecretInfo> = {}): SecretInfo => ({
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
  ...over,
});

/** Held by `ci-bot`, so the loaded policies mark it agent-gated. */
const GATED = secret();
/** No agent holds a row on it — granting here is the flip the editor predicts. */
const UNGATED = secret({ handle: "secret://open-key", name: "open-key", project: null });

const policy = (over: Partial<AgentPolicy> = {}): AgentPolicy => ({
  policy_id: "p-1",
  secret_id: "s-1",
  handle: GATED.handle,
  permissions: ["read", "use"],
  expires_at: null,
  created_at: 0,
  ...over,
});

const POLICIES: Record<string, AgentPolicy[]> = { "ci-bot": [policy()], "old-bot": [] };

const access = (over: Partial<AccessPolicy> = {}): AccessPolicy => ({
  id: "ap-1",
  secret_id: "s-1",
  principal_type: "agent",
  principal_id: "ci-bot",
  permissions: ["read", "use"],
  created_at: 0,
  expires_at: null,
  created_by: "cli",
  ...over,
});

/**
 * What `GET /secrets/:handle/policies` answers per column — agent rows
 * included, because that route lists every principal. `UNGATED` answers the
 * empty list, which is what keeps the no-grants marker and both grant
 * predictions saying what they said before the column read existed.
 */
const ACCESS: Record<string, AccessPolicy[]> = { [GATED.handle]: [access()] };

const api = (over: Partial<ApiClient> = {}): ApiClient =>
  ({
    listAgents: vi.fn((status?: string) =>
      Promise.resolve(status === "all" ? [ACTIVE, INACTIVE] : [ACTIVE]),
    ),
    listSecrets: vi.fn().mockResolvedValue([GATED, UNGATED]),
    listAgentPolicies: vi.fn((name: string) => Promise.resolve(POLICIES[name] ?? [])),
    getAccessPolicies: vi.fn((handle: string) => Promise.resolve(ACCESS[handle] ?? [])),
    setAgentPermissions: vi
      .fn()
      .mockResolvedValue({ policy: null, gated_before: false, gated_after: false }),
    ...over,
  }) as ApiClient;

const cell = (agentName: string, handle: string): HTMLElement => {
  const el = document.querySelector<HTMLElement>(
    `td[data-agent="${agentName}"][data-secret="${handle}"]`,
  );
  if (el === null) throw new Error(`cell ${agentName} × ${handle} is not rendered`);
  return el;
};

const columns = (): number => document.querySelectorAll("thead th").length;

describe("PermissionsPage", () => {
  it("renders a row per agent and a column per secret", async () => {
    render(<PermissionsPage api={api()} />);
    await waitFor(() => expect(cell("ci-bot", GATED.handle)).toBeTruthy());
    expect(document.querySelectorAll("tbody tr").length).toBe(1);
    // The agent column plus one per secret.
    expect(columns()).toBe(3);
    expect(screen.getByText("test-key")).toBeTruthy();
    expect(screen.getByText("open-key")).toBeTruthy();
  });

  it("shows permission chips in a granted cell and an em dash in an empty one", async () => {
    render(<PermissionsPage api={api()} />);
    await waitFor(() => expect(cell("ci-bot", GATED.handle)).toBeTruthy());
    expect(cell("ci-bot", GATED.handle).textContent).toContain("read");
    expect(cell("ci-bot", GATED.handle).textContent).toContain("use");
    expect(cell("ci-bot", UNGATED.handle).textContent).toBe("—");
  });

  it("marks a secret no loaded agent holds a row on as having no grants", async () => {
    render(<PermissionsPage api={api()} />);
    await waitFor(() => expect(screen.getByText("no grants")).toBeTruthy());
    const marked = document.querySelectorAll('thead th .chip[data-tone="warn"]');
    expect(marked.length).toBe(1);
    expect(marked[0]?.closest("th")?.textContent).toContain("open-key");
    expect(screen.getByText("granted").closest("th")?.textContent).toContain("test-key");
  });

  it("includes inactive agents on request and makes their cells read-only", async () => {
    const listAgents = vi.fn((status?: string) =>
      Promise.resolve(status === "all" ? [ACTIVE, INACTIVE] : [ACTIVE]),
    );
    render(<PermissionsPage api={api({ listAgents })} />);
    await waitFor(() => expect(cell("ci-bot", UNGATED.handle)).toBeTruthy());
    fireEvent.click(screen.getByLabelText(/Show inactive/));
    await waitFor(() => expect(listAgents).toHaveBeenCalledWith("all"));
    await waitFor(() => expect(cell("old-bot", UNGATED.handle)).toBeTruthy());
    // The engine would refuse an inactive agent's grant with AGENT_INACTIVE, so
    // the cell never opens an editor in the first place.
    expect(cell("old-bot", UNGATED.handle).getAttribute("data-readonly")).toBe("true");
    fireEvent.click(cell("old-bot", UNGATED.handle));
    expect(screen.queryByText("Save")).toBeNull();
  });

  it("never offers create as a grantable permission", async () => {
    render(<PermissionsPage api={api()} />);
    await waitFor(() => expect(cell("ci-bot", UNGATED.handle)).toBeTruthy());
    fireEvent.click(cell("ci-bot", UNGATED.handle));
    for (const permission of ["list", "read", "use", "rotate", "revoke", "admin"]) {
      expect(screen.getByLabelText(permission)).toBeTruthy();
    }
    expect(screen.queryByLabelText("create")).toBeNull();
  });

  it("predicts the first-grant flip before the PUT and writes only after Confirm", async () => {
    const setAgentPermissions = vi
      .fn()
      .mockResolvedValue({ policy: null, gated_before: false, gated_after: true });
    render(<PermissionsPage api={api({ setAgentPermissions })} />);
    await waitFor(() => expect(cell("ci-bot", UNGATED.handle)).toBeTruthy());
    fireEvent.click(cell("ci-bot", UNGATED.handle));
    fireEvent.click(screen.getByLabelText("use"));
    fireEvent.click(screen.getByText("Save"));
    const prediction = screen.getByText(/first grant/);
    expect(prediction.textContent).toContain(UNGATED.handle);
    // The prediction is what the operator confirms — nothing is written yet.
    expect(setAgentPermissions).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText("Confirm"));
    await waitFor(() =>
      expect(setAgentPermissions).toHaveBeenCalledWith("ci-bot", UNGATED.handle, {
        permissions: ["use"],
        expires_at: undefined,
      }),
    );
  });

  it("predicts the last-grant flip when the secret's only grant is cleared", async () => {
    const setAgentPermissions = vi
      .fn()
      .mockResolvedValue({ policy: null, gated_before: true, gated_after: false });
    render(<PermissionsPage api={api({ setAgentPermissions })} />);
    await waitFor(() => expect(cell("ci-bot", GATED.handle)).toBeTruthy());
    fireEvent.click(cell("ci-bot", GATED.handle));
    fireEvent.click(screen.getByText("Clear"));
    const prediction = screen.getByText(/last grant/);
    expect(prediction.textContent).toContain(GATED.handle);
    expect(setAgentPermissions).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText("Confirm"));
    await waitFor(() =>
      expect(setAgentPermissions).toHaveBeenCalledWith("ci-bot", GATED.handle, {
        permissions: [],
        expires_at: undefined,
      }),
    );
  });

  it("makes no request when Clear is used on an empty cell", async () => {
    const setAgentPermissions = vi.fn();
    render(<PermissionsPage api={api({ setAgentPermissions })} />);
    await waitFor(() => expect(cell("ci-bot", UNGATED.handle)).toBeTruthy());
    fireEvent.click(cell("ci-bot", UNGATED.handle));
    fireEvent.click(screen.getByText("Clear"));
    expect(setAgentPermissions).not.toHaveBeenCalled();
    expect(screen.queryByText("Clear")).toBeNull();
  });

  it("writes without a confirmation step when neither gate flips", async () => {
    const setAgentPermissions = vi
      .fn()
      .mockResolvedValue({ policy: null, gated_before: true, gated_after: true });
    render(<PermissionsPage api={api({ setAgentPermissions })} />);
    await waitFor(() => expect(cell("ci-bot", GATED.handle)).toBeTruthy());
    fireEvent.click(cell("ci-bot", GATED.handle));
    fireEvent.click(screen.getByLabelText("read"));
    fireEvent.click(screen.getByText("Save"));
    expect(screen.queryByText("Confirm")).toBeNull();
    await waitFor(() =>
      expect(setAgentPermissions).toHaveBeenCalledWith("ci-bot", GATED.handle, {
        permissions: ["use"],
        expires_at: undefined,
      }),
    );
  });

  it("sends the expiry as epoch milliseconds", async () => {
    const setAgentPermissions = vi
      .fn()
      .mockResolvedValue({ policy: null, gated_before: true, gated_after: true });
    render(<PermissionsPage api={api({ setAgentPermissions })} />);
    await waitFor(() => expect(cell("ci-bot", GATED.handle)).toBeTruthy());
    fireEvent.click(cell("ci-bot", GATED.handle));
    fireEvent.input(screen.getByLabelText("Expires"), { target: { value: "2027-01-02T03:04" } });
    fireEvent.click(screen.getByText("Save"));
    await waitFor(() =>
      expect(setAgentPermissions).toHaveBeenCalledWith("ci-bot", GATED.handle, {
        permissions: ["read", "use"],
        expires_at: new Date("2027-01-02T03:04").getTime(),
      }),
    );
  });

  it("states the engine's result when the gating flipped, and reloads the matrix", async () => {
    const listAgents = vi.fn().mockResolvedValue([ACTIVE]);
    const setAgentPermissions = vi
      .fn()
      .mockResolvedValue({ policy: null, gated_before: false, gated_after: true });
    render(<PermissionsPage api={api({ listAgents, setAgentPermissions })} />);
    await waitFor(() => expect(cell("ci-bot", UNGATED.handle)).toBeTruthy());
    fireEvent.click(cell("ci-bot", UNGATED.handle));
    fireEvent.click(screen.getByLabelText("use"));
    fireEvent.click(screen.getByText("Save"));
    fireEvent.click(screen.getByText("Confirm"));
    // The response is the truth — the prediction was only advisory.
    await waitFor(() => expect(screen.getByText(/received its first grant/)).toBeTruthy());
    await waitFor(() => expect(listAgents).toHaveBeenCalledTimes(2));
  });

  it("preselects a single column from the ?secret= query", async () => {
    window.location.hash = "#/permissions?secret=myproj%2Ftest-key";
    render(<PermissionsPage api={api()} />);
    await waitFor(() => expect(cell("ci-bot", GATED.handle)).toBeTruthy());
    // The query carries the scheme-less path, which is what `secretPath` yields.
    expect(columns()).toBe(2);
    expect(document.querySelector(`td[data-secret="${UNGATED.handle}"]`)).toBeNull();
  });

  it("filters the columns by secret name or project", async () => {
    render(<PermissionsPage api={api()} />);
    await waitFor(() => expect(cell("ci-bot", UNGATED.handle)).toBeTruthy());
    fireEvent.input(screen.getByLabelText("Filter secrets"), { target: { value: "myproj" } });
    await waitFor(() => expect(columns()).toBe(2));
    expect(document.querySelector(`td[data-secret="${UNGATED.handle}"]`)).toBeNull();
  });

  it("surfaces a refused write instead of swallowing it", async () => {
    const setAgentPermissions = vi.fn().mockRejectedValue(new Error("ACCESS_DENIED"));
    render(<PermissionsPage api={api({ setAgentPermissions })} />);
    await waitFor(() => expect(cell("ci-bot", GATED.handle)).toBeTruthy());
    fireEvent.click(cell("ci-bot", GATED.handle));
    fireEvent.click(screen.getByLabelText("read"));
    fireEvent.click(screen.getByText("Save"));
    await waitFor(() => expect(screen.getByText("ACCESS_DENIED")).toBeTruthy());
  });

  it("names the grant command when a policy-gated cell write is refused", async () => {
    window.sessionStorage.setItem(
      "harpoc.ui.token",
      jwt({ sub: "web-ui", principal_type: "user", jti: "j-1" }),
    );
    const setAgentPermissions = vi
      .fn()
      .mockRejectedValue(new ApiError(403, "ACCESS_DENIED", "Access denied"));
    render(<PermissionsPage api={api({ setAgentPermissions })} />);
    await waitFor(() => expect(cell("ci-bot", GATED.handle)).toBeTruthy());
    fireEvent.click(cell("ci-bot", GATED.handle));
    fireEvent.click(screen.getByLabelText("read"));
    fireEvent.click(screen.getByText("Save"));
    await waitFor(() =>
      expect(
        screen.getByText(
          `harpoc policy grant ${GATED.handle} --principal-type user --principal-id web-ui --permissions admin`,
        ),
      ).toBeTruthy(),
    );
  });

  it("falls back to the CLI's default principal type when the claim is absent", async () => {
    window.sessionStorage.setItem("harpoc.ui.token", jwt({ sub: "ci-bot" }));
    const setAgentPermissions = vi
      .fn()
      .mockRejectedValue(new ApiError(403, "ACCESS_DENIED", "Access denied"));
    render(<PermissionsPage api={api({ setAgentPermissions })} />);
    await waitFor(() => expect(cell("ci-bot", GATED.handle)).toBeTruthy());
    fireEvent.click(cell("ci-bot", GATED.handle));
    fireEvent.click(screen.getByLabelText("read"));
    fireEvent.click(screen.getByText("Save"));
    await waitFor(() =>
      expect(
        screen.getByText(
          `harpoc policy grant ${GATED.handle} --principal-type agent --principal-id ci-bot --permissions admin`,
        ),
      ).toBeTruthy(),
    );
  });

  it("leaves a refusal that is not ACCESS_DENIED without the grant hint", async () => {
    const setAgentPermissions = vi
      .fn()
      .mockRejectedValue(new ApiError(400, "SCHEMA_VALIDATION_ERROR", "Bad expiry"));
    render(<PermissionsPage api={api({ setAgentPermissions })} />);
    await waitFor(() => expect(cell("ci-bot", GATED.handle)).toBeTruthy());
    fireEvent.click(cell("ci-bot", GATED.handle));
    fireEvent.click(screen.getByLabelText("read"));
    fireEvent.click(screen.getByText("Save"));
    await waitFor(() => expect(screen.getByText("Bad expiry")).toBeTruthy());
    expect(screen.queryByText(/harpoc policy grant/)).toBeNull();
  });

  it("names the grant command when a loaded secret's cell write is refused 404", async () => {
    // The engine conceals a policy refusal on a secret the caller holds no row
    // on as SECRET_NOT_FOUND (R5), so on a handle the page is still listing the
    // remedy is the same grant the 403 branch already names.
    window.sessionStorage.setItem(
      "harpoc.ui.token",
      jwt({ sub: "web-ui", principal_type: "user", jti: "j-1" }),
    );
    const setAgentPermissions = vi
      .fn()
      .mockRejectedValue(new ApiError(404, "SECRET_NOT_FOUND", "Secret not found"));
    render(<PermissionsPage api={api({ setAgentPermissions })} />);
    await waitFor(() => expect(cell("ci-bot", GATED.handle)).toBeTruthy());
    fireEvent.click(cell("ci-bot", GATED.handle));
    fireEvent.click(screen.getByLabelText("read"));
    fireEvent.click(screen.getByText("Save"));
    await waitFor(() =>
      expect(
        screen.getByText(
          `harpoc policy grant ${GATED.handle} --principal-type user --principal-id web-ui --permissions admin`,
        ),
      ).toBeTruthy(),
    );
  });

  it("keeps no grant hint when the refused handle is no longer a loaded secret", async () => {
    // A genuinely deleted secret answers 404 too, and no grant brings it back.
    // The page tells the two apart by whether it is still listing the handle —
    // here the column vanishes under the open editor.
    const listSecrets = vi
      .fn()
      .mockResolvedValueOnce([GATED, UNGATED])
      .mockResolvedValue([UNGATED]);
    const setAgentPermissions = vi
      .fn()
      .mockRejectedValue(new ApiError(404, "SECRET_NOT_FOUND", "Secret not found"));
    render(<PermissionsPage api={api({ listSecrets, setAgentPermissions })} />);
    await waitFor(() => expect(cell("ci-bot", GATED.handle)).toBeTruthy());
    fireEvent.click(cell("ci-bot", GATED.handle));
    fireEvent.click(screen.getByLabelText(/Show inactive/));
    // The reloaded matrix must be on screen, not the loading gap `useAsync`
    // opens when a dep changes: with no data the editor's own first-grant
    // prediction fires and the write never leaves.
    await waitFor(() => {
      expect(document.querySelector(`td[data-secret="${UNGATED.handle}"]`)).toBeTruthy();
      expect(document.querySelector(`td[data-secret="${GATED.handle}"]`)).toBeNull();
    });
    fireEvent.click(screen.getByLabelText("read"));
    fireEvent.click(screen.getByText("Save"));
    await waitFor(() => expect(screen.getByText("Secret not found")).toBeTruthy());
    expect(screen.queryByText(/harpoc policy grant/)).toBeNull();
  });

  it("marks a secret held only by a tool principal as granted", async () => {
    render(
      <PermissionsPage
        api={api({
          getAccessPolicies: vi.fn((handle: string) =>
            Promise.resolve(
              handle === UNGATED.handle
                ? [access({ id: "ap-2", principal_type: "tool", principal_id: "ci-runner" })]
                : (ACCESS[handle] ?? []),
            ),
          ),
        })}
      />,
    );
    await waitFor(() => expect(cell("ci-bot", UNGATED.handle)).toBeTruthy());
    const column = screen.getByText("open-key").closest("th");
    await waitFor(() => expect(column?.textContent).toContain("granted"));
    expect(document.querySelectorAll('thead th .chip[data-tone="warn"]').length).toBe(0);
    // The holder is named: no agent row explains the marker, and an operator
    // reading "granted" over a column of em dashes needs to know which
    // principal accounts for it.
    expect(screen.getByText(/\+1 other principal/).textContent).toContain("tool:ci-runner");
    expect(cell("ci-bot", UNGATED.handle).textContent).toBe("—");
  });

  it("drops an expired policy row: an expired-only column reads no grants and names no holder", async () => {
    const expired = access({
      id: "ap-3",
      principal_type: "tool",
      principal_id: "old-runner",
      expires_at: Date.now() - 60_000,
    });
    const live = access({
      id: "ap-4",
      principal_type: "tool",
      principal_id: "ci-runner",
      expires_at: Date.now() + 60_000,
    });
    render(
      <PermissionsPage
        api={api({
          getAccessPolicies: vi.fn((handle: string) =>
            Promise.resolve(handle === UNGATED.handle ? [expired] : [live]),
          ),
        })}
      />,
    );
    await waitFor(() => expect(cell("ci-bot", UNGATED.handle)).toBeTruthy());
    const open = screen.getByText("open-key").closest("th");
    await waitFor(() => expect(open?.textContent).toContain("no grants"));
    expect(open?.textContent).not.toContain("old-runner");
    // The agent's cell agrees with the header on the expired-only column: no
    // row of its own on `open-key`, so the dash and never a chip.
    expect(cell("ci-bot", UNGATED.handle).textContent).toBe("—");
    const gated = screen.getByText("test-key").closest("th");
    await waitFor(() => expect(gated?.textContent).toContain("granted"));
    expect(gated?.textContent).toContain("tool:ci-runner");
  });

  it("an agent's own expired row renders no chips: the cell agrees with the header", async () => {
    const expiredOwn = policy({
      policy_id: "p-2",
      secret_id: "s-2",
      handle: UNGATED.handle,
      expires_at: Date.now() - 60_000,
    });
    render(
      <PermissionsPage
        api={api({
          listAgentPolicies: vi.fn((name: string) =>
            Promise.resolve(name === "ci-bot" ? [policy(), expiredOwn] : []),
          ),
          getAccessPolicies: vi.fn((handle: string) =>
            Promise.resolve(
              handle === UNGATED.handle
                ? [
                    access({
                      id: "ap-5",
                      secret_id: "s-2",
                      expires_at: Date.now() - 60_000,
                    }),
                  ]
                : [access()],
            ),
          ),
        })}
      />,
    );
    await waitFor(() => expect(cell("ci-bot", UNGATED.handle)).toBeTruthy());
    const open = screen.getByText("open-key").closest("th");
    await waitFor(() => expect(open?.textContent).toContain("no grants"));
    // The agent's own row on `open-key` has expired: the cell reads what the
    // header reads, and the live grant on the other column is untouched.
    expect(cell("ci-bot", UNGATED.handle).textContent).toBe("—");
    expect(cell("ci-bot", GATED.handle).textContent).toContain("read");
  });

  it("the holders fallback ignores an agent's expired row when the column read is refused", async () => {
    const expiredOwn = policy({
      policy_id: "p-2",
      secret_id: "s-2",
      handle: UNGATED.handle,
      expires_at: Date.now() - 60_000,
    });
    render(
      <PermissionsPage
        api={api({
          listAgentPolicies: vi.fn((name: string) =>
            Promise.resolve(name === "ci-bot" ? [policy(), expiredOwn] : []),
          ),
          getAccessPolicies: vi.fn((handle: string) =>
            handle === UNGATED.handle
              ? Promise.reject(new ApiError(403, "ACCESS_DENIED", "Access denied"))
              : Promise.resolve([access()]),
          ),
        })}
      />,
    );
    await waitFor(() => expect(cell("ci-bot", UNGATED.handle)).toBeTruthy());
    expect(cell("ci-bot", UNGATED.handle).textContent).toBe("—");
    const open = screen.getByText("open-key").closest("th");
    expect(open?.textContent).not.toContain("granted");
  });

  it("clears an expired-only cell with a PUT of no permissions and no confirm", async () => {
    const expiredOwn = policy({
      policy_id: "p-2",
      secret_id: "s-2",
      handle: UNGATED.handle,
      expires_at: Date.now() - 60_000,
    });
    const setAgentPermissions = vi
      .fn()
      .mockResolvedValue({ policy: null, gated_before: false, gated_after: false });
    render(
      <PermissionsPage
        api={api({
          listAgentPolicies: vi.fn((name: string) =>
            Promise.resolve(name === "ci-bot" ? [policy(), expiredOwn] : []),
          ),
          setAgentPermissions,
        })}
      />,
    );
    await waitFor(() => expect(cell("ci-bot", UNGATED.handle)).toBeTruthy());
    expect(cell("ci-bot", UNGATED.handle).textContent).toBe("—");
    fireEvent.click(cell("ci-bot", UNGATED.handle));
    fireEvent.click(screen.getByText("Clear"));
    // No live grant gates the column, so there is no ungating to confirm —
    // but the expired row is stored, so the clear is written.
    expect(screen.queryByText("Confirm")).toBeNull();
    await waitFor(() =>
      expect(setAgentPermissions).toHaveBeenCalledWith("ci-bot", UNGATED.handle, {
        permissions: [],
        expires_at: undefined,
      }),
    );
    await waitFor(() => expect(screen.queryByText("Clear")).toBeNull());
  });

  it("predicts the first-grant flip when granting on an expired-only cell", async () => {
    const expiredOwn = policy({
      policy_id: "p-2",
      secret_id: "s-2",
      handle: UNGATED.handle,
      expires_at: Date.now() - 60_000,
    });
    const setAgentPermissions = vi
      .fn()
      .mockResolvedValue({ policy: null, gated_before: false, gated_after: true });
    render(
      <PermissionsPage
        api={api({
          listAgentPolicies: vi.fn((name: string) =>
            Promise.resolve(name === "ci-bot" ? [policy(), expiredOwn] : []),
          ),
          setAgentPermissions,
        })}
      />,
    );
    await waitFor(() => expect(cell("ci-bot", UNGATED.handle)).toBeTruthy());
    fireEvent.click(cell("ci-bot", UNGATED.handle));
    fireEvent.click(screen.getByLabelText("use"));
    fireEvent.click(screen.getByText("Save"));
    // An expired row is no grant: the prediction says what the engine's
    // `gated_before` will say.
    expect(screen.getByText(/first grant/).textContent).toContain(UNGATED.handle);
    expect(setAgentPermissions).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText("Confirm"));
    await waitFor(() =>
      expect(setAgentPermissions).toHaveBeenCalledWith("ci-bot", UNGATED.handle, {
        permissions: ["use"],
        expires_at: undefined,
      }),
    );
  });

  it("renders the chips of a grant that expires in the future", async () => {
    const future = policy({
      policy_id: "p-2",
      secret_id: "s-2",
      handle: UNGATED.handle,
      expires_at: Date.now() + 60_000,
    });
    render(
      <PermissionsPage
        api={api({
          listAgentPolicies: vi.fn((name: string) =>
            Promise.resolve(name === "ci-bot" ? [policy(), future] : []),
          ),
          getAccessPolicies: vi.fn((handle: string) =>
            Promise.resolve(
              handle === UNGATED.handle
                ? [access({ id: "ap-5", secret_id: "s-2", expires_at: Date.now() + 60_000 })]
                : [access()],
            ),
          ),
        })}
      />,
    );
    await waitFor(() => expect(cell("ci-bot", UNGATED.handle)).toBeTruthy());
    await waitFor(() => expect(cell("ci-bot", UNGATED.handle).textContent).toContain("read"));
    expect(cell("ci-bot", UNGATED.handle).textContent).toContain("use");
  });

  it("reads the access policies of the preselected column only", async () => {
    window.location.hash = "#/permissions?secret=myproj%2Ftest-key";
    const getAccessPolicies = vi.fn((handle: string) => Promise.resolve(ACCESS[handle] ?? []));
    render(<PermissionsPage api={api({ getAccessPolicies })} />);
    await waitFor(() => expect(cell("ci-bot", GATED.handle)).toBeTruthy());
    // Settled with the cell above: the preselect narrows in the render that
    // mounts the table (the preselect case's register), so a barrier on the
    // count has nothing to wait for — the pin is the one read below.
    expect(columns()).toBe(2);
    // One `secret.read { config: "access_policies" }` row per column on
    // screen, none for the column the preselect hides.
    expect(getAccessPolicies.mock.calls.map((c) => c[0])).toEqual([GATED.handle]);
  });

  it("reads each visible column once and never again on a filter keystroke", async () => {
    const getAccessPolicies = vi.fn((handle: string) => Promise.resolve(ACCESS[handle] ?? []));
    render(<PermissionsPage api={api({ getAccessPolicies })} />);
    await waitFor(() => expect(cell("ci-bot", UNGATED.handle)).toBeTruthy());
    expect(getAccessPolicies.mock.calls.map((c) => c[0]).sort()).toEqual(
      [GATED.handle, UNGATED.handle].sort(),
    );
    fireEvent.input(screen.getByLabelText("Filter secrets"), { target: { value: "myproj" } });
    await waitFor(() => expect(columns()).toBe(2));
    expect(getAccessPolicies).toHaveBeenCalledTimes(2);
  });

  it("falls back to the agent rows for a column the caller may not read", async () => {
    // A scoped admin token is refused per secret. The column then says what the
    // agent listings already said rather than claiming the secret has no
    // holders — a refusal is not an answer.
    render(
      <PermissionsPage
        api={api({
          getAccessPolicies: vi
            .fn()
            .mockRejectedValue(new ApiError(403, "ACCESS_DENIED", "Access denied")),
        })}
      />,
    );
    await waitFor(() => expect(cell("ci-bot", GATED.handle)).toBeTruthy());
    expect(screen.getByText("granted").closest("th")?.textContent).toContain("test-key");
    expect(document.querySelectorAll('thead th .chip[data-tone="warn"]').length).toBe(1);
    expect(screen.queryByText(/other principal/)).toBeNull();
  });

  it("clears one holder's cell without a confirm while another agent still holds the secret", async () => {
    const second = agent({ id: "a-3", name: "other-bot" });
    const setAgentPermissions = vi
      .fn()
      .mockResolvedValue({ policy: null, gated_before: true, gated_after: true });
    render(
      <PermissionsPage
        api={api({
          listAgents: vi.fn().mockResolvedValue([ACTIVE, second]),
          listAgentPolicies: vi.fn((name: string) =>
            Promise.resolve(name === "ci-bot" ? [policy()] : [policy({ policy_id: "p-2" })]),
          ),
          setAgentPermissions,
        })}
      />,
    );
    await waitFor(() => expect(cell("other-bot", GATED.handle)).toBeTruthy());
    fireEvent.click(cell("ci-bot", GATED.handle));
    fireEvent.click(screen.getByText("Clear"));
    // The secret stays gated through the other agent's row, so there is no
    // ungating to confirm.
    expect(screen.queryByText("Confirm")).toBeNull();
    await waitFor(() =>
      expect(setAgentPermissions).toHaveBeenCalledWith("ci-bot", GATED.handle, {
        permissions: [],
        expires_at: undefined,
      }),
    );
  });

  it("states that nothing changed when a confirmed ungating did not happen", async () => {
    const setAgentPermissions = vi
      .fn()
      .mockResolvedValue({ policy: null, gated_before: true, gated_after: true });
    render(<PermissionsPage api={api({ setAgentPermissions })} />);
    await waitFor(() => expect(cell("ci-bot", GATED.handle)).toBeTruthy());
    fireEvent.click(cell("ci-bot", GATED.handle));
    fireEvent.click(screen.getByText("Clear"));
    fireEvent.click(screen.getByText("Confirm"));
    await waitFor(() =>
      expect(screen.getByText(`No change: ${GATED.handle} already had grants.`)).toBeTruthy(),
    );
  });

  it("states that nothing changed when a confirmed first grant did not happen", async () => {
    const setAgentPermissions = vi
      .fn()
      .mockResolvedValue({ policy: null, gated_before: false, gated_after: false });
    render(<PermissionsPage api={api({ setAgentPermissions })} />);
    await waitFor(() => expect(cell("ci-bot", UNGATED.handle)).toBeTruthy());
    fireEvent.click(cell("ci-bot", UNGATED.handle));
    fireEvent.click(screen.getByLabelText("use"));
    fireEvent.click(screen.getByText("Save"));
    fireEvent.click(screen.getByText("Confirm"));
    await waitFor(() =>
      expect(screen.getByText(`No change: ${UNGATED.handle} still has no grants.`)).toBeTruthy(),
    );
  });

  it("shows an error when the matrix cannot be loaded", async () => {
    render(
      <PermissionsPage
        api={api({ listAgents: vi.fn().mockRejectedValue(new Error("ACCESS_DENIED")) })}
      />,
    );
    await waitFor(() => expect(screen.getByText("ACCESS_DENIED")).toBeTruthy());
  });

  it("never describes a secret as governed by token scope alone", async () => {
    render(<PermissionsPage api={api()} />);
    await waitFor(() => expect(cell("ci-bot", GATED.handle)).toBeTruthy());
    expect(document.body.textContent).not.toContain("ungated");
    expect(document.body.textContent).not.toContain("policy-gated");
  });
});
