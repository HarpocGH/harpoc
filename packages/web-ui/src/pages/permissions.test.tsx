import type { Agent, AgentPolicy } from "@harpoc/shared";
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

const api = (over: Partial<ApiClient> = {}): ApiClient =>
  ({
    listAgents: vi.fn((status?: string) =>
      Promise.resolve(status === "all" ? [ACTIVE, INACTIVE] : [ACTIVE]),
    ),
    listSecrets: vi.fn().mockResolvedValue([GATED, UNGATED]),
    listAgentPolicies: vi.fn((name: string) => Promise.resolve(POLICIES[name] ?? [])),
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
