import type { Agent, AgentPolicy, IssuedToken } from "@harpoc/shared";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ApiClient, AuditEventWire } from "../api/client";
import { AgentDetailPage } from "./agent-detail";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
beforeEach(() => {
  window.location.hash = "";
});

const agent = (over: Partial<Agent> = {}): Agent => ({
  id: "id-1",
  name: "ci-bot",
  description: "CI runner",
  owner: "platform",
  status: "active",
  created_at: 0,
  updated_at: 0,
  deactivated_at: null,
  last_active_at: null,
  active_tokens: 2,
  grants: 1,
  ...over,
});

const policy = (over: Partial<AgentPolicy> = {}): AgentPolicy => ({
  policy_id: "p-1",
  secret_id: "s-1",
  handle: "secret://myproj/test-key",
  permissions: ["read", "use"],
  expires_at: null,
  created_at: 0,
  ...over,
});

const token = (over: Partial<IssuedToken> = {}): IssuedToken => ({
  jti: "jti-1",
  subject: "ci-bot",
  principal_type: "agent",
  agent: "ci-bot",
  scope: ["read", "use"],
  project: null,
  secrets: null,
  label: "deploy",
  issued_at: 0,
  expires_at: 1700000000000,
  revoked_at: null,
  status: "active",
  ...over,
});

const event = (over: Partial<AuditEventWire> = {}): AuditEventWire => ({
  id: 1,
  timestamp: 1700000000000,
  event_type: "secret.use",
  secret_id: "s-1",
  principal_type: "agent",
  principal_id: "ci-bot",
  detail: null,
  ip_address: null,
  session_id: null,
  success: true,
  ...over,
});

const api = (over: Partial<ApiClient> = {}): ApiClient =>
  ({
    getAgent: vi.fn().mockResolvedValue(agent()),
    listAgentPolicies: vi.fn().mockResolvedValue([policy()]),
    listTokens: vi.fn().mockResolvedValue([token()]),
    queryAudit: vi.fn().mockResolvedValue([event()]),
    updateAgent: vi.fn().mockResolvedValue(agent()),
    deactivateAgent: vi.fn().mockResolvedValue({ revoked_tokens: 3 }),
    activateAgent: vi.fn().mockResolvedValue(agent()),
    deleteAgent: vi.fn().mockResolvedValue({ revoked_tokens: 3, removed_grants: 4 }),
    ...over,
  }) as ApiClient;

const href = (selector: string): string | undefined =>
  document.querySelector<HTMLAnchorElement>(selector)?.getAttribute("href") ?? undefined;

describe("AgentDetailPage", () => {
  it("renders the agent metadata", async () => {
    render(<AgentDetailPage api={api()} name="ci-bot" />);
    await waitFor(() => expect(screen.getByRole("heading", { name: /ci-bot/ })).toBeTruthy());
    expect(screen.getByText("active_tokens")).toBeTruthy();
    expect(screen.getByText("platform")).toBeTruthy();
  });

  it("lists the agent's grants with links to the secret and to the matrix", async () => {
    render(<AgentDetailPage api={api()} name="ci-bot" />);
    await waitFor(() => expect(screen.getByRole("heading", { name: "Grants" })).toBeTruthy());
    expect(href('a[href^="#/secrets/"]')).toBe("#/secrets/myproj%2Ftest-key");
    expect(href('a[href^="#/permissions"]')).toBe("#/permissions?secret=myproj%2Ftest-key");
    expect(screen.getByText("read")).toBeTruthy();
    expect(screen.getByText("use")).toBeTruthy();
  });

  it("lists the agent's tokens, scoped to this agent and including its dead ones", async () => {
    const listTokens = vi.fn().mockResolvedValue([token()]);
    render(<AgentDetailPage api={api({ listTokens })} name="ci-bot" />);
    await waitFor(() => expect(screen.getByRole("heading", { name: "Tokens" })).toBeTruthy());
    // `all`: after Deactivate the tokens it revoked must still show, with the
    // chip that says so — a default `active` listing would empty the table.
    expect(listTokens).toHaveBeenCalledWith({ agent: "ci-bot", status: "all" });
    expect(screen.getByText("jti-1")).toBeTruthy();
    expect(screen.getByText("deploy")).toBeTruthy();
  });

  it("chips a revoked token as a fault and an expired one neutrally", async () => {
    const listTokens = vi
      .fn()
      .mockResolvedValue([
        token({ status: "revoked", revoked_at: 1700000000000 }),
        token({ jti: "jti-2", status: "expired" }),
      ]);
    render(<AgentDetailPage api={api({ listTokens })} name="ci-bot" />);
    await waitFor(() => expect(screen.getByRole("heading", { name: "Tokens" })).toBeTruthy());
    expect(screen.getByText("revoked", { selector: ".chip" }).getAttribute("data-tone")).toBe(
      "bad",
    );
    expect(screen.getByText("expired", { selector: ".chip" }).getAttribute("data-tone")).toBe("");
  });

  it("reads recent activity through the principal filters and links to the audit page", async () => {
    const queryAudit = vi.fn().mockResolvedValue([event()]);
    render(<AgentDetailPage api={api({ queryAudit })} name="ci-bot" />);
    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "Recent activity" })).toBeTruthy(),
    );
    expect(queryAudit).toHaveBeenCalledWith({
      principal_type: "agent",
      principal_id: "ci-bot",
      limit: 50,
    });
    expect(screen.getByText("secret.use")).toBeTruthy();
    expect(href('a[href^="#/audit"]')).toBe("#/audit?principal_type=agent&principal_id=ci-bot");
  });

  it("saves both fields, so editing one does not clear the other", async () => {
    // PUT is replace semantics — an omitted field is cleared server-side.
    const updateAgent = vi.fn().mockResolvedValue(agent({ description: "edited" }));
    render(<AgentDetailPage api={api({ updateAgent })} name="ci-bot" />);
    await waitFor(() => expect(screen.getByLabelText("Description")).toBeTruthy());
    fireEvent.input(screen.getByLabelText("Description"), { target: { value: "edited" } });
    fireEvent.click(screen.getByText("Save"));
    await waitFor(() =>
      expect(updateAgent).toHaveBeenCalledWith("ci-bot", {
        description: "edited",
        owner: "platform",
      }),
    );
  });

  it("omits an emptied field, which is how replace semantics clear it", async () => {
    const updateAgent = vi.fn().mockResolvedValue(agent({ owner: null }));
    render(<AgentDetailPage api={api({ updateAgent })} name="ci-bot" />);
    await waitFor(() => expect(screen.getByLabelText("Owner")).toBeTruthy());
    fireEvent.input(screen.getByLabelText("Owner"), { target: { value: "" } });
    fireEvent.click(screen.getByText("Save"));
    await waitFor(() =>
      expect(updateAgent).toHaveBeenCalledWith("ci-bot", { description: "CI runner" }),
    );
  });

  it("deactivates, reports the revoked count and reloads", async () => {
    const getAgent = vi.fn().mockResolvedValue(agent());
    const deactivateAgent = vi.fn().mockResolvedValue({ revoked_tokens: 3 });
    render(<AgentDetailPage api={api({ getAgent, deactivateAgent })} name="ci-bot" />);
    await waitFor(() => expect(screen.getByText("Deactivate")).toBeTruthy());
    fireEvent.click(screen.getByText("Deactivate"));
    await waitFor(() => expect(deactivateAgent).toHaveBeenCalledWith("ci-bot"));
    await waitFor(() => expect(screen.getByText(/3 token/)).toBeTruthy());
    await waitFor(() => expect(getAgent).toHaveBeenCalledTimes(2));
  });

  it("offers Activate instead of Deactivate for an inactive agent", async () => {
    const activateAgent = vi.fn().mockResolvedValue(agent());
    render(
      <AgentDetailPage
        api={api({
          getAgent: vi.fn().mockResolvedValue(agent({ status: "inactive" })),
          activateAgent,
        })}
        name="ci-bot"
      />,
    );
    await waitFor(() => expect(screen.getByText("Activate")).toBeTruthy());
    expect(screen.queryByText("Deactivate")).toBeNull();
    fireEvent.click(screen.getByText("Activate"));
    await waitFor(() => expect(activateAgent).toHaveBeenCalledWith("ci-bot"));
  });

  it("does not delete when the confirmation is declined", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
    const deleteAgent = vi.fn().mockResolvedValue({ revoked_tokens: 3, removed_grants: 4 });
    render(<AgentDetailPage api={api({ deleteAgent })} name="ci-bot" />);
    await waitFor(() => expect(screen.getByText("Delete agent")).toBeTruthy());
    fireEvent.click(screen.getByText("Delete agent"));
    expect(confirmSpy).toHaveBeenCalled();
    expect(deleteAgent).not.toHaveBeenCalled();
  });

  it("names the cascade counts in the confirmation, then deletes and leaves the page", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    const deleteAgent = vi.fn().mockResolvedValue({ revoked_tokens: 3, removed_grants: 4 });
    render(<AgentDetailPage api={api({ deleteAgent })} name="ci-bot" />);
    await waitFor(() => expect(screen.getByText("Delete agent")).toBeTruthy());
    fireEvent.click(screen.getByText("Delete agent"));
    const prompt = String(confirmSpy.mock.calls[0]?.[0] ?? "");
    // The counts are the whole point of the confirmation: deleting an agent
    // revokes its live tokens and drops its grants, and both are irreversible.
    expect(prompt).toContain("2");
    expect(prompt).toContain("1");
    expect(prompt).toContain("ci-bot");
    await waitFor(() => expect(deleteAgent).toHaveBeenCalledWith("ci-bot"));
    await waitFor(() => expect(window.location.hash).toBe("#/agents"));
  });

  it("shows a refused action rather than swallowing it", async () => {
    render(
      <AgentDetailPage
        api={api({ deactivateAgent: vi.fn().mockRejectedValue(new Error("ACCESS_DENIED")) })}
        name="ci-bot"
      />,
    );
    await waitFor(() => expect(screen.getByText("Deactivate")).toBeTruthy());
    fireEvent.click(screen.getByText("Deactivate"));
    await waitFor(() => expect(screen.getByText("ACCESS_DENIED")).toBeTruthy());
  });

  it("shows an error message when the agent cannot be loaded", async () => {
    render(
      <AgentDetailPage
        api={api({ getAgent: vi.fn().mockRejectedValue(new Error("AGENT_NOT_FOUND")) })}
        name="ghost"
      />,
    );
    await waitFor(() => expect(screen.getByText("AGENT_NOT_FOUND")).toBeTruthy());
  });

  it("says so when the agent holds no grants, tokens or activity", async () => {
    render(
      <AgentDetailPage
        api={api({
          listAgentPolicies: vi.fn().mockResolvedValue([]),
          listTokens: vi.fn().mockResolvedValue([]),
          queryAudit: vi.fn().mockResolvedValue([]),
        })}
        name="ci-bot"
      />,
    );
    await waitFor(() => expect(screen.getByText(/No grants/)).toBeTruthy());
    expect(screen.getByText(/No tokens/)).toBeTruthy();
    expect(screen.getByText(/No recent activity/)).toBeTruthy();
  });

  it("re-enables Deactivate after a refusal", async () => {
    render(
      <AgentDetailPage
        api={api({ deactivateAgent: vi.fn().mockRejectedValue(new Error("ACCESS_DENIED")) })}
        name="ci-bot"
      />,
    );
    const button = (await screen.findByRole("button", {
      name: "Deactivate",
    })) as HTMLButtonElement;
    fireEvent.click(button);
    await screen.findByText("ACCESS_DENIED");
    expect(button.disabled).toBe(false);
  });

  it("disables Deactivate while the call is in flight", async () => {
    render(
      <AgentDetailPage
        api={api({ deactivateAgent: vi.fn().mockReturnValue(new Promise(() => undefined)) })}
        name="ci-bot"
      />,
    );
    const button = (await screen.findByRole("button", {
      name: "Deactivate",
    })) as HTMLButtonElement;
    fireEvent.click(button);
    await waitFor(() => expect(button.disabled).toBe(true));
  });

  it("clears the previous notice when the delete confirmation is declined", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
    const deleteAgent = vi.fn().mockResolvedValue({ revoked_tokens: 3, removed_grants: 4 });
    render(<AgentDetailPage api={api({ deleteAgent })} name="ci-bot" />);
    fireEvent.click(await screen.findByRole("button", { name: "Deactivate" }));
    await screen.findByText(/3 token/);
    fireEvent.click(screen.getByRole("button", { name: "Delete agent" }));
    await waitFor(() => expect(screen.queryByText(/3 token/)).toBeNull());
    expect(confirmSpy).toHaveBeenCalled();
    expect(deleteAgent).not.toHaveBeenCalled();
  });
});
