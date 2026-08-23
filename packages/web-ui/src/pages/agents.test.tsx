import type { Agent } from "@harpoc/shared";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ApiClient } from "../api/client";
import { AgentsPage } from "./agents";

afterEach(cleanup);
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
  last_active_at: 1700000000000,
  active_tokens: 2,
  grants: 3,
  ...over,
});

const api = (over: Partial<ApiClient> = {}): ApiClient =>
  ({
    listAgents: vi.fn().mockResolvedValue([agent()]),
    registerAgent: vi.fn().mockResolvedValue(agent({ name: "new-bot" })),
    ...over,
  }) as ApiClient;

function submitRegisterForm(container: HTMLElement): void {
  const form = container.querySelector("form");
  if (form === null) throw new Error("register form missing");
  fireEvent.submit(form);
}

describe("AgentsPage", () => {
  it("lists agents with their status, owner and counts", async () => {
    render(<AgentsPage api={api()} />);
    await waitFor(() => expect(screen.getByText("ci-bot")).toBeTruthy());
    expect(screen.getByText("platform")).toBeTruthy();
    expect(screen.getByText("2")).toBeTruthy();
    expect(screen.getByText("3")).toBeTruthy();
    expect(document.querySelector('.chip[data-tone="ok"]')?.textContent).toBe("active");
  });

  it("asks for active agents only until Show inactive is ticked", async () => {
    const listAgents = vi.fn().mockResolvedValue([agent()]);
    render(<AgentsPage api={api({ listAgents })} />);
    await waitFor(() => expect(listAgents).toHaveBeenCalledWith("active"));
    fireEvent.click(screen.getByLabelText(/Show inactive/));
    await waitFor(() => expect(listAgents).toHaveBeenCalledWith("all"));
  });

  it("tones an inactive agent as bad rather than leaving the chip blank", async () => {
    render(
      <AgentsPage
        api={api({ listAgents: vi.fn().mockResolvedValue([agent({ status: "inactive" })]) })}
      />,
    );
    await waitFor(() => expect(screen.getByText("ci-bot")).toBeTruthy());
    expect(document.querySelector('.chip[data-tone="bad"]')?.textContent).toBe("inactive");
  });

  it("navigates to the agent detail when a row is clicked", async () => {
    render(<AgentsPage api={api()} />);
    await waitFor(() => expect(screen.getByText("ci-bot")).toBeTruthy());
    fireEvent.click(screen.getByText("ci-bot"));
    expect(window.location.hash).toBe("#/agents/ci-bot");
  });

  it("registers an agent with the typed input and reloads the list", async () => {
    const listAgents = vi.fn().mockResolvedValue([agent()]);
    const registerAgent = vi.fn().mockResolvedValue(agent({ name: "new-bot" }));
    const { container } = render(<AgentsPage api={api({ listAgents, registerAgent })} />);
    await waitFor(() => expect(screen.getByText("ci-bot")).toBeTruthy());

    fireEvent.input(screen.getByLabelText("Name"), { target: { value: "new-bot" } });
    fireEvent.input(screen.getByLabelText("Description"), { target: { value: "does things" } });
    fireEvent.input(screen.getByLabelText("Owner"), { target: { value: "sre" } });
    submitRegisterForm(container);

    await waitFor(() =>
      expect(registerAgent).toHaveBeenCalledWith({
        name: "new-bot",
        description: "does things",
        owner: "sre",
      }),
    );
    await waitFor(() => expect(listAgents).toHaveBeenCalledTimes(2));
  });

  it("omits the optional fields rather than registering them as empty strings", async () => {
    // The schemas cap their length but store what arrives: an empty string is a
    // description of "", not an absent one.
    const registerAgent = vi.fn().mockResolvedValue(agent({ name: "bare" }));
    const { container } = render(<AgentsPage api={api({ registerAgent })} />);
    await waitFor(() => expect(screen.getByText("ci-bot")).toBeTruthy());
    fireEvent.input(screen.getByLabelText("Name"), { target: { value: "bare" } });
    submitRegisterForm(container);
    await waitFor(() => expect(registerAgent).toHaveBeenCalledWith({ name: "bare" }));
  });

  it("clears the register form after a successful registration", async () => {
    const { container } = render(<AgentsPage api={api()} />);
    await waitFor(() => expect(screen.getByText("ci-bot")).toBeTruthy());
    fireEvent.input(screen.getByLabelText("Name"), { target: { value: "new-bot" } });
    submitRegisterForm(container);
    await waitFor(() => expect((screen.getByLabelText("Name") as HTMLInputElement).value).toBe(""));
  });

  it("shows a refused registration and does not reload the list", async () => {
    const listAgents = vi.fn().mockResolvedValue([agent()]);
    const registerAgent = vi.fn().mockRejectedValue(new Error("AGENT_ALREADY_EXISTS"));
    const { container } = render(<AgentsPage api={api({ listAgents, registerAgent })} />);
    await waitFor(() => expect(screen.getByText("ci-bot")).toBeTruthy());
    fireEvent.input(screen.getByLabelText("Name"), { target: { value: "ci-bot" } });
    submitRegisterForm(container);
    await waitFor(() => expect(screen.getByText("AGENT_ALREADY_EXISTS")).toBeTruthy());
    expect(listAgents).toHaveBeenCalledTimes(1);
  });

  it("shows an error message when listAgents fails", async () => {
    render(<AgentsPage api={api({ listAgents: vi.fn().mockRejectedValue(new Error("boom")) })} />);
    await waitFor(() => expect(screen.getByText("boom")).toBeTruthy());
  });

  it("shows the CLI-pointing empty state", async () => {
    render(<AgentsPage api={api({ listAgents: vi.fn().mockResolvedValue([]) })} />);
    await waitFor(() => expect(screen.getByText(/No agents/)).toBeTruthy());
    expect(screen.getByText(/harpoc agent register/)).toBeTruthy();
  });
});
