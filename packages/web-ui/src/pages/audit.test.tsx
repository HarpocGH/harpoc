import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ApiClient, AuditEventWire } from "../api/client";
import { AuditPage } from "./audit";

afterEach(cleanup);
beforeEach(() => {
  window.location.hash = "";
});

const event = (over: Partial<AuditEventWire>): AuditEventWire => ({
  id: 1,
  timestamp: 1700000000000,
  event_type: "secret.use",
  secret_id: null,
  principal_type: null,
  principal_id: null,
  detail: null,
  ip_address: null,
  session_id: null,
  success: true,
  ...over,
});

function api(over: Partial<ApiClient> = {}): ApiClient {
  return {
    queryAudit: vi
      .fn()
      .mockResolvedValue([
        event({}),
        event({ id: 2, event_type: "access.denied", success: false }),
      ]),
    verifyAuditChain: vi.fn().mockResolvedValue({ valid: true, checked: 5, first_broken_id: null }),
    ...over,
  } as ApiClient;
}

describe("AuditPage", () => {
  it("renders rows and marks failures in the bad tone", async () => {
    render(<AuditPage api={api()} />);
    await waitFor(() => expect(screen.getByText("access.denied")).toBeTruthy());
    expect(document.querySelector('.chip[data-tone="bad"]')).toBeTruthy();
  });

  it("passes the success filter through", async () => {
    const fake = api();
    render(<AuditPage api={fake} />);
    fireEvent.change(screen.getByLabelText("Outcome"), { target: { value: "failed" } });
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenCalledWith(expect.objectContaining({ success: false })),
    );
  });

  it("forwards the principal filters into the query", async () => {
    const fake = api();
    render(<AuditPage api={fake} />);
    fireEvent.change(screen.getByLabelText("Principal type"), { target: { value: "agent" } });
    fireEvent.input(screen.getByLabelText("Principal id"), { target: { value: "ci-bot" } });
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenCalledWith(
        expect.objectContaining({ principal_type: "agent", principal_id: "ci-bot" }),
      ),
    );
  });

  it("omits an emptied principal filter rather than querying for the empty string", async () => {
    const fake = api();
    render(<AuditPage api={fake} />);
    fireEvent.input(screen.getByLabelText("Principal id"), { target: { value: "ci-bot" } });
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenCalledWith(
        expect.objectContaining({ principal_id: "ci-bot" }),
      ),
    );
    fireEvent.input(screen.getByLabelText("Principal id"), { target: { value: "" } });
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenLastCalledWith(
        expect.objectContaining({ principal_id: undefined }),
      ),
    );
  });

  it("prefilters from the hash query the agent detail links to", async () => {
    // `#/audit?principal_type=agent&principal_id=<name>` is the agent-detail
    // page's "open in Audit" link: landing on it must prefilter the first load,
    // not just prefill inputs the operator has to re-trigger.
    window.location.hash = "#/audit?principal_type=agent&principal_id=ci-bot";
    const fake = api();
    render(<AuditPage api={fake} />);
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenCalledWith(
        expect.objectContaining({ principal_type: "agent", principal_id: "ci-bot" }),
      ),
    );
    expect((screen.getByLabelText("Principal type") as HTMLSelectElement).value).toBe("agent");
    expect((screen.getByLabelText("Principal id") as HTMLInputElement).value).toBe("ci-bot");
  });

  it("decodes the hash query once, not twice", async () => {
    // `URLSearchParams` already decodes; a second pass would corrupt a
    // principal id carrying a percent sign.
    window.location.hash = "#/audit?principal_id=ci%252Fbot";
    const fake = api();
    render(<AuditPage api={fake} />);
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenCalledWith(
        expect.objectContaining({ principal_id: "ci%2Fbot" }),
      ),
    );
  });

  it("ignores a principal type the union does not carry", async () => {
    window.location.hash = "#/audit?principal_type=wizard";
    const fake = api();
    render(<AuditPage api={fake} />);
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenCalledWith(
        expect.objectContaining({ principal_type: undefined }),
      ),
    );
  });

  it("verify renders an intact chain", async () => {
    render(<AuditPage api={api()} />);
    fireEvent.click(screen.getByRole("button", { name: "Verify chain" }));
    await waitFor(() => expect(screen.getByText(/chain intact — 5 rows checked/)).toBeTruthy());
  });

  it("verify renders a break with its row id", async () => {
    const fake = api({
      verifyAuditChain: vi
        .fn()
        .mockResolvedValue({ valid: false, checked: 5, first_broken_id: 42 }),
    });
    render(<AuditPage api={fake} />);
    fireEvent.click(screen.getByRole("button", { name: "Verify chain" }));
    await waitFor(() => expect(screen.getByText(/chain broken at row 42/)).toBeTruthy());
  });
});
