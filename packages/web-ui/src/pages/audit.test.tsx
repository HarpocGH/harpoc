import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ApiClient, AuditEventWire } from "../api/client";
import { AuditPage } from "./audit";

afterEach(cleanup);

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
    verifyAuditChain: vi
      .fn()
      .mockResolvedValue({ valid: true, checked: 5, legacy: 1, first_broken_id: null }),
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

  it("verify renders an intact chain", async () => {
    render(<AuditPage api={api()} />);
    fireEvent.click(screen.getByRole("button", { name: "Verify chain" }));
    await waitFor(() => expect(screen.getByText(/chain intact/)).toBeTruthy());
  });

  it("verify renders a break with its row id", async () => {
    const fake = api({
      verifyAuditChain: vi
        .fn()
        .mockResolvedValue({ valid: false, checked: 5, legacy: 0, first_broken_id: 42 }),
    });
    render(<AuditPage api={fake} />);
    fireEvent.click(screen.getByRole("button", { name: "Verify chain" }));
    await waitFor(() => expect(screen.getByText(/chain broken at row 42/)).toBeTruthy());
  });
});
