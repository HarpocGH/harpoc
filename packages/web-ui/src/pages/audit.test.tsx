import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import { createApiClient } from "../api/client";
import type { ApiClient } from "../api/client";
import { makeEvent } from "../__fixtures__/builders";
import { AuditPage } from "./audit";

afterEach(cleanup);
beforeEach(() => {
  window.location.hash = "";
});

const event = makeEvent;

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

/** Clicks the filter form's Apply button. */
function apply(): void {
  fireEvent.click(screen.getByRole("button", { name: "Apply" }));
}

/** Submits the filter form, as Enter in one of its text inputs does. */
function pressEnter(): void {
  const form = (screen.getByLabelText("Principal id") as HTMLInputElement).form;
  if (form === null) throw new Error("filter form missing");
  fireEvent.submit(form);
}

/** Types into the three text filters without applying them. */
function typeTextFilters(): void {
  fireEvent.input(screen.getByLabelText("Event type"), { target: { value: "secret.use" } });
  fireEvent.input(screen.getByLabelText("Principal id"), { target: { value: "ci-bot" } });
  fireEvent.input(screen.getByLabelText("Limit"), { target: { value: "25" } });
}

/** Waits for the flushed tick, so a negative reads the settled page. */
const flushed = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));

/** The query parameters of one request a stubbed fetch received. */
function queryOf(fetchFn: Mock<typeof fetch>, index: number): URLSearchParams {
  const url = String(fetchFn.mock.calls[index]?.[0] ?? "");
  return new URLSearchParams(url.includes("?") ? url.slice(url.indexOf("?") + 1) : "");
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
    apply();
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
    apply();
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenCalledWith(
        expect.objectContaining({ principal_id: "ci-bot" }),
      ),
    );
    fireEvent.input(screen.getByLabelText("Principal id"), { target: { value: "" } });
    apply();
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenLastCalledWith(
        expect.objectContaining({ principal_id: undefined }),
      ),
    );
  });

  // M-P1-6 (test-review-2026-10-09): the event-type and limit filters reach the
  // query the page sends — `api/client.test.ts` pins the query string they become.
  it("forwards the event-type filter, and omits it once emptied", async () => {
    const fake = api();
    render(<AuditPage api={fake} />);
    fireEvent.input(screen.getByLabelText("Event type"), { target: { value: "secret.use" } });
    apply();
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenCalledWith(
        expect.objectContaining({ event_type: "secret.use" }),
      ),
    );
    fireEvent.input(screen.getByLabelText("Event type"), { target: { value: "" } });
    apply();
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenLastCalledWith(
        expect.objectContaining({ event_type: undefined }),
      ),
    );
  });

  it("forwards the limit as a number, and falls back to 100 once emptied", async () => {
    const fake = api();
    render(<AuditPage api={fake} />);
    fireEvent.input(screen.getByLabelText("Limit"), { target: { value: "25" } });
    apply();
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenCalledWith(expect.objectContaining({ limit: 25 })),
    );
    fireEvent.input(screen.getByLabelText("Limit"), { target: { value: "" } });
    apply();
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenLastCalledWith(expect.objectContaining({ limit: 100 })),
    );
  });

  it("applies a zero limit as 100 and shows the applied limit in the input", async () => {
    const fake = api();
    render(<AuditPage api={fake} />);
    fireEvent.input(screen.getByLabelText("Limit"), { target: { value: "25" } });
    apply();
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenLastCalledWith(expect.objectContaining({ limit: 25 })),
    );
    fireEvent.input(screen.getByLabelText("Limit"), { target: { value: "0" } });
    apply();
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenLastCalledWith(expect.objectContaining({ limit: 100 })),
    );
    expect((screen.getByLabelText("Limit") as HTMLInputElement).value).toBe("100");
  });

  it("sends no query on a keystroke in the event type, principal id or limit input", async () => {
    const fake = api();
    render(<AuditPage api={fake} />);
    await waitFor(() => expect(fake.queryAudit).toHaveBeenCalledTimes(1));
    typeTextFilters();
    await flushed();
    expect(fake.queryAudit).toHaveBeenCalledTimes(1);
  });

  it("applies the three typed text filters in one query on Apply", async () => {
    const fake = api();
    render(<AuditPage api={fake} />);
    await waitFor(() => expect(fake.queryAudit).toHaveBeenCalledTimes(1));
    typeTextFilters();
    apply();
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenLastCalledWith(
        expect.objectContaining({ event_type: "secret.use", principal_id: "ci-bot", limit: 25 }),
      ),
    );
    expect(fake.queryAudit).toHaveBeenCalledTimes(2);
  });

  it("applies the three typed text filters in one query on Enter", async () => {
    const fake = api();
    render(<AuditPage api={fake} />);
    await waitFor(() => expect(fake.queryAudit).toHaveBeenCalledTimes(1));
    typeTextFilters();
    pressEnter();
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenLastCalledWith(
        expect.objectContaining({ event_type: "secret.use", principal_id: "ci-bot", limit: 25 }),
      ),
    );
    expect(fake.queryAudit).toHaveBeenCalledTimes(2);
  });

  it("queries at once on a select change, leaving an unapplied text draft out", async () => {
    const fake = api();
    render(<AuditPage api={fake} />);
    await waitFor(() => expect(fake.queryAudit).toHaveBeenCalledTimes(1));
    fireEvent.input(screen.getByLabelText("Principal id"), { target: { value: "ci-bot" } });
    fireEvent.change(screen.getByLabelText("Outcome"), { target: { value: "failed" } });
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenLastCalledWith(
        expect.objectContaining({ success: false, principal_id: undefined }),
      ),
    );
    expect(fake.queryAudit).toHaveBeenCalledTimes(2);
  });

  it("queries at once on a principal type change, with no Apply", async () => {
    const fake = api();
    render(<AuditPage api={fake} />);
    await waitFor(() => expect(fake.queryAudit).toHaveBeenCalledTimes(1));
    fireEvent.change(screen.getByLabelText("Principal type"), { target: { value: "agent" } });
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenLastCalledWith(
        expect.objectContaining({ principal_type: "agent" }),
      ),
    );
    expect(fake.queryAudit).toHaveBeenCalledTimes(2);
  });

  it("hides reads at first: show reads is unticked and the first query excludes vault.read", async () => {
    const fake = api();
    render(<AuditPage api={fake} />);
    await waitFor(() => expect(fake.queryAudit).toHaveBeenCalledTimes(1));
    expect(fake.queryAudit).toHaveBeenCalledWith(
      expect.objectContaining({ exclude_event_type: "vault.read" }),
    );
    expect((screen.getByLabelText("show reads") as HTMLInputElement).checked).toBe(false);
  });

  it("queries at once without the exclusion once show reads is ticked, and with it once unticked", async () => {
    const fake = api();
    render(<AuditPage api={fake} />);
    await waitFor(() => expect(fake.queryAudit).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByLabelText("show reads"));
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenLastCalledWith(
        expect.objectContaining({ exclude_event_type: undefined }),
      ),
    );
    fireEvent.click(screen.getByLabelText("show reads"));
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenLastCalledWith(
        expect.objectContaining({ exclude_event_type: "vault.read" }),
      ),
    );
    expect(fake.queryAudit).toHaveBeenCalledTimes(3);
  });

  it("omits the exclusion while the applied event type is vault.read, and sends it for any other", async () => {
    const fake = api();
    render(<AuditPage api={fake} />);
    fireEvent.input(screen.getByLabelText("Event type"), { target: { value: "vault.read" } });
    apply();
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenLastCalledWith(
        expect.objectContaining({ event_type: "vault.read", exclude_event_type: undefined }),
      ),
    );
    fireEvent.input(screen.getByLabelText("Event type"), { target: { value: "secret.use" } });
    apply();
    await waitFor(() =>
      expect(fake.queryAudit).toHaveBeenLastCalledWith(
        expect.objectContaining({ event_type: "secret.use", exclude_event_type: "vault.read" }),
      ),
    );
    expect((screen.getByLabelText("show reads") as HTMLInputElement).checked).toBe(false);
  });

  it("sends exclude_event_type=vault.read on the wire, and drops the parameter once show reads is ticked", async () => {
    const fetchFn = vi.fn<typeof fetch>(
      async () => new Response(JSON.stringify({ data: [] }), { status: 200 }),
    );
    render(<AuditPage api={createApiClient(() => "t", fetchFn)} />);
    await waitFor(() => expect(fetchFn).toHaveBeenCalledTimes(1));
    expect(queryOf(fetchFn, 0).get("exclude_event_type")).toBe("vault.read");
    fireEvent.click(screen.getByLabelText("show reads"));
    await waitFor(() => expect(fetchFn).toHaveBeenCalledTimes(2));
    expect(queryOf(fetchFn, 1).has("exclude_event_type")).toBe(false);
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

  it("renders the recorded peer address, and a dash where none was recorded", async () => {
    const fake = api({
      queryAudit: vi
        .fn()
        .mockResolvedValue([
          event({ ip_address: "127.0.0.1" }),
          event({ id: 2, event_type: "access.denied", success: false }),
        ]),
    });
    render(<AuditPage api={fake} />);
    await waitFor(() => expect(screen.getByText("127.0.0.1")).toBeTruthy());
    // The second row's peer is NULL — the trail's own answer for a row written
    // off the wire, and the table's placeholder for it is the dash.
    const second = document.querySelectorAll("tbody tr:nth-child(2) td");
    expect(second[3]?.textContent).toBe("-");
  });

  it("carries an ip column between principal and outcome", async () => {
    render(<AuditPage api={api()} />);
    await waitFor(() => expect(screen.getByText("access.denied")).toBeTruthy());
    const headers = [...document.querySelectorAll("thead th")].map((th) => th.textContent);
    expect(headers).toEqual(["time", "event", "principal", "ip", "outcome"]);
  });
});
