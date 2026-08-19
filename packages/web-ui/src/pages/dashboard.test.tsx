import { cleanup, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AuditEventWire, SecretInfo } from "../api/client";
import type { ApiClient } from "../api/client";
import { DashboardPage } from "./dashboard";

afterEach(cleanup);
beforeEach(() => {
  window.location.hash = "";
});

const secret = (over: Partial<SecretInfo>): SecretInfo => ({
  handle: "secret://k1",
  name: "k1",
  type: "api_key",
  project: null,
  status: "active",
  version: 1,
  createdAt: 0,
  updatedAt: 0,
  expiresAt: null,
  rotatedAt: null,
  ...over,
});

const failedEvent = (over: Partial<AuditEventWire> = {}): AuditEventWire => ({
  id: 41,
  timestamp: 1_700_000_000_000,
  event_type: "access.denied",
  secret_id: "id-1",
  principal_type: "agent",
  principal_id: "agent-7",
  detail: null,
  ip_address: null,
  session_id: null,
  success: false,
  ...over,
});

function api(over: Partial<ApiClient>): ApiClient {
  return {
    listSecrets: vi.fn().mockResolvedValue([secret({}), secret({ name: "k2", status: "expired" })]),
    queryAudit: vi.fn().mockResolvedValue([]),
    expiringReport: vi.fn().mockResolvedValue({
      expiring: [secret({ handle: "secret://soon", name: "soon", expiresAt: Date.now() + 1000 })],
      oauth_refresh_needed: [
        {
          handle: "secret://o1",
          name: "o1",
          project: null,
          provider: "github",
          access_token_expires_at: 1_700_000_000_000,
          has_refresh_token: true,
          refresh_status: "ok",
        },
      ],
      certificates_nearing_renewal: [],
    }),
    ...over,
  } as ApiClient;
}

describe("DashboardPage", () => {
  it("renders counts and the attention lists", async () => {
    render(<DashboardPage api={api({})} />);
    await waitFor(() => expect(screen.getByText(/2 secrets/)).toBeTruthy());
    expect(screen.getByText("soon")).toBeTruthy();
    expect(screen.getByText("o1")).toBeTruthy();
  });

  it("says all clear when nothing needs attention", async () => {
    render(
      <DashboardPage
        api={api({
          expiringReport: vi.fn().mockResolvedValue({
            expiring: [],
            oauth_refresh_needed: [],
            certificates_nearing_renewal: [],
          }),
        })}
      />,
    );
    await waitFor(() => expect(screen.getByText(/Nothing needs attention/)).toBeTruthy());
  });

  it("shows real OAuth metadata (provider, token expiry) in the attention row", async () => {
    render(<DashboardPage api={api({})} />);
    await waitFor(() => expect(screen.getByText("o1")).toBeTruthy());
    expect(screen.getByText("github")).toBeTruthy();
    expect(screen.getByText("1700000000000")).toBeTruthy();
  });

  it("shows real certificate metadata (subject, not_after) in the attention row", async () => {
    render(
      <DashboardPage
        api={api({
          expiringReport: vi.fn().mockResolvedValue({
            expiring: [],
            oauth_refresh_needed: [],
            certificates_nearing_renewal: [
              {
                handle: "secret://c1",
                name: "c1",
                project: null,
                subject: "CN=example.com",
                not_after: 1_800_000_000_000,
                auto_renew: true,
                renew_before_days: 30,
                renewal_status: "expiring_soon",
              },
            ],
          }),
        })}
      />,
    );
    await waitFor(() => expect(screen.getByText("c1")).toBeTruthy());
    expect(screen.getByText("CN=example.com")).toBeTruthy();
    expect(screen.getByText("1800000000000")).toBeTruthy();
  });

  it("navigates to secret detail when an expiring-secret row is clicked", async () => {
    const { fireEvent } = await import("@testing-library/preact");
    render(<DashboardPage api={api({})} />);
    await waitFor(() => expect(screen.getByText("soon")).toBeTruthy());
    const before = window.location.hash;
    fireEvent.click(screen.getByText("soon"));
    expect(window.location.hash).not.toBe(before);
    expect(window.location.hash).toBe("#/secrets/soon");
  });

  it("addresses a project-scoped expiring secret by its handle, not its bare name", async () => {
    // `name` alone loses the project: `secret://myproj/rotate-me` and a
    // project-less `rotate-me` are different secrets, and the route segment the
    // detail page is addressed by is the scheme-less handle — the same form the
    // secrets list navigates with.
    const { fireEvent } = await import("@testing-library/preact");
    render(
      <DashboardPage
        api={api({
          expiringReport: vi.fn().mockResolvedValue({
            expiring: [
              secret({
                handle: "secret://myproj/rotate-me",
                name: "rotate-me",
                project: "myproj",
                expiresAt: Date.now() + 1000,
              }),
            ],
            oauth_refresh_needed: [],
            certificates_nearing_renewal: [],
          }),
        })}
      />,
    );
    await waitFor(() => expect(screen.getByText("rotate-me")).toBeTruthy());
    fireEvent.click(screen.getByText("rotate-me"));
    expect(window.location.hash).toBe("#/secrets/myproj%2Frotate-me");
  });

  it("shows an error message when listSecrets fails", async () => {
    render(
      <DashboardPage api={api({ listSecrets: vi.fn().mockRejectedValue(new Error("boom")) })} />,
    );
    await waitFor(() => expect(screen.getByText("boom")).toBeTruthy());
  });

  it("lists recent audit failures with their event type, principal and a failed chip", async () => {
    const queryAudit = vi.fn().mockResolvedValue([failedEvent()]);
    render(<DashboardPage api={api({ queryAudit })} />);
    await waitFor(() => expect(screen.getByText("access.denied")).toBeTruthy());
    expect(queryAudit).toHaveBeenCalledWith({ success: false, limit: 5 });
    expect(screen.getByText("Recent audit failures")).toBeTruthy();
    expect(screen.getByText("agent-7")).toBeTruthy();
    expect(screen.getByText(new Date(1_700_000_000_000).toISOString())).toBeTruthy();
    expect(screen.getByText("failed").getAttribute("data-tone")).toBe("bad");
  });

  it("counts audit failures toward the attention total", async () => {
    // A failure-only vault is not an all-clear vault: the line claims nothing
    // needs attention, so every list it summarises has to be in the count.
    render(
      <DashboardPage
        api={api({
          expiringReport: vi.fn().mockResolvedValue({
            expiring: [],
            oauth_refresh_needed: [],
            certificates_nearing_renewal: [],
          }),
          queryAudit: vi.fn().mockResolvedValue([failedEvent()]),
        })}
      />,
    );
    await waitFor(() => expect(screen.getByText("access.denied")).toBeTruthy());
    expect(screen.queryByText(/Nothing needs attention/)).toBeNull();
  });

  it("still says all clear when the failures list is empty too", async () => {
    render(
      <DashboardPage
        api={api({
          expiringReport: vi.fn().mockResolvedValue({
            expiring: [],
            oauth_refresh_needed: [],
            certificates_nearing_renewal: [],
          }),
          queryAudit: vi.fn().mockResolvedValue([]),
        })}
      />,
    );
    await waitFor(() => expect(screen.getByText(/Nothing needs attention/)).toBeTruthy());
    expect(screen.queryByText("Recent audit failures")).toBeNull();
  });

  it("tones the expiring-secret row's chip amber, not the neutral 'warn' literal", async () => {
    render(<DashboardPage api={api({})} />);
    await waitFor(() => expect(screen.getByText("expiring")).toBeTruthy());
    expect(screen.getByText("expiring").getAttribute("data-tone")).toBe("warn");
    expect(screen.queryByText("warn")).toBeNull();
  });
});
