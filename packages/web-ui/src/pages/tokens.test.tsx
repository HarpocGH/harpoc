import type { IssuedToken } from "@harpoc/shared";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ApiClient } from "../api/client";
import { setToken } from "../auth/token-store";
import { TokensPage } from "./tokens";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
beforeEach(() => {
  window.sessionStorage.clear();
  window.location.hash = "";
});

const HOUR = 3_600_000;

const token = (over: Partial<IssuedToken> = {}): IssuedToken => ({
  jti: "jti-1",
  subject: "ci-bot",
  principal_type: "agent",
  agent: "ci-bot",
  scope: ["read", "use"],
  project: "myproj",
  secrets: ["db-*"],
  label: "deploy",
  issued_at: 1700000000000,
  expires_at: Date.now() + 3 * HOUR,
  revoked_at: null,
  status: "active",
  ...over,
});

const api = (over: Partial<ApiClient> = {}): ApiClient =>
  ({
    listTokens: vi.fn().mockResolvedValue([token()]),
    revokeToken: vi.fn().mockResolvedValue(undefined),
    ...over,
  }) as ApiClient;

const b64url = (text: string): string =>
  btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/** A session JWT carrying `jti` — payload only; nothing here verifies it. */
const sessionJwt = (jti: string): string =>
  `${b64url('{"alg":"HS256"}')}.${b64url(JSON.stringify({ jti, sub: "web-ui" }))}.sig`;

const href = (selector: string): string | undefined =>
  document.querySelector<HTMLAnchorElement>(selector)?.getAttribute("href") ?? undefined;

const SELF_REVOKE_WARNING =
  "This is the token this session is using — revoking it signs you out. Revoke anyway?";

describe("TokensPage", () => {
  it("lists a token's claims metadata across the columns", async () => {
    render(<TokensPage api={api()} />);
    await waitFor(() => expect(screen.getByText("deploy")).toBeTruthy());
    expect(screen.getByText("myproj")).toBeTruthy();
    expect(screen.getByText("db-*")).toBeTruthy();
    expect(screen.getByText("read, use")).toBeTruthy();
    expect(screen.getByText(new Date(1700000000000).toISOString())).toBeTruthy();
  });

  it("links the agent column to the agent detail", async () => {
    render(<TokensPage api={api()} />);
    await waitFor(() => expect(screen.getByText("deploy")).toBeTruthy());
    expect(href('a[href^="#/agents/"]')).toBe("#/agents/ci-bot");
  });

  it("shows a dash rather than a link for a token with no agent", async () => {
    render(
      <TokensPage
        api={api({
          listTokens: vi
            .fn()
            .mockResolvedValue([token({ agent: null, project: null, secrets: null, label: null })]),
        })}
      />,
    );
    await waitFor(() => expect(screen.getByText("ci-bot")).toBeTruthy());
    expect(href('a[href^="#/agents/"]')).toBeUndefined();
  });

  it("reads an empty pattern list as unrestricted rather than leaving the cell blank", async () => {
    // An absent or empty `secrets` claim means unrestricted (auth token
    // --secrets); a blank cell reads as a rendering fault instead.
    render(
      <TokensPage api={api({ listTokens: vi.fn().mockResolvedValue([token({ secrets: [] })]) })} />,
    );
    await waitFor(() => expect(screen.getByText("deploy")).toBeTruthy());
    const cells = [...document.querySelectorAll("tbody td")].map((c) => c.textContent);
    expect(cells).toContain("-");
    expect(cells).not.toContain("");
  });

  it("asks for active tokens by default", async () => {
    const listTokens = vi.fn().mockResolvedValue([token()]);
    render(<TokensPage api={api({ listTokens })} />);
    await waitFor(() => expect(listTokens).toHaveBeenCalledWith({ status: "active" }));
  });

  it("re-queries when the status filter changes", async () => {
    const listTokens = vi.fn().mockResolvedValue([token()]);
    render(<TokensPage api={api({ listTokens })} />);
    await waitFor(() => expect(listTokens).toHaveBeenCalledWith({ status: "active" }));
    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "all" } });
    await waitFor(() => expect(listTokens).toHaveBeenCalledWith({ status: "all" }));
  });

  it("passes a typed agent filter and omits an emptied one", async () => {
    const listTokens = vi.fn().mockResolvedValue([token()]);
    render(<TokensPage api={api({ listTokens })} />);
    await waitFor(() => expect(listTokens).toHaveBeenCalledWith({ status: "active" }));
    fireEvent.input(screen.getByLabelText("Agent"), { target: { value: "ci-bot" } });
    await waitFor(() =>
      expect(listTokens).toHaveBeenCalledWith({ status: "active", agent: "ci-bot" }),
    );
    fireEvent.input(screen.getByLabelText("Agent"), { target: { value: "" } });
    await waitFor(() => expect(listTokens).toHaveBeenLastCalledWith({ status: "active" }));
  });

  it("counts an expiry under the hour down in minutes, in the warn tone", async () => {
    render(
      <TokensPage
        api={api({
          listTokens: vi.fn().mockResolvedValue([token({ expires_at: Date.now() + 42 * 60_000 })]),
        })}
      />,
    );
    await waitFor(() => expect(screen.getByText("in 42 min")).toBeTruthy());
    expect(screen.getByText("in 42 min").getAttribute("data-tone")).toBe("warn");
  });

  it("counts a longer expiry down in hours, without the warn tone", async () => {
    render(<TokensPage api={api()} />);
    await waitFor(() => expect(screen.getByText("in 3 h")).toBeTruthy());
    expect(screen.getByText("in 3 h").getAttribute("data-tone")).not.toBe("warn");
  });

  it("counts a multi-day expiry down in days", async () => {
    render(
      <TokensPage
        api={api({
          listTokens: vi.fn().mockResolvedValue([token({ expires_at: Date.now() + 72 * HOUR })]),
        })}
      />,
    );
    await waitFor(() => expect(screen.getByText("in 3 d")).toBeTruthy());
  });

  it("says expired rather than counting a past expiry down", async () => {
    render(
      <TokensPage
        api={api({
          listTokens: vi
            .fn()
            .mockResolvedValue([
              token({ status: "expired", expires_at: Date.now() - 5 * HOUR, agent: null }),
            ]),
        })}
      />,
    );
    await waitFor(() =>
      expect(screen.getByText("expired", { selector: ".countdown" })).toBeTruthy(),
    );
    expect(document.body.textContent).not.toContain("in -");
  });

  it("tones a revoked token bad and an expired one muted", async () => {
    render(
      <TokensPage
        api={api({
          listTokens: vi
            .fn()
            .mockResolvedValue([
              token({ status: "revoked", revoked_at: 1700000001000 }),
              token({ jti: "jti-2", status: "expired", expires_at: Date.now() - HOUR }),
            ]),
        })}
      />,
    );
    // Scoped to `.chip`: the status filter's own `<option>` carries the same
    // text, and an unscoped match resolves against it before the rows land.
    await waitFor(() =>
      expect(screen.getByText("revoked", { selector: ".chip" }).getAttribute("data-tone")).toBe(
        "bad",
      ),
    );
    // An expired token is history, not a fault: it is muted, not wax-red.
    expect(screen.getByText("expired", { selector: ".chip" }).getAttribute("data-tone")).toBe("");
  });

  it("offers Revoke on an active token only", async () => {
    render(
      <TokensPage
        api={api({
          listTokens: vi
            .fn()
            .mockResolvedValue([token({ jti: "jti-2", status: "revoked", agent: null })]),
        })}
      />,
    );
    await waitFor(() => expect(screen.getByText("revoked", { selector: ".chip" })).toBeTruthy());
    expect(screen.queryByRole("button", { name: "Revoke" })).toBeNull();
  });

  it("revokes after a confirmation and reloads the list", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    const listTokens = vi.fn().mockResolvedValue([token()]);
    const revokeToken = vi.fn().mockResolvedValue(undefined);
    render(<TokensPage api={api({ listTokens, revokeToken })} />);
    await waitFor(() => expect(screen.getByRole("button", { name: "Revoke" })).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    expect(confirmSpy).toHaveBeenCalled();
    await waitFor(() => expect(revokeToken).toHaveBeenCalledWith("jti-1"));
    await waitFor(() => expect(listTokens).toHaveBeenCalledTimes(2));
  });

  it("does not revoke when the confirmation is declined", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    const revokeToken = vi.fn().mockResolvedValue(undefined);
    render(<TokensPage api={api({ revokeToken })} />);
    await waitFor(() => expect(screen.getByRole("button", { name: "Revoke" })).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    expect(revokeToken).not.toHaveBeenCalled();
  });

  it("warns in the confirmation when the row is the session's own token", async () => {
    setToken(sessionJwt("jti-1"));
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
    render(<TokensPage api={api()} />);
    await waitFor(() => expect(screen.getByRole("button", { name: "Revoke" })).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    expect(String(confirmSpy.mock.calls[0]?.[0] ?? "")).toBe(SELF_REVOKE_WARNING);
  });

  it("does not warn about self-revocation for somebody else's token", async () => {
    setToken(sessionJwt("jti-other"));
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
    render(<TokensPage api={api()} />);
    await waitFor(() => expect(screen.getByRole("button", { name: "Revoke" })).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    const prompt = String(confirmSpy.mock.calls[0]?.[0] ?? "");
    expect(prompt).not.toBe(SELF_REVOKE_WARNING);
    expect(prompt).toContain("jti-1");
  });

  it("does not warn about self-revocation when the session token cannot be decoded", async () => {
    setToken("not-a-jwt");
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
    render(<TokensPage api={api()} />);
    await waitFor(() => expect(screen.getByRole("button", { name: "Revoke" })).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    expect(String(confirmSpy.mock.calls[0]?.[0] ?? "")).not.toBe(SELF_REVOKE_WARNING);
  });

  it("shows a refused revoke rather than swallowing it", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(
      <TokensPage
        api={api({ revokeToken: vi.fn().mockRejectedValue(new Error("ACCESS_DENIED")) })}
      />,
    );
    await waitFor(() => expect(screen.getByRole("button", { name: "Revoke" })).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(screen.getByText("ACCESS_DENIED")).toBeTruthy());
  });

  it("points at the CLI when nothing matches the filter", async () => {
    render(<TokensPage api={api({ listTokens: vi.fn().mockResolvedValue([]) })} />);
    await waitFor(() => expect(screen.getByText(/No tokens/)).toBeTruthy());
    expect(screen.getByText(/harpoc auth token/)).toBeTruthy();
  });

  it("shows an error message when the listing fails", async () => {
    render(<TokensPage api={api({ listTokens: vi.fn().mockRejectedValue(new Error("boom")) })} />);
    await waitFor(() => expect(screen.getByText("boom")).toBeTruthy());
  });
});
