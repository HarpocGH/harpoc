import { cleanup, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AccessPolicy } from "@harpoc/shared";
import type { ApiClient, SecretInfo } from "../api/client";
import { SecretDetailPage } from "./secret-detail";

afterEach(cleanup);

const secret = (over: Partial<SecretInfo> = {}): SecretInfo => ({
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

const grant = (over: Partial<AccessPolicy> = {}): AccessPolicy => ({
  id: "pol-1",
  secret_id: "sec-1",
  principal_type: "agent",
  principal_id: "agent-7",
  permissions: ["read"],
  created_at: 0,
  expires_at: null,
  created_by: "cli",
  ...over,
});

function api(over: Partial<ApiClient> = {}): ApiClient {
  return {
    getSecret: vi.fn().mockResolvedValue(secret()),
    getInjectionPolicy: vi.fn().mockResolvedValue({ response_mode: "filtered" }),
    getAccessPolicies: vi.fn().mockResolvedValue([]),
    getOAuthStatus: vi.fn().mockResolvedValue({ provider: "github" }),
    getCertificateStatus: vi.fn().mockResolvedValue({ issuer: "LE" }),
    ...over,
  } as ApiClient;
}

describe("SecretDetailPage", () => {
  it("renders metadata and injection policy", async () => {
    render(<SecretDetailPage api={api()} handle="k1" />);
    await waitFor(() => expect(screen.getByText("k1")).toBeTruthy());
    expect(screen.getByText("response_mode")).toBeTruthy();
    expect(screen.getByText("filtered")).toBeTruthy();
  });

  it("renders the OAuth status panel for oauth_token secrets", async () => {
    const fake = api({
      getSecret: vi
        .fn()
        .mockResolvedValue(secret({ handle: "secret://o1", name: "o1", type: "oauth_token" })),
    });
    render(<SecretDetailPage api={fake} handle="o1" />);
    await waitFor(() => expect(screen.getByText("OAuth status")).toBeTruthy());
    expect(fake.getOAuthStatus).toHaveBeenCalledWith("o1");
    expect(screen.getByText("github")).toBeTruthy();
    expect(screen.getByText(/harpoc oauth connect/)).toBeTruthy();
  });

  it("renders the certificate status panel for certificate secrets", async () => {
    const fake = api({
      getSecret: vi
        .fn()
        .mockResolvedValue(secret({ handle: "secret://c1", name: "c1", type: "certificate" })),
    });
    render(<SecretDetailPage api={fake} handle="c1" />);
    await waitFor(() => expect(screen.getByText("Certificate status")).toBeTruthy());
    expect(fake.getCertificateStatus).toHaveBeenCalledWith("c1");
    expect(screen.getByText("LE")).toBeTruthy();
    expect(fake.getOAuthStatus).not.toHaveBeenCalled();
  });

  it("fetches no OAuth/cert status for api_key secrets", async () => {
    const fake = api();
    render(<SecretDetailPage api={fake} handle="k1" />);
    await waitFor(() => expect(screen.getByText("k1")).toBeTruthy());
    expect(fake.getOAuthStatus).not.toHaveBeenCalled();
    expect(fake.getCertificateStatus).not.toHaveBeenCalled();
  });

  it("drops the OAuth panel when the page moves on to a non-OAuth secret", async () => {
    // The shell keeps one SecretDetailPage instance across a route change, so a
    // stale `type` must not outlive the handle it was loaded for: it would both
    // query the OAuth route for an api_key secret and leave the previous
    // secret's provider on screen under the new secret's name.
    const fake = api({
      getSecret: vi
        .fn()
        .mockResolvedValueOnce(secret({ handle: "secret://o1", name: "o1", type: "oauth_token" }))
        .mockResolvedValue(secret()),
    });
    const { rerender } = render(<SecretDetailPage api={fake} handle="o1" />);
    await waitFor(() => expect(screen.getByText("OAuth status")).toBeTruthy());

    rerender(<SecretDetailPage api={fake} handle="k1" />);
    await waitFor(() => expect(screen.getByText("k1")).toBeTruthy());
    expect(screen.queryByText("OAuth status")).toBeNull();
    expect(fake.getOAuthStatus).not.toHaveBeenCalledWith("k1");
  });

  it("points at the CLI when a secret carries no per-secret grants", async () => {
    render(<SecretDetailPage api={api()} handle="k1" />);
    await waitFor(() => expect(screen.getByText(/No per-secret grants/)).toBeTruthy());
    expect(screen.getByText(/harpoc policy grant/)).toBeTruthy();
  });

  it("lists per-secret grants when the secret has them", async () => {
    render(
      <SecretDetailPage
        api={api({
          getAccessPolicies: vi
            .fn()
            .mockResolvedValue([
              grant(),
              grant({ id: "pol-2", principal_id: "agent-8", permissions: ["read", "use"] }),
            ]),
        })}
        handle="k1"
      />,
    );
    await waitFor(() => expect(screen.getByText(/agent-7/)).toBeTruthy());
    expect(screen.getByText(/agent-8/)).toBeTruthy();
    expect(screen.queryByText(/No per-secret grants/)).toBeNull();
  });

  it("shows the error instead of the page when the secret cannot be loaded", async () => {
    render(
      <SecretDetailPage
        api={api({ getSecret: vi.fn().mockRejectedValue(new Error("boom")) })}
        handle="k1"
      />,
    );
    await waitFor(() => expect(screen.getByText("boom")).toBeTruthy());
    expect(screen.queryByText("Injection policy")).toBeNull();
  });

  it("mounts the actions slot", async () => {
    const { container } = render(<SecretDetailPage api={api()} handle="k1" />);
    await waitFor(() => expect(screen.getByText("k1")).toBeTruthy());
    expect(container.querySelector("section#actions")).toBeTruthy();
  });
});
