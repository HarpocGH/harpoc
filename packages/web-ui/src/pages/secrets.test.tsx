import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ApiClient, SecretInfo } from "../api/client";
import { SecretsPage } from "./secrets";

afterEach(cleanup);
beforeEach(() => {
  window.location.hash = "";
});

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

const api = (over: Partial<ApiClient> = {}): ApiClient =>
  ({
    listSecrets: vi
      .fn()
      .mockResolvedValue([secret(), secret({ handle: "secret://k2", name: "k2" })]),
    ...over,
  }) as ApiClient;

describe("SecretsPage", () => {
  it("lists secrets and filters by name", async () => {
    render(<SecretsPage api={api()} />);
    await waitFor(() => expect(screen.getByText("k1")).toBeTruthy());
    expect(screen.getByText("k2")).toBeTruthy();
    fireEvent.input(screen.getByLabelText("Filter"), { target: { value: "k1" } });
    await waitFor(() => expect(screen.queryByText("k2")).toBeNull());
  });

  it("filters by project as well as by name", async () => {
    render(
      <SecretsPage
        api={api({
          listSecrets: vi
            .fn()
            .mockResolvedValue([
              secret(),
              secret({ handle: "secret://myproj/k2", name: "k2", project: "myproj" }),
            ]),
        })}
      />,
    );
    await waitFor(() => expect(screen.getByText("k1")).toBeTruthy());
    fireEvent.input(screen.getByLabelText("Filter"), { target: { value: "myproj" } });
    await waitFor(() => expect(screen.queryByText("k1")).toBeNull());
    expect(screen.getByText("k2")).toBeTruthy();
  });

  it("says the filter matched nothing rather than rendering a bare page", async () => {
    render(<SecretsPage api={api()} />);
    await waitFor(() => expect(screen.getByText("k1")).toBeTruthy());
    fireEvent.input(screen.getByLabelText("Filter"), { target: { value: "no-such-secret" } });
    await waitFor(() => expect(screen.getByText(/No secrets match/)).toBeTruthy());
    // The filter is not the vault: an empty result set must not read as "the
    // vault holds nothing", which is the other empty state's claim.
    expect(screen.queryByText(/No secrets yet/)).toBeNull();
  });

  it("shows the CLI-pointing empty state", async () => {
    render(<SecretsPage api={api({ listSecrets: vi.fn().mockResolvedValue([]) })} />);
    await waitFor(() => expect(screen.getByText(/No secrets yet/)).toBeTruthy());
    expect(screen.getByText(/harpoc secret set/)).toBeTruthy();
  });

  it("navigates to the secret detail when a row is clicked", async () => {
    render(<SecretsPage api={api()} />);
    await waitFor(() => expect(screen.getByText("k1")).toBeTruthy());
    fireEvent.click(screen.getByText("k1"));
    expect(window.location.hash).toBe("#/secrets/k1");
  });

  it("addresses a project-scoped secret by its handle, not its bare name", async () => {
    // `name` alone loses the project: `secret://myproj/test-key` and a
    // project-less `test-key` are different secrets, and the API's `:handle`
    // param is the scheme-less handle — the same `myproj%2Ftest-key` segment
    // the shell's route test decodes.
    render(
      <SecretsPage
        api={api({
          listSecrets: vi
            .fn()
            .mockResolvedValue([
              secret({ handle: "secret://myproj/test-key", name: "test-key", project: "myproj" }),
            ]),
        })}
      />,
    );
    await waitFor(() => expect(screen.getByText("test-key")).toBeTruthy());
    fireEvent.click(screen.getByText("test-key"));
    expect(window.location.hash).toBe("#/secrets/myproj%2Ftest-key");
  });

  it("shows an error message when listSecrets fails", async () => {
    render(
      <SecretsPage api={api({ listSecrets: vi.fn().mockRejectedValue(new Error("boom")) })} />,
    );
    await waitFor(() => expect(screen.getByText("boom")).toBeTruthy());
  });

  it("mounts the create-form slot", async () => {
    const { container } = render(<SecretsPage api={api()} />);
    await waitFor(() => expect(screen.getByText("k1")).toBeTruthy());
    expect(container.querySelector("section#create")).toBeTruthy();
  });
});
