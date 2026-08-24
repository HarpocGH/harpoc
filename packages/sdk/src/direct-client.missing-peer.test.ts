import { readFileSync } from "node:fs";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { DirectClient } from "./direct-client.js";
import { importPeer } from "./import-peer.js";

/**
 * Every lazy peer load must go through `importPeer`, so an absent
 * `@harpoc/oauth-proxy` / `@harpoc/cert-manager` surfaces as MISSING_DEPENDENCY
 * rather than Node's raw ERR_MODULE_NOT_FOUND. Standing in for the loader is
 * what makes the routing observable: vitest replaces a throwing `vi.mock`
 * factory with its own Error (the original only survives on `cause`), so
 * mocking the peers themselves cannot reproduce a resolution failure.
 *
 * Its own file so the loader stand-in cannot leak into `direct-client.test.ts`,
 * which drives the same methods against the real peers.
 */
vi.mock("./import-peer.js", () => ({ importPeer: vi.fn() }));

const importPeerMock = vi.mocked(importPeer);

const engine = {} as never;

const OAUTH_INPUT = {
  name: "gh",
  provider: "github",
  grant_type: "authorization_code",
  client_id: "cid",
} as const;

async function rejectionOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (err) {
    return err;
  }
  throw new Error("expected the call to reject");
}

function expectMissing(err: unknown, specifier: string): void {
  expect(err).toBeInstanceOf(VaultError);
  expect((err as VaultError).code).toBe(ErrorCode.MISSING_DEPENDENCY);
  expect((err as VaultError).statusCode).toBe(501);
  expect((err as VaultError).message).toContain(specifier);
}

describe("DirectClient with the optional peers absent", () => {
  beforeEach(() => {
    importPeerMock.mockReset();
    importPeerMock.mockImplementation((specifier: string) =>
      Promise.reject(VaultError.missingDependency(specifier)),
    );
  });

  it("startOAuthFlow reports MISSING_DEPENDENCY (501) from the manager build site", async () => {
    const client = new DirectClient(engine);
    expectMissing(await rejectionOf(client.startOAuthFlow(OAUTH_INPUT)), "@harpoc/oauth-proxy");
    expect(importPeerMock).toHaveBeenCalledWith("@harpoc/oauth-proxy", expect.any(Function));
  });

  it("startOAuthFlow reports MISSING_DEPENDENCY from the startOAuthFlowResult site", async () => {
    const client = new DirectClient(engine, { oauthManager: {} as never });
    expectMissing(await rejectionOf(client.startOAuthFlow(OAUTH_INPUT)), "@harpoc/oauth-proxy");
    expect(importPeerMock).toHaveBeenCalledWith("@harpoc/oauth-proxy", expect.any(Function));
  });

  it("generateCsr reports MISSING_DEPENDENCY (501)", async () => {
    const client = new DirectClient(engine);
    expectMissing(
      await rejectionOf(client.generateCsr("web", { subject: "example.com" })),
      "@harpoc/cert-manager",
    );
    expect(importPeerMock).toHaveBeenCalledWith("@harpoc/cert-manager", expect.any(Function));
  });

  it("a closed client refuses startOAuthFlow before paying the peer import", async () => {
    const client = new DirectClient(engine);
    client.close();
    const err = await rejectionOf(client.startOAuthFlow(OAUTH_INPUT));
    expect((err as VaultError).code).toBe(ErrorCode.INVALID_INPUT);
    expect(importPeerMock).not.toHaveBeenCalled();
  });

  // Vite rewrites a dynamic specifier to a resolved path in the transformed
  // thunk, so the literal the confinement tripwire reads out of `dist` can only
  // be pinned at the source. This also covers the sites no method above reaches.
  it("routes every lazy peer import through importPeer, literal specifier intact", () => {
    const source = readFileSync(new URL("./direct-client.ts", import.meta.url), "utf-8");
    const compact = source.replace(/\s+/g, "");
    for (const specifier of ["@harpoc/oauth-proxy", "@harpoc/cert-manager"]) {
      expect(compact).toContain(`importPeer("${specifier}",()=>import("${specifier}")`);
    }
    expect(compact).not.toContain('awaitimport("');
    expect(compact.split("importPeer(").length - 1).toBe(3);
  });
});
