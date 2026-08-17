import { describe, expect, it, vi } from "vitest";
import { ErrorCode, OAuthGrantType, VaultError } from "@harpoc/shared";
import type { CallerContext, StartOAuthFlowInput } from "@harpoc/shared";
import type { OAuthManager } from "./oauth-manager.js";
import { PENDING_AUTHORIZATION_MESSAGE, startOAuthFlowResult } from "./start-flow-result.js";

function baseInput(overrides: Partial<StartOAuthFlowInput> = {}): StartOAuthFlowInput {
  return {
    name: "gh-token",
    provider: "github",
    grant_type: OAuthGrantType.AUTHORIZATION_CODE,
    client_id: "client-1",
    ...overrides,
  };
}

const CALLER = { principal_type: "agent", principal_id: "agent-1" } as unknown as CallerContext;

function stubManager(): {
  manager: OAuthManager;
  fns: Record<
    "startAuthorizationCodeDeferred" | "startDeviceCode" | "startClientCredentials",
    ReturnType<typeof vi.fn>
  >;
} {
  const fns = {
    startAuthorizationCodeDeferred: vi.fn().mockResolvedValue({
      handle: "secret://gh-token",
      secretId: "sid-1",
      authUrl: "https://github.com/login/oauth/authorize?state=x",
      completion: Promise.resolve(),
    }),
    startDeviceCode: vi.fn().mockResolvedValue({
      handle: "secret://gh-token",
      status: "pending_authorization",
      auth_url: "https://github.com/login/device",
      user_code: "ABCD-EFGH",
      message: "Enter the code at the URL",
      completion: Promise.resolve(),
    }),
    startClientCredentials: vi.fn().mockResolvedValue({
      handle: "secret://gh-token",
      status: "authorized",
      message: "Token acquired and stored",
    }),
  };
  return { manager: fns as unknown as OAuthManager, fns };
}

describe("startOAuthFlowResult", () => {
  it("authorization_code projects exactly the wire fields, never secretId or completion", async () => {
    const { manager } = stubManager();
    const result = await startOAuthFlowResult(manager, baseInput());
    expect(Object.keys(result).sort()).toEqual(["auth_url", "handle", "message", "status"]);
    expect(result.status).toBe("pending_authorization");
    expect(result.auth_url).toBe("https://github.com/login/oauth/authorize?state=x");
    expect(result.message).toBe(PENDING_AUTHORIZATION_MESSAGE);
  });

  it("the pending message names a reachable completion signal", () => {
    // A provider that issues no refresh token never reaches refresh_status
    // "ok" (computeOAuthRefreshStatus short-circuits to no_refresh_token), so
    // the instruction must point at a signal every successful flow produces.
    expect(PENDING_AUTHORIZATION_MESSAGE).toContain("has_access_token");
    expect(PENDING_AUTHORIZATION_MESSAGE).not.toContain("refresh_status");
  });

  it("device_code projects the five wire fields and forwards project and caller", async () => {
    const { manager, fns } = stubManager();
    const result = await startOAuthFlowResult(
      manager,
      baseInput({ grant_type: OAuthGrantType.DEVICE_CODE, project: "proj" }),
      CALLER,
    );
    expect(Object.keys(result).sort()).toEqual([
      "auth_url",
      "handle",
      "message",
      "status",
      "user_code",
    ]);
    expect(fns.startDeviceCode).toHaveBeenCalledWith(
      "gh-token",
      expect.objectContaining({ provider: "github" }),
      "proj",
      CALLER,
    );
  });

  it("client_credentials projects handle, status and message and forwards the caller", async () => {
    const { manager, fns } = stubManager();
    const result = await startOAuthFlowResult(
      manager,
      baseInput({
        grant_type: OAuthGrantType.CLIENT_CREDENTIALS,
        client_secret: "s3cret-value",
      }),
      CALLER,
    );
    expect(Object.keys(result).sort()).toEqual(["handle", "message", "status"]);
    expect(result.status).toBe("authorized");
    expect(fns.startClientCredentials).toHaveBeenCalledWith(
      "gh-token",
      expect.objectContaining({ client_secret: "s3cret-value" }),
      undefined,
      CALLER,
    );
  });

  it("client_credentials without a client_secret is refused before the manager is called", async () => {
    const { manager, fns } = stubManager();
    await expect(
      startOAuthFlowResult(manager, baseInput({ grant_type: OAuthGrantType.CLIENT_CREDENTIALS })),
    ).rejects.toMatchObject({ code: ErrorCode.SCHEMA_VALIDATION_ERROR });
    await expect(
      startOAuthFlowResult(manager, baseInput({ grant_type: OAuthGrantType.CLIENT_CREDENTIALS })),
    ).rejects.toBeInstanceOf(VaultError);
    expect(fns.startClientCredentials).not.toHaveBeenCalled();
  });

  it("forwards the caller on the authorization_code arm", async () => {
    const { manager, fns } = stubManager();
    await startOAuthFlowResult(manager, baseInput(), CALLER);
    expect(fns.startAuthorizationCodeDeferred).toHaveBeenCalledWith(
      "gh-token",
      expect.objectContaining({ provider: "github" }),
      undefined,
      CALLER,
    );
  });
});
