import { describe, expect, it } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { importPeer } from "./import-peer.js";

function moduleNotFound(message: string, code = "ERR_MODULE_NOT_FOUND"): Error {
  const err = new Error(message);
  (err as NodeJS.ErrnoException).code = code;
  return err;
}

async function rejectionOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (err) {
    return err;
  }
  throw new Error("expected the call to reject");
}

describe("importPeer", () => {
  it("passes the loaded module through untouched", async () => {
    const mod = { OAuthManager: (): void => {} };
    await expect(importPeer("@harpoc/oauth-proxy", () => Promise.resolve(mod))).resolves.toBe(mod);
  });

  it("reports an absent peer as MISSING_DEPENDENCY (501) naming the specifier", async () => {
    const err = await rejectionOf(
      importPeer("@harpoc/oauth-proxy", () =>
        Promise.reject(
          moduleNotFound(
            "Cannot find package '@harpoc/oauth-proxy' imported from /x/direct-client.js",
          ),
        ),
      ),
    );
    expect(err).toBeInstanceOf(VaultError);
    expect((err as VaultError).code).toBe(ErrorCode.MISSING_DEPENDENCY);
    expect((err as VaultError).statusCode).toBe(501);
    expect((err as VaultError).message).toBe(
      'Optional dependency "@harpoc/oauth-proxy" is not installed. Install it to use this feature.',
    );
  });

  it("recognises the CommonJS resolution code too", async () => {
    const err = await rejectionOf(
      importPeer("@harpoc/cert-manager", () =>
        Promise.reject(
          moduleNotFound("Cannot find module '@harpoc/cert-manager'", "MODULE_NOT_FOUND"),
        ),
      ),
    );
    expect((err as VaultError).code).toBe(ErrorCode.MISSING_DEPENDENCY);
  });

  it("a missing transitive dependency is not misreported as a missing peer", async () => {
    const raw = moduleNotFound(
      "Cannot find package 'some-transitive-dep' imported from /n/@harpoc/oauth-proxy/dist/index.js",
    );
    const err = await rejectionOf(importPeer("@harpoc/oauth-proxy", () => Promise.reject(raw)));
    expect(err).toBe(raw);
    expect(err).not.toBeInstanceOf(VaultError);
  });

  it("rethrows an unrelated failure from the peer's own module body", async () => {
    const raw = new TypeError("boom");
    const err = await rejectionOf(importPeer("@harpoc/oauth-proxy", () => Promise.reject(raw)));
    expect(err).toBe(raw);
  });

  it("rethrows a non-Error rejection", async () => {
    const err = await rejectionOf(importPeer("@harpoc/oauth-proxy", () => Promise.reject("nope")));
    expect(err).toBe("nope");
  });

  // The one test here that lets a real resolution fail: it holds only while
  // vitest's SSR loader keeps Node's ERR_MODULE_NOT_FOUND shape. A failure
  // after a vitest bump is that coupling breaking, not the mapper regressing.
  it("wraps the genuine resolution failure of an uninstalled package", async () => {
    const specifier = "@harpoc/definitely-not-installed";
    const err = await rejectionOf(
      importPeer(specifier, () => import(/* @vite-ignore */ specifier)),
    );
    expect(err).toBeInstanceOf(VaultError);
    expect((err as VaultError).code).toBe(ErrorCode.MISSING_DEPENDENCY);
  });
});
