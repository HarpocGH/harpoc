import { afterEach, describe, it, expect, vi } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { DirectClient } from "./direct-client.js";
import {
  LEAF_PEM,
  PLAIN_KEY_PEM,
  createFakeCertManager,
  createMockEngine,
} from "./__fixtures__/direct-client-fixtures.js";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("DirectClient", () => {
  /**
   * D4 says the OAuth and certificate peers are loaded by `import()` only when
   * one of their methods is actually called, and that each client builds its
   * manager once. Every other test here injects a fake, so the real dynamic
   * import ran only on the OAuth side (the background-failure test in
   * direct-client.test.ts) and neither side pinned the cache — a lost
   * `if (!this.xInstance)` would have rebuilt a manager per call, silently.
   */
  describe("lazy optional peers (no injected manager)", () => {
    it("lazily builds the real CertManager when none is injected", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      try {
        const ref = await client.importCertificate("web", {
          private_key_pem: PLAIN_KEY_PEM,
          certificate_pem: LEAF_PEM,
        });

        expect(ref).toEqual({ handle: "secret://web", secretId: "uuid-web" });
        // The real manager's own mapping: a bundle split into leaf + chain, then
        // the engine's positional signature. A fake could not produce this.
        expect(engine.importCertificate).toHaveBeenCalledWith(
          "web",
          PLAIN_KEY_PEM,
          {
            certificatePem: LEAF_PEM,
            chainPem: undefined,
            autoRenew: false,
            renewBeforeDays: 30,
          },
          undefined,
          undefined,
        );
      } finally {
        client.close();
      }
    });

    it("caches the lazily built managers (one instance per client)", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);
      // The cache is the property under test, so reference equality through the
      // private loaders is the honest pin — no public method exposes it.
      const load = client as never as {
        loadOAuthManager(): Promise<unknown>;
        loadCertManager(): Promise<unknown>;
      };

      try {
        expect(await load.loadOAuthManager()).toBe(await load.loadOAuthManager());
        expect(await load.loadCertManager()).toBe(await load.loadCertManager());
      } finally {
        client.close();
      }
    });

    // RED before the promise memoization: each un-awaited first call passed the
    // `if (!instance)` check, so two managers were built and the field kept the
    // second — close() then cancelled a manager the first caller never had.
    it("two concurrent first calls share one manager", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);
      const load = client as never as {
        loadOAuthManager(): Promise<{ cancelPendingFlows: () => void }>;
      };

      try {
        const [first, second] = await Promise.all([
          load.loadOAuthManager(),
          load.loadOAuthManager(),
        ]);
        expect(first).toBe(second);
      } finally {
        client.close();
      }
    });

    // RED before the promise memoization independently of the identity check:
    // the second manager is reachable by nobody, so close() leaves it uncancelled.
    it("close() cancels every OAuth manager the client built", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);
      const internals = client as never as {
        buildOAuthManager(): Promise<{ cancelPendingFlows: () => void }>;
        loadOAuthManager(): Promise<{ cancelPendingFlows: () => void }>;
      };
      const built: Array<{ cancelPendingFlows: () => void }> = [];
      const original = internals.buildOAuthManager;
      vi.spyOn(internals, "buildOAuthManager").mockImplementation(async () => {
        const manager = await original.call(client);
        vi.spyOn(manager, "cancelPendingFlows");
        built.push(manager);
        return manager;
      });

      try {
        const [a, b] = await Promise.all([
          internals.loadOAuthManager(),
          internals.loadOAuthManager(),
        ]);
        client.close();
        expect(built).toHaveLength(1);
        for (const manager of built) expect(manager.cancelPendingFlows).toHaveBeenCalledTimes(1);
        expect(a).toBe(b);
      } finally {
        client.close();
      }
    });

    it("two concurrent first calls share one CertManager", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);
      const load = client as never as { loadCertManager(): Promise<unknown> };

      try {
        const [first, second] = await Promise.all([load.loadCertManager(), load.loadCertManager()]);
        expect(first).toBe(second);
      } finally {
        client.close();
      }
    });

    it("a failed load does not stick — the next call retries", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);
      const build = vi
        .spyOn(
          client as never as { buildOAuthManager: () => Promise<unknown> },
          "buildOAuthManager",
        )
        .mockRejectedValueOnce(new Error("optional peer not installed"));
      const load = client as never as { loadOAuthManager(): Promise<unknown> };

      try {
        await expect(load.loadOAuthManager()).rejects.toThrow("optional peer not installed");
      } finally {
        build.mockRestore();
      }
      try {
        await expect(load.loadOAuthManager()).resolves.toBeDefined();
      } finally {
        client.close();
      }
    });

    // RED today: close() reads only oauthManagerInstance, which the build sets on
    // resolve — a close() during the load cancels nothing, and the flow started
    // afterwards pins the event loop for the whole callback timeout.
    it("close() during an in-flight peer load leaves no uncancelled manager", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);
      const internals = client as never as {
        buildOAuthManager(): Promise<unknown>;
        loadOAuthManager(): Promise<unknown>;
      };
      const manager = { cancelPendingFlows: vi.fn() };
      let release: (m: unknown) => void = () => {};
      vi.spyOn(internals, "buildOAuthManager").mockImplementation(
        () =>
          new Promise((resolve) => {
            release = resolve as (m: unknown) => void;
          }),
      );

      const pending = internals.loadOAuthManager();
      pending.catch(() => {});
      client.close();
      release(manager);

      await expect(pending).rejects.toMatchObject({
        code: ErrorCode.INVALID_INPUT,
        message: "DirectClient is closed",
      });
      expect(manager.cancelPendingFlows).toHaveBeenCalledTimes(1);
    });

    it("a load started after close() refuses before building", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);
      const internals = client as never as {
        buildOAuthManager(): Promise<unknown>;
        loadOAuthManager(): Promise<unknown>;
      };
      const build = vi.spyOn(internals, "buildOAuthManager");
      client.close();

      await expect(internals.loadOAuthManager()).rejects.toMatchObject({
        code: ErrorCode.INVALID_INPUT,
        message: "DirectClient is closed",
      });
      expect(build).not.toHaveBeenCalled();
    });

    // RED without loadCertManager's post-await check: the build resolves after
    // close() and hands the caller a manager on a client the embedder has
    // already shut down. No cancel to assert — CertManager holds no socket.
    it("close() during an in-flight CertManager load refuses the resolved manager", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);
      const internals = client as never as {
        buildCertManager(): Promise<unknown>;
        loadCertManager(): Promise<unknown>;
      };
      const manager = {};
      let release: (m: unknown) => void = () => {};
      vi.spyOn(internals, "buildCertManager").mockImplementation(
        () =>
          new Promise((resolve) => {
            release = resolve as (m: unknown) => void;
          }),
      );

      const pending = internals.loadCertManager();
      pending.catch(() => {});
      client.close();
      release(manager);

      await expect(pending).rejects.toMatchObject({
        code: ErrorCode.INVALID_INPUT,
        message: "DirectClient is closed",
      });
    });

    it("a CertManager load started after close() refuses before building", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);
      const internals = client as never as {
        buildCertManager(): Promise<unknown>;
        loadCertManager(): Promise<unknown>;
      };
      const build = vi.spyOn(internals, "buildCertManager");
      client.close();

      await expect(internals.loadCertManager()).rejects.toMatchObject({
        code: ErrorCode.INVALID_INPUT,
        message: "DirectClient is closed",
      });
      expect(build).not.toHaveBeenCalled();
    });

    // RED without the post-load re-check: the loader's own checks run before it
    // hands the manager back, so a close() landing after them — modelled here by
    // closing from inside the loader — must be seen by the method itself.
    describe("the three cert-manager calls re-check closed after the load", () => {
      it.each([
        [
          "importCertificate",
          (c: DirectClient) =>
            c.importCertificate("web", {
              private_key_pem: PLAIN_KEY_PEM,
              certificate_pem: LEAF_PEM,
            }),
        ],
        ["generateCsr", (c: DirectClient) => c.generateCsr("web", { subject: "web.example.com" })],
        ["renewCertificate", (c: DirectClient) => c.renewCertificate("secret://web")],
      ] as const)("%s refuses when the client closed during the load", async (name, call) => {
        const engine = createMockEngine();
        const client = new DirectClient(engine as never);
        const manager = createFakeCertManager();
        const internals = client as never as {
          loadCertManager(): Promise<unknown>;
        };
        vi.spyOn(internals, "loadCertManager").mockImplementation(async () => {
          client.close();
          return manager;
        });

        await expect(call(client)).rejects.toMatchObject({
          code: ErrorCode.INVALID_INPUT,
          message: "DirectClient is closed",
        });
        expect(manager[name]).not.toHaveBeenCalled();
      });
    });

    // Mock-free twin of the OAuth warm-client pin: an injected manager makes
    // the loader resolve without yielding, so a close() landing right after
    // the call is seen only by the method's own re-check (RED for import and
    // csr without it). renewCertificate awaits resolveSecretId first, so the
    // loader's own check refuses it there and this row pins the refusal only.
    describe("the three cert-manager calls racing close() on a warm client", () => {
      it.each([
        [
          "importCertificate",
          (c: DirectClient) =>
            c.importCertificate("web", {
              private_key_pem: PLAIN_KEY_PEM,
              certificate_pem: LEAF_PEM,
            }),
        ],
        ["generateCsr", (c: DirectClient) => c.generateCsr("web", { subject: "web.example.com" })],
        ["renewCertificate", (c: DirectClient) => c.renewCertificate("secret://web")],
      ] as const)("%s starts nothing on the injected manager", async (name, call) => {
        const engine = createMockEngine();
        const certManager = createFakeCertManager();
        const client = new DirectClient(engine as never, { certManager: certManager as never });

        const pending = call(client);
        pending.catch(() => {});
        client.close();

        await expect(pending).rejects.toMatchObject({
          code: ErrorCode.INVALID_INPUT,
          message: "DirectClient is closed",
        });
        expect(certManager[name]).not.toHaveBeenCalled();
      });
    });

    // RED without the `=== attempt` identity guard: the stale catch clears the
    // NEWER attempt, and the next caller builds a third manager close() never
    // reaches.
    it("a stale rejection does not clear a newer in-flight load", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);
      const internals = client as never as {
        buildOAuthManager(): Promise<unknown>;
        loadOAuthManager(): Promise<unknown>;
        oauthManagerLoad?: Promise<unknown>;
      };
      const secondManager = { cancelPendingFlows: vi.fn() };
      let release: (m: unknown) => void = () => {};
      const build = vi
        .spyOn(internals, "buildOAuthManager")
        .mockRejectedValueOnce(new Error("optional peer not installed"))
        .mockImplementationOnce(
          () =>
            new Promise((resolve) => {
              release = resolve as (m: unknown) => void;
            }),
        );

      try {
        const first = internals.loadOAuthManager();
        first.catch(() => {});
        const attempt = internals.oauthManagerLoad as Promise<unknown>;

        let newer: Promise<unknown> | undefined;
        attempt.catch(() => {
          newer = internals.loadOAuthManager();
          newer.catch(() => {});
        });

        const second = internals.loadOAuthManager();
        second.catch(() => {});

        await expect(first).rejects.toThrow("optional peer not installed");
        await expect(second).rejects.toThrow("optional peer not installed");

        const third = internals.loadOAuthManager();
        release(secondManager);

        expect(await third).toBe(secondManager);
        expect(await (newer as Promise<unknown>)).toBe(secondManager);
        expect(build).toHaveBeenCalledTimes(2);
      } finally {
        client.close();
      }
    });

    it("a stale CertManager rejection does not clear a newer in-flight load", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);
      const internals = client as never as {
        buildCertManager(): Promise<unknown>;
        loadCertManager(): Promise<unknown>;
        certManagerLoad?: Promise<unknown>;
      };
      const secondManager = {};
      let release: (m: unknown) => void = () => {};
      const build = vi
        .spyOn(internals, "buildCertManager")
        .mockRejectedValueOnce(new Error("optional peer not installed"))
        .mockImplementationOnce(
          () =>
            new Promise((resolve) => {
              release = resolve as (m: unknown) => void;
            }),
        );

      try {
        const first = internals.loadCertManager();
        first.catch(() => {});
        const attempt = internals.certManagerLoad as Promise<unknown>;

        let newer: Promise<unknown> | undefined;
        attempt.catch(() => {
          newer = internals.loadCertManager();
          newer.catch(() => {});
        });

        const second = internals.loadCertManager();
        second.catch(() => {});

        await expect(first).rejects.toThrow("optional peer not installed");
        await expect(second).rejects.toThrow("optional peer not installed");

        const third = internals.loadCertManager();
        release(secondManager);

        expect(await third).toBe(secondManager);
        expect(await (newer as Promise<unknown>)).toBe(secondManager);
        expect(build).toHaveBeenCalledTimes(2);
      } finally {
        client.close();
      }
    });
  });
});
