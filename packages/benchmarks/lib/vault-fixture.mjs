// Throwaway vault fixture. Resolves @harpoc/core as an ordinary workspace
// dependency, so run `pnpm install && pnpm build` first — the package exports
// its built dist.

import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

export {
  VaultEngine,
  SessionManager,
  DpapiSessionKeyProtector,
  NoneSessionKeyProtector,
  wipeBuffer,
} from "@harpoc/core";

import { VaultEngine, NoneSessionKeyProtector } from "@harpoc/core";

/**
 * Create an initialized, unlocked vault in a fresh temp directory.
 * Default protector is `none` so keystore cost cannot pollute unrelated
 * scenarios; session-load passes explicit protectors per variant.
 */
export async function createVault({ protector } = {}) {
  const dir = await mkdtemp(join(tmpdir(), "harpoc-bench-"));
  const sessionPath = join(dir, "session.json");
  const engine = new VaultEngine({
    dbPath: join(dir, "default.vault.db"),
    sessionPath,
    sessionKeyProtector: protector ?? new NoneSessionKeyProtector(),
  });
  const password = `bench-${randomBytes(12).toString("base64url")}`;
  await engine.initVault(password);

  return {
    dir,
    engine,
    password,
    sessionPath,
    async cleanup() {
      try {
        await engine.lock();
      } catch {
        // already locked — fine
      }
      await engine.destroy(); // closes the SQLite handle — rm fails with EBUSY otherwise
      try {
        await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
      } catch (err) {
        // A Windows handle race can survive the retries; a leftover OS-temp dir
        // must not fail a completed benchmark run.
        console.error(`warning: could not remove ${dir}: ${err?.message ?? err}`);
      }
    },
  };
}

/** Create one dummy secret; returns its `secret://` handle. */
export async function createBenchSecret(engine, name, value) {
  const res = await engine.createSecret({ name, type: "api_key", value });
  return typeof res?.handle === "string" ? res.handle : `secret://${name}`;
}
