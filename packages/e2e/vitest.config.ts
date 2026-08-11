import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "e2e",
    // Containers are shared mutable state, and the real Argon2id runs the
    // RFC 9106 high-security profile (2 GiB per derivation) — never run these
    // files in parallel.
    fileParallelism: false,
    // Container bring-up, TLS handshakes and real key derivation are slow by
    // design.
    testTimeout: 120_000,
    hookTimeout: 180_000,
    // One run, one evidence file: emit() appends, the reset truncates.
    globalSetup: ["./src/evidence/reset.ts"],
    env: {
      // Keystore session wrapping off, as in every other package's suite: the
      // harness measures credential opacity, not the platform keystore.
      HARPOC_SESSION_KEYSTORE: "off",
    },
  },
});
