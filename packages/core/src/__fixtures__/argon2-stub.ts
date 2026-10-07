import { createHash } from "node:crypto";
import type * as Argon2 from "../crypto/argon2.js";

/**
 * The engine suites' Argon2 stand-in: `deriveKey` becomes one SHA-256 over
 * password ‖ salt and every other export stays real. Production Argon2id
 * costs 2 GiB and 200–500 ms per derivation; the KDF itself is pinned by
 * `crypto/argon2.test.ts` (known answer) and `crypto/argon2.params.test.ts`.
 *
 *   vi.mock("./crypto/argon2.js", async (importOriginal) =>
 *     (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
 *   );
 */
export async function argon2Stub(importOriginal: () => Promise<unknown>): Promise<typeof Argon2> {
  const original = (await importOriginal()) as typeof Argon2;
  return {
    ...original,
    deriveKey: async (password: string, salt: Uint8Array): Promise<Uint8Array> =>
      new Uint8Array(createHash("sha256").update(password).update(salt).digest()),
  };
}
