import { describe, expect, it, vi } from "vitest";
import { hash } from "argon2";
import {
  ARGON2_HASH_LENGTH,
  ARGON2_MEMORY_COST,
  ARGON2_PARALLELISM,
  ARGON2_TIME_COST,
  ARGON2_VERSION,
} from "@harpoc/shared";
import { deriveKey } from "./argon2.js";

// Spy-wrap the real module: the derivation stays genuine, the call arguments
// become observable. constants.test.ts pins the numeric values; this pins that
// they (and the argon2id type) actually REACH hash() — an in-file downgrade to
// Argon2i or lower memory previously had no failing test.
vi.mock("argon2", { spy: true });

describe("deriveKey parameter forwarding", () => {
  it("passes exactly the pinned production parameters and argon2id to hash()", async () => {
    const salt = new Uint8Array(16).fill(1);
    await deriveKey("param-check", salt);

    expect(vi.mocked(hash)).toHaveBeenCalledWith(
      "param-check",
      expect.objectContaining({
        type: 2, // argon2id
        memoryCost: ARGON2_MEMORY_COST,
        timeCost: ARGON2_TIME_COST,
        parallelism: ARGON2_PARALLELISM,
        hashLength: ARGON2_HASH_LENGTH,
        version: ARGON2_VERSION,
        raw: true,
      }),
    );
  });
});
