import { ErrorCode } from "@harpoc/shared";
import type { RenderEntry } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { describe, expect, it } from "vitest";
import { FP_HOST, HOST_KEY, KEY_A } from "./__fixtures__/ssh-public-keys.js";
import { renderEntryDetail, renderEntryDigest } from "./render-entry-digest.js";

/** M is the entry of shared's `render-entry.test.ts`, whose canonical bytes are pinned there; its name is not digested. */
const M: RenderEntry = {
  name: "m",
  host: "h",
  port: 22,
  user: "u",
  path: "/f",
  host_keys: [HOST_KEY],
  template: "",
};
const E1: RenderEntry = {
  name: "env",
  host: "h1.example",
  port: 22,
  user: "deploy",
  path: "/srv/app/.env",
  host_keys: [HOST_KEY],
  template: "TOKEN={{secret://bot-token}}\n",
};
const M_DIGEST = "96717df99b88991ff8131c11f46017b08e324765301ff8426199251f0d759ded";
const E1_DIGEST = "7c6a834469ef5a6c2a4b422775e89bf38a601de3f618e3615c684734ca914b66";
const TWO_KEYS_DIGEST = "4b1c13ad5122003ab7d60cd5fefc55f2364174c81fb334885d8bcb776ec8d981";

describe("renderEntryDigest", () => {
  it("renderEntryDigest is the SHA-256 of the canonical bytes", () => {
    expect(renderEntryDigest(M)).toBe(M_DIGEST);
    expect(renderEntryDigest(E1)).toBe(E1_DIGEST);
  });

  it.each<[string, Partial<RenderEntry>, string]>([
    [
      "host",
      { host: "h2.example" },
      "d3b7fed3d1ad460088631f27c57ab14271f8fff5e81bd12a580dcfc89c527af7",
    ],
    ["port", { port: 2222 }, "82ccb88c2fd441c47e21863af0a40ad41f51795126561d5af3dad3d3ea3f2aaf"],
    [
      "user",
      { user: "deploy2" },
      "2ade49fe2a58c81047e78fa135aeab37c0444c58b05398d6e8b4aa46408336e0",
    ],
    [
      "path",
      { path: "/srv/app/.env2" },
      "4d3c2466a7dc20a54e16d5e001e3c9aef5abd385ab4c5b7e61ea426d4649ec76",
    ],
    [
      "host_keys",
      { host_keys: [KEY_A] },
      "76981663d43bb2aebed48286e770c7efa1b1a11680d88b92fb0a197fe31022b4",
    ],
    [
      "template",
      { template: "TOKEN={{secret://bot-token}}\r\n" },
      "b00da41734a54e27574c5df91ec2941e40dc577c49800d5205e2dc93341820f7",
    ],
    ["name (not digested)", { name: "other" }, E1_DIGEST],
    ["host key order, one", { host_keys: [HOST_KEY, KEY_A] }, TWO_KEYS_DIGEST],
    ["host key order, the other", { host_keys: [KEY_A, HOST_KEY] }, TWO_KEYS_DIGEST],
  ])(
    "each digested part moves it, the name and the keys' order do not: %s",
    (_part, change, digest) => {
      expect(renderEntryDigest({ ...E1, ...change })).toBe(digest);
    },
  );
});

describe("renderEntryDetail", () => {
  it("renderEntryDetail is the row's view of the entry", () => {
    expect(renderEntryDetail(E1)).toEqual({
      name: "env",
      host: "h1.example",
      port: 22,
      user: "deploy",
      path: "/srv/app/.env",
      host_key_fingerprints: [FP_HOST],
      slots: ["secret://bot-token"],
      digest: E1_DIGEST,
    });
  });

  it("names each slot once, in its first occurrence's order", () => {
    expect(
      renderEntryDetail({ ...E1, template: "{{secret://b}}{{secret://ops/a}}{{secret://b}}" })
        .slots,
    ).toEqual(["secret://b", "secret://ops/a"]);
  });

  it("a stored host key line that does not parse is corruption", async () => {
    const err = await expectVaultError(
      () => renderEntryDetail({ ...E1, host_keys: ["ssh-ed25519 x"] }),
      ErrorCode.VAULT_CORRUPTED,
    );
    expect(err.message).toBe("Vault corrupted: a render host key line does not parse");
  });

  it("a stored template that does not parse is corruption", async () => {
    const err = await expectVaultError(
      () => renderEntryDetail({ ...E1, template: "TOKEN={{secret://bot-token" }),
      ErrorCode.VAULT_CORRUPTED,
    );
    expect(err.message).toBe("Vault corrupted: a render template does not parse");
  });
});
