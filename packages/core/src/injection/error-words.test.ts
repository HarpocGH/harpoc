import { describe, expect, it } from "vitest";
import { renderVaultText, vaultText } from "@harpoc/shared";
import {
  LOCAL_ERROR_CODES,
  PLATFORM_WORDS,
  REMOTE_ERROR_CODES,
  SIGNAL_WORDS,
  errnoToken,
} from "./error-words.js";

describe("the error words", () => {
  it("the lists hold what node names", () => {
    for (const code of ["ENOENT", "EACCES", "EADDRINUSE", "ENOTFOUND", "EAI_AGAIN", "UNKNOWN"]) {
      expect(LOCAL_ERROR_CODES.has(code), code).toBe(true);
    }
    expect(REMOTE_ERROR_CODES.has("UND_ERR_SOCKET")).toBe(true);
    expect(REMOTE_ERROR_CODES.has("CERT_HAS_EXPIRED")).toBe(true);
    expect([...REMOTE_ERROR_CODES].filter((code) => code.startsWith("ERR_SSL_"))).toEqual([]);
    expect(renderVaultText(vaultText`${errnoToken("ERR_SSL_WRONG_VERSION_NUMBER")}`)).toBe(
      "unknown error",
    );
    expect(PLATFORM_WORDS.includes(process.platform)).toBe(true);
  });

  it("an errno code the list holds is a token, and the other word stands for the rest", () => {
    expect(errnoToken("EADDRINUSE")).toMatchObject({ kind: "token", text: "EADDRINUSE" });
    expect(errnoToken(98)).toMatchObject({ kind: "words", text: "unknown error" });
    expect(errnoToken("not a code", "no code")).toMatchObject({ kind: "words", text: "no code" });
  });

  it("the signal words are the signals os names", () => {
    expect(SIGNAL_WORDS.has("SIGTERM")).toBe(true);
    expect(SIGNAL_WORDS.has("SIGNOPE")).toBe(false);
  });
});
