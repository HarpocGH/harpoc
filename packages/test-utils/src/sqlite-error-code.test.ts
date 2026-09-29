import { describe, expect, it } from "vitest";
import { sqliteErrorCode } from "./sqlite-error-code.js";

const coded = (code: unknown): Error => Object.assign(new Error("constraint failed"), { code });

describe("sqliteErrorCode", () => {
  it("returns the code of a thrown error that carries one", () => {
    expect(
      sqliteErrorCode(() => {
        throw coded("SQLITE_CONSTRAINT_NOTNULL");
      }),
    ).toBe("SQLITE_CONSTRAINT_NOTNULL");
  });

  it("returns undefined when the call succeeds", () => {
    expect(sqliteErrorCode(() => ({ changes: 1 }))).toBeUndefined();
  });

  it("returns undefined for a throw without a string code", () => {
    expect(
      sqliteErrorCode(() => {
        throw new Error("plain");
      }),
    ).toBeUndefined();
    expect(
      sqliteErrorCode(() => {
        throw coded(19);
      }),
    ).toBeUndefined();
  });

  it("invokes the function exactly once", () => {
    let calls = 0;
    sqliteErrorCode(() => {
      calls += 1;
      throw coded("SQLITE_CONSTRAINT_CHECK");
    });
    expect(calls).toBe(1);
  });
});
