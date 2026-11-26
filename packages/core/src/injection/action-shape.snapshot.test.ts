import { describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { snapshotAction } from "./action-shape.js";

const PLAIN_DATA = "action must be plain data";

describe("snapshotAction", () => {
  it("an own getter is read once", () => {
    let reads = 0;
    const action = Object.defineProperty({}, "type", {
      enumerable: true,
      get: () => {
        reads += 1;
        return "http";
      },
    });

    const copy = snapshotAction(action);

    expect(reads).toBe(1);
    expect(Object.getOwnPropertyDescriptor(copy, "type")).toStrictEqual({
      value: "http",
      writable: true,
      enumerable: true,
      configurable: true,
    });
  });

  it.each<[string, () => unknown]>([
    ["a Proxy is refused", () => new Proxy({ type: "http" }, {})],
    [
      "a Proxy inside an array is refused",
      () => ({ type: "process", command: "id", args: [new Proxy({}, {})] }),
    ],
    ["a function as a value is refused", () => ({ type: "http", url: () => "https://a.example" })],
    [
      "a getter that throws is refused",
      () =>
        Object.defineProperty({}, "type", {
          enumerable: true,
          get: () => {
            throw new Error("raw-marker");
          },
        }),
    ],
  ])("%s", async (_title, make) => {
    const action = make();

    const err = await expectVaultError(() => snapshotAction(action), ErrorCode.INVALID_INPUT);

    expect(err.message).toBe(PLAIN_DATA);
  });

  it("an inherited type is not copied", () => {
    const copy = snapshotAction(Object.create({ type: "http" }));

    expect("type" in (copy as object)).toBe(false);
  });

  it("undefined stays", () => {
    const copy = snapshotAction({ type: "http", body: undefined });

    expect(Object.hasOwn(copy as object, "body")).toBe(true);
  });

  it("a 10 MiB body is copied", () => {
    const action = { type: "http", body: "x".repeat(10 * 1024 * 1024) };

    const copy = snapshotAction(action);

    expect(Object.is(copy, action)).toBe(false);
    expect(copy).toStrictEqual(action);
  });
});
