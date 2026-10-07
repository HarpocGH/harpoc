import { describe, expect, it } from "vitest";
import { CappedOutput } from "./capped-output.js";

describe("CappedOutput", () => {
  it("keeps output under the cap verbatim and unflagged", () => {
    const out = new CappedOutput(8);
    out.push(Buffer.from("abc"));
    out.push(Buffer.from("def"));
    expect(out.toString()).toBe("abcdef");
    expect(out.truncated).toBe(false);
  });

  it("keeps a chunk that lands exactly on the cap, unflagged", () => {
    const out = new CappedOutput(6);
    out.push(Buffer.from("abcdef"));
    expect(out.toString()).toBe("abcdef");
    expect(out.truncated).toBe(false);
  });

  it("cuts a chunk that straddles the cap at the cap and flags it", () => {
    const out = new CappedOutput(8);
    out.push(Buffer.from("abcde"));
    out.push(Buffer.from("fghij"));
    expect(out.toString()).toBe("abcdefgh");
    expect(out.truncated).toBe(true);
  });

  it("drops every chunk once full and flags it", () => {
    const out = new CappedOutput(4);
    out.push(Buffer.from("abcd"));
    out.push(Buffer.from("efgh"));
    expect(out.toString()).toBe("abcd");
    expect(out.truncated).toBe(true);
  });
});
