import { cleanup, render, screen } from "@testing-library/preact";
import { afterEach, describe, expect, it } from "vitest";
import { MetaTable } from "./meta-table";

afterEach(cleanup);

function cellFor(key: string): string {
  const row = screen.getByText(key).closest("tr");
  if (row === null) throw new Error(`no row for ${key}`);
  return row.querySelector("td")?.textContent ?? "";
}

describe("MetaTable", () => {
  it("renders one row per defined entry", () => {
    render(<MetaTable entries={{ handle: "secret://k", version: 3 }} />);
    expect(document.querySelectorAll("tbody tr").length).toBe(2);
    expect(cellFor("handle")).toBe("secret://k");
    expect(cellFor("version")).toBe("3");
  });

  it("drops undefined entries but keeps null and false", () => {
    render(<MetaTable entries={{ a: undefined, b: null, c: false }} />);
    expect(document.querySelectorAll("tbody tr").length).toBe(2);
    expect(cellFor("b")).toBe("null");
    expect(cellFor("c")).toBe("false");
  });

  it("serializes an object value rather than printing [object Object]", () => {
    render(<MetaTable entries={{ policy: { scopes: ["read"] } }} />);
    expect(cellFor("policy")).toBe('{"scopes":["read"]}');
  });

  it("shows the empty state when nothing survives the filter", () => {
    render(<MetaTable entries={{ a: undefined }} />);
    expect(screen.getByText("No data.")).toBeTruthy();
    expect(document.querySelector("table")).toBeNull();
  });
});
