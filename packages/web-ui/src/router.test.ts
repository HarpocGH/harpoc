import { beforeEach, describe, expect, it } from "vitest";
import { currentRoute, navigate } from "./router";

beforeEach(() => {
  history.replaceState(null, "", "/ui");
  window.location.hash = "";
});

describe("hash router", () => {
  it("reads the fragment as the route", () => {
    window.location.hash = "#/secrets";
    expect(currentRoute()).toBe("/secrets");
  });

  it("falls back to / for an empty fragment", () => {
    expect(currentRoute()).toBe("/");
  });

  it("falls back to / for a fragment that is not a route", () => {
    // `#token=…` is the launch fragment; it must never become a route.
    window.location.hash = "#token=abc";
    expect(currentRoute()).toBe("/");
  });

  it("keeps a percent-encoded handle segment intact", () => {
    window.location.hash = "#/secrets/myproj%2Ftest-key";
    expect(currentRoute()).toBe("/secrets/myproj%2Ftest-key");
  });

  it("navigate writes the fragment currentRoute reads back", () => {
    navigate("/audit");
    expect(window.location.hash).toBe("#/audit");
    expect(currentRoute()).toBe("/audit");
  });
});
