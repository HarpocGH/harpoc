import { beforeEach, describe, expect, it } from "vitest";
import { adoptLaunchToken, clearToken, getToken, setToken } from "./token-store";

beforeEach(() => {
  window.sessionStorage.clear();
  history.replaceState(null, "", "/ui");
});

describe("token store", () => {
  it("adopts #token=… into sessionStorage and scrubs the fragment", () => {
    history.replaceState(null, "", "/ui#token=abc.def.ghi");
    adoptLaunchToken();
    expect(getToken()).toBe("abc.def.ghi");
    expect(window.location.hash).toBe("");
  });

  it("leaves storage untouched without a token fragment", () => {
    history.replaceState(null, "", "/ui#/secrets");
    adoptLaunchToken();
    expect(getToken()).toBeNull();
    expect(window.location.hash).toBe("#/secrets");
  });

  it("ignores an empty token fragment", () => {
    history.replaceState(null, "", "/ui#token=");
    adoptLaunchToken();
    expect(getToken()).toBeNull();
  });

  it("keeps the path and query when scrubbing the fragment", () => {
    history.replaceState(null, "", "/ui?theme=dark#token=jwt-1");
    adoptLaunchToken();
    expect(window.location.pathname).toBe("/ui");
    expect(window.location.search).toBe("?theme=dark");
    expect(window.location.hash).toBe("");
  });

  it("set/clear round-trip", () => {
    setToken("t1");
    expect(getToken()).toBe("t1");
    clearToken();
    expect(getToken()).toBeNull();
  });
});
