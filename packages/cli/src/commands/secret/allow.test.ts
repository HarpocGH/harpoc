import { describe, expect, it } from "vitest";
import type { InjectionPolicy } from "@harpoc/shared";
import { mergePolicy } from "./allow.js";

const current: InjectionPolicy = {
  url_allowlist: ["https://api.github.com/*"],
  command_allowlist: ["gh"],
  env_allowlist: ["HOME"],
  host_allowlist: ["db.example.com:5432"],
  response_mode: "status_only",
  response_header_allowlist: ["Content-Type"],
};

describe("mergePolicy", () => {
  it("preserves omitted groups — a --url update cannot reset the response mode", () => {
    const merged = mergePolicy(current, { url: ["https://api.example.com/*"] });
    expect(merged.url_allowlist).toEqual(["https://api.example.com/*"]);
    expect(merged.command_allowlist).toEqual(["gh"]);
    expect(merged.env_allowlist).toEqual(["HOME"]);
    expect(merged.host_allowlist).toEqual(["db.example.com:5432"]);
    expect(merged.response_mode).toBe("status_only");
    expect(merged.response_header_allowlist).toEqual(["Content-Type"]);
  });

  it("replaces a provided group wholesale", () => {
    const merged = mergePolicy(current, { command: ["git"] });
    expect(merged.command_allowlist).toEqual(["git"]);
    expect(merged.url_allowlist).toEqual(["https://api.github.com/*"]);
  });

  it("sets the response mode without touching the allowlists", () => {
    const merged = mergePolicy(current, { responseMode: "filtered" });
    expect(merged.response_mode).toBe("filtered");
    expect(merged.command_allowlist).toEqual(["gh"]);
    expect(merged.response_header_allowlist).toEqual(["Content-Type"]);
  });

  it("replaces the response header allowlist when provided", () => {
    const merged = mergePolicy(current, { responseHeader: ["X-Request-Id"] });
    expect(merged.response_header_allowlist).toEqual(["X-Request-Id"]);
    expect(merged.response_mode).toBe("status_only");
  });

  it("--clear resets the policy before applying the other flags", () => {
    const merged = mergePolicy(current, { clear: true, url: ["https://only.example.com/*"] });
    expect(merged).toEqual({
      url_allowlist: ["https://only.example.com/*"],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [],
      response_mode: "filtered",
      response_header_allowlist: [],
    });
  });

  it("--clear alone yields the default policy", () => {
    const merged = mergePolicy(current, { clear: true });
    expect(merged.response_mode).toBe("filtered");
    expect(merged.url_allowlist).toEqual([]);
    expect(merged.response_header_allowlist).toEqual([]);
  });
});
