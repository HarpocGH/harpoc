import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { listWindowsAcl, parseWindowsAcl } from "./owner-only.js";

// restrictWindowsAclToOwner is pinned through its first caller, the session file's ACL step
// (session-manager.permissions.test.ts — the argv, shell:false, the failure report, the real path).

describe("parseWindowsAcl", () => {
  it("reads the user, the owner and every rule by SID, a deny rule as allow: false", () => {
    const text = [
      "user S-1-5-21-1000-2000-3000-1001",
      "owner S-1-5-32-544",
      "rule 1 S-1-1-0",
      "rule 0 S-1-5-18",
      "rule 0 S-1-5-21-1000-2000-3000-1001",
      "",
    ].join("\r\n");
    expect(parseWindowsAcl(text)).toEqual({
      user: "S-1-5-21-1000-2000-3000-1001",
      owner: "S-1-5-32-544",
      rules: [
        { allow: false, sid: "S-1-1-0" },
        { allow: true, sid: "S-1-5-18" },
        { allow: true, sid: "S-1-5-21-1000-2000-3000-1001" },
      ],
    });
  });

  it.each([
    ["a localized name in place of a SID", "user S-1-5-18\nowner S-1-5-18\nrule 0 Everyone\n"],
    ["an unknown rule type", "user S-1-5-18\nowner S-1-5-18\nrule 2 S-1-1-0\n"],
    ["a stray line", "user S-1-5-18\nowner S-1-5-18\nWARNING: something\n"],
    ["no owner line", "user S-1-5-18\nrule 0 S-1-5-18\n"],
    ["nothing at all", ""],
  ])("throws on %s — never a partial list", (_, text) => {
    expect(() => parseWindowsAcl(text)).toThrow(/^ACL listing: (unexpected|incomplete) output$/);
  });
});

describe.runIf(process.platform === "win32")("listWindowsAcl on win32", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "harpoc-owner-only-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("lists a temporary file's inherited SYSTEM, Administrators and user rules, under a non-ASCII directory name", async () => {
    const nested = join(dir, "schlüssel");
    mkdirSync(nested);
    const path = join(nested, "unlock.key");
    writeFileSync(path, "not a key");
    const acl = await listWindowsAcl(path);
    expect(acl.user).toMatch(/^S-1-5-/);
    expect(acl.rules.filter((rule) => rule.allow).map((rule) => rule.sid)).toEqual(
      expect.arrayContaining(["S-1-5-18", "S-1-5-32-544", acl.user]),
    );
  });
});
