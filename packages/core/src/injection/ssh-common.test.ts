import { existsSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { describe, expect, it } from "vitest";
import { writeKnownHosts } from "./ssh-common.js";

describe("writeKnownHosts", () => {
  it("writes every pin on its own line, newline-terminated, and removes its directory on dispose", () => {
    const first = "[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfirst";
    const second = "deploy.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAsecond";
    const kh = writeKnownHosts([first, second]);
    try {
      expect(readFileSync(kh.file, "utf8")).toBe(`${first}\n${second}\n`);
    } finally {
      kh.dispose();
    }
    expect(existsSync(dirname(kh.file))).toBe(false);
  });
});
