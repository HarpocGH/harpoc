import { existsSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { describe, expect, it } from "vitest";
import { sshHardeningArgs, writeKnownHosts } from "./ssh-common.js";

describe("sshHardeningArgs", () => {
  it("S9: trusts the pinned known_hosts alone — the host-wide global known_hosts is switched off", () => {
    const args = sshHardeningArgs(
      "/tmp/harpoc-ssh-x/known_hosts",
      "/tmp/harpoc-ssh-id-x/identity.pub",
    );
    const at = args.indexOf("GlobalKnownHostsFile=none");
    expect(at).toBeGreaterThan(0);
    expect(args[at - 1]).toBe("-o");
    expect(args).toContain('UserKnownHostsFile="/tmp/harpoc-ssh-x/known_hosts"');
    expect(args).toContain("StrictHostKeyChecking=yes");
  });
});

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
