import { existsSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { describe, expect, it } from "vitest";
import { sftpActionSchema, sshActionSchema } from "@harpoc/shared";
import { isSshName, sshHardeningArgs, writeKnownHosts } from "./ssh-common.js";

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

const VALID_SSH = {
  type: "ssh",
  host: "deploy.example.com",
  user: "deploy",
  command: "whoami",
} as const;

const VALID_SFTP = {
  type: "sftp",
  host: "deploy.example.com",
  user: "deploy",
  operation: "list",
  remote_path: "/srv/reports",
} as const;

const PARITY: ReadonlyArray<readonly [string, unknown, boolean]> = [
  ["a lowercase host name", "deploy.example.com", true],
  ["an uppercase name", "Deploy.EXAMPLE.com", true],
  ["a name with _", "build_host.example", true],
  ["a leading digit", "1host.example", true],
  ["an IPv4 literal", "127.0.0.1", true],
  ["a one-character name", "a", true],
  ["a 255-character name", "a".repeat(255), true],
  ["a 256-character name", "a".repeat(256), false],
  ["the empty string", "", false],
  ["a leading .", ".example", false],
  ["a leading _", "_host.example", false],
  ["a leading -", "-oProxyCommand=x", false],
  ["a trailing line feed", "ok.example\n", false],
  ["an @ ahead of a name", "evil.example@ok.example", false],
  ["an ssh:// URI carrying a port", "ssh://evil.example:2222", false],
  ["a :port suffix", "ok.example:2222", false],
  ["a space", "ok example", false],
  ["a %-token in a host", "x%h.example", false],
  ["an IPv6 literal with a zone id", "fe80::1%eth0", false],
  ["a name outside ASCII", "ünï.example", false],
  ["a /", "a/b.example", false],
  ["brackets", "[ok.example]", false],
  ["a #", "ok.example#x", false],
  ["a %-token in a user", "x%hy", false],
  ["an environment expansion", "a$" + "{HOME}b", false],
  ["a :", "u:x", false],
  ["an @", "a@b", false],
  ["a : that ends sftp's host part", "evil.example:sub", false],
  ["an sftp:// URI", "sftp://x@evil.example:2222/", false],
  ["an @ and brackets", "u@[evil.example]", false],
  ["a number", 123, false],
  ["a boolean", true, false],
  ["null", null, false],
  ["undefined", undefined, false],
  ["an array holding a name", ["ok.example"], false],
];

describe("isSshName — parity with sshHostSchema and sshUserSchema: the parsed interfaces see no change", () => {
  it("control: the base ssh and sftp actions parse", () => {
    expect(sshActionSchema.safeParse(VALID_SSH).success).toBe(true);
    expect(sftpActionSchema.safeParse(VALID_SFTP).success).toBe(true);
  });

  it.each(PARITY)("%s", (_label, value, admitted) => {
    const isName = isSshName(value as string);
    expect(isName, "ssh host").toBe(
      sshActionSchema.safeParse({ ...VALID_SSH, host: value }).success,
    );
    expect(isName, "ssh user").toBe(
      sshActionSchema.safeParse({ ...VALID_SSH, user: value }).success,
    );
    expect(isName, "sftp host").toBe(
      sftpActionSchema.safeParse({ ...VALID_SFTP, host: value }).success,
    );
    expect(isName, "sftp user").toBe(
      sftpActionSchema.safeParse({ ...VALID_SFTP, user: value }).success,
    );
    expect(isName, "admitted").toBe(admitted);
  });
});
