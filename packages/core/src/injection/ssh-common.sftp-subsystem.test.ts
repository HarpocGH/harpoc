import { describe, expect, it } from "vitest";
import { sshHardeningArgs, sshSftpSubsystemArgs } from "./ssh-common.js";

const KNOWN_HOSTS = {
  file: "/t/harpoc-ssh-x/known_hosts",
  globalFile: "/t/harpoc-ssh-x/global_known_hosts",
};
const IDENTITY = "/t/harpoc-ssh-id-x/identity.pub";

describe("sshSftpSubsystemArgs", () => {
  it("the argv, letter for letter", () => {
    expect(sshSftpSubsystemArgs(KNOWN_HOSTS, IDENTITY, 15)).toEqual([
      "-F",
      "none",
      "-o",
      "StrictHostKeyChecking=yes",
      "-o",
      'UserKnownHostsFile="/t/harpoc-ssh-x/known_hosts"',
      "-o",
      'GlobalKnownHostsFile="/t/harpoc-ssh-x/global_known_hosts"',
      "-o",
      "IdentitiesOnly=yes",
      "-i",
      "/t/harpoc-ssh-id-x/identity.pub",
      "-o",
      "BatchMode=yes",
      "-o",
      "PasswordAuthentication=no",
      "-o",
      "ConnectTimeout=15",
      "-T",
      "-o",
      "LogLevel=ERROR",
      "-o",
      "RequestTTY=no",
      "-o",
      "EscapeChar=none",
      "-o",
      "ClearAllForwardings=yes",
      "-o",
      "ForwardAgent=no",
      "-o",
      "ForwardX11=no",
      "-o",
      "PermitLocalCommand=no",
    ]);
  });

  it("it shares its first 18 words with sshHardeningArgs", () => {
    const hardening = sshHardeningArgs(KNOWN_HOSTS, IDENTITY, 15);
    expect(hardening.length).toBe(18);
    expect(sshSftpSubsystemArgs(KNOWN_HOSTS, IDENTITY, 15).slice(0, 18)).toEqual(hardening);
  });

  it("no word of it is a password, a terminal or a forwarding switch on", () => {
    const argv = sshSftpSubsystemArgs(KNOWN_HOSTS, IDENTITY, 15);
    for (const word of [
      "PasswordAuthentication=yes",
      "RequestTTY=yes",
      "RequestTTY=force",
      "-t",
      "ForwardAgent=yes",
      "-A",
      "-X",
      "-Y",
    ]) {
      expect(argv.includes(word)).toBe(false);
    }
  });
});
