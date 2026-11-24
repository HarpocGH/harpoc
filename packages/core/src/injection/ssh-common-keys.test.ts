import {
  MAX_SSH_KEY_LINE_CHARS,
  SSH_INSTALL_KEY_TYPES,
  sshBootstrapPolicySchema,
} from "@harpoc/shared";
import { describe, expect, it } from "vitest";
import {
  HOST_KEY,
  KEY_A,
  KEY_B,
  rsaLineOfLength,
  SSH_PUBLIC_KEY_VECTORS,
} from "./__fixtures__/ssh-public-keys.js";
import type { SshPublicKey } from "./ssh-common-keys.js";
import { parseSshPublicKey, sameSshKey, sshKeyFingerprint } from "./ssh-common-keys.js";

const base64Of = (line: string): string => line.slice(line.indexOf(" ") + 1);

const REFUSED_LINES: Array<[string, string]> = [
  ["a comment", `${HOST_KEY} c`],
  ["two spaces", HOST_KEY.replace(" ", "  ")],
  ["a tab", HOST_KEY.replace(" ", "\t")],
  ["a final line feed", `${HOST_KEY}\n`],
  ["a leading space", ` ${HOST_KEY}`],
  ["an options prefix", `restrict ${HOST_KEY}`],
  ["an ed25519 blob named ssh-rsa", `ssh-rsa ${base64Of(HOST_KEY)}`],
  ["an rsa blob named ssh-ed25519", `ssh-ed25519 ${base64Of(KEY_B)}`],
  ["the padding removed", KEY_A.replace(/qGU=$/, "qGU")],
  ["non-zero bits past the last byte", KEY_A.replace(/qGU=$/, "qGV=")],
  ["a certificate type", `ssh-ed25519-cert-v01@openssh.com ${base64Of(HOST_KEY)}`],
  ["ssh-dss", `ssh-dss ${base64Of(HOST_KEY)}`],
  ["a blob holding the type alone", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"],
  ["an empty base64", "ssh-ed25519 "],
  [
    "the base64url alphabet",
    `ssh-ed25519 ${base64Of(HOST_KEY).replace(/\+/g, "-").replace(/\//g, "_")}`,
  ],
  ["a line longer than 4096 characters", `ssh-rsa ${"A".repeat(MAX_SSH_KEY_LINE_CHARS - 7)}`],
  ["a well-formed ssh-rsa line of 4100 characters", rsaLineOfLength(4100)],
];

const ADMITTED_LINES: Array<[string, string]> = [
  ...SSH_PUBLIC_KEY_VECTORS.map(({ type, line }): [string, string] => [type, line]),
  ["a well-formed ssh-rsa line of 4096 characters", rsaLineOfLength(4096)],
];

describe("ssh-common-keys", () => {
  it.each(SSH_PUBLIC_KEY_VECTORS.map(({ type, line, fingerprint }) => [type, line, fingerprint]))(
    "sshKeyFingerprint is ssh-keygen -l's for each accepted type: %s",
    (_type, line, fingerprint) => {
      const key = parseSshPublicKey(line, SSH_INSTALL_KEY_TYPES) as SshPublicKey;
      expect(sshKeyFingerprint(key.blob)).toBe(fingerprint);
    },
  );

  it.each([
    ...ADMITTED_LINES.map(([name, line]) => [name, line, true] as const),
    ...REFUSED_LINES.map(([name, line]) => [name, line, false] as const),
  ])(
    "parseSshPublicKey admits exactly the lines the stored schema admits: %s",
    (_name, line, admitted) => {
      const key = parseSshPublicKey(line, SSH_INSTALL_KEY_TYPES);
      const stored = sshBootstrapPolicySchema.shape.install_keys.safeParse([line]).success;
      expect(key !== null).toBe(admitted);
      expect(stored).toBe(admitted);
      if (key !== null) {
        expect(key.type).toBe(line.slice(0, line.indexOf(" ")));
        expect(key.blob.equals(Buffer.from(base64Of(line), "base64"))).toBe(true);
        expect(key.line).toBe(line);
      }
    },
  );

  it("sameSshKey compares type and bytes", () => {
    const ed25519 = parseSshPublicKey(HOST_KEY, SSH_INSTALL_KEY_TYPES) as SshPublicKey;
    const again = parseSshPublicKey(HOST_KEY, SSH_INSTALL_KEY_TYPES) as SshPublicKey;
    const a = parseSshPublicKey(KEY_A, SSH_INSTALL_KEY_TYPES) as SshPublicKey;
    const b = parseSshPublicKey(KEY_B, SSH_INSTALL_KEY_TYPES) as SshPublicKey;
    expect(sameSshKey(ed25519, again)).toBe(true);
    expect(sameSshKey(a, b)).toBe(false);
    expect(sameSshKey({ ...ed25519, type: "ssh-rsa" }, ed25519)).toBe(false);
  });
});
