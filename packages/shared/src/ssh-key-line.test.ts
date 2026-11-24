import { describe, expect, it } from "vitest";

import {
  MAX_SSH_KEY_LINE_CHARS,
  SSH_HOST_KEY_TYPES,
  SSH_INSTALL_KEY_TYPES,
  sshKeyLineType,
} from "./ssh-key-line.js";

const ED25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICn+7qKS67vacwftKjgcrwUlmC2TZ6j0dyFpyO5UDiVx";
const ECDSA_256 =
  "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCz9X9B5Ls3wqgwaWax6lXZilG0yR+qBdY+tYQpr1fpizTydsdzfyl0ESyVBtR6XYCQum8+x0NktMqPL7ISyqGU=";
const ECDSA_384 =
  "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBHMUmaoExpiRETXc3VVrlP2B5QERTZiJLMA+BK4ydD+oiHDrAGcVo51kAns8lQDe2TPYsO5O86k1TEZWzhErJLSZp15Akl3MKPsmvRPcaBeE3K82UepQMc3yh5EorUysfw==";
const ECDSA_521 =
  "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAHSVGsJeZAn6x1PBj0c4Pv6E57bBZ/Ph+n3eP2Ajeuxivr1iiS+eT5WnUh2i7ReNJbNfTAjD+OM0PcwwDcp24VM9QEctYRhYEY+UzaxAkAuWWV4tBc5MqTWqzVW7hMSvaYlZKd3mB9gJCIrKP0iQnJAYOckkwTscX3Xu2B56lCF7KtPdw==";
const RSA_3072 =
  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDiRlhkneupuv3jgo1YA59JtrC+7Q9ocZXT54nv4vvv+77sjQ4T/HHrNVmc0ia2WVSMzcUQiBdgrdSYHcUp4P1dlo0Y552j00fGAo1KeQX93kqrQCpIm3QnKeYE4LpWjkdBdKI0xDLiak2HfYfC63uqcz0tNIKO1nQdlETEGe7tSQyVV/2KrIf8fTfRCRzSEXVxb4wgiZmSp4dcBqYYAIYulxSnJQaJr/idz/Md+Adqsz0GQIuspKHhajbpDakIMx+pJYv9LeIyKVFsu0AJMvn+mcz5W5dQpjdd+ECnNj1Kt1+9afM5fXOwakSqPYkX3Z52c9V6Bi4yT4mXIKt5eMrPWkMivj6imynq8WCGWTgZeIH2rFCmfRTiJh4jd70gm7SHCw9As/XER4bcyawV8Wh13sHICyTFpIbtoSHkUFYMJ8fS59ALDICSjypVUL6qUKrhV1lkqfObz4hGJCXk1K2jiE+cuRaq7Bp5qfpmkKMx6KzrdbNeNcSMGV7h+EWTJ9U=";
const SK_ED25519 =
  "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIEINLyuDfy3/jy8/r3dZMETntyjcGo9rV7Bi3GNUlp60AAAABHNzaDo=";
const SK_ECDSA =
  "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBCz9X9B5Ls3wqgwaWax6lXZilG0yR+qBdY+tYQpr1fpizTydsdzfyl0ESyVBtR6XYCQum8+x0NktMqPL7ISyqGUAAAAEc3NoOg==";

const base64Of = (line: string): string => line.slice(line.indexOf(" ") + 1);

function sshString(bytes: Buffer): Buffer {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

/** A well-formed `ssh-rsa` line of exactly `chars` characters: the type, the exponent 65537 and a modulus that fills the rest. */
function rsaLineOfLength(chars: number): string {
  const head = Buffer.concat([
    sshString(Buffer.from("ssh-rsa")),
    sshString(Buffer.from([1, 0, 1])),
  ]);
  const modulus = Buffer.alloc(((chars - "ssh-rsa ".length) / 4) * 3 - head.length - 4, 0xa5);
  modulus[0] = 0;
  return `ssh-rsa ${Buffer.concat([head, sshString(modulus)]).toString("base64")}`;
}

describe("sshKeyLineType", () => {
  it.each([
    [ED25519, "ssh-ed25519", "ssh-ed25519"],
    [ECDSA_256, "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256"],
    [ECDSA_384, "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384"],
    [ECDSA_521, "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp521"],
    [RSA_3072, "ssh-rsa", "ssh-rsa"],
    [SK_ED25519, "sk-ssh-ed25519@openssh.com", null],
    [SK_ECDSA, "sk-ecdsa-sha2-nistp256@openssh.com", null],
  ] as const)(
    "admits each listed type's line, the host list without the sk types: %s",
    (line, installType, hostType) => {
      expect(sshKeyLineType(line, SSH_INSTALL_KEY_TYPES)).toBe(installType);
      expect(sshKeyLineType(line, SSH_HOST_KEY_TYPES)).toBe(hostType);
    },
  );

  it.each([
    ["a comment", `${ED25519} c`],
    ["two spaces", ED25519.replace(" ", "  ")],
    ["a tab", ED25519.replace(" ", "\t")],
    ["a final line feed", `${ED25519}\n`],
    ["a leading space", ` ${ED25519}`],
    ["an options prefix", `restrict ${ED25519}`],
    ["an ed25519 blob named ssh-rsa", `ssh-rsa ${base64Of(ED25519)}`],
    ["an rsa blob named ssh-ed25519", `ssh-ed25519 ${base64Of(RSA_3072)}`],
    ["the padding removed", ECDSA_256.replace(/qGU=$/, "qGU")],
    ["non-zero bits past the last byte", ECDSA_256.replace(/qGU=$/, "qGV=")],
    ["a certificate type", `ssh-ed25519-cert-v01@openssh.com ${base64Of(ED25519)}`],
    ["ssh-dss", `ssh-dss ${base64Of(ED25519)}`],
    ["a blob holding the type alone", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"],
    ["an empty base64", "ssh-ed25519 "],
    [
      "the base64url alphabet",
      `ssh-ed25519 ${base64Of(ED25519).replace(/\+/g, "-").replace(/\//g, "_")}`,
    ],
    ["a line longer than 4096 characters", `ssh-rsa ${"A".repeat(MAX_SSH_KEY_LINE_CHARS - 7)}`],
  ])("refuses every other spelling: %s", (_name, line) => {
    expect(sshKeyLineType(line, SSH_INSTALL_KEY_TYPES)).toBeNull();
  });

  it("the bound is 4096 characters: a well-formed ssh-rsa line of 4096 is admitted, one of 4100 refused", () => {
    const atBound = rsaLineOfLength(4096);
    const pastBound = rsaLineOfLength(4100);
    expect(atBound.length).toBe(4096);
    expect(pastBound.length).toBe(4100);
    expect(sshKeyLineType(atBound, SSH_HOST_KEY_TYPES)).toBe("ssh-rsa");
    expect(sshKeyLineType(pastBound, SSH_HOST_KEY_TYPES)).toBeNull();
  });
});
