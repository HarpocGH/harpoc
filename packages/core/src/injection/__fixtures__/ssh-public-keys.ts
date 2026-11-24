import type { SshBootstrapAction, SshBootstrapPolicy } from "@harpoc/shared";

/**
 * Seven public key lines made by `ssh-keygen` 10.0p2 for the ssh bootstrap's
 * rows (the two `sk-` blobs built by hand from a real point), with the SHA-256
 * fingerprint `ssh-keygen -l -E sha256` prints for each. Public halves only.
 */
export const HOST_KEY =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICn+7qKS67vacwftKjgcrwUlmC2TZ6j0dyFpyO5UDiVx";
export const KEY_A =
  "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCz9X9B5Ls3wqgwaWax6lXZilG0yR+qBdY+tYQpr1fpizTydsdzfyl0ESyVBtR6XYCQum8+x0NktMqPL7ISyqGU=";
export const KEY_ECDSA_384 =
  "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBHMUmaoExpiRETXc3VVrlP2B5QERTZiJLMA+BK4ydD+oiHDrAGcVo51kAns8lQDe2TPYsO5O86k1TEZWzhErJLSZp15Akl3MKPsmvRPcaBeE3K82UepQMc3yh5EorUysfw==";
export const KEY_ECDSA_521 =
  "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAHSVGsJeZAn6x1PBj0c4Pv6E57bBZ/Ph+n3eP2Ajeuxivr1iiS+eT5WnUh2i7ReNJbNfTAjD+OM0PcwwDcp24VM9QEctYRhYEY+UzaxAkAuWWV4tBc5MqTWqzVW7hMSvaYlZKd3mB9gJCIrKP0iQnJAYOckkwTscX3Xu2B56lCF7KtPdw==";
export const KEY_B =
  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDiRlhkneupuv3jgo1YA59JtrC+7Q9ocZXT54nv4vvv+77sjQ4T/HHrNVmc0ia2WVSMzcUQiBdgrdSYHcUp4P1dlo0Y552j00fGAo1KeQX93kqrQCpIm3QnKeYE4LpWjkdBdKI0xDLiak2HfYfC63uqcz0tNIKO1nQdlETEGe7tSQyVV/2KrIf8fTfRCRzSEXVxb4wgiZmSp4dcBqYYAIYulxSnJQaJr/idz/Md+Adqsz0GQIuspKHhajbpDakIMx+pJYv9LeIyKVFsu0AJMvn+mcz5W5dQpjdd+ECnNj1Kt1+9afM5fXOwakSqPYkX3Z52c9V6Bi4yT4mXIKt5eMrPWkMivj6imynq8WCGWTgZeIH2rFCmfRTiJh4jd70gm7SHCw9As/XER4bcyawV8Wh13sHICyTFpIbtoSHkUFYMJ8fS59ALDICSjypVUL6qUKrhV1lkqfObz4hGJCXk1K2jiE+cuRaq7Bp5qfpmkKMx6KzrdbNeNcSMGV7h+EWTJ9U=";
export const SK_KEY =
  "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIEINLyuDfy3/jy8/r3dZMETntyjcGo9rV7Bi3GNUlp60AAAABHNzaDo=";
export const SK_ECDSA_KEY =
  "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBCz9X9B5Ls3wqgwaWax6lXZilG0yR+qBdY+tYQpr1fpizTydsdzfyl0ESyVBtR6XYCQum8+x0NktMqPL7ISyqGUAAAAEc3NoOg==";

function sshString(bytes: Buffer): Buffer {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

/** A well-formed `ssh-rsa` line of exactly `chars` characters: the type, the exponent 65537 and a modulus that fills the rest. */
export function rsaLineOfLength(chars: number): string {
  const head = Buffer.concat([
    sshString(Buffer.from("ssh-rsa")),
    sshString(Buffer.from([1, 0, 1])),
  ]);
  const modulus = Buffer.alloc(((chars - "ssh-rsa ".length) / 4) * 3 - head.length - 4, 0xa5);
  modulus[0] = 0;
  return `ssh-rsa ${Buffer.concat([head, sshString(modulus)]).toString("base64")}`;
}

export const FP_HOST = "SHA256:dngXInM6F9ixKWjZmnsLT+7TH7k+7qKeHsHP6BtaKS8";
export const FP_A = "SHA256:q8YVFr5esdIRtsv6rByNXElSFad0IqkOijGT0O/PhDE";
export const FP_B = "SHA256:SX8ctW9qqWqHjIMiS8HZyhU9i3Zoky3H/LS59nbEspI";

/** A bootstrap block over these keys. */
export const BLOCK: SshBootstrapPolicy = {
  host: "h1.example",
  port: 22,
  user: "ubuntu",
  host_keys: [HOST_KEY],
  install_keys: [KEY_A, KEY_B],
  sudoers: true,
};

/** A bootstrap action within that block. */
export const BOOT: SshBootstrapAction = {
  type: "ssh",
  operation: "bootstrap",
  host: "h1.example",
  user: "ubuntu",
  public_key: KEY_A,
};

/** The `secret.use` row form of `BOOT`: context, operation, host, port, user, the key's fingerprint and the sudoers flag. */
export const B0: Readonly<Record<string, unknown>> = {
  context: "ssh",
  operation: "bootstrap",
  host: "h1.example",
  port: 22,
  user: "ubuntu",
  key_fingerprint: FP_A,
  sudoers: false,
};

export const SSH_PUBLIC_KEY_VECTORS: ReadonlyArray<{
  type: string;
  line: string;
  fingerprint: string;
}> = [
  { type: "ssh-ed25519", line: HOST_KEY, fingerprint: FP_HOST },
  { type: "ecdsa-sha2-nistp256", line: KEY_A, fingerprint: FP_A },
  {
    type: "ecdsa-sha2-nistp384",
    line: KEY_ECDSA_384,
    fingerprint: "SHA256:lp2HdVQliN6AxTXSP7UkWcTUfgE6wcFXSnyBMLZAF/E",
  },
  {
    type: "ecdsa-sha2-nistp521",
    line: KEY_ECDSA_521,
    fingerprint: "SHA256:8fUDTL6ACjm39cs6/x0TllrI2ZSKl6lLB0frQ4MRcdA",
  },
  { type: "ssh-rsa", line: KEY_B, fingerprint: FP_B },
  {
    type: "sk-ssh-ed25519@openssh.com",
    line: SK_KEY,
    fingerprint: "SHA256:eT8Dgo9s8NiVYvHjogf1VzPwtrczsCuFhQw7+i71X3w",
  },
  {
    type: "sk-ecdsa-sha2-nistp256@openssh.com",
    line: SK_ECDSA_KEY,
    fingerprint: "SHA256:NmkrZYvoigYefeiHjzW8UpuJD8tWb3fk0lY+dUrjJ8A",
  },
];
