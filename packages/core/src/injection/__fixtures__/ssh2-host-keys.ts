import ssh2 from "ssh2";

const { utils } = ssh2;

export interface Ssh2KeyPair {
  private: string;
  public: string;
}

const ATTEMPTS = 16;

// ssh2 1.17.0 drops a leading zero byte of an ed25519 public key: one generated pair in 256 cannot be parsed back.
export function generateEd25519HostKeys(
  generate: () => Ssh2KeyPair = () => utils.generateKeyPairSync("ed25519"),
): Ssh2KeyPair {
  for (let attempt = 0; attempt < ATTEMPTS; attempt++) {
    const pair = generate();
    if (!(utils.parseKey(pair.private) instanceof Error)) return pair;
  }
  throw new Error(
    `ssh2 generated no ed25519 key pair it can parse back in ${String(ATTEMPTS)} attempts`,
  );
}
