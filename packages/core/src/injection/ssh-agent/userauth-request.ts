import { SshReader } from "./ssh-wire.js";

/**
 * The data an SSH client asks its agent to sign during public-key user authentication
 * (RFC 4252 § 7): `string session identifier · byte SSH_MSG_USERAUTH_REQUEST · string user
 * name · string service name · string method · boolean TRUE · string public key algorithm
 * · string public key blob`, followed by `string server host key` for OpenSSH's
 * `publickey-hostbound-v00@openssh.com` method (OpenSSH ≥ 8.9 against a server that
 * offers it). Parsed as OpenSSH's own agent does (`ssh-agent.c` `parse_userauth_request`):
 * the service must be `ssh-connection` and the algorithm must name the key's type.
 */
const SSH_MSG_USERAUTH_REQUEST = 50;

const USERAUTH_PUBLICKEY = "publickey";
const USERAUTH_PUBLICKEY_HOSTBOUND = "publickey-hostbound-v00@openssh.com";

export type UserauthMethod = typeof USERAUTH_PUBLICKEY | typeof USERAUTH_PUBLICKEY_HOSTBOUND;

export interface UserauthRequest {
  sessionId: Buffer;
  user: string;
  service: string;
  method: UserauthMethod;
  algorithm: string;
  publicKeyBlob: Buffer;
  /** The server host key the hostbound method signs over; absent for `publickey`. */
  hostKeyBlob?: Buffer;
}

/**
 * Parse sign-request data as a userauth request; null for anything else — an empty
 * session identifier, another message number, a FALSE signature flag, another service,
 * another method, an algorithm that does not name the key's type, truncation or trailing
 * bytes. An SSHSIG blob (`ssh-keygen -Y sign`) is not one.
 */
export function parseUserauthRequest(data: Buffer): UserauthRequest | null {
  try {
    const r = new SshReader(data);
    const sessionId = r.readString();
    if (sessionId.length === 0) return null;
    if (r.readByte() !== SSH_MSG_USERAUTH_REQUEST) return null;
    const user = r.readCString();
    const service = r.readCString();
    const method = r.readCString();
    if (r.readByte() !== 1) return null;
    const algorithm = r.readCString();
    const publicKeyBlob = r.readString();
    if (service !== "ssh-connection" || !algorithmNamesKeyType(algorithm, publicKeyBlob)) {
      return null;
    }
    if (method === USERAUTH_PUBLICKEY) {
      if (r.remaining !== 0) return null;
      return { sessionId, user, service, method, algorithm, publicKeyBlob };
    }
    if (method === USERAUTH_PUBLICKEY_HOSTBOUND) {
      const hostKeyBlob = r.readString();
      if (r.remaining !== 0) return null;
      return { sessionId, user, service, method, algorithm, publicKeyBlob, hostKeyBlob };
    }
    return null;
  } catch {
    return null;
  }
}

function algorithmNamesKeyType(algorithm: string, publicKeyBlob: Buffer): boolean {
  const keyType = new SshReader(publicKeyBlob).readCString();
  if (keyType === "ssh-rsa") {
    return algorithm === "ssh-rsa" || algorithm === "rsa-sha2-256" || algorithm === "rsa-sha2-512";
  }
  return algorithm === keyType;
}
