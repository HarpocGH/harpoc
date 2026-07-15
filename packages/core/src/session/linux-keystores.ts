import { existsSync } from "node:fs";
import { VaultError } from "@harpoc/shared";
import { runKeystoreHelper } from "./keystore-helper.js";
import type { KeystoreHelperResult } from "./keystore-helper.js";
import type { WrappingKeyStore } from "./wrapping-key-store.js";

/**
 * Fixed candidate directories — never PATH (the DPAPI pinned-path doctrine).
 * Distro-standard locations for keyutils and libsecret tools; /bin covers
 * pre-usr-merge layouts.
 */
const LINUX_KEYSTORE_BIN_DIRS = ["/usr/bin", "/bin"];

const DEFAULT_SERVICE = "harpoc.session-wrap.v1";
const DEFAULT_ACCOUNT = "harpoc";
const DEFAULT_LABEL = "Harpoc session wrapping key";
const DEFAULT_KEY_DESCRIPTION = "harpoc:session-wrap:v1";
const DEFAULT_KEYRING = "@u";

const WRAPPING_KEY_HEX_PATTERN = /\b[0-9a-f]{64}\b/;
const KEY_ID_PATTERN = /^\d+$/;
const KEYCTL_MISS_PATTERN = /required key not available/i;

/**
 * Resolve a Linux keystore bridge binary from the fixed candidate list.
 * Returns null when absent — unlike `security`/`powershell.exe` these are not
 * OS-guaranteed, and absence simply disables the tier at selection time.
 */
export function findLinuxKeystoreBinary(
  name: string,
  probe: (path: string) => boolean = existsSync,
): string | null {
  for (const dir of LINUX_KEYSTORE_BIN_DIRS) {
    const candidate = `${dir}/${name}`;
    if (probe(candidate)) return candidate;
  }
  return null;
}

function failure(label: string, result: KeystoreHelperResult): VaultError {
  const detail = result.stderr.replace(/\s+/g, " ").trim().slice(0, 200);
  return VaultError.sessionFileError(
    `${label} failed (exit ${result.exitCode})${detail ? `: ${detail}` : ""}`,
  );
}

export interface SecretServiceWrappingKeyStoreOptions {
  /** Path to the secret-tool binary (default: resolved from /usr/bin, /bin). */
  executablePath?: string;
  /** Kill the helper and reject after this many milliseconds (default 15000). */
  timeoutMs?: number;
  /** Secret Service item `service` attribute (default harpoc.session-wrap.v1; test seam). */
  service?: string;
  /** Secret Service item `account` attribute (default harpoc; test seam). */
  account?: string;
  /** Human-readable item label. */
  label?: string;
}

/**
 * Secret Service (libsecret) store for the session wrapping key — the D-Bus
 * desktop tier on Linux. Bridges via `secret-tool`; the hex wrapping key
 * crosses on stdin (store) / stdout (lookup), never argv. A locked or absent
 * keyring throws and takes the caller's fallback/fail-closed paths.
 */
export class SecretServiceWrappingKeyStore implements WrappingKeyStore {
  readonly scheme = "secret-service" as const;
  private readonly executablePath: string;
  private readonly timeoutMs: number | undefined;
  private readonly service: string;
  private readonly account: string;
  private readonly label: string;

  constructor(options: SecretServiceWrappingKeyStoreOptions = {}) {
    this.executablePath =
      options.executablePath ?? findLinuxKeystoreBinary("secret-tool") ?? "/usr/bin/secret-tool";
    this.timeoutMs = options.timeoutMs;
    this.service = options.service ?? DEFAULT_SERVICE;
    this.account = options.account ?? DEFAULT_ACCOUNT;
    this.label = options.label ?? DEFAULT_LABEL;
  }

  async loadWrappingKey(): Promise<Uint8Array | null> {
    const result = await this.run(
      "Secret Service read",
      ["lookup", "service", this.service, "account", this.account],
      "",
      false,
    );
    const match = WRAPPING_KEY_HEX_PATTERN.exec(result.stdout);
    if (match) {
      return new Uint8Array(Buffer.from(match[0], "hex"));
    }
    // secret-tool lookup signals a clean miss with a non-zero exit and no
    // diagnostics; anything on stderr is an operational failure (no D-Bus,
    // locked keyring) and must not be mistaken for "no item yet".
    if (result.exitCode !== 0 && result.stderr.trim() === "") {
      return null;
    }
    throw failure("Secret Service read", result);
  }

  async storeWrappingKey(key: Uint8Array): Promise<void> {
    await this.run(
      "Secret Service write",
      ["store", `--label=${this.label}`, "service", this.service, "account", this.account],
      Buffer.from(key).toString("hex"),
      true,
    );
  }

  private run(
    label: string,
    args: string[],
    stdinPayload: string,
    expectZeroExit: boolean,
  ): Promise<KeystoreHelperResult> {
    const options: Parameters<typeof runKeystoreHelper>[3] = { label, expectZeroExit };
    if (this.timeoutMs !== undefined) {
      options.timeoutMs = this.timeoutMs;
    }
    return runKeystoreHelper(this.executablePath, args, stdinPayload, options);
  }
}

export interface KeyringWrappingKeyStoreOptions {
  /** Path to the keyctl binary (default: resolved from /usr/bin, /bin). */
  executablePath?: string;
  /** Kill the helper and reject after this many milliseconds (default 15000). */
  timeoutMs?: number;
  /** Key description (default harpoc:session-wrap:v1; test seam). */
  description?: string;
  /** Target keyring (default @u — the per-UID user keyring). */
  keyring?: string;
}

/**
 * Kernel keyring store for the session wrapping key — the headless tier on
 * Linux. Bridges via `keyctl` against the `@u` user keyring; the hex wrapping
 * key crosses on stdin (`padd`) / stdout (`pipe`), never argv. Keys die at
 * reboot (and may be garbage-collected when the user's last session ends) —
 * the wrapped session file then fails closed and a fresh unlock re-creates
 * everything, acceptable under the 24 h absolute session ceiling.
 */
export class KeyringWrappingKeyStore implements WrappingKeyStore {
  readonly scheme = "keyring" as const;
  private readonly executablePath: string;
  private readonly timeoutMs: number | undefined;
  private readonly description: string;
  private readonly keyring: string;

  constructor(options: KeyringWrappingKeyStoreOptions = {}) {
    this.executablePath =
      options.executablePath ?? findLinuxKeystoreBinary("keyctl") ?? "/usr/bin/keyctl";
    this.timeoutMs = options.timeoutMs;
    this.description = options.description ?? DEFAULT_KEY_DESCRIPTION;
    this.keyring = options.keyring ?? DEFAULT_KEYRING;
  }

  async loadWrappingKey(): Promise<Uint8Array | null> {
    const search = await this.run(
      "Kernel keyring search",
      ["search", this.keyring, "user", this.description],
      "",
      false,
    );
    if (search.exitCode !== 0) {
      if (KEYCTL_MISS_PATTERN.test(search.stderr)) {
        return null;
      }
      throw failure("Kernel keyring search", search);
    }
    const keyId = search.stdout.trim();
    if (!KEY_ID_PATTERN.test(keyId)) {
      throw VaultError.sessionFileError("Kernel keyring search returned malformed output");
    }

    const pipe = await this.run("Kernel keyring read", ["pipe", keyId], "", true);
    const match = WRAPPING_KEY_HEX_PATTERN.exec(pipe.stdout);
    if (!match) {
      throw VaultError.sessionFileError("Kernel keyring read returned malformed output");
    }
    return new Uint8Array(Buffer.from(match[0], "hex"));
  }

  async storeWrappingKey(key: Uint8Array): Promise<void> {
    await this.run(
      "Kernel keyring write",
      ["padd", "user", this.description, this.keyring],
      Buffer.from(key).toString("hex"),
      true,
    );
  }

  private run(
    label: string,
    args: string[],
    stdinPayload: string,
    expectZeroExit: boolean,
  ): Promise<KeystoreHelperResult> {
    const options: Parameters<typeof runKeystoreHelper>[3] = { label, expectZeroExit };
    if (this.timeoutMs !== undefined) {
      options.timeoutMs = this.timeoutMs;
    }
    return runKeystoreHelper(this.executablePath, args, stdinPayload, options);
  }
}
