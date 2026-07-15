import { VaultError } from "@harpoc/shared";
import { runKeystoreHelper } from "./keystore-helper.js";
import type { WrappingKeyStore } from "./wrapping-key-store.js";

const DEFAULT_SECURITY_PATH = "/usr/bin/security";
const DEFAULT_SERVICE = "harpoc.session-wrap.v1";
const DEFAULT_ACCOUNT = "harpoc";

/**
 * The service/account/keychain values are embedded in a `security -i` command
 * line (tokenized by security's own parser), so they are restricted to a safe
 * charset — no whitespace, no quotes. Defaults are constants; overrides are
 * test seams.
 */
const SAFE_TOKEN_PATTERN = /^[A-Za-z0-9._/-]+$/;

const WRAPPING_KEY_HEX_PATTERN = /\b[0-9a-f]{64}\b/;
const ITEM_NOT_FOUND_PATTERN = /could not be found/i;

export interface KeychainWrappingKeyStoreOptions {
  /** Path to the security binary (default: the OS-shipped /usr/bin/security). */
  executablePath?: string;
  /** Kill the helper and reject after this many milliseconds (default 15000). */
  timeoutMs?: number;
  /** Keychain item service name (default harpoc.session-wrap.v1; test seam). */
  service?: string;
  /** Keychain item account name (default harpoc; test seam). */
  account?: string;
  /** Explicit keychain path (default: the user's search list / login keychain; CI seam). */
  keychain?: string;
}

/**
 * macOS Keychain store for the session wrapping key (thesis §4.6). Bridges via
 * the OS-shipped `security` binary in interactive mode (`security -i`): the
 * full command — including the hex-encoded wrapping key on `add-generic-password
 * -w` — crosses on stdin, never argv, so key material is invisible to `ps`.
 * A locked keychain (headless SSH, `errSecInteractionNotAllowed`) throws and
 * takes the caller's existing fallback/fail-closed paths; the timeout guards a
 * hung UI unlock prompt.
 */
export class KeychainWrappingKeyStore implements WrappingKeyStore {
  readonly scheme = "keychain" as const;
  private readonly executablePath: string;
  private readonly timeoutMs: number | undefined;
  private readonly service: string;
  private readonly account: string;
  private readonly keychain: string | undefined;

  constructor(options: KeychainWrappingKeyStoreOptions = {}) {
    this.executablePath = options.executablePath ?? DEFAULT_SECURITY_PATH;
    this.timeoutMs = options.timeoutMs;
    this.service = options.service ?? DEFAULT_SERVICE;
    this.account = options.account ?? DEFAULT_ACCOUNT;
    this.keychain = options.keychain;
    for (const [name, value] of [
      ["service", this.service],
      ["account", this.account],
      ["keychain", this.keychain ?? "-"],
    ] as const) {
      if (!SAFE_TOKEN_PATTERN.test(value)) {
        throw VaultError.sessionFileError(`keychain ${name} contains unsupported characters`);
      }
    }
  }

  async loadWrappingKey(): Promise<Uint8Array | null> {
    const command =
      `find-generic-password -s ${this.service} -a ${this.account} -w` +
      (this.keychain ? ` ${this.keychain}` : "");
    const result = await this.run("Keychain read", command, false);

    const match = WRAPPING_KEY_HEX_PATTERN.exec(result.stdout);
    if (match) {
      return new Uint8Array(Buffer.from(match[0], "hex"));
    }
    if (ITEM_NOT_FOUND_PATTERN.test(result.stderr)) {
      return null;
    }
    const detail = result.stderr.replace(/\s+/g, " ").trim().slice(0, 200);
    throw VaultError.sessionFileError(
      `Keychain read failed (exit ${result.exitCode})${detail ? `: ${detail}` : ""}`,
    );
  }

  async storeWrappingKey(key: Uint8Array): Promise<void> {
    const hex = Buffer.from(key).toString("hex");
    const command =
      `add-generic-password -U -s ${this.service} -a ${this.account} -w ${hex}` +
      (this.keychain ? ` ${this.keychain}` : "");
    await this.run("Keychain write", command, true);
  }

  private run(
    label: string,
    command: string,
    expectZeroExit: boolean,
  ): ReturnType<typeof runKeystoreHelper> {
    const options: Parameters<typeof runKeystoreHelper>[3] = { label, expectZeroExit };
    if (this.timeoutMs !== undefined) {
      options.timeoutMs = this.timeoutMs;
    }
    return runKeystoreHelper(this.executablePath, ["-i"], `${command}\n`, options);
  }
}
