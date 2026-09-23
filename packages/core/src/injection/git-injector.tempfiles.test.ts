import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { InjectionPolicy } from "@harpoc/shared";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { GitInjector } from "./git-injector.js";
import { spawnCaptured } from "./spawn-captured.js";
import { system32Path } from "../win32-paths.js";

vi.mock("./spawn-captured.js", () => ({ spawnCaptured: vi.fn() }));
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, writeFileSync: vi.fn(actual.writeFileSync) };
});

if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}

const GIT = resolveExecutable("git", controlledPathDirs());
const SSH = resolveExecutable("ssh", controlledPathDirs());
const describeGit = GIT ? describe : describe.skip;
const describeGitSsh = GIT && SSH ? describe : describe.skip;

function overrideTempEnv(dir: string): { TMPDIR?: string; TMP?: string; TEMP?: string } {
  const saved = { TMPDIR: process.env.TMPDIR, TMP: process.env.TMP, TEMP: process.env.TEMP };
  process.env.TMPDIR = dir;
  process.env.TMP = dir;
  process.env.TEMP = dir;
  return saved;
}

function restoreTempEnv(saved: { TMPDIR?: string; TMP?: string; TEMP?: string }): void {
  if (saved.TMPDIR === undefined) delete process.env.TMPDIR;
  else process.env.TMPDIR = saved.TMPDIR;
  if (saved.TMP === undefined) delete process.env.TMP;
  else process.env.TMP = saved.TMP;
  if (saved.TEMP === undefined) delete process.env.TEMP;
  else process.env.TEMP = saved.TEMP;
}

function ioError(code: string): NodeJS.ErrnoException {
  const err = new Error(`${code}: injected`) as NodeJS.ErrnoException;
  err.code = code;
  return err;
}

function policy(overrides: Partial<InjectionPolicy> = {}): InjectionPolicy {
  return {
    url_allowlist: [],
    command_allowlist: [],
    env_allowlist: [],
    host_allowlist: [],
    response_mode: "filtered",
    response_header_allowlist: [],
    network_isolation: false,
    fs_isolation: false,
    smtp_recipient_allowlist: [],
    imap_read_only: false,
    strict_tree_exit: false,
    ...overrides,
  };
}

function httpsPolicy(): InjectionPolicy {
  return policy({ command_allowlist: [GIT as string], url_allowlist: ["https://8.8.8.8/*"] });
}

let tempRoot: string;
let saved: { TMPDIR?: string; TMP?: string; TEMP?: string };

beforeEach(() => {
  tempRoot = mkdtempSync(join(tmpdir(), "harpoc-git-tempfiles-"));
  saved = overrideTempEnv(tempRoot);
  vi.mocked(spawnCaptured).mockReset();
});

afterEach(() => {
  restoreTempEnv(saved);
  vi.mocked(writeFileSync).mockReset();
  rmSync(tempRoot, { recursive: true, force: true });
});

describeGit("the askpass write fails (HTTPS)", () => {
  it("leaves no vault-authored directory behind and propagates the error", async () => {
    vi.mocked(writeFileSync).mockImplementationOnce((path) => {
      if (String(path).includes("askpass")) throw ioError("EACCES");
      throw new Error("unexpected first write");
    });
    const injector = new GitInjector(null);
    await expect(
      injector.executeWithSecret(
        { type: "git", operation: "clone", repository: "https://8.8.8.8/org/repo.git" },
        new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
        httpsPolicy(),
        undefined,
      ),
    ).rejects.toThrow("EACCES");
    expect(readdirSync(tempRoot)).toEqual([]);
    expect(spawnCaptured).not.toHaveBeenCalled();
  });
});

describeGitSsh("the known_hosts write fails (SSH)", () => {
  it("leaves no vault-authored directory behind and propagates the error", async () => {
    vi.mocked(writeFileSync).mockImplementationOnce((path) => {
      if (String(path).endsWith("known_hosts")) throw ioError("EACCES");
      throw new Error("unexpected first write");
    });
    const { privateKey: keyPem } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const injector = new GitInjector(null);
    await expect(
      injector.executeWithSecret(
        { type: "git", operation: "clone", repository: "git@github.com:org/repo.git" },
        new Uint8Array(Buffer.from(keyPem)),
        policy({ command_allowlist: [GIT as string], host_allowlist: ["github.com"] }),
        { ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] } },
      ),
    ).rejects.toThrow("EACCES");
    expect(readdirSync(tempRoot)).toEqual([]);
    expect(spawnCaptured).not.toHaveBeenCalled();
  });
});
