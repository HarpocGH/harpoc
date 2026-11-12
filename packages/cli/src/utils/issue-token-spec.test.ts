import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, parse, sep } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import {
  assertIssueTokenFile,
  parseIssueTokenSpec,
  parseIssueTokenSpecs,
} from "./issue-token-spec.js";
import { expectVaultError } from "@harpoc/test-utils";

/** `icacls.exe` on a directory this file created, through no shell, under a deadline. */
function icacls(path: string, ...args: string[]): void {
  const res = spawnSync(
    `${process.env.SystemRoot as string}\\System32\\icacls.exe`,
    [path, ...args],
    {
      shell: false,
      windowsHide: true,
      timeout: 15_000,
      encoding: "utf8",
    },
  );
  if (res.status !== 0) {
    expect.fail(
      `icacls ${[path, ...args].join(" ")} exited ${String(res.status)}${res.error === undefined ? "" : ` (${res.error.message})`}: ${res.stderr}`,
    );
  }
}

const FILE = "/run/harpoc/alice/token.jwt";
const REQUIRED = "(agent, file, scope and secrets are required)";
const PERMISSIONS = "(list, read, use, create, rotate, revoke, admin)";
const PATTERN = "(letters, digits, _, - and the * wildcard)";

describe("parseIssueTokenSpec", () => {
  it("parses the four required keys; ttl defaults to the 24 h cap, 1440 minutes", () => {
    expect(parseIssueTokenSpec(`agent=alice,file=${FILE},scope=use,secrets=db-*`)).toEqual({
      agent: "alice",
      file: FILE,
      scope: ["use"],
      secrets: ["db-*"],
      ttlMinutes: 1440,
    });
  });

  it("splits scope and secrets on +, in order, and takes the keys in any order", () => {
    expect(
      parseIssueTokenSpec(
        "ttl=60,secrets=db-*+api-key,scope=use+read,file=/run/harpoc/bob/token.jwt,agent=bob",
      ),
    ).toEqual({
      agent: "bob",
      file: "/run/harpoc/bob/token.jwt",
      scope: ["use", "read"],
      secrets: ["db-*", "api-key"],
      ttlMinutes: 60,
    });
  });

  it("admits every permission the engine knows", () => {
    const spec = parseIssueTokenSpec(
      `agent=alice,file=${FILE},scope=list+read+use+create+rotate+revoke+admin,secrets=*`,
    );
    expect(spec.scope).toEqual(["list", "read", "use", "create", "rotate", "revoke", "admin"]);
  });

  it("keeps a file path whole: only the first = splits a part, and + is no separator there", () => {
    const spec = parseIssueTokenSpec(
      "agent=alice,file=/run/harpoc/a=b+c/token.jwt,scope=use,secrets=db-*",
    );
    expect(spec.file).toBe("/run/harpoc/a=b+c/token.jwt");
  });

  it("accepts ttl 1440, the cap, and refuses 1441 — never clamped", async () => {
    const base = `agent=alice,file=${FILE},scope=use,secrets=db-*`;
    expect(parseIssueTokenSpec(`${base},ttl=1440`).ttlMinutes).toBe(1440);
    const err = await expectVaultError(
      () => parseIssueTokenSpec(`${base},ttl=1441`),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe("--issue-token: ttl exceeds the 24 h token cap (1440)");
  });

  it.each(["0", "-5", "1.5", "1e3", "0x10", " 60", "60m"])(
    "refuses ttl=%j: a whole number of minutes, decimal digits only",
    async (ttl) => {
      const err = await expectVaultError(
        () => parseIssueTokenSpec(`agent=alice,file=${FILE},scope=use,secrets=db-*,ttl=${ttl}`),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe("--issue-token: ttl must be a whole number of minutes (1-1440)");
    },
  );

  it.each([
    { label: "an empty spec", spec: "", message: '"" is not key=value' },
    {
      label: "a part without =",
      spec: `agent=alice,file=${FILE},scope=use,secrets=db-*,ttl`,
      message: '"ttl" is not key=value',
    },
    {
      label: "auth token's comma list (the spec's own separator)",
      spec: `agent=alice,file=${FILE},scope=use,read,secrets=db-*`,
      message: '"read" is not key=value',
    },
    {
      label: "a file path holding a comma (it cannot be named)",
      spec: "agent=alice,file=/run/harpoc/a,b/token.jwt,scope=use,secrets=db-*",
      message: '"b/token.jwt" is not key=value',
    },
    {
      label: "an unknown key",
      spec: `agent=alice,file=${FILE},scope=use,secrets=db-*,project=p`,
      message: 'unknown key "project" (agent, file, scope, secrets, ttl)',
    },
    {
      label: "a key in another case",
      spec: `Agent=alice,file=${FILE},scope=use,secrets=db-*`,
      message: 'unknown key "Agent" (agent, file, scope, secrets, ttl)',
    },
    {
      label: "a space after the comma (nothing is trimmed)",
      spec: `agent=alice, file=${FILE},scope=use,secrets=db-*`,
      message: 'unknown key " file" (agent, file, scope, secrets, ttl)',
    },
    {
      label: "a repeated key",
      spec: `agent=alice,agent=bob,file=${FILE},scope=use,secrets=db-*`,
      message: "agent given twice",
    },
    {
      label: "an empty value",
      spec: `agent=alice,file=${FILE},scope=,secrets=db-*`,
      message: "scope is empty",
    },
    {
      label: "a missing agent",
      spec: `file=${FILE},scope=use,secrets=db-*`,
      message: `agent is missing ${REQUIRED}`,
    },
    {
      label: "a missing file",
      spec: "agent=alice,scope=use,secrets=db-*",
      message: `file is missing ${REQUIRED}`,
    },
    {
      label: "a missing scope",
      spec: `agent=alice,file=${FILE},secrets=db-*`,
      message: `scope is missing ${REQUIRED}`,
    },
    {
      label: "a missing secrets",
      spec: `agent=alice,file=${FILE},scope=use`,
      message: `secrets is missing ${REQUIRED}`,
    },
    {
      label: "an agent that is not an agent name",
      spec: `agent=al ice,file=${FILE},scope=use,secrets=db-*`,
      message: 'agent "al ice" is not an agent name (letters, digits, _ and -; at most 255)',
    },
    {
      label: "a scope member outside Permission",
      spec: `agent=alice,file=${FILE},scope=use+write,secrets=db-*`,
      message: `scope: "write" is not a permission ${PERMISSIONS}`,
    },
    {
      label: "a permission in another case",
      spec: `agent=alice,file=${FILE},scope=USE,secrets=db-*`,
      message: `scope: "USE" is not a permission ${PERMISSIONS}`,
    },
    {
      label: "an empty scope member",
      spec: `agent=alice,file=${FILE},scope=use+,secrets=db-*`,
      message: `scope: "" is not a permission ${PERMISSIONS}`,
    },
    {
      label: "a secrets member outside the pattern grammar",
      spec: `agent=alice,file=${FILE},scope=use,secrets=db.*`,
      message: `secrets: "db.*" is not a secret name or pattern ${PATTERN}`,
    },
    {
      label: "a handle in place of a name",
      spec: `agent=alice,file=${FILE},scope=use,secrets=secret://db`,
      message: `secrets: "secret://db" is not a secret name or pattern ${PATTERN}`,
    },
    {
      label: "an empty secrets member",
      spec: `agent=alice,file=${FILE},scope=use,secrets=db-*+`,
      message: `secrets: "" is not a secret name or pattern ${PATTERN}`,
    },
    {
      label: "a relative file",
      spec: "agent=alice,file=token.jwt,scope=use,secrets=db-*",
      message: 'file "token.jwt" is not an absolute path',
    },
    {
      label: "a dot-relative file",
      spec: "agent=alice,file=./run/token.jwt,scope=use,secrets=db-*",
      message: 'file "./run/token.jwt" is not an absolute path',
    },
  ])("refuses $label INVALID_INPUT, naming the field", async ({ spec, message }) => {
    const err = await expectVaultError(() => parseIssueTokenSpec(spec), ErrorCode.INVALID_INPUT);
    expect(err.message).toBe(`--issue-token: ${message}`);
  });

  it("refuses an agent name over 255 characters", async () => {
    const agent = "a".repeat(256);
    const err = await expectVaultError(
      () => parseIssueTokenSpec(`agent=${agent},file=${FILE},scope=use,secrets=db-*`),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(
      `--issue-token: agent "${agent}" is not an agent name (letters, digits, _ and -; at most 255)`,
    );
  });
});

describe("parseIssueTokenSpecs", () => {
  it("parses every value, in order; no value, no spec", () => {
    expect(parseIssueTokenSpecs([])).toEqual([]);
    expect(
      parseIssueTokenSpecs([
        `agent=alice,file=${FILE},scope=use,secrets=db-*`,
        "agent=bob,file=/run/harpoc/bob/token.jwt,scope=use,secrets=api-*,ttl=720",
      ]).map((spec) => [spec.agent, spec.ttlMinutes]),
    ).toEqual([
      ["alice", 1440],
      ["bob", 720],
    ]);
  });

  it.each([FILE, "/run/harpoc/alice/../alice/token.jwt"])(
    "refuses a second spec naming the same token file (%s)",
    async (second) => {
      const err = await expectVaultError(
        () =>
          parseIssueTokenSpecs([
            `agent=alice,file=${FILE},scope=use,secrets=db-*`,
            `agent=alice,file=${second},scope=use+read,secrets=db-*`,
          ]),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe(
        `--issue-token: file ${JSON.stringify(second)} is named by two specs (one token file per spec)`,
      );
    },
  );
});

describe("assertIssueTokenFile", () => {
  const LINK_REFUSAL = "is a symbolic link or junction";
  const AGENT = "nosuchuser-c1";
  let dir: string;
  const links: string[] = [];

  /** A link at `path` to `target`, unlinked after the row: a junction on win32 (no privilege needed), a symbolic link elsewhere (the type is ignored there). */
  function link(target: string, path: string): string {
    symlinkSync(target, path, "junction");
    links.push(path);
    return path;
  }

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "harpoc-issue-token-spec-"));
  });

  afterEach(() => {
    for (const path of links.splice(0)) unlinkSync(path);
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("accepts a token file to be created in an existing directory, and an existing file", () => {
    expect(() => assertIssueTokenFile(join(dir, "token.jwt"), AGENT)).not.toThrow();
    writeFileSync(join(dir, "old.jwt"), "");
    expect(() => assertIssueTokenFile(join(dir, "old.jwt"), AGENT)).not.toThrow();
  });

  it("refuses a token file whose directory does not exist", async () => {
    const file = join(dir, "missing", "token.jwt");
    const err = await expectVaultError(
      () => assertIssueTokenFile(file, AGENT),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(
      `--issue-token: file ${file}: no such directory: ${join(dir, "missing")}`,
    );
  });

  it("refuses a token file whose directory is a file", async () => {
    writeFileSync(join(dir, "plain"), "");
    const file = join(dir, "plain", "token.jwt");
    const err = await expectVaultError(
      () => assertIssueTokenFile(file, AGENT),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(`--issue-token: file ${file}: not a directory: ${join(dir, "plain")}`);
  });

  it("refuses a token file that is a directory: the rotation renames a file over it", async () => {
    const file = join(dir, "token.jwt");
    mkdirSync(file);
    const err = await expectVaultError(
      () => assertIssueTokenFile(file, AGENT),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(`--issue-token: file ${file} is a directory`);
  });

  it("refuses a token file whose directory is a link (a junction on Windows, a symbolic link elsewhere)", async () => {
    mkdirSync(join(dir, "target"));
    const linked = link(join(dir, "target"), join(dir, "bob"));
    const file = join(linked, "token.jwt");
    const err = await expectVaultError(
      () => assertIssueTokenFile(file, AGENT),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message.includes(LINK_REFUSAL)).toBe(true);
    expect(err.message).toBe(
      `--issue-token: file ${file}: the directory is a symbolic link or junction: ${linked}`,
    );
  });

  it("refuses a token file whose directory is a link spelled with a final dot segment, naming the directory as given (a junction on Windows, a symbolic link elsewhere)", async () => {
    mkdirSync(join(dir, "target"));
    const linked = `${link(join(dir, "target"), join(dir, "bob"))}${sep}.`;
    const file = `${linked}${sep}token.jwt`;
    const err = await expectVaultError(
      () => assertIssueTokenFile(file, AGENT),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message.includes(LINK_REFUSAL)).toBe(true);
    expect(err.message).toBe(
      `--issue-token: file ${file}: the directory is a symbolic link or junction: ${linked}`,
    );
  });

  it("refuses a token file that is a dangling link (a junction on Windows, a symbolic link elsewhere)", async () => {
    const file = link(join(dir, "missing"), join(dir, "token.jwt"));
    const err = await expectVaultError(
      () => assertIssueTokenFile(file, AGENT),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message.includes(LINK_REFUSAL)).toBe(true);
    expect(err.message).toBe(`--issue-token: file ${file} is a symbolic link or junction`);
  });

  it.skipIf(process.platform === "win32")(
    "refuses a token file that is a symbolic link to a file (POSIX; a symbolic link to a file needs a privilege on Windows)",
    async () => {
      writeFileSync(join(dir, "real.jwt"), "");
      const file = link(join(dir, "real.jwt"), join(dir, "token.jwt"));
      const err = await expectVaultError(
        () => assertIssueTokenFile(file, AGENT),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message.includes(LINK_REFUSAL)).toBe(true);
      expect(err.message).toBe(`--issue-token: file ${file} is a symbolic link or junction`);
    },
  );

  it("refuses a token file that is a link to a directory as a link, not as a directory (a junction on Windows, a symbolic link elsewhere)", async () => {
    mkdirSync(join(dir, "target"));
    const file = link(join(dir, "target"), join(dir, "token.jwt"));
    const err = await expectVaultError(
      () => assertIssueTokenFile(file, AGENT),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message.includes(LINK_REFUSAL)).toBe(true);
    expect(err.message).toBe(`--issue-token: file ${file} is a symbolic link or junction`);
  });

  it("accepts a token file whose directory's parent is a link: only the final component is judged (a junction on Windows, a symbolic link elsewhere)", () => {
    mkdirSync(join(dir, "real-parent", "alice"), { recursive: true });
    chmodSync(join(dir, "real-parent", "alice"), 0o750);
    const linkParent = link(join(dir, "real-parent"), join(dir, "link-parent"));
    expect(() => assertIssueTokenFile(join(linkParent, "alice", "token.jwt"), AGENT)).not.toThrow();
  });

  it.skipIf(process.platform === "win32").each([
    { mode: 0o755, octal: "0755", why: "world-accessible" },
    { mode: 0o770, octal: "0770", why: "group-writable" },
  ])(
    "refuses a token file whose directory is $why ($octal), naming the directory (chmod; POSIX: mode bits)",
    async ({ mode, octal }) => {
      chmodSync(dir, mode);
      const file = join(dir, "token.jwt");
      const err = await expectVaultError(
        () => assertIssueTokenFile(file, AGENT),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe(
        `--issue-token: file ${file}: mode ${octal} is not 0750 or stricter (group-writable or world-accessible): ${dir}`,
      );
    },
  );

  it.skipIf(process.platform === "win32" || process.geteuid?.() === 0)(
    "refuses a token file whose directory another uid owns (the filesystem root, root's own; POSIX only, skipped where the suite runs as root)",
    async () => {
      const root = parse(dir).root;
      const file = join(root, "harpoc-c1-token.jwt");
      const err = await expectVaultError(
        () => assertIssueTokenFile(file, AGENT),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe(
        `--issue-token: file ${file}: owned by uid 0, not by this process's uid ${String(process.geteuid?.())}: ${root}`,
      );
    },
  );

  it.skipIf(process.platform === "win32").each([
    { mode: 0o700, octal: "0700 (mkdtemp's)" },
    { mode: 0o750, octal: "0750" },
  ])("accepts a token file whose directory is $octal (chmod; POSIX: mode bits)", ({ mode }) => {
    chmodSync(dir, mode);
    expect((statSync(dir).mode & 0o7777) === mode).toBe(true);
    expect(() => assertIssueTokenFile(join(dir, "token.jwt"), AGENT)).not.toThrow();
  });

  it.skipIf(process.platform === "win32" || process.platform === "darwin")(
    "accepts a token file whose directory is 02750 (set-group-ID: the recipe's consumer directory; chmod; POSIX: mode bits — not on macOS, where the runner's chmod returns without the set-group-ID bit: ci.yml 43159556338)",
    () => {
      const mode = 0o2750;
      chmodSync(dir, mode);
      expect((statSync(dir).mode & 0o7777) === mode).toBe(true);
      expect(() => assertIssueTokenFile(join(dir, "token.jwt"), AGENT)).not.toThrow();
    },
  );

  it.runIf(process.platform === "win32")(
    "refuses a token file whose directory's access list grants Users read and execute — the token file would inherit it (Windows; icacls on this row's own directory)",
    async () => {
      icacls(dir, "/grant", "*S-1-5-32-545:(OI)(CI)(RX)");
      const file = join(dir, "token.jwt");
      const err = await expectVaultError(
        () => assertIssueTokenFile(file, AGENT),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe(
        `--issue-token: file ${file}: the access list grants S-1-5-32-545 0x001200A9; only this process's account, SYSTEM, Administrators may hold a grant (no local account is named "${AGENT}"): ${dir}`,
      );
    },
  );

  it.runIf(process.platform === "win32")(
    "accepts a token file in a mkdtemp directory on Windows: the trusted three alone, the agent naming no local account",
    () => {
      expect(() => assertIssueTokenFile(join(dir, "token.jwt"), AGENT)).not.toThrow();
    },
  );
});
