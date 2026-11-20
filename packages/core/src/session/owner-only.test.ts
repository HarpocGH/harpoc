import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  closeSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { connect, createServer } from "node:net";
import type { Server, Socket } from "node:net";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { system32Path } from "../win32-paths.js";
import { runKeystoreHelper } from "./keystore-helper.js";
import {
  TRUSTED_INSTALLER_SID,
  WINDOWS_PIPE_CONSUMER_RIGHTS,
  WINDOWS_READ_EXECUTE_RIGHTS,
  foreignToVaultAccounts,
  holdsOnlyVaultAccounts,
  listWindowsAcl,
  listWindowsAclChain,
  listWindowsAclSync,
  parseWindowsAcl,
  restrictWindowsAclToVaultAccounts,
  restrictWindowsPipeToAccount,
} from "./owner-only.js";
import type { WindowsAclEntry, WindowsAclListing } from "./owner-only.js";
import { WIN32_TRUSTED_SIDS } from "./path-trust.js";

vi.mock("./keystore-helper.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./keystore-helper.js")>();
  return { ...actual, runKeystoreHelper: vi.fn(actual.runKeystoreHelper) };
});

// restrictWindowsAclToOwner is pinned through its first caller, the session file's ACL step
// (session-manager.permissions.test.ts — the argv, shell:false, the failure report, the real path).

const USERS_SID = "S-1-5-32-545";

describe("parseWindowsAcl", () => {
  it("reads the user, the owner and every rule by SID with its mask and flags, a deny rule as allow: false", () => {
    const text = [
      "user S-1-5-21-1000-2000-3000-1001",
      "owner S-1-5-32-544",
      "rule 1 S-1-1-0 001F01FF 0 0 0",
      "rule 0 S-1-5-18 001F01FF 1 3 0",
      "rule 0 S-1-3-0 10000000 1 3 2",
      "rule 0 S-1-5-21-1000-2000-3000-1001 001200A9 0 3 0",
      "",
    ].join("\r\n");
    expect(parseWindowsAcl(text)).toEqual({
      user: "S-1-5-21-1000-2000-3000-1001",
      owner: "S-1-5-32-544",
      rules: [
        {
          allow: false,
          sid: "S-1-1-0",
          rights: 0x1f01ff,
          inherited: false,
          inheritance: 0,
          propagation: 0,
        },
        {
          allow: true,
          sid: "S-1-5-18",
          rights: 0x1f01ff,
          inherited: true,
          inheritance: 3,
          propagation: 0,
        },
        {
          allow: true,
          sid: "S-1-3-0",
          rights: 0x10000000,
          inherited: true,
          inheritance: 3,
          propagation: 2,
        },
        {
          allow: true,
          sid: "S-1-5-21-1000-2000-3000-1001",
          rights: 0x1200a9,
          inherited: false,
          inheritance: 3,
          propagation: 0,
        },
      ],
    });
  });

  it("reads a generic-read mask (the sign bit) as an unsigned number", () => {
    const acl = parseWindowsAcl("user S-1-5-18\nowner S-1-5-18\nrule 0 S-1-5-18 80000000 0 0 0\n");
    expect(acl.rules[0]?.rights).toBe(0x80000000);
  });

  it("reads the asked account's SID, and '-' (no local account by that name) as null", () => {
    expect(
      parseWindowsAcl("user S-1-5-18\nowner S-1-5-18\naccount S-1-5-21-1-2-3-1002\n").account,
    ).toBe("S-1-5-21-1-2-3-1002");
    expect(parseWindowsAcl("user S-1-5-18\nowner S-1-5-18\naccount -\n").account).toBeNull();
    expect(parseWindowsAcl("user S-1-5-18\nowner S-1-5-18\n")).not.toHaveProperty("account");
  });

  it.each([
    ["User", "account S-1-5-21-1-2-3-1001 User", "User"],
    ["Group", "account S-1-5-21-1-2-3-1001 Group", "Group"],
    ["another class as other", "account S-1-5-21-1-2-3-1001 Computer", "other"],
    ["the script's failed read as other", "account S-1-5-21-1-2-3-1001 other", "other"],
    ["a missing class as other", "account S-1-5-21-1-2-3-1001", "other"],
  ])("reads the account's class: %s", (_, line, accountClass) => {
    expect(parseWindowsAcl(`user S-1-5-18\nowner S-1-5-18\n${line}\n`)).toStrictEqual({
      user: "S-1-5-18",
      owner: "S-1-5-18",
      account: "S-1-5-21-1-2-3-1001",
      accountClass,
      rules: [],
    });
  });

  it("reads 'account -' as before: null, with no class", () => {
    expect(parseWindowsAcl("user S-1-5-18\nowner S-1-5-18\naccount -\n")).toStrictEqual({
      user: "S-1-5-18",
      owner: "S-1-5-18",
      account: null,
      rules: [],
    });
  });

  it.each([
    [
      "a localized name in place of a SID",
      "user S-1-5-18\nowner S-1-5-18\nrule 0 Everyone 001F01FF 0 0 0\n",
    ],
    ["an unknown rule type", "user S-1-5-18\nowner S-1-5-18\nrule 2 S-1-1-0 001F01FF 0 0 0\n"],
    ["a rule without its mask and flags", "user S-1-5-18\nowner S-1-5-18\nrule 0 S-1-1-0\n"],
    [
      "a mask that is not eight hex digits",
      "user S-1-5-18\nowner S-1-5-18\nrule 0 S-1-1-0 1F01FF 0 0 0\n",
    ],
    [
      "an inherited flag that is not 0 or 1",
      "user S-1-5-18\nowner S-1-5-18\nrule 0 S-1-1-0 001F01FF 2 0 0\n",
    ],
    ["a second account line", "user S-1-5-18\nowner S-1-5-18\naccount -\naccount S-1-5-18\n"],
    ["a stray line", "user S-1-5-18\nowner S-1-5-18\nWARNING: something\n"],
    ["no owner line", "user S-1-5-18\nrule 0 S-1-5-18 001F01FF 0 0 0\n"],
    ["nothing at all", ""],
  ])("throws on %s — never a partial list", (_, text) => {
    expect(() => parseWindowsAcl(text)).toThrow(/^ACL listing: (unexpected|incomplete) output$/);
  });
});

/** `icacls <dir> /inheritance:r` with this account, SYSTEM and Administrators full, plus `extra`. */
function restrict(dir: string, ...extra: string[]): void {
  const res = spawnSync(
    system32Path("icacls.exe"),
    [
      dir,
      "/inheritance:r",
      "/grant:r",
      `${userInfo().username}:(OI)(CI)F`,
      "/grant:r",
      "*S-1-5-18:(OI)(CI)F",
      "/grant:r",
      "*S-1-5-32-544:(OI)(CI)F",
      ...extra,
    ],
    { shell: false, windowsHide: true, timeout: 15_000 },
  );
  expect(res.status).toBe(0);
}

describe.runIf(process.platform === "win32")(
  "listWindowsAcl and listWindowsAclSync on win32",
  () => {
    let dir: string;

    beforeEach(() => {
      dir = mkdtempSync(join(tmpdir(), "harpoc-owner-only-"));
    });

    afterEach(() => {
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    it("lists a temporary file's inherited SYSTEM, Administrators and user rules, under a non-ASCII directory name", async () => {
      const nested = join(dir, "schlüssel");
      mkdirSync(nested);
      const path = join(nested, "unlock.key");
      writeFileSync(path, "not a key");
      const acl = await listWindowsAcl(path);
      expect(acl.user).toMatch(/^S-1-5-/);
      expect(acl.rules.filter((rule) => rule.allow).map((rule) => rule.sid)).toEqual(
        expect.arrayContaining(["S-1-5-18", "S-1-5-32-544", acl.user]),
      );
      expect((acl as WindowsAclListing).rules.every((rule) => rule.inherited)).toBe(true);
    });

    it("lists a directory's explicit rules with their masks: (OI)(CI)F as 0x001F01FF, (OI)(CI)(RX) as 0x001200A9", () => {
      const consumer = join(dir, "agent1");
      mkdirSync(consumer);
      restrict(consumer, "/grant:r", `*${USERS_SID}:(OI)(CI)(RX)`);
      const acl = listWindowsAclSync(consumer);
      // An elevated administrator's new directory is owned by Administrators (the GitHub runners run
      // elevated), a standard token's by the account; judgeWindowsDirAcl trusts both owners.
      expect([acl.user, "S-1-5-32-544"]).toContain(acl.owner);
      const bySid = new Map(acl.rules.map((rule) => [rule.sid, rule]));
      expect([...bySid.keys()].sort()).toEqual(
        [acl.user, "S-1-5-18", "S-1-5-32-544", USERS_SID].sort(),
      );
      for (const sid of [acl.user, "S-1-5-18", "S-1-5-32-544"]) {
        expect(bySid.get(sid)).toEqual({
          allow: true,
          sid,
          rights: 0x1f01ff,
          inherited: false,
          inheritance: 3,
          propagation: 0,
        });
      }
      expect(bySid.get(USERS_SID)?.rights).toBe(WINDOWS_READ_EXECUTE_RIGHTS);
    });

    it("resolves the asked account machine-qualified: this account's name to its SID and class User, a well-known group's name to none", () => {
      const own = listWindowsAclSync(dir, { account: userInfo().username });
      expect(own.account).toBe(own.user);
      expect(own.accountClass).toBe("User");
      expect(listWindowsAclSync(dir, { account: "users" }).account).toBeNull();
      expect(listWindowsAclSync(dir, { account: "everyone" }).account).toBeNull();
    });

    // RP-B7-3: the token file needs no icacls — its temporary inherits the consumer directory's ACEs.
    it("a file Node creates wx in a consumer directory carries exactly the directory's four grants, inherited", () => {
      const consumer = join(dir, "agent1");
      mkdirSync(consumer);
      restrict(consumer, "/grant:r", `*${USERS_SID}:(OI)(CI)(RX)`);
      const token = join(consumer, "token.jwt");
      closeSync(openSync(token, "wx", 0o640));
      const acl = listWindowsAclSync(token);
      expect(acl.rules.every((rule) => rule.allow && rule.inherited)).toBe(true);
      expect(new Map(acl.rules.map((rule) => [rule.sid, rule.rights]))).toEqual(
        new Map([
          [USERS_SID, WINDOWS_READ_EXECUTE_RIGHTS],
          ["S-1-5-32-544", 0x1f01ff],
          ["S-1-5-18", 0x1f01ff],
          [acl.user, 0x1f01ff],
        ]),
      );
    });

    it("throws, value-free, on a path that does not exist", () => {
      expect(() => listWindowsAclSync(join(dir, "missing"))).toThrow(
        /^ACL listing failed \(exit 1\)$/,
      );
    });
  },
);

describe.runIf(process.platform === "win32")("restrictWindowsPipeToAccount on win32", () => {
  let server: Server | undefined;
  const clients: Socket[] = [];

  afterEach(async () => {
    for (const client of clients.splice(0)) client.destroy();
    if (server) await new Promise<void>((resolve) => (server as Server).close(() => resolve()));
    server = undefined;
  });

  /** The pipe's DACL in SDDL, read through a fresh client handle (ReadData and ReadPermissions — .NET needs a direction). */
  function pipeSddl(path: string): string {
    const name = path.slice("\\\\.\\pipe\\".length);
    const res = spawnSync(
      system32Path("WindowsPowerShell", "v1.0", "powershell.exe"),
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        `$c=[System.IO.Pipes.NamedPipeClientStream]::new('.','${name}',[System.IO.Pipes.PipeAccessRights]'ReadData, ReadPermissions',[System.IO.Pipes.PipeOptions]::None,[System.Security.Principal.TokenImpersonationLevel]::Identification,[System.IO.HandleInheritability]::None);$c.Connect(5000);[System.Console]::Out.WriteLine($c.GetAccessControl().GetSecurityDescriptorSddlForm('Access'));$c.Dispose()`,
      ],
      { encoding: "utf8", shell: false, windowsHide: true, timeout: 15_000 },
    );
    expect(res.status).toBe(0);
    return res.stdout.trim();
  }

  function connectClient(path: string): Promise<Socket> {
    return new Promise((resolve, reject) => {
      const client = connect(path);
      clients.push(client);
      client.once("error", reject);
      client.once("connect", () => resolve(client));
    });
  }

  function listen(path: string): Promise<Server> {
    return new Promise((resolve, reject) => {
      const created = createServer((stream) => stream.on("error", () => undefined));
      created.once("error", reject);
      created.listen(path, () => resolve(created));
    });
  }

  it("replaces Node's default pipe DACL (Everyone and Anonymous read) with this account, SYSTEM, Administrators and the consumer", async () => {
    const path = `\\\\.\\pipe\\harpoc-owner-only-${randomBytes(6).toString("hex")}`;
    server = await listen(path);
    const acl = await restrictWindowsPipeToAccount(path, USERS_SID);
    expect(new Map(acl.rules.map((rule) => [rule.sid, rule.rights]))).toEqual(
      new Map([
        ["S-1-5-18", 0x1f019f],
        ["S-1-5-32-544", 0x1f019f],
        [USERS_SID, 0x12019b],
        [acl.user, 0x1f019f],
      ]),
    );
    expect(acl.rules.some((rule) => rule.sid === "S-1-1-0" || rule.sid === "S-1-5-7")).toBe(false);
  });

  it("the replaced DACL holds across the further pipe instances libuv creates for later clients", async () => {
    const path = `\\\\.\\pipe\\harpoc-owner-only-${randomBytes(6).toString("hex")}`;
    server = await listen(path);
    let accepted = 0;
    server.on("connection", () => (accepted += 1));
    await restrictWindowsPipeToAccount(path, USERS_SID);
    await Promise.all([connectClient(path), connectClient(path), connectClient(path)]);
    await vi.waitFor(() => expect(accepted).toBeGreaterThanOrEqual(4));
    for (const client of clients.splice(0)) client.destroy();

    const sddl = pipeSddl(path);
    expect(sddl.startsWith("D:P")).toBe(true);
    expect(sddl).toContain("(A;;0x12019b;;;BU)");
    expect(sddl).not.toContain(";;;WD)");
    expect(sddl).not.toContain(";;;AN)");
  });

  it("rejects a path that is not a pipe and a consumer that is not a SID, before any host runs", async () => {
    await expect(restrictWindowsPipeToAccount("C:\\run\\agent1", USERS_SID)).rejects.toThrow(
      "pipe access list: not a pipe path or not a SID",
    );
    await expect(restrictWindowsPipeToAccount("\\\\.\\pipe\\x", "users")).rejects.toThrow(
      "pipe access list: not a pipe path or not a SID",
    );
  });

  it("rejects when no pipe of that name is listening", async () => {
    await expect(
      restrictWindowsPipeToAccount(
        `\\\\.\\pipe\\harpoc-owner-only-${randomBytes(6).toString("hex")}`,
        USERS_SID,
      ),
    ).rejects.toThrow(/pipe access list failed \(exit 1\)/);
  });
});

describe.runIf(process.platform === "win32")("WINDOWS_PIPE_CONSUMER_RIGHTS on win32", () => {
  it("a pipe whose protected DACL grants this account the consumer rights alone opens GENERIC_READ | GENERIC_WRITE and round-trips a byte", () => {
    const name = `harpoc-owner-only-${randomBytes(6).toString("hex")}`;
    const res = spawnSync(
      system32Path("WindowsPowerShell", "v1.0", "powershell.exe"),
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "$ErrorActionPreference='Stop';" +
          "$sec=[System.IO.Pipes.PipeSecurity]::new();$sec.SetAccessRuleProtection($true,$false);" +
          `$sec.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new([System.Security.Principal.WindowsIdentity]::GetCurrent().User,[System.IO.Pipes.PipeAccessRights]${String(WINDOWS_PIPE_CONSUMER_RIGHTS)},'Allow'));` +
          `$srv=[System.IO.Pipes.NamedPipeServerStream]::new('${name}',[System.IO.Pipes.PipeDirection]::InOut,1,[System.IO.Pipes.PipeTransmissionMode]::Byte,[System.IO.Pipes.PipeOptions]::Asynchronous,4096,4096,$sec);` +
          "try{$w=$srv.WaitForConnectionAsync();" +
          `$cli=[System.IO.Pipes.NamedPipeClientStream]::new('.','${name}',[System.IO.Pipes.PipeDirection]::InOut);` +
          "try{$cli.Connect(5000);[void]$w.Wait(5000);$cli.WriteByte(42);$cli.Flush();$srv.WriteByte($srv.ReadByte()+1);$srv.Flush();[System.Console]::Out.Write('round trip '+$cli.ReadByte())}" +
          "catch{$e=$_.Exception;while($null -ne $e.InnerException){$e=$e.InnerException};[System.Console]::Out.Write($e.GetType().Name)}" +
          "finally{$cli.Dispose()}}finally{$srv.Dispose()}",
      ],
      { encoding: "utf8", shell: false, windowsHide: true, timeout: 15_000 },
    );
    expect(res.status).toBe(0);
    expect(res.stdout).toBe("round trip 43");
  });
});

describe("restrictWindowsPipeToAccount's read-back check (the host's output stubbed)", () => {
  const PIPE = "\\\\.\\pipe\\harpoc-owner-only-read-back";
  const ME = "S-1-5-21-1000-2000-3000-1001";
  const SYSTEM_RULE = "rule 0 S-1-5-18 001F019F 0 0 0";
  const ADMINISTRATORS_RULE = "rule 0 S-1-5-32-544 001F019F 0 0 0";
  const OWNER_RULE = `rule 0 ${ME} 001F019F 0 0 0`;
  const CONSUMER_RULE = `rule 0 ${USERS_SID} 0012019B 0 0 0`;

  afterEach(() => {
    vi.mocked(runKeystoreHelper).mockReset();
  });

  function readBack(...rules: string[]): void {
    vi.mocked(runKeystoreHelper).mockResolvedValueOnce({
      stdout: [`user ${ME}`, `owner ${ME}`, ...rules, ""].join("\r\n"),
      stderr: "",
      exitCode: 0,
    });
  }

  it("accepts exactly this account, SYSTEM and Administrators at full control and the consumer at its rights", async () => {
    readBack(SYSTEM_RULE, ADMINISTRATORS_RULE, CONSUMER_RULE, OWNER_RULE);
    const acl = await restrictWindowsPipeToAccount(PIPE, USERS_SID);
    expect(acl.rules.map((rule) => rule.sid).sort()).toEqual(
      [ME, "S-1-5-18", "S-1-5-32-544", USERS_SID].sort(),
    );
  });

  it("rejects a read-back in which a trusted SID holds less than full control", async () => {
    readBack(SYSTEM_RULE, "rule 0 S-1-5-32-544 00120089 0 0 0", CONSUMER_RULE, OWNER_RULE);
    await expect(restrictWindowsPipeToAccount(PIPE, USERS_SID)).rejects.toThrow(
      "pipe access list: not as set",
    );
  });

  it("rejects a read-back missing a trusted SID, another rule standing in its place", async () => {
    readBack(SYSTEM_RULE, SYSTEM_RULE, CONSUMER_RULE, OWNER_RULE);
    await expect(restrictWindowsPipeToAccount(PIPE, USERS_SID)).rejects.toThrow(
      "pipe access list: not as set",
    );
  });
});

describe.runIf(process.platform === "win32")("listWindowsAclChain on win32", () => {
  let dir: string;

  beforeEach(() => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-owner-only-")));
    vi.mocked(runKeystoreHelper).mockClear();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("lists C:\\ and the temporary directory in one host run and in that order, C:\\ owned by SYSTEM, Administrators or TrustedInstaller", async () => {
    const temp = realpathSync(tmpdir());
    const chain = await listWindowsAclChain(["C:\\", temp]);
    expect(runKeystoreHelper).toHaveBeenCalledTimes(1);
    expect(chain).toHaveLength(2);
    expect(chain[0]).toEqual(listWindowsAclSync("C:\\"));
    expect(chain[1]).toEqual(listWindowsAclSync(temp));
    expect(WIN32_TRUSTED_SIDS).toContain(chain[0]?.owner);
  });

  it("rejects, value-free, when a path does not exist", async () => {
    await expect(listWindowsAclChain(["C:\\", join(dir, "missing")])).rejects.toThrow(
      /^ACL listing failed$/,
    );
  });
});

describe("listWindowsAclChain's answer check (the host's output stubbed)", () => {
  const ME = "S-1-5-21-1000-2000-3000-1001";
  const PATHS = ["C:\\", "C:\\ProgramData"];
  const ROOT = ["path 0", `user ${ME}`, `owner ${TRUSTED_INSTALLER_SID}`];
  const PROGRAM_DATA = [
    "path 1",
    `user ${ME}`,
    "owner S-1-5-18",
    `rule 0 ${USERS_SID} 00000116 0 1 0`,
  ];

  beforeEach(() => {
    vi.mocked(runKeystoreHelper).mockClear();
  });

  afterEach(() => {
    vi.mocked(runKeystoreHelper).mockReset();
  });

  function answer(lines: string[]): void {
    vi.mocked(runKeystoreHelper).mockResolvedValueOnce({
      stdout: [...lines, ""].join("\r\n"),
      stderr: "",
      exitCode: 0,
    });
  }

  it("hands every path as one base64 line in one host run, under the listing's timeout, and reads one listing per path in the order asked", async () => {
    answer([...ROOT, ...PROGRAM_DATA]);
    const chain = await listWindowsAclChain(PATHS);
    expect(runKeystoreHelper).toHaveBeenCalledTimes(1);
    const [, , stdin, options] = vi.mocked(runKeystoreHelper).mock.calls[0] ?? [];
    expect(stdin).toBe(
      `${PATHS.map((path) => Buffer.from(path, "utf8").toString("base64")).join("\n")}\n`,
    );
    expect(options?.timeoutMs).toBe(15_000);
    expect(chain).toEqual([
      { user: ME, owner: TRUSTED_INSTALLER_SID, rules: [] },
      {
        user: ME,
        owner: "S-1-5-18",
        rules: [
          {
            allow: true,
            sid: USERS_SID,
            rights: 0x116,
            inherited: false,
            inheritance: 1,
            propagation: 0,
          },
        ],
      },
    ]);
  });

  it.each([
    ["fewer listings than paths", [...ROOT]],
    [
      "more listings than paths",
      [...ROOT, ...PROGRAM_DATA, "path 2", `user ${ME}`, "owner S-1-5-18"],
    ],
    ["the listings out of order", [...PROGRAM_DATA, ...ROOT]],
    ["a listing before its path line", [...ROOT.slice(1), "path 0", ...PROGRAM_DATA]],
    ["a listing without its owner", [...ROOT.slice(0, 2), ...PROGRAM_DATA]],
  ])("rejects %s — never a partial chain", async (_, lines) => {
    answer(lines);
    await expect(listWindowsAclChain(PATHS)).rejects.toThrow(
      /^ACL listing: (unexpected|incomplete) output$/,
    );
  });

  it("rejects value-free when the host run rejects: nothing of its message is passed on", async () => {
    vi.mocked(runKeystoreHelper).mockRejectedValueOnce(
      new Error("ACL listing failed (exit 1): Exception calling GetAccessControl"),
    );
    await expect(listWindowsAclChain(PATHS)).rejects.toThrow(/^ACL listing failed$/);
  });
});

describe("foreignToVaultAccounts", () => {
  const ME = "S-1-5-21-1000-2000-3000-1001";
  const NEIGHBOUR = "S-1-5-21-1000-2000-3000-1002";

  function entry(sid: string, allow = true, propagation = 0): WindowsAclEntry {
    return { allow, sid, rights: 0x1200a9, inherited: false, inheritance: 3, propagation };
  }

  const VAULT_RULES = [entry(ME), entry("S-1-5-18"), entry("S-1-5-32-544")];

  it("names nothing where this account, SYSTEM or Administrators own and they alone hold allow entries, a deny entry of another SID aside", () => {
    for (const owner of [ME, "S-1-5-18", "S-1-5-32-544"]) {
      expect(
        foreignToVaultAccounts({
          user: ME,
          owner,
          rules: [entry(NEIGHBOUR, false), ...VAULT_RULES],
        }),
      ).toBeUndefined();
    }
  });

  it("names another owner, before any entry", () => {
    expect(
      foreignToVaultAccounts({
        user: ME,
        owner: TRUSTED_INSTALLER_SID,
        rules: [...VAULT_RULES, entry(USERS_SID)],
      }),
    ).toEqual({ owner: TRUSTED_INSTALLER_SID });
  });

  it("names the first allow entry of another SID, an inherit-only one included", () => {
    const inheritOnly = entry(NEIGHBOUR, true, 2);
    expect(
      foreignToVaultAccounts({
        user: ME,
        owner: ME,
        rules: [...VAULT_RULES, inheritOnly, entry(USERS_SID)],
      }),
    ).toEqual({ grant: inheritOnly });
  });
});

describe("holdsOnlyVaultAccounts", () => {
  const ME = "S-1-5-21-1000-2000-3000-1001";
  const NEIGHBOUR = "S-1-5-21-1000-2000-3000-1002";

  function entry(sid: string, allow = true, propagation = 0): WindowsAclEntry {
    return { allow, sid, rights: 0x1f01ff, inherited: false, inheritance: 3, propagation };
  }

  const VAULT_RULES = [entry(ME), entry("S-1-5-18"), entry("S-1-5-32-544")];

  it("holds this account, SYSTEM or Administrators as owner with no other allow entry; a deny entry is not judged", () => {
    for (const owner of [ME, "S-1-5-18", "S-1-5-32-544"]) {
      expect(holdsOnlyVaultAccounts({ user: ME, owner, rules: VAULT_RULES })).toBe(true);
    }
    expect(
      holdsOnlyVaultAccounts({
        user: ME,
        owner: ME,
        rules: [...VAULT_RULES, entry(NEIGHBOUR, false)],
      }),
    ).toBe(true);
  });

  it("is false for another owner, TrustedInstaller included, and for another SID's allow entry, an inherit-only one included", () => {
    for (const owner of [NEIGHBOUR, TRUSTED_INSTALLER_SID]) {
      expect(holdsOnlyVaultAccounts({ user: ME, owner, rules: VAULT_RULES })).toBe(false);
    }
    for (const extra of [entry(USERS_SID), entry(USERS_SID, true, 2)]) {
      expect(holdsOnlyVaultAccounts({ user: ME, owner: ME, rules: [...VAULT_RULES, extra] })).toBe(
        false,
      );
    }
  });
});

describe.runIf(process.platform === "win32")("restrictWindowsAclToVaultAccounts on win32", () => {
  let dir: string;
  let file: string;

  beforeEach(() => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-owner-only-")));
    file = join(dir, "harpoc-20261119T120000Z.db.0123456789ab.tmp");
    writeFileSync(file, "");
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("leaves a fresh file allow entries for exactly this account, SYSTEM and Administrators, full control each, and holdsOnlyVaultAccounts is true", () => {
    restrictWindowsAclToVaultAccounts(file);
    const acl = listWindowsAclSync(file);
    expect(acl.rules).toHaveLength(3);
    expect(new Map(acl.rules.map((rule) => [rule.sid, rule]))).toEqual(
      new Map(
        [acl.user, "S-1-5-18", "S-1-5-32-544"].map((sid) => [
          sid,
          { allow: true, sid, rights: 0x1f01ff, inherited: false, inheritance: 0, propagation: 0 },
        ]),
      ),
    );
    expect(holdsOnlyVaultAccounts(acl)).toBe(true);
  });

  it("after icacls /grant Users:R, holdsOnlyVaultAccounts is false", () => {
    restrictWindowsAclToVaultAccounts(file);
    const res = spawnSync(system32Path("icacls.exe"), [file, "/grant", `*${USERS_SID}:R`], {
      shell: false,
      windowsHide: true,
      timeout: 15_000,
    });
    expect(res.status).toBe(0);
    expect(holdsOnlyVaultAccounts(listWindowsAclSync(file))).toBe(false);
  });
});
