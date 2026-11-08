import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { getPkgRoot } from "@harpoc/test-utils";
import { POWERSHELL } from "./helpers/spawn-cli.js";

const deployRoot = resolve(getPkgRoot(import.meta.url), "..", "..", "deploy");

/** Every shell script under deploy/, relative to it with `/` separators, sorted. */
const SCRIPTS = readdirSync(deployRoot, { recursive: true, encoding: "utf8" })
  .filter((p) => p.endsWith(".sh"))
  .map((p) => p.split(sep).join("/"))
  .sort();

const ENROLL = resolve(deployRoot, "linux", "enroll-unlock-key.sh");

describe("deploy scripts (deployment model B)", () => {
  it("finds exactly the scripts the deployment ships", () => {
    expect(SCRIPTS).toEqual([
      "dev-container/run.sh",
      "linux/enroll-unlock-key.sh",
      "linux/install-two-identity.sh",
    ]);
  });

  it.each(SCRIPTS)("%s starts with the bash shebang and set -eu", (script) => {
    const lines = readFileSync(resolve(deployRoot, script), "utf8").split("\n");
    expect(lines.slice(0, 2)).toEqual(["#!/usr/bin/env bash", "set -eu"]);
  });

  it("linux/enroll-unlock-key.sh never prints, copies or encodes the key file (no cat, od, base64, cp … on it; no xtrace)", () => {
    const lines = readFileSync(ENROLL, "utf8").split("\n");
    const touching = lines.filter((l) => !/^\s*#/.test(l) && l.includes('"$key_file"'));
    expect(touching.length).toBeGreaterThan(0);
    const sink =
      /\b(cat|xxd|od|hexdump|base64|base32|head|tail|dd|tee|cp|install|less|more|strings|sed|awk|grep|read|xargs|sha256sum|openssl)\b/;
    expect(touching.filter((l) => sink.test(l))).toEqual([]);
    expect(lines.some((l) => /\bset -[a-z]*x|xtrace/.test(l))).toBe(false);
  });

  it("linux/enroll-unlock-key.sh defaults to systemd-creds' own auto mode, never to the host key", () => {
    const text = readFileSync(ENROLL, "utf8");
    expect(text).toContain('mode="${2:-auto}"');
    expect(text).toContain('--with-key="$mode"');
  });
});

describe.skipIf(process.platform === "win32")(
  "deploy scripts on POSIX (the recipes target Linux; on win32 `bash` may resolve to Git Bash or the WSL launcher, and git there tracks no mode)",
  () => {
    it.each(SCRIPTS)("%s parses under bash -n", (script) => {
      const run = spawnSync("bash", ["-n", resolve(deployRoot, script)], {
        encoding: "utf8",
        timeout: 10_000,
      });
      expect(run.error).toBeUndefined();
      expect(run.stderr).toBe("");
      expect(run.status).toBe(0);
    });

    it.each(SCRIPTS)("%s is executable (the index mode git checks out)", (script) => {
      expect(statSync(resolve(deployRoot, script)).mode & 0o111).toBe(0o111);
    });

    it.each([
      { args: [], says: "expected <key-file> [mode]" },
      { args: ["-k"], says: "the key file must be a path" },
      { args: ["", "auto"], says: "the key file must be a path" },
      { args: ["/nonexistent/unlock.key", "null"], says: "unknown mode: null" },
      { args: ["/nonexistent/unlock.key", "auto", "extra"], says: "expected <key-file> [mode]" },
    ])(
      "linux/enroll-unlock-key.sh $args refuses with exit 2 before its root check",
      ({ args, says }) => {
        const run = spawnSync("bash", [ENROLL, ...args], { encoding: "utf8", timeout: 10_000 });
        expect(run.error).toBeUndefined();
        expect(run.status).toBe(2);
        expect(run.stderr).toContain(`enroll-unlock-key.sh: ${says}`);
        expect(run.stderr).not.toContain("must run as root");
      },
    );

    it("linux/enroll-unlock-key.sh --help prints the usage and exits 0", () => {
      const run = spawnSync("bash", [ENROLL, "--help"], { encoding: "utf8", timeout: 10_000 });
      expect(run.status).toBe(0);
      expect(run.stdout).toContain(
        "Usage: enroll-unlock-key.sh <key-file> [auto|tpm2|host+tpm2|host]",
      );
      expect(run.stderr).toBe("");
    });

    // As root the script passes its root check and would read the system; the runners run as a user.
    it.skipIf(process.getuid?.() === 0)(
      "linux/enroll-unlock-key.sh with valid arguments stops at its root check for a non-root user (exit 1, nothing read)",
      () => {
        const run = spawnSync("bash", [ENROLL, "/nonexistent/unlock.key", "host"], {
          encoding: "utf8",
          timeout: 10_000,
        });
        expect(run.status).toBe(1);
        expect(run.stderr).toBe("enroll-unlock-key.sh: must run as root\n");
      },
    );
  },
);

/** Every PowerShell script under deploy/, relative to it with `/` separators, sorted. */
const PS_SCRIPTS = readdirSync(deployRoot, { recursive: true, encoding: "utf8" })
  .filter((p) => p.endsWith(".ps1"))
  .map((p) => p.split(sep).join("/"))
  .sort();

const ICACLS = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "icacls.exe");

const psText = (script: string): string => readFileSync(resolve(deployRoot, script), "utf8");

describe("deploy PowerShell scripts (deployment model B on Windows)", () => {
  it("finds exactly the PowerShell scripts the deployment ships", () => {
    expect(PS_SCRIPTS).toEqual([
      "windows/enroll-unlock-key.ps1",
      "windows/install-two-identity.ps1",
      "windows/register-service.ps1",
    ]);
  });

  it.each(PS_SCRIPTS)(
    "%s is ASCII with LF line ends (Windows PowerShell 5.1 reads a file without a byte order mark in the ANSI code page)",
    (script) => {
      const bytes = readFileSync(resolve(deployRoot, script));
      expect(bytes.every((byte) => byte < 0x80)).toBe(true);
      expect(bytes.includes(0x0d)).toBe(false);
    },
  );

  it.each(PS_SCRIPTS)(
    "%s opens with #Requires -Version 5.1, runs strict after its param block, and checks elevation itself after its arguments (no #Requires -RunAsAdministrator)",
    (script) => {
      const text = psText(script);
      expect(text.split("\n")[0]).toBe("#Requires -Version 5.1");
      expect(text).toContain(
        ")\nSet-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n",
      );
      expect(/#Requires\s+-RunAsAdministrator/i.test(text)).toBe(false);
      expect(text).toContain("IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)");
      expect(text.indexOf("if (-not (Test-Elevated))")).toBeGreaterThan(text.indexOf("cnotmatch"));
    },
  );

  it.each(PS_SCRIPTS)(
    "%s binds no argument by position ([CmdletBinding(PositionalBinding = $false)]: a bare name is the binder's refusal, never the vault account)",
    (script) => {
      expect(psText(script)).toContain("\n[CmdletBinding(PositionalBinding = $false)]\nparam(\n");
    },
  );

  // RD-B7-5: a directory named after a device (nul, com1 ...) is the device, not a directory.
  it("windows/install-two-identity.ps1 refuses Windows' reserved device names, as a usage error before its administrator check", () => {
    const text = psText("windows/install-two-identity.ps1");
    expect(text).toContain("$ReservedDeviceName = '^(con|prn|aux|nul|com[1-9]|lpt[1-9])$'");
    const check = text.indexOf("if ($agent -match $ReservedDeviceName)");
    expect(check).toBeGreaterThan(-1);
    expect(text.indexOf("if ($VaultUser -match $ReservedDeviceName)")).toBeGreaterThan(-1);
    expect(text.indexOf("if (-not (Test-Elevated))")).toBeGreaterThan(check);
  });

  it("windows/install-two-identity.ps1 tests for a reparse point and for an item that is not a directory, each twice: with its arguments before the administrator check, and in Set-HarpocDirectory right before it creates or re-ACLs the directory", () => {
    const text = psText("windows/install-two-identity.ps1");
    const body = text.indexOf("function Set-HarpocDirectory(");
    for (const [test, refusal] of [
      [
        "-band [System.IO.FileAttributes]::ReparsePoint) -ne 0",
        'is a reparse point (junction or symbolic link); remove it" 2',
      ],
      [
        "-band [System.IO.FileAttributes]::Directory) -eq 0",
        'exists and is not a directory; remove it" 2',
      ],
    ] as const) {
      const first = text.indexOf(test);
      const second = text.indexOf(test, first + test.length);
      expect(first, test).toBeGreaterThan(-1);
      expect(first, test).toBeLessThan(text.indexOf("if (-not (Test-Elevated))"));
      expect(second, test).toBeGreaterThan(body);
      expect(second, test).toBeLessThan(text.indexOf("New-Item -ItemType Directory", body));
      expect(text.indexOf(test, second + test.length), test).toBe(-1);
      expect(text.split(refusal).length - 1, refusal).toBe(2);
    }
  });

  it("windows/install-two-identity.ps1 refuses an existing directory that carries a deny entry, in Set-HarpocDirectory before its grants (exit 1: the daemon would be denied on its own directory)", () => {
    const text = psText("windows/install-two-identity.ps1");
    const body = text.indexOf("function Set-HarpocDirectory(");
    const deny = text.indexOf("if ($rule.AccessControlType -eq 'Deny')", body);
    expect(deny).toBeGreaterThan(body);
    expect(deny).toBeLessThan(text.indexOf("/inheritance:r /grant:r", body));
    expect(text).toContain(
      'Stop-WithError "$Path carries a deny entry for $($rule.IdentityReference.Value); remove it" 1',
    );
  });

  it.each(PS_SCRIPTS)(
    "%s never puts a password into a string, an output, a file or an argv (no schtasks /rp, no plain-text conversion)",
    (script) => {
      const lines = psText(script)
        .split("\n")
        .filter((l) => !/^\s*#/.test(l));
      const interpolated = /"[^"]*\$\{?(Password|plain|credential)\b[^"]*"/i;
      expect(lines.filter((l) => interpolated.test(l))).toEqual([]);
      const sink =
        /\b(ConvertFrom-SecureString|AsPlainText|schtasks|Write-Host|Write-Output|Out-File|Set-Content|Add-Content|Start-Transcript)\b/i;
      expect(lines.filter((l) => sink.test(l))).toEqual([]);
      const plain = lines.filter((l) => /\$plain\b/.test(l)).map((l) => l.trim());
      for (const line of plain) {
        expect(
          line === "$plain = (New-Object System.Net.NetworkCredential('', $Password)).Password" ||
            line === "$plain = $null" ||
            line.startsWith("Register-ScheduledTask "),
          `a line handles the plain password outside its three places: ${line.slice(0, 40)}`,
        ).toBe(true);
      }
    },
  );
});

/** One argument as the Windows C runtime reads it back (the scripts' ConvertTo-Argument, for paths without quotes). */
const winArg = (value: string): string => (/\s/.test(value) ? `"${value}"` : value);

describe.skipIf(process.platform !== "win32")(
  "deploy PowerShell scripts on win32 (the pinned Windows PowerShell 5.1 host; a .ps1 runs under -ExecutionPolicy Bypass, the client default refuses script files)",
  () => {
    let root = "";
    let cli = "";
    let elevated = false;
    let junction = "";
    const denied: string[] = [];

    function runPs1(
      script: string,
      args: string[],
    ): { status: number | null; stdout: string; stderr: string } {
      const run = spawnSync(
        POWERSHELL,
        [
          "-NoProfile",
          "-NonInteractive",
          "-ExecutionPolicy",
          "Bypass",
          "-File",
          resolve(deployRoot, script),
          ...args,
        ],
        { shell: false, windowsHide: true, encoding: "utf8", timeout: 30_000 },
      );
      expect(run.error).toBeUndefined();
      return { status: run.status, stdout: run.stdout, stderr: run.stderr };
    }

    beforeAll(() => {
      root = mkdtempSync(join(tmpdir(), "harpoc-deploy-ps1-"));
      cli = join(root, "cli");
      mkdirSync(join(cli, "dist"), { recursive: true });
      writeFileSync(join(cli, "dist", "index.js"), "");
      const probe = spawnSync(
        POWERSHELL,
        [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
        ],
        { shell: false, windowsHide: true, encoding: "utf8", timeout: 30_000 },
      );
      elevated = probe.stdout.trim() === "True";
    });

    afterAll(() => {
      if (junction !== "") rmdirSync(junction);
      const resets = denied.map((dir) => ({
        dir,
        status: spawnSync(ICACLS, [dir, "/reset"], {
          shell: false,
          windowsHide: true,
          timeout: 30_000,
        }).status,
      }));
      for (const reset of resets) expect(reset.status, reset.dir).toBe(0);
      if (root !== "")
        rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    it.each(PS_SCRIPTS)(
      "%s parses with no error: its param block, then Set-StrictMode and $ErrorActionPreference as its first two statements, no elevation requirement",
      (script) => {
        const run = spawnSync(
          POWERSHELL,
          [
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$t=$null;$e=$null;$a=[System.Management.Automation.Language.Parser]::ParseFile($env:HARPOC_PS1,[ref]$t,[ref]$e);" +
              "[Console]::Out.WriteLine('errors '+$e.Count);" +
              "[Console]::Out.WriteLine('param '+($null -ne $a.ParamBlock));" +
              "[Console]::Out.WriteLine('first '+$a.EndBlock.Statements[0].Extent.Text);" +
              "[Console]::Out.WriteLine('second '+$a.EndBlock.Statements[1].Extent.Text);" +
              "[Console]::Out.WriteLine('elevation '+($null -ne $a.ScriptRequirements -and $a.ScriptRequirements.IsElevationRequired))",
          ],
          {
            shell: false,
            windowsHide: true,
            encoding: "utf8",
            timeout: 30_000,
            env: { ...process.env, HARPOC_PS1: resolve(deployRoot, script) },
          },
        );
        expect(run.status).toBe(0);
        expect(run.stdout.trim().split(/\r?\n/)).toEqual([
          "errors 0",
          "param True",
          "first Set-StrictMode -Version Latest",
          "second $ErrorActionPreference = 'Stop'",
          "elevation False",
        ]);
      },
    );

    it.each(PS_SCRIPTS)("%s -Help prints its usage and exits 0", (script) => {
      const run = runPs1(script, ["-Help"]);
      expect(run.status).toBe(0);
      expect(run.stdout).toContain(`Usage: ${script.slice("windows/".length)}`);
      expect(run.stderr).toBe("");
    });

    it("register-service.ps1 -DryRun prints the startup task: the memory session, the DPAPI-sealed key, no time limit — and registers nothing", () => {
      const programData = join(root, "ProgramData");
      mkdirSync(programData);
      const base = join(programData, "harpoc");
      const spec = `agent=agent-k,file=${join(base, "run", "agent-k", "token.jwt")},scope=use,secrets=api-key`;
      const run = runPs1("windows/register-service.ps1", [
        "-DryRun",
        "-Node",
        process.execPath,
        "-Cli",
        cli,
        "-ProgramData",
        programData,
        "-Proxy",
        "-SshAgent",
        "-IssueToken",
        spec,
      ]);
      expect(run.stderr).toBe("");
      expect(run.status).toBe(0);
      const vault = join(base, "vault");
      const argument = [
        join(cli, "dist", "index.js"),
        "--vault-dir",
        vault,
        "server",
        "start",
        "--rest",
        "--session",
        "memory",
        "--unlock-key-dpapi",
        join(vault, "unlock.key.dpapi"),
        "--runtime-dir",
        join(base, "run"),
        "--proxy",
        "--ssh-agent",
        "--issue-token",
        spec,
      ]
        .map(winArg)
        .join(" ");
      expect(run.stdout.trim().split(/\r?\n/)).toEqual([
        "task Harpoc",
        `principal ${process.env["COMPUTERNAME"] ?? ""}\\harpoc (logon type Password, run level Limited)`,
        `execute ${process.execPath}`,
        `argument ${argument}`,
        `working directory ${base}`,
        "trigger at startup",
        "settings ExecutionTimeLimit=PT0S RestartCount=2 RestartInterval=PT1M MultipleInstances=IgnoreNew StartWhenAvailable AllowStartIfOnBatteries DontStopIfGoingOnBatteries",
        "dry run: nothing registered",
      ]);
      expect(existsSync(base)).toBe(false);
    });

    it.each([
      {
        script: "install-two-identity.ps1",
        args: () => ["-AgentUser", "Agent"],
        says: "not a consumer name",
      },
      {
        script: "install-two-identity.ps1",
        args: () => ["-AgentUser", "harpoc"],
        says: "the vault user cannot be an agent user",
      },
      {
        script: "install-two-identity.ps1",
        args: () => ["-AgentUser", "nul"],
        says: "a Windows reserved device name cannot be a consumer name: nul",
      },
      {
        script: "install-two-identity.ps1",
        args: () => ["-AgentUser", "agent-a,com1"],
        says: "a Windows reserved device name cannot be a consumer name: com1",
      },
      {
        script: "install-two-identity.ps1",
        args: () => ["-VaultUser", "lpt9"],
        says: "a Windows reserved device name cannot be the vault account: lpt9",
      },
      {
        script: "install-two-identity.ps1",
        args: () => ["-AgentUser", "no-such-agent-b7"],
        says: "no such local account: no-such-agent-b7",
      },
      {
        script: "install-two-identity.ps1",
        args: () => ["-VaultUser", "Harpoc"],
        says: "not an account name",
      },
      {
        script: "install-two-identity.ps1",
        args: () => ["-ProgramData", "relative"],
        says: "-ProgramData must be an absolute path",
      },
      {
        script: "register-service.ps1",
        args: () => ["-DryRun", "-Node", join(root, "absent", "node.exe")],
        says: "-Node: no such file",
      },
      {
        script: "register-service.ps1",
        args: () => ["-DryRun", "-Node", process.execPath, "-Cli", join(root, "absent")],
        says: "-Cli: no built CLI",
      },
      {
        script: "register-service.ps1",
        args: () => ["-Node", process.execPath, "-Cli", cli, "-IssueToken", "-x"],
        says: "-IssueToken: not a spec",
      },
      {
        script: "enroll-unlock-key.ps1",
        args: () => ["-Out", "relative.dpapi"],
        says: "-Out must be an absolute path",
      },
      {
        script: "enroll-unlock-key.ps1",
        args: () => ["-Out", join(cli, "dist", "index.js")],
        says: "exists; the sealed key is written to a new file only",
      },
    ])(
      "$script refuses ($says) with exit 2 before its administrator check",
      ({ script, args, says }) => {
        const run = runPs1(`windows/${script}`, args());
        expect(run.status).toBe(2);
        expect(run.stderr.startsWith(`${script}: `)).toBe(true);
        expect(run.stderr).toContain(says);
        expect(run.stderr).not.toContain("must run elevated");
      },
    );

    // Elevated, the scripts pass their administrator check and would create the account, the
    // directories and the task: the runners run elevated, so this row is the desktop's.
    it("with valid arguments each script stops at its administrator check for a non-elevated user (exit 1, nothing created)", (ctx) => {
      if (elevated) ctx.skip();
      const programData = join(root, "ProgramData-valid");
      mkdirSync(programData);
      const base = join(programData, "harpoc");
      for (const [script, args] of [
        ["install-two-identity.ps1", ["-ProgramData", programData]],
        [
          "register-service.ps1",
          ["-Node", process.execPath, "-Cli", cli, "-ProgramData", programData],
        ],
        [
          "enroll-unlock-key.ps1",
          ["-Node", process.execPath, "-Cli", cli, "-Out", join(root, "unlock.key.dpapi")],
        ],
      ] as const) {
        const run = runPs1(`windows/${script}`, [...args]);
        expect(run.status, script).toBe(1);
        expect(run.stderr).toBe(`${script}: must run elevated (an Administrator PowerShell)\r\n`);
      }
      expect(existsSync(base)).toBe(false);
      expect(existsSync(join(root, "unlock.key.dpapi"))).toBe(false);
    });

    // Elevated, the layout is readable and the scripts go on past their checks: like the row above, the desktop's.
    it("on the layout the recipe leaves (harpoc and harpoc\\vault open to SYSTEM and Administrators alone) install-two-identity.ps1 and enroll-unlock-key.ps1 stop at their administrator check for a non-elevated user (exit 1, no PowerShell text)", (ctx) => {
      if (elevated) ctx.skip();
      const programData = join(root, "ProgramData-installed");
      const base = join(programData, "harpoc");
      const vault = join(base, "vault");
      mkdirSync(vault, { recursive: true });
      writeFileSync(join(vault, "unlock.key.dpapi"), "");
      for (const dir of [vault, base]) {
        denied.unshift(dir);
        const acl = spawnSync(
          ICACLS,
          [dir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"],
          { shell: false, windowsHide: true, encoding: "utf8", timeout: 30_000 },
        );
        expect(acl.status).toBe(0);
      }
      for (const [script, args] of [
        ["install-two-identity.ps1", ["-ProgramData", programData]],
        [
          "enroll-unlock-key.ps1",
          ["-Node", process.execPath, "-Cli", cli, "-ProgramData", programData],
        ],
        [
          "enroll-unlock-key.ps1",
          [
            "-Node",
            process.execPath,
            "-Cli",
            cli,
            "-ProgramData",
            programData,
            "-Out",
            join(vault, "absent.dpapi"),
          ],
        ],
      ] as const) {
        const run = runPs1(`windows/${script}`, [...args]);
        expect(run.status, script).toBe(1);
        expect(run.stderr).toBe(`${script}: must run elevated (an Administrator PowerShell)\r\n`);
      }
    });

    it("install-two-identity.ps1 refuses an existing harpoc directory that is a junction (a reparse point) as a usage error before its administrator check", () => {
      const programData = join(root, "ProgramData-junction");
      const target = join(root, "junction-target");
      mkdirSync(programData);
      mkdirSync(target);
      const link = join(programData, "harpoc");
      symlinkSync(target, link, "junction");
      junction = link;
      const run = runPs1("windows/install-two-identity.ps1", ["-ProgramData", programData]);
      expect(run.stderr).toBe(
        `install-two-identity.ps1: ${link} is a reparse point (junction or symbolic link); remove it\r\n`,
      );
      expect(run.status).toBe(2);
      expect(readdirSync(target)).toEqual([]);
    });

    it("install-two-identity.ps1 refuses an existing harpoc that is a file, not a directory, as a usage error before its administrator check", () => {
      const programData = join(root, "ProgramData-file");
      mkdirSync(programData);
      const file = join(programData, "harpoc");
      writeFileSync(file, "");
      const run = runPs1("windows/install-two-identity.ps1", ["-ProgramData", programData]);
      expect(run.stderr).toBe(
        `install-two-identity.ps1: ${file} exists and is not a directory; remove it\r\n`,
      );
      expect(run.status).toBe(2);
    });
  },
);
