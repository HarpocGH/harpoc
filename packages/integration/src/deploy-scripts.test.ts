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
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { getPkgRoot } from "@harpoc/test-utils";
import { POWERSHELL } from "./helpers/spawn-cli.js";

const repoRoot = resolve(getPkgRoot(import.meta.url), "..", "..");
const deployRoot = resolve(repoRoot, "deploy");

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

  it("windows/register-service.ps1 grants the vault account Log on as a batch job before it registers the task, reads the grant back before it prompts for the password, and refuses an account that is denied it", () => {
    const text = psText("windows/register-service.ps1");
    expect(text).toContain("$BatchLogonRight = 'SeBatchLogonRight'");
    expect(text).toContain("$DenyBatchLogonRight = 'SeDenyBatchLogonRight'");
    const elevation = text.lastIndexOf("if (-not (Test-Elevated))");
    const grant = text.indexOf("Invoke-AccountRights 'add' $account.SID.Value $BatchLogonRight");
    const register = text.indexOf("Register-ScheduledTask -TaskName");
    expect(elevation).toBeGreaterThan(-1);
    expect(grant).toBeGreaterThan(elevation);
    expect(grant).toBeLessThan(register);
    const deny = text.indexOf("if ($held -contains $DenyBatchLogonRight)");
    expect(deny).toBeGreaterThan(elevation);
    expect(deny).toBeLessThan(grant);
    const readBack = text.indexOf("-notcontains $BatchLogonRight");
    expect(readBack).toBeGreaterThan(grant);
    expect(readBack).toBeLessThan(register);
    const promptAt = text.indexOf("Read-Host -AsSecureString");
    expect(promptAt).toBeGreaterThan(readBack);
    expect(promptAt).toBeLessThan(register);
  });

  it("windows/register-service.ps1's account-rights helper calls the three LSA account-rights functions and handles no secret", () => {
    const text = psText("windows/register-service.ps1");
    const start = text.indexOf("$AccountRightsSource = @'\n");
    const end = text.indexOf("\n'@\n", start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const helper = text.slice(start, end);
    for (const call of [
      "LsaEnumerateAccountRights",
      "LsaAddAccountRights",
      "LsaRemoveAccountRights",
    ]) {
      expect(helper.includes(call), call).toBe(true);
    }
    expect(helper).toContain("LsaRemoveAccountRights(policy, SidBytes(sid), false, rights, 1)");
    expect(/password|plain|credential|securestring|logonuser/i.test(helper)).toBe(false);
  });

  it("windows/register-service.ps1 -Unregister takes the account name alone, checks elevation itself, and only then removes the task and the right", () => {
    const text = psText("windows/register-service.ps1");
    const branch = text.indexOf("if ($Unregister) {");
    expect(branch).toBeGreaterThan(text.indexOf("cnotmatch"));
    const refusal = text.indexOf("-Unregister takes -VaultUser alone");
    const elevation = text.indexOf("if (-not (Test-Elevated))");
    expect(refusal).toBeGreaterThan(branch);
    expect(refusal).toBeLessThan(elevation);
    expect(text.indexOf("Unregister-ScheduledTask -TaskName $TaskName")).toBeGreaterThan(elevation);
    expect(text.indexOf("Invoke-AccountRights 'remove'")).toBeGreaterThan(elevation);
    expect(text).toContain(
      "Get-ScheduledTask -TaskName $TaskName -TaskPath '\\' -ErrorAction SilentlyContinue",
    );
    expect(text).toContain(
      "Unregister-ScheduledTask -TaskName $TaskName -TaskPath '\\' -Confirm:$false",
    );
  });
});

/** The `run:` block of e2e.yml's task smoke step as lines without the block's indentation, read by text from the step's `name:` line; empty when the step or its block is not where it stands. */
function taskSmokeStep(): string[] {
  const lines = readFileSync(resolve(repoRoot, ".github", "workflows", "e2e.yml"), "utf8").split(
    /\r?\n/,
  );
  const stepAt = lines.indexOf(
    "      - name: Register, start and stop the daemon as a startup task (the Password-logon cell)",
  );
  const run = lines.indexOf("        run: |", stepAt);
  if (stepAt < 0 || run < 0 || lines.slice(stepAt + 1, run).some((l) => l.startsWith("      - "))) {
    return [];
  }
  const indent = /^ +/.exec(lines[run + 1] ?? "")?.[0] ?? "";
  if (indent.length <= 8) return [];
  const block: string[] = [];
  for (const line of lines.slice(run + 1)) {
    if (line.trim() !== "" && !line.startsWith(indent)) break;
    block.push(line.slice(indent.length));
  }
  return block;
}

describe("e2e.yml's task smoke step (the Password-logon cell, its PowerShell read as text)", () => {
  it("the step's last statement is $global:LASTEXITCODE = 0, and Invoke-Diagnostic resets it after its try / catch (a native exit code a diagnostic leaves is never the step's status)", () => {
    const block = taskSmokeStep();
    expect(block.filter((l) => l.trim() !== "").at(-1)).toBe("$global:LASTEXITCODE = 0");
    const text = block.join("\n");
    const start = text.indexOf("function Invoke-Diagnostic(");
    const end = text.indexOf("\n}\n", start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const diagnostic = text.slice(start, end);
    const guarded = diagnostic.indexOf("\n  try { & $Body } catch {");
    expect(guarded).toBeGreaterThan(-1);
    expect(diagnostic.indexOf("\n  $global:LASTEXITCODE = 0", guarded + 1)).toBeGreaterThan(
      guarded,
    );
  });

  it("no statement that writes to the job log names a password variable, and the batch logon's unmanaged copy of the vault account's password is zeroed in a finally", () => {
    const block = taskSmokeStep();
    const text = block.join("\n");
    for (const secret of [
      "$vaultSecure",
      "$password",
      "$smokePassword",
      "$InputText",
      "$line",
      "$bytes",
      "$env:HARPOC_TWO_USER_VAULT_PASSWORD",
    ]) {
      expect(text.includes(secret), secret).toBe(true);
    }
    const names =
      /\$\{?(?:\w+:)?(vaultSecure|password|smokePassword|InputText|line|bytes)\b|HARPOC_TWO_USER_VAULT_PASSWORD/i;
    const writes =
      /\b(Write-(Output|Host|Warning|Error|Information|Verbose|Debug)|Out-(String|Host|Default)|throw)\b|(?<![\w.$:-])(echo|write)(?![\w-])|\[(System\.)?Console\]::((Out|Error)\.)?Write|^\s*(\$\{?[\w:]+\}?|"[^"]*"|'[^']*')\s*$/i;
    const statements = block.filter((l) => !/^\s*#/.test(l));
    expect(statements.filter((l) => writes.test(l)).length).toBeGreaterThan(0);
    expect(statements.filter((l) => names.test(l)).length).toBeGreaterThan(0);
    expect(statements.filter((l) => writes.test(l) && names.test(l))).toEqual([]);
    expect(text.split("SecureStringTo").length - 1).toBe(1);
    const probe = text.indexOf("function Test-BatchLogon {");
    const probeEnd = text.indexOf("\n}\n", probe);
    expect(probe).toBeGreaterThan(-1);
    expect(probeEnd).toBeGreaterThan(probe);
    expect(text.slice(probe, probeEnd)).toContain(
      "\n  $password = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($vaultSecure)\n" +
        "  try { $code = [HarpocSmokeLogon]::Batch($vaultUser, $password) } finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($password) }\n",
    );
  });
});

/** One argument as the Windows C runtime reads it back (the scripts' ConvertTo-Argument, for paths without quotes). */
const winArg = (value: string): string => (/\s/.test(value) ? `"${value}"` : value);

/** A recipe row's spawn budget: a module-loading cmdlet answers in tens of seconds under the full gate on windows-latest (`decisions.md` § "The WMI listing series"). */
const PS1_TIMEOUT_MS = 180_000;

/** The recipe rows' environment: the inherited one with `PSModulePath` narrowed to the in-box modules the three scripts load (Management, Utility, Security, LocalAccounts, ScheduledTasks). */
function recipeEnvironment(): NodeJS.ProcessEnv {
  return {
    ...Object.fromEntries(
      Object.entries(process.env).filter(([name]) => name.toLowerCase() !== "psmodulepath"),
    ),
    PSModulePath: join(
      process.env["SystemRoot"] ?? "C:\\Windows",
      "System32",
      "WindowsPowerShell",
      "v1.0",
      "Modules",
    ),
  };
}

/** The elevation probe's answer: exit 0 and exactly `True` or `False`; anything else throws, naming the status. */
function elevationVerdict(probe: {
  status: number | null;
  stdout: string | null | undefined;
  error?: Error;
  signal?: NodeJS.Signals | null;
}): boolean {
  if (probe.status === 0 && (probe.stdout === "True" || probe.stdout === "False")) {
    return probe.stdout === "True";
  }
  const code = (probe.error as NodeJS.ErrnoException | undefined)?.code;
  const cause = [code, probe.signal].filter((part) => part !== undefined && part !== null);
  throw new Error(
    `the elevation probe answered exit ${String(probe.status)}${cause.length > 0 ? ` (${cause.join(", ")})` : ""}, stdout ${JSON.stringify((probe.stdout ?? "").slice(0, 80))}: not exactly True or False`,
  );
}

describe("the elevation probe's verdict (the win32 suite's beforeAll — it fails closed)", () => {
  it("reads exit 0 with exactly True as elevated and exactly False as not", () => {
    expect(elevationVerdict({ status: 0, stdout: "True" })).toBe(true);
    expect(elevationVerdict({ status: 0, stdout: "False" })).toBe(false);
  });

  it.each([
    [
      "a timeout",
      {
        status: null,
        stdout: "",
        error: Object.assign(new Error("spawnSync powershell.exe ETIMEDOUT"), {
          code: "ETIMEDOUT",
        }),
        signal: "SIGTERM" as const,
      },
      /^the elevation probe answered exit null \(ETIMEDOUT, SIGTERM\)/,
    ],
    [
      "a host that cannot be spawned",
      {
        status: null,
        stdout: undefined,
        error: Object.assign(new Error("spawnSync powershell.exe ENOENT"), { code: "ENOENT" }),
      },
      /^the elevation probe answered exit null \(ENOENT\), stdout "": not exactly True or False$/,
    ],
    ["a non-zero status", { status: 1, stdout: "True" }, /^the elevation probe answered exit 1\b/],
    [
      "other text",
      { status: 0, stdout: "WARNING: x\r\nTrue" },
      /^the elevation probe answered exit 0\b/,
    ],
    ["no output", { status: 0, stdout: "" }, /^the elevation probe answered exit 0\b/],
  ])("refuses %s, naming the status — never a silent 'not elevated'", (_, probe, says) => {
    expect(() => elevationVerdict(probe)).toThrow(says);
  });
});

describe.skipIf(process.platform !== "win32")(
  "deploy PowerShell scripts on win32 (the pinned Windows PowerShell 5.1 host; a .ps1 runs under -ExecutionPolicy Bypass, the client default refuses script files)",
  () => {
    let root = "";
    let cli = "";
    let elevated = false;
    let junction = "";
    const denied: string[] = [];

    let rowStart = 0;

    beforeEach(() => {
      rowStart = performance.now();
    });

    function runPs1(
      script: string,
      args: string[],
    ): { status: number | null; stdout: string; stderr: string; measured: string } {
      const started = performance.now();
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
        {
          shell: false,
          windowsHide: true,
          encoding: "utf8",
          timeout: PS1_TIMEOUT_MS,
          env: recipeEnvironment(),
        },
      );
      const ended = performance.now();
      const measured = `${script}: exit ${String(run.status)}, error ${(run.error as NodeJS.ErrnoException | undefined)?.code ?? "none"}, the spawn ${String(Math.round(ended - started))} ms, the row ${String(Math.round(ended - rowStart))} ms`;
      expect(run.error, measured).toBeUndefined();
      return { status: run.status, stdout: run.stdout, stderr: run.stderr, measured };
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
          "[System.Console]::Out.Write([System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))",
        ],
        { shell: false, windowsHide: true, encoding: "utf8", timeout: 30_000 },
      );
      elevated = elevationVerdict(probe);
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

    it.each(PS_SCRIPTS)(
      "%s -Help prints its usage and exits 0",
      (script) => {
        const run = runPs1(script, ["-Help"]);
        expect(run.status, run.measured).toBe(0);
        expect(run.stdout).toContain(`Usage: ${script.slice("windows/".length)}`);
        expect(run.stderr, run.measured).toBe("");
      },
      210_000,
    );

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
      expect(run.stderr, run.measured).toBe("");
      expect(run.status, run.measured).toBe(0);
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
        "right SeBatchLogonRight (Log on as a batch job), granted to the principal unless held",
        `execute ${process.execPath}`,
        `argument ${argument}`,
        `working directory ${base}`,
        "trigger at startup",
        "settings ExecutionTimeLimit=PT0S RestartCount=2 RestartInterval=PT1M MultipleInstances=IgnoreNew StartWhenAvailable AllowStartIfOnBatteries DontStopIfGoingOnBatteries",
        "dry run: nothing registered",
      ]);
      expect(existsSync(base)).toBe(false);
    }, 210_000);

    it("register-service.ps1's account-rights helper compiles under the pinned host and lists an account's own rights without a change", () => {
      const sids = elevated ? ["S-1-0-0", "S-1-5-32-544"] : ["S-1-0-0"];
      const run = spawnSync(
        POWERSHELL,
        [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "$ErrorActionPreference='Stop';$t=$null;$e=$null;$a=[System.Management.Automation.Language.Parser]::ParseFile($env:HARPOC_PS1,[ref]$t,[ref]$e);" +
            "$s=$a.Find({param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$AccountRightsSource'},$true);" +
            "Add-Type -TypeDefinition $s.Right.Expression.Value;" +
            "foreach($sid in $env:HARPOC_SIDS -split ','){[Console]::Out.WriteLine($sid+' '+@([Harpoc.Deploy.AccountRights]::Enumerate($sid)).Count)}",
        ],
        {
          shell: false,
          windowsHide: true,
          encoding: "utf8",
          timeout: PS1_TIMEOUT_MS,
          env: {
            ...recipeEnvironment(),
            HARPOC_PS1: resolve(deployRoot, "windows/register-service.ps1"),
            HARPOC_SIDS: sids.join(","),
          },
        },
      );
      expect(run.error).toBeUndefined();
      expect(run.stderr).toBe("");
      expect(run.status).toBe(0);
      const lines = run.stdout.trim().split(/\r?\n/);
      expect(lines.length).toBe(sids.length);
      expect(lines[0]).toBe("S-1-0-0 0");
      if (elevated) expect(lines[1]).toMatch(/^S-1-5-32-544 [1-9]\d*$/);
    }, 210_000);

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
        script: "register-service.ps1",
        args: () => ["-Unregister", "-DryRun"],
        says: "-Unregister takes -VaultUser alone",
      },
      {
        script: "register-service.ps1",
        args: () => ["-Unregister", "-ProgramData", join(root, "ProgramData-unregister")],
        says: "register-service.ps1: -Unregister takes -VaultUser alone",
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
        expect(run.status, run.measured).toBe(2);
        expect(run.stderr.startsWith(`${script}: `)).toBe(true);
        expect(run.stderr).toContain(says);
        expect(run.stderr).not.toContain("must run elevated");
      },
      210_000,
    );

    // Elevated, the scripts pass their administrator check and would create the account, the
    // directories and the task, and `-Unregister` would remove the task and the right: the
    // runners run elevated, so this row is the desktop's.
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
        ["register-service.ps1", ["-Unregister"]],
        [
          "enroll-unlock-key.ps1",
          ["-Node", process.execPath, "-Cli", cli, "-Out", join(root, "unlock.key.dpapi")],
        ],
      ] as const) {
        const run = runPs1(`windows/${script}`, [...args]);
        expect(run.status, run.measured).toBe(1);
        expect(run.stderr, run.measured).toBe(
          `${script}: must run elevated (an Administrator PowerShell)\r\n`,
        );
      }
      expect(existsSync(base)).toBe(false);
      expect(existsSync(join(root, "unlock.key.dpapi"))).toBe(false);
    }, 750_000);

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
        expect(run.status, run.measured).toBe(1);
        expect(run.stderr, run.measured).toBe(
          `${script}: must run elevated (an Administrator PowerShell)\r\n`,
        );
      }
    }, 630_000);

    it("install-two-identity.ps1 refuses an existing harpoc directory that is a junction (a reparse point) as a usage error before its administrator check", () => {
      const programData = join(root, "ProgramData-junction");
      const target = join(root, "junction-target");
      mkdirSync(programData);
      mkdirSync(target);
      const link = join(programData, "harpoc");
      symlinkSync(target, link, "junction");
      junction = link;
      const run = runPs1("windows/install-two-identity.ps1", ["-ProgramData", programData]);
      expect(run.stderr, run.measured).toBe(
        `install-two-identity.ps1: ${link} is a reparse point (junction or symbolic link); remove it\r\n`,
      );
      expect(run.status, run.measured).toBe(2);
      expect(readdirSync(target)).toEqual([]);
    }, 210_000);

    it("install-two-identity.ps1 refuses an existing harpoc that is a file, not a directory, as a usage error before its administrator check", () => {
      const programData = join(root, "ProgramData-file");
      mkdirSync(programData);
      const file = join(programData, "harpoc");
      writeFileSync(file, "");
      const run = runPs1("windows/install-two-identity.ps1", ["-ProgramData", programData]);
      expect(run.stderr, run.measured).toBe(
        `install-two-identity.ps1: ${file} exists and is not a directory; remove it\r\n`,
      );
      expect(run.status, run.measured).toBe(2);
    }, 210_000);
  },
);
