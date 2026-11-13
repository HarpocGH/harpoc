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

const RUN_SH = resolve(deployRoot, "dev-container", "run.sh");

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

  it("dev-container/run.sh refuses with exit 75 while a running container mounts the harpoc-dev-work volume, before docker run (docker ps without -a: a stopped container that still names the volume is no refusal)", () => {
    const text = readFileSync(RUN_SH, "utf8");
    const check = text.indexOf('\nrunning="$(docker ps -q --filter volume=harpoc-dev-work)"\n');
    const refusal = text.indexOf(
      '\nif [ -n "$running" ]; then\n  echo "run.sh: another run.sh is using the harpoc-dev-work volume" >&2\n  exit 75\nfi\n',
    );
    expect(check).toBeGreaterThan(-1);
    expect(refusal).toBeGreaterThan(check);
    expect(text.indexOf("docker run ")).toBeGreaterThan(refusal);
    expect(text.split("docker ps").length - 1).toBe(1);
  });

  it("dev-container/run.sh runs the whole suite cold and serially: pnpm test --force --concurrency=1 (no replay from /work/.turbo, no starved Argon2 inits)", () => {
    const lines = readFileSync(RUN_SH, "utf8").split("\n");
    expect(lines).toContain(
      `suite='dbus-run-session -- sh -c '"'"'echo harpoc-ci | gnome-keyring-daemon --unlock; keyctl link @u @s || true; pnpm test --force --concurrency=1'"'"`,
    );
  });

  it("dev-container/run.sh refuses with exit 2, before its memory check and before docker build, when HARPOC_DEV_MIN_AVAILABLE_MB is not a whole number of MB (a malformed value never skips the memory check)", () => {
    const text = readFileSync(RUN_SH, "utf8");
    const guard = text.indexOf(
      [
        "",
        'case "$min_available_mb" in',
        "  *[!0-9]*)",
        '    echo "run.sh: HARPOC_DEV_MIN_AVAILABLE_MB must be a whole number of MB (0 skips the check)" >&2',
        "    exit 2",
        "    ;;",
        "esac",
        "",
      ].join("\n"),
    );
    const read = text.indexOf('\nmin_available_mb="${HARPOC_DEV_MIN_AVAILABLE_MB:-');
    expect(guard).toBeGreaterThan(-1);
    expect(read).toBeGreaterThan(-1);
    expect(guard).toBeGreaterThan(read);
    expect(text.indexOf('\nif ! [ "$min_available_mb" -eq 0 ]; then\n')).toBeGreaterThan(guard);
    expect(text.indexOf("docker build ")).toBeGreaterThan(guard);
  });

  it("dev-container/run.sh refuses with exit 75 before docker build when the host's available memory is under HARPOC_DEV_MIN_AVAILABLE_MB, naming both numbers (default 8192, 0 skips the check; FreePhysicalMemory under Git Bash, MemAvailable on Linux, no check elsewhere)", () => {
    const text = readFileSync(RUN_SH, "utf8");
    const read = text.indexOf('\nmin_available_mb="${HARPOC_DEV_MIN_AVAILABLE_MB:-8192}"\n');
    const check = text.indexOf(
      [
        "",
        'if ! [ "$min_available_mb" -eq 0 ]; then',
        '  case "$(uname -s)" in',
        "    MINGW* | MSYS*)",
        '      available_mb="$(powershell.exe -NoProfile -Command "[int]((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory/1024)")"',
        "      available_mb=${available_mb%$'\\r'}",
        "      ;;",
        "    Linux) available_mb=\"$(awk '/^MemAvailable:/ { print int($2 / 1024) }' /proc/meminfo)\" ;;",
        "    *) available_mb= ;;",
        "  esac",
        '  if [ -n "$available_mb" ] && ! [ "$available_mb" -ge "$min_available_mb" ]; then',
        '    echo "run.sh: the host has $available_mb MB of memory available, under HARPOC_DEV_MIN_AVAILABLE_MB=$min_available_mb (0 skips the check)" >&2',
        "    exit 75",
        "  fi",
        "fi",
        "",
      ].join("\n"),
    );
    expect(read).toBeGreaterThan(-1);
    expect(check).toBeGreaterThan(read);
    expect(text.indexOf("docker build ")).toBeGreaterThan(check);
    expect(text.split("HARPOC_DEV_MIN_AVAILABLE_MB:-").length - 1).toBe(1);
  });

  it("dev-container/run.sh's usage text names HARPOC_DEV_MIN_AVAILABLE_MB with its default and the value that skips the check", () => {
    const text = readFileSync(RUN_SH, "utf8");
    const start = text.indexOf("cat <<USAGE\n");
    const end = text.indexOf("\nUSAGE\n", start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    expect(text.slice(start, end)).toContain(
      "\n  HARPOC_DEV_MIN_AVAILABLE_MB\n                     the host's available memory in MB below which run.sh refuses\n                     (default 8192; 0 skips the check)",
    );
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

  it.each(PS_SCRIPTS)(
    "%s turns module auto-loading off directly after $ErrorActionPreference, then defines Import-InBoxModule and imports Utility and Management with it: its one Import-Module takes the manifest's path under $PSHOME, never a bare module name, and a module not found there exactly once ends the script with exit 1",
    (script) => {
      const text = psText(script);
      const head = [
        "$ErrorActionPreference = 'Stop'",
        "$PSModuleAutoLoadingPreference = 'None'",
        "",
        "# Import an in-box module by its manifest's path under $PSHOME, never through PSModulePath;",
        "# a module not found there exactly once ends the script (exit 1).",
        "function Import-InBoxModule([string]$Name) {",
        "  $manifests = @()",
        "  try {",
        "    $manifests = [System.IO.Directory]::GetFiles([System.IO.Path]::Combine($PSHOME, 'Modules', $Name), \"$Name.psd1\", [System.IO.SearchOption]::AllDirectories)",
        "  } catch {",
        "    $manifests = @()",
        "  }",
        "  if ($manifests.Count -ne 1) {",
        '    [Console]::Error.WriteLine("the in-box module $Name was not found under $PSHOME")',
        "    exit 1",
        "  }",
        "  Import-Module -Name $manifests[0]",
        "}",
        "",
        "Import-InBoxModule 'Microsoft.PowerShell.Utility'",
        "Import-InBoxModule 'Microsoft.PowerShell.Management'",
        ...(script === "windows/install-two-identity.ps1"
          ? ["Import-InBoxModule 'Microsoft.PowerShell.LocalAccounts'"]
          : []),
        "",
        "$Prog = ",
      ].join("\n");
      expect(text).toContain(`)\nSet-StrictMode -Version Latest\n${head}`);
      expect(text.split("$PSModuleAutoLoadingPreference").length - 1).toBe(1);
      expect(text.split("Import-Module").length - 1).toBe(1);
      expect(text.split("function Import-InBoxModule(").length - 1).toBe(1);
    },
  );

  it("each elevated half imports its modules after its elevation check and before its first state-changing call, so a module the image lacks ends the script before any account, grant, registration or write: enroll-unlock-key.ps1 before Start-Process, install-two-identity.ps1 before New-LocalUser, register-service.ps1's -Unregister before Unregister-ScheduledTask and its registration before the grant", () => {
    const halves = [
      {
        script: "windows/enroll-unlock-key.ps1",
        checks: 1,
        nth: 0,
        imports: ["Microsoft.PowerShell.LocalAccounts", "Microsoft.PowerShell.Security"],
        change: "Start-Process -FilePath $Node",
      },
      {
        script: "windows/install-two-identity.ps1",
        checks: 1,
        nth: 0,
        imports: ["Microsoft.PowerShell.Security"],
        change: "New-LocalUser -Name $VaultUser",
      },
      {
        script: "windows/register-service.ps1",
        checks: 2,
        nth: 0,
        imports: ["Microsoft.PowerShell.LocalAccounts", "ScheduledTasks"],
        change: "Unregister-ScheduledTask -TaskName $TaskName",
      },
      {
        script: "windows/register-service.ps1",
        checks: 2,
        nth: 1,
        imports: ["Microsoft.PowerShell.LocalAccounts", "ScheduledTasks"],
        change: "Invoke-AccountRights 'add' $account.SID.Value $BatchLogonRight",
      },
    ];
    for (const half of halves) {
      const text = psText(half.script);
      const checks = [...text.matchAll(/if \(-not \(Test-Elevated\)\)/g)].map(
        (match) => match.index,
      );
      expect(checks.length, half.script).toBe(half.checks);
      const elevation = checks[half.nth] ?? -1;
      expect(elevation, half.script).toBeGreaterThan(-1);
      expect(text.split(half.change).length - 1, half.change).toBe(1);
      const change = text.indexOf(half.change);
      for (const moduleName of half.imports) {
        const at = text.indexOf(`Import-InBoxModule '${moduleName}'`, elevation);
        expect(at, `${half.script}: ${moduleName} after the elevation check`).toBeGreaterThan(
          elevation,
        );
        expect(at, `${half.script}: ${moduleName} before ${half.change}`).toBeLessThan(change);
      }
    }
  });

  it("every account-name pattern of the PowerShell scripts ends with \\z, none with $ (.NET's $ also matches before a final line feed, so a name with a trailing line feed passed it)", () => {
    const counts = Object.fromEntries(
      PS_SCRIPTS.map((script) => {
        const text = psText(script);
        return [
          script,
          {
            endsZ: text.split("'^[a-z0-9_][a-z0-9_-]{0,19}\\z'").length - 1,
            endsDollar: text.split("'^[a-z0-9_][a-z0-9_-]{0,19}$'").length - 1,
          },
        ];
      }),
    );
    expect(counts).toEqual({
      "windows/enroll-unlock-key.ps1": { endsZ: 1, endsDollar: 0 },
      "windows/install-two-identity.ps1": { endsZ: 2, endsDollar: 0 },
      "windows/register-service.ps1": { endsZ: 1, endsDollar: 0 },
    });
  });

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

  it("windows/enroll-unlock-key.ps1 names a launch that could not start: directly after Start-Process and before its generic failure, an exit of -1073741502 (0xC0000142) ends the script with exit 1 and a message of its own naming the desktop the launch needs, and its usage text says where to run it", () => {
    const text = psText("windows/enroll-unlock-key.ps1");
    const launch = "$process = Start-Process -FilePath $Node";
    const branch = "if ($process.ExitCode -eq -1073741502) {";
    const generic = "if ($process.ExitCode -ne 0) {";
    const genericFailure =
      '  Stop-WithError "the enrolment as $VaultUser failed (exit $($process.ExitCode)); nothing sealed" 1';
    const desktopFailure =
      "  Stop-WithError \"the CLI could not start as $VaultUser (exit 0xC0000142: the process could not initialise): a launch as another account needs this session's desktop - run this script in an elevated PowerShell window on the machine's own desktop (the console or a Remote Desktop session), not from a scheduled task or a service; nothing sealed\" 1";
    for (const needle of [launch, branch, generic, genericFailure, desktopFailure]) {
      expect(text.split(needle).length - 1, needle).toBe(1);
    }
    const launchAt = text.indexOf(launch);
    const branchAt = text.indexOf(branch);
    expect(branchAt).toBeGreaterThan(launchAt);
    expect(branchAt).toBeLessThan(text.indexOf(generic));
    expect(text).toContain(
      ` -Wait -PassThru\n${branch}\n${desktopFailure}\n}\n${generic}\n${genericFailure}\n}\n`,
    );
    const usage = [
      "Run it in an elevated PowerShell window on the machine's own desktop (the console or a Remote",
      "Desktop session): it asks for a password and opens a console window. If the launch as",
      "<VaultUser> ends before the CLI starts with exit 0xC0000142 - seen for the same Win32 call",
      "from a scheduled task - the script says so; nothing is sealed.",
    ].join("\n");
    expect(text.split(usage).length - 1).toBe(1);
    expect(text).toContain(
      `No byte of the key and no password is printed.\n\n${usage}\n\nExit status:`,
    );
  });
});

/** The lines of the workflow file `workflow` under .github/workflows/, read by text. */
function workflowLines(workflow: "ci.yml" | "e2e.yml"): string[] {
  return readFileSync(resolve(repoRoot, ".github", "workflows", workflow), "utf8").split(/\r?\n/);
}

/** The steps of the job `jobId` in `workflow`, each as its lines with their indentation from its `- ` line to the next step or the job's end; empty when the job is not where it stands. */
function workflowJobSteps(workflow: "ci.yml" | "e2e.yml", jobId: string): string[][] {
  const lines = workflowLines(workflow);
  const jobAt = lines.indexOf(`  ${jobId}:`);
  if (jobAt < 0) return [];
  const steps: string[][] = [];
  for (const line of lines.slice(jobAt + 1)) {
    if (/^ {0,2}\S/.test(line)) break;
    if (line.startsWith("      - ")) steps.push([line]);
    else steps.at(-1)?.push(line);
  }
  return steps;
}

/** The `run:` block of the e2e.yml step named `stepName` as lines without the block's indentation, read by text from the step's `name:` line; empty when the step or its block is not where it stands. */
function e2eStepBlock(stepName: string): string[] {
  const lines = workflowLines("e2e.yml");
  const stepAt = lines.indexOf(`      - name: ${stepName}`);
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

/** The `run:` block of e2e.yml's task smoke step (`e2eStepBlock`). */
function taskSmokeStep(): string[] {
  return e2eStepBlock(
    "Register, start and stop the daemon as a startup task (the Password-logon cell)",
  );
}

/** The `run:` block of e2e.yml's provisioning step (`e2eStepBlock`). */
function provisioningStep(): string[] {
  return e2eStepBlock("Create the agent account and provision the layout with the deploy recipe");
}

/** The index of the `}` that closes the `{` at `openAt` in a step's PowerShell, by brace count (no string there holds a brace); -1 when it is never closed. */
function closingBrace(text: string, openAt: number): number {
  let depth = 0;
  for (let at = openAt; at < text.length; at++) {
    if (text[at] === "{") depth++;
    else if (text[at] === "}" && --depth === 0) return at;
  }
  return -1;
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

  it("runs register-service.ps1 a second time once the health route read unlocked and the task's instance is stopped (at most 30 s for it to leave Running), before the teardown, its [Console]::Out captured and printed, and fails unless that run exits 0 and prints the recipe's already-held line for the vault account (the branch where the account holds SeBatchLogonRight)", () => {
    const recipe = psText("windows/register-service.ps1");
    expect(recipe).toContain("\n$BatchLogonRight = 'SeBatchLogonRight'\n");
    expect(recipe).toContain('\n$principalName = "$env:COMPUTERNAME\\$VaultUser"\n');
    expect(recipe).toContain(
      '\nif ($held -contains $BatchLogonRight) {\n  [Console]::Out.WriteLine("right $BatchLogonRight (Log on as a batch job) already held by $principalName")\n} else {\n',
    );
    expect(recipe).toContain("\nExit status: 0 done, 1 not elevated or a command failed");
    const text = taskSmokeStep().join("\n");
    const register =
      "& .\\deploy\\windows\\register-service.ps1 -Node $node -Cli $cli -Password $vaultSecure";
    expect(text.split(register).length - 1).toBe(2);
    const first = text.indexOf(register);
    const second = text.indexOf(register, first + 1);
    const gate = text.indexOf("\n  if ($state -ne 'unlocked') {");
    const gateEnd = gate < 0 ? -1 : closingBrace(text, text.indexOf("{", gate));
    const teardown = text.indexOf("\n} catch {\n  $failure = $_\n} finally {\n");
    const unregister = text.indexOf("& .\\deploy\\windows\\register-service.ps1 -Unregister");
    expect(first).toBeGreaterThan(-1);
    expect(gate).toBeGreaterThan(first);
    expect(gateEnd).toBeGreaterThan(gate);
    expect(second).toBeGreaterThan(gateEnd);
    expect(teardown).toBeGreaterThan(second);
    expect(unregister).toBeGreaterThan(teardown);
    const stop = text.indexOf("\n  Stop-ScheduledTask -TaskName Harpoc\n", gateEnd);
    const wait = text.indexOf(
      "\n  while ((Get-ScheduledTask -TaskName Harpoc).State -eq 'Running'",
      gateEnd,
    );
    expect(stop).toBeGreaterThan(gateEnd);
    expect(wait).toBeGreaterThan(stop);
    expect(second).toBeGreaterThan(wait);
    expect(text.slice(gateEnd + 1, teardown)).toBe(
      [
        "",
        "  Stop-ScheduledTask -TaskName Harpoc",
        "  $stopDeadline = [DateTime]::UtcNow.AddSeconds(30)",
        "  while ((Get-ScheduledTask -TaskName Harpoc).State -eq 'Running' -and [DateTime]::UtcNow -lt $stopDeadline) { Start-Sleep -Seconds 1 }",
        "  if ((Get-ScheduledTask -TaskName Harpoc).State -eq 'Running') { throw 'the Harpoc task still read Running 30 s after Stop-ScheduledTask, before the second registration' }",
        "  $global:LASTEXITCODE = 0",
        "  $rerunWriter = New-Object System.IO.StringWriter",
        "  $consoleOut = [Console]::Out",
        "  [Console]::SetOut($rerunWriter)",
        "  try {",
        "    & .\\deploy\\windows\\register-service.ps1 -Node $node -Cli $cli -Password $vaultSecure",
        "    $rerunExit = $LASTEXITCODE",
        "  } finally {",
        "    [Console]::SetOut($consoleOut)",
        "    $rerunOutput = $rerunWriter.ToString()",
        "    Write-Output '--- the recipe run a second time, the vault account holding the right'",
        "    Write-Output $rerunOutput",
        "  }",
        '  if ($rerunExit -ne 0) { throw "register-service.ps1 run a second time exited $rerunExit" }',
        '  if (-not $rerunOutput.Contains("right SeBatchLogonRight (Log on as a batch job) already held by $env:COMPUTERNAME\\$vaultUser")) { throw "register-service.ps1 run a second time did not print that $env:COMPUTERNAME\\$vaultUser already holds SeBatchLogonRight" }',
        "  Invoke-Diagnostic 'the task after the second registration' { Show-TaskLine 'Harpoc' }",
      ].join("\n"),
    );
  });
});

describe("e2e.yml's provisioning step (the deploy recipe's run, its PowerShell read as text)", () => {
  it("every Get-LocalGroupMember sits in a try's body with -ErrorAction Stop and a catch that throws naming the exception's type, and the step prints no exception's message (a listing that fails ends the step with a fixed text, never a raw error record)", () => {
    const text = provisioningStep().join("\n");
    const lineAt = (at: number): string =>
      text.slice(text.lastIndexOf("\n", at) + 1).split("\n", 1)[0] ?? "";
    const guarded = (at: number): boolean => {
      const tryAt = text.lastIndexOf("try {", at);
      const tryEnd = tryAt < 0 ? -1 : closingBrace(text, tryAt + "try ".length);
      if (tryEnd < at || !lineAt(at).includes("-ErrorAction Stop")) return false;
      if (!text.startsWith(" catch {", tryEnd + 1)) return false;
      const catchOpen = tryEnd + " catch ".length + 1;
      const catchEnd = closingBrace(text, catchOpen);
      const handler = catchEnd < 0 ? "" : text.slice(catchOpen, catchEnd);
      const sid = /-SID '(S-1-5-32-\d+)'/.exec(lineAt(at))?.[1];
      return (
        handler.includes("throw ") &&
        handler.includes("$_.Exception.GetType().FullName") &&
        sid !== undefined &&
        handler.includes(`(${sid})`)
      );
    };
    const calls = [...text.matchAll(/\bGet-LocalGroupMember\b/g)].map((match) => match.index);
    expect(calls.length).toBeGreaterThan(0);
    expect(calls.filter((at) => !guarded(at)).map((at) => lineAt(at).trim())).toEqual([]);
    expect(text.includes(".Exception.Message")).toBe(false);
    expect(
      text.includes("$adminSids -contains $vaultSid -or $adminSids -contains $agentSid"),
      "the Administrators decision compares SIDs",
    ).toBe(true);
    expect(text.includes("$_.Name"), "no group listing is read by name").toBe(false);
  });
});

describe("e2e.yml's two-identity-windows job (its steps read as text)", () => {
  it("runs e2e's four Windows unit files after the task smoke step, unless the run was cancelled, under pwsh and with no tier variable (the seven win32-gated rows, no fleet, outside the gate)", () => {
    const steps = workflowJobSteps("e2e.yml", "two-identity-windows");
    const smokeAt = steps.findIndex(
      (step) =>
        step[0] ===
        "      - name: Register, start and stop the daemon as a startup task (the Password-logon cell)",
    );
    const unitAt = steps.findIndex(
      (step) => step[0] === "      - name: Run e2e's Windows unit files (no fleet)",
    );
    expect(smokeAt).toBeGreaterThan(-1);
    expect(steps[unitAt]).toEqual([
      "      - name: Run e2e's Windows unit files (no fleet)",
      "        if: ${{ !cancelled() }}",
      "        shell: pwsh",
      "        run: pnpm --filter @harpoc/e2e test:e2e src/assert/process-inventory-windows.test.ts src/harness/runas-windows.test.ts src/harness/two-identity-windows.test.ts src/harness/fixtures.test.ts",
    ]);
    expect(unitAt).toBeGreaterThan(smokeAt);
  });
});

describe("ci.yml's Linux filesystem-isolation probe step (read as text)", () => {
  it("names no ubuntu release in its name, its comment or its notice (neither today's image nor an ubuntu-<version>: the image moves, and the step prints which tier it offers)", () => {
    const probes = workflowJobSteps("ci.yml", "build-and-test").filter(
      (step) =>
        (step[0] ?? "").startsWith("      - name: Probe filesystem isolation (diagnostic") &&
        step.includes("        if: runner.os == 'Linux'"),
    );
    expect(probes.length).toBe(1);
    const step = probes[0] ?? [];
    const comment = step.filter((line) => line.startsWith("        # "));
    const notices = [...step.join("\n").matchAll(/::notice::([^"\n]*)/g)].map(
      (match) => match[1] ?? "",
    );
    expect(comment.length).toBeGreaterThan(0);
    expect(notices.length).toBe(1);
    expect(notices[0]?.startsWith("setpriv Landlock unavailable (")).toBe(true);
    expect(
      [step[0] ?? "", ...comment, ...notices].filter((text) => /today's|ubuntu[- ]?\d/i.test(text)),
    ).toEqual([]);
  });
});

/** One argument as the Windows C runtime reads it back (the scripts' ConvertTo-Argument, for paths without quotes). */
const winArg = (value: string): string => (/\s/.test(value) ? `"${value}"` : value);

/** A recipe row's spawn budget: a module-loading cmdlet answers in tens of seconds under the full gate on windows-latest (`decisions.md` § "The WMI listing series"). The budget is 300 s because on a loaded Windows CI leg `register-service.ps1 -DryRun` ran 175 s of the former 180 s, the cost being the first module autoload of a fresh `powershell.exe`. */
const PS1_TIMEOUT_MS = 300_000;

/** The recipe rows' environment: the inherited one with `PSModulePath` narrowed to the in-box modules directory the three scripts import from (Management, Utility, Security, LocalAccounts, ScheduledTasks); Windows PowerShell 5.1 puts `C:\Program Files\WindowsPowerShell\Modules` back ahead of the narrowed path (measured), so the child sees that directory, then the in-box one; a recipe child loads no module through either: each recipe turns auto-loading off and imports a module by its manifest's path under `$PSHOME`. */
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
      env: NodeJS.ProcessEnv = recipeEnvironment(),
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
          env,
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
      "%s calls only commands it resolves without auto-loading (the census through the pinned host's parser): a function it defines, a native program by its path under $env:SystemRoot, a cmdlet of Microsoft.PowerShell.Core, or a cmdlet whose module an Import-InBoxModule call imports before the call, in a block that encloses it",
      (script) => {
        const run = spawnSync(
          POWERSHELL,
          [
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$PSModuleAutoLoadingPreference='None';" +
              "foreach($m in 'Microsoft.PowerShell.Utility','Microsoft.PowerShell.Management','Microsoft.PowerShell.Security','Microsoft.PowerShell.LocalAccounts','ScheduledTasks'){Import-Module -Name ([System.IO.Directory]::GetFiles([System.IO.Path]::Combine($PSHOME,'Modules',$m),$m+'.psd1',[System.IO.SearchOption]::AllDirectories)[0])};" +
              "$t=$null;$e=$null;$a=[System.Management.Automation.Language.Parser]::ParseFile($env:HARPOC_PS1,[ref]$t,[ref]$e);" +
              "[Console]::Out.WriteLine('errors '+$e.Count);" +
              "foreach($f in $a.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]},$true)){[Console]::Out.WriteLine('function '+$f.Name)};" +
              "$sets=@($a.FindAll({param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [System.Management.Automation.Language.VariableExpressionAst]},$true));" +
              "foreach($c in $a.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst]},$true)){$name=$c.GetCommandName();$v=$c.CommandElements[0];" +
              "if($null -eq $name){$by='';if($c.InvocationOperator -eq 'Ampersand' -and $v -is [System.Management.Automation.Language.VariableExpressionAst]){$by=@($sets|Where-Object{$_.Left.VariablePath.UserPath -eq $v.VariablePath.UserPath}|ForEach-Object{$_.Right.Extent.Text}) -join ' | '};" +
              "[Console]::Out.WriteLine('native '+$c.Extent.StartLineNumber+' '+$by)}else{" +
              "$info=@(Get-Command -Name $name -ListImported -ErrorAction SilentlyContinue);$module='-';if($info.Count -gt 0 -and $info[0].ModuleName -ne ''){$module=$info[0].ModuleName};" +
              "[Console]::Out.WriteLine('command '+$c.Extent.StartOffset+' '+$c.Extent.StartLineNumber+' '+$name+' '+$module);" +
              "if($name -eq 'Import-InBoxModule' -and $c.CommandElements.Count -eq 2 -and $c.CommandElements[1] -is [System.Management.Automation.Language.StringConstantExpressionAst]){" +
              "$b=$c.Parent;while($null -ne $b -and -not($b -is [System.Management.Automation.Language.StatementBlockAst] -or $b -is [System.Management.Automation.Language.NamedBlockAst])){$b=$b.Parent};" +
              "[Console]::Out.WriteLine('import '+$c.Extent.StartOffset+' '+$b.Extent.StartOffset+' '+$b.Extent.EndOffset+' '+$c.CommandElements[1].Value)}}}",
          ],
          {
            shell: false,
            windowsHide: true,
            encoding: "utf8",
            timeout: PS1_TIMEOUT_MS,
            env: { ...recipeEnvironment(), HARPOC_PS1: resolve(deployRoot, script) },
          },
        );
        expect(run.error).toBeUndefined();
        expect(run.stderr).toBe("");
        expect(run.status).toBe(0);
        const rows = run.stdout.trim().split(/\r?\n/);
        expect(rows[0]).toBe("errors 0");
        const fields = rows.map((row) => row.split(" "));
        const defined = new Set(fields.filter((f) => f[0] === "function").map((f) => f[1] ?? ""));
        const imports = fields
          .filter((f) => f[0] === "import")
          .map(([, at, from, to, source]) => ({
            at: Number(at),
            from: Number(from),
            to: Number(to),
            source: source ?? "",
          }));
        const commands = fields
          .filter((f) => f[0] === "command")
          .map(([, at, line, command, source]) => ({
            at: Number(at),
            line: line ?? "",
            command: command ?? "",
            source: source ?? "",
          }));
        expect(commands.length).toBeGreaterThan(0);
        const unresolved = commands
          .filter(
            ({ at, command, source }) =>
              !defined.has(command) &&
              source !== "Microsoft.PowerShell.Core" &&
              !imports.some((i) => i.source === source && i.at < at && i.from <= at && at <= i.to),
          )
          .map(({ line, command, source }) => `line ${line}: ${command} (${source})`);
        const byExpression = rows
          .filter((row) => row.startsWith("native "))
          .filter(
            (row) => !/^native \d+ Join-Path \$env:SystemRoot 'System32\\[\w.-]+\.exe'$/.test(row),
          );
        expect([...unresolved, ...byExpression]).toEqual([]);
      },
      PS1_TIMEOUT_MS + 30_000,
    );

    it.each(PS_SCRIPTS)(
      "%s -Help prints its usage and exits 0",
      (script) => {
        const run = runPs1(script, ["-Help"]);
        expect(run.status, run.measured).toBe(0);
        expect(run.stdout).toContain(`Usage: ${script.slice("windows/".length)}`);
        expect(run.stderr, run.measured).toBe("");
      },
      PS1_TIMEOUT_MS + 30_000,
    );

    it(
      "register-service.ps1 -DryRun prints the startup task: the memory session, the DPAPI-sealed key, no time limit — and registers nothing",
      () => {
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
      },
      PS1_TIMEOUT_MS + 30_000,
    );

    function standIn(label: string): { env: NodeJS.ProcessEnv; marker: string } {
      const dir = join(root, `stand-in-${label}`);
      const moduleDir = join(dir, "Microsoft.PowerShell.Management");
      mkdirSync(moduleDir, { recursive: true });
      writeFileSync(
        join(moduleDir, "Microsoft.PowerShell.Management.psd1"),
        "@{ RootModule = 'Microsoft.PowerShell.Management.psm1'; ModuleVersion = '1.0'; FunctionsToExport = @('Test-Path', 'Join-Path'); CmdletsToExport = @(); AliasesToExport = @(); VariablesToExport = @() }\n",
      );
      writeFileSync(
        join(moduleDir, "Microsoft.PowerShell.Management.psm1"),
        [
          "[System.IO.File]::WriteAllText([System.IO.Path]::Combine($PSScriptRoot, 'loaded.marker'), 'loaded')",
          "function Test-Path([string]$LiteralPath, [string]$PathType) {",
          "  if ($PathType -eq 'Leaf') { return [System.IO.File]::Exists($LiteralPath) }",
          "  return [System.IO.Directory]::Exists($LiteralPath)",
          "}",
          "function Join-Path([string]$Path, [string]$ChildPath) {",
          "  return [System.IO.Path]::Combine($Path, $ChildPath)",
          "}",
          "",
        ].join("\n"),
      );
      const env = recipeEnvironment();
      return {
        env: { ...env, PSModulePath: `${dir};${env["PSModulePath"] ?? ""}` },
        marker: join(moduleDir, "loaded.marker"),
      };
    }

    it(
      "register-service.ps1 -DryRun under a PSModulePath whose first directory holds a stand-in Microsoft.PowerShell.Management (Test-Path and Join-Path) prints today's registration and exits 0, and the stand-in never loads: the recipe imports the in-box module by its path under $PSHOME",
      () => {
        const { env, marker } = standIn("dry-run");
        const run = runPs1(
          "windows/register-service.ps1",
          ["-DryRun", "-Node", process.execPath, "-Cli", cli],
          env,
        );
        const base = join(process.env["ProgramData"] ?? "", "harpoc");
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
        ]
          .map(winArg)
          .join(" ");
        expect(run.stderr, run.measured).toBe("");
        expect(run.status, run.measured).toBe(0);
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
        expect(existsSync(marker), run.measured).toBe(false);
      },
      PS1_TIMEOUT_MS + 30_000,
    );

    it.each([
      {
        script: "install-two-identity.ps1",
        args: () => ["-ProgramData", root, "-AgentUser", "Agent"],
        says: "not a consumer name",
      },
      {
        script: "enroll-unlock-key.ps1",
        args: () => [
          "-Node",
          process.execPath,
          "-Cli",
          join(root, "absent"),
          "-Out",
          join(root, "stand-in.dpapi"),
        ],
        says: "-Cli: no built CLI",
      },
    ])(
      "$script under a PSModulePath whose first directory holds a stand-in Microsoft.PowerShell.Management refuses ($says) with exit 2 after its first Test-Path, and the stand-in never loads",
      ({ script, args, says }) => {
        const { env, marker } = standIn(script);
        const run = runPs1(`windows/${script}`, args(), env);
        expect(run.status, run.measured).toBe(2);
        expect(run.stderr.startsWith(`${script}: `), run.measured).toBe(true);
        expect(run.stderr).toContain(says);
        expect(existsSync(marker), run.measured).toBe(false);
      },
      PS1_TIMEOUT_MS + 30_000,
    );

    it(
      "register-service.ps1's account-rights helper compiles under the pinned host and lists an account's own rights without a change",
      () => {
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
      },
      PS1_TIMEOUT_MS + 30_000,
    );

    it(
      "register-service.ps1's Import-InBoxModule, taken through the pinned host's parser and run in a scratch host at its default error preference, ends the host with exit 1 and its not-found line for a module that is not under $PSHOME, and nothing after the call runs (the three recipes' helpers are one text, pinned above)",
      () => {
        const run = spawnSync(
          POWERSHELL,
          [
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$t=$null;$e=$null;$a=[System.Management.Automation.Language.Parser]::ParseFile($env:HARPOC_PS1,[ref]$t,[ref]$e);" +
              "$f=$a.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Import-InBoxModule'},$true);" +
              ". ([scriptblock]::Create($f.Extent.Text));" +
              "Import-InBoxModule 'Harpoc.NoSuchModule';" +
              "[Console]::Out.WriteLine('after Import-InBoxModule')",
          ],
          {
            shell: false,
            windowsHide: true,
            encoding: "utf8",
            timeout: PS1_TIMEOUT_MS,
            env: {
              ...recipeEnvironment(),
              HARPOC_PS1: resolve(deployRoot, "windows/register-service.ps1"),
            },
          },
        );
        expect(run.error).toBeUndefined();
        expect(run.status).toBe(1);
        expect(run.stderr).toContain("the in-box module Harpoc.NoSuchModule was not found under");
        expect(run.stdout.includes("after Import-InBoxModule")).toBe(false);
      },
      PS1_TIMEOUT_MS + 30_000,
    );

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
      PS1_TIMEOUT_MS + 30_000,
    );

    it.each([
      {
        script: "register-service.ps1",
        args: () => ["-DryRun", "-VaultUser", "harpoc\n", "-Node", process.execPath, "-Cli", cli],
        otherwise: "the -DryRun exit",
      },
      {
        script: "install-two-identity.ps1",
        args: () => ["-VaultUser", "harpoc\n", "-ProgramData", "relative"],
        otherwise: "-ProgramData must be an absolute path",
      },
      {
        script: "enroll-unlock-key.ps1",
        args: () => ["-VaultUser", "harpoc\n", "-Out", "relative.dpapi"],
        otherwise: "-Out must be an absolute path",
      },
      {
        script: "register-service.ps1",
        args: () => ["-Unregister", "-DryRun", "-VaultUser", "harpoc\n"],
        otherwise: "-Unregister takes -VaultUser alone",
      },
    ])(
      "$script refuses an account name that ends in a line feed (not an account name) with exit 2 before its administrator check, where it otherwise stops at $otherwise",
      ({ script, args }) => {
        const run = runPs1(`windows/${script}`, args());
        expect(run.status, run.measured).toBe(2);
        expect(run.stderr.startsWith(`${script}: not an account name (`), run.measured).toBe(true);
        expect(run.stdout, run.measured).toBe("");
      },
      PS1_TIMEOUT_MS + 30_000,
    );

    // Elevated, the scripts pass their administrator check and would create the account, the
    // directories and the task, and `-Unregister` would remove the task and the right: the
    // runners run elevated, so this row is the desktop's.
    it(
      "with valid arguments each script stops at its administrator check for a non-elevated user (exit 1, nothing created)",
      (ctx) => {
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
      },
      4 * PS1_TIMEOUT_MS + 30_000,
    );

    // Elevated, the layout is readable and the scripts go on past their checks: like the row above, the desktop's.
    it(
      "on the layout the recipe leaves (harpoc and harpoc\\vault open to SYSTEM and Administrators alone) install-two-identity.ps1 and enroll-unlock-key.ps1 stop at their administrator check for a non-elevated user (exit 1, no PowerShell text)",
      (ctx) => {
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
      },
      3 * (PS1_TIMEOUT_MS + 30_000),
    );

    it(
      "install-two-identity.ps1 refuses an existing harpoc directory that is a junction (a reparse point) as a usage error before its administrator check",
      () => {
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
      },
      PS1_TIMEOUT_MS + 30_000,
    );

    it(
      "install-two-identity.ps1 refuses an existing harpoc that is a file, not a directory, as a usage error before its administrator check",
      () => {
        const programData = join(root, "ProgramData-file");
        mkdirSync(programData);
        const file = join(programData, "harpoc");
        writeFileSync(file, "");
        const run = runPs1("windows/install-two-identity.ps1", ["-ProgramData", programData]);
        expect(run.stderr, run.measured).toBe(
          `install-two-identity.ps1: ${file} exists and is not a directory; remove it\r\n`,
        );
        expect(run.status, run.measured).toBe(2);
      },
      PS1_TIMEOUT_MS + 30_000,
    );
  },
);
